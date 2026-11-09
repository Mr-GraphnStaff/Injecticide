"""Trusted correction review/activation and read-only scanner delivery."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from .catalog import Catalog
from .correction_learning import SCHEMA, canonical, pack_digest, validate_proposal, gate_summary
from .correction_rules import contract_digest, validate_pack, load_cases

ENVELOPE = "injecticide.approved-corrections.v1"
RECEIPT = "injecticide.correction-gate.v1"
SCANNER_VERSION = "0.18.0"
GATE_REVISION = 1

def validate_receipt(value, pack, *, fresh=True):
    fields={"schema","pack_sha256","contract_sha256","scanner_source_sha256","scanner_version",
            "gate_revision","issued_at","passed","fp_reductions","protected_preserved",
            "protected_losses","cases"}
    if (not isinstance(value,dict) or set(value)!=fields or value["schema"]!=RECEIPT
            or value["pack_sha256"]!=pack_digest(pack)
            or value["contract_sha256"]!=contract_digest()
            or value["scanner_version"]!=SCANNER_VERSION
            or type(value["gate_revision"]) is not int or value["gate_revision"]!=GATE_REVISION or value["passed"] is not True
            or not re.fullmatch(r"[a-f0-9]{64}",str(value["scanner_source_sha256"]))
            or type(value["fp_reductions"]) is not int or value["fp_reductions"]<1
            or type(value["protected_preserved"]) is not int or value["protected_preserved"]<1
            or type(value["protected_losses"]) is not int or value["protected_losses"]!=0 or not isinstance(value["cases"],list)):
        raise ValueError("Actual scanner gate receipt is missing or mismatched")
    issued=datetime.fromisoformat(value["issued_at"])
    if issued.tzinfo is None or (fresh and not -30<=(datetime.now(timezone.utc)-issued).total_seconds()<=900):
        raise ValueError("Actual scanner gate receipt expired")
    corpus={item["id"]:item for item in load_cases()}
    known=set(corpus)
    reductions=preserved=losses=0
    observed=set()
    for item in value["cases"]:
        if (not isinstance(item,dict) or set(item)!={"id","baseline","corrected","expected","baseline_outcomes","corrected_outcomes"}
                or item["id"] not in known or item["id"] in observed
                or not isinstance(item["baseline"],list) or not isinstance(item["corrected"],list)
                or any(not isinstance(x,str) or not re.fullmatch(r"[a-z0-9_]{1,64}",x)
                       for x in item["baseline"]+item["corrected"])):
            raise ValueError("Invalid scanner contrastive case evidence")
        source=corpus[item["id"]]
        if item["expected"]!=source["expected"]:
            raise ValueError("Operator receipt changed source-owned labels")
        before,after=set(item["baseline"]),set(item["corrected"])
        if len(before)!=len(item["baseline"]) or len(after)!=len(item["corrected"]):
            raise ValueError("Duplicate observed detector outcome")
        for key in ["baseline_outcomes","corrected_outcomes"]:
            if not isinstance(item[key],list) or len(item[key])>256 or any(not isinstance(x,str) or not re.fullmatch(r"[a-f0-9]{64}",x) for x in item[key]):
                raise ValueError("Invalid protected finding fingerprints")
        if source["expected"]=="keep":
            original,updated=Counter(item["baseline_outcomes"]),Counter(item["corrected_outcomes"])
            preserved+=sum((original & updated).values())
            losses+=sum((original-updated).values())
        elif any(rule["detector"]==source["detector"] and source["feature"] in rule["all_features"] for rule in pack["rules"]):
            reductions+=int(source["detector"] in before-after)
        observed.add(item["id"])
    if (value["fp_reductions"]!=reductions or value["protected_preserved"]!=preserved
            or value["protected_losses"]!=losses or losses):
        raise ValueError("Actual scanner outcome counts do not match evidence")
    if observed!=known or gate_summary(pack)["passed"] is not True:
        raise ValueError("Incomplete source-owned scanner gate")
    return value

class CorrectionStore:
    def __init__(self,catalog,folder):
        self.catalog,self.folder=catalog,Path(folder)
        self.stop_event=threading.Event()
        self.thread=threading.Thread(target=self.run,name="correction-inbox",daemon=True)
        self.last_error=None
        with catalog.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS correction_proposals(
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,artifact_sha TEXT UNIQUE NOT NULL,
                 pack_sha TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'review');
                CREATE TABLE IF NOT EXISTS correction_activations(
                 revision INTEGER PRIMARY KEY AUTOINCREMENT,pack_sha TEXT,payload TEXT,
                 receipt TEXT,created_at TEXT NOT NULL,action TEXT NOT NULL);
            """)

    def import_files(self):
        count=0
        if not self.folder.is_dir() or self.folder.is_symlink():
            return {"imported":0,"last_error":None}
        for path in sorted(self.folder.glob("*.json"))[:1000]:
            try:
                if not re.fullmatch(r"[a-f0-9]{64}\.json",path.name) or path.is_symlink():
                    continue
                fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
                with os.fdopen(fd,"rb") as stream:raw=stream.read(65537)
                if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=path.stem:
                    raise ValueError("Correction inbox integrity")
                value=json.loads(raw)
                if not isinstance(value,dict):raise ValueError("Correction record must be an object")
                if value.get("schema")!=SCHEMA:
                    continue
                validate_proposal(value)
                with self.catalog.db() as db:
                    if db.execute("SELECT count(*) FROM correction_proposals").fetchone()[0]>=1000:
                        raise OverflowError("Correction review capacity")
                    count+=db.execute("INSERT OR IGNORE INTO correction_proposals(artifact_sha,pack_sha,payload) VALUES(?,?,?)",
                                      (path.stem,value["pack_sha256"],canonical(value).decode())).rowcount
            except (ValueError,TypeError,KeyError,OSError,OverflowError) as error:
                self.last_error=type(error).__name__
        return {"imported":count,"last_error":self.last_error}

    def list(self,after_id=0,limit=20):
        if type(after_id) is not int or after_id<0 or type(limit) is not int or not 1<=limit<=100:
            raise ValueError("Invalid correction page")
        with self.catalog.db() as db:
            rows=db.execute("SELECT * FROM correction_proposals WHERE seq>? ORDER BY seq LIMIT ?",(after_id,limit)).fetchall()
        return {"items":[{"sequence":r["seq"],"pack_sha256":r["pack_sha"],"state":r["state"],
                          "proposal":json.loads(r["payload"])} for r in rows],
                "authority":"untrusted_proposals_not_active_rules"}

    def get(self,sha):
        if not re.fullmatch(r"[a-f0-9]{64}",sha):
            raise ValueError("Expected correction pack digest")
        with self.catalog.db() as db:
            row=db.execute("SELECT * FROM correction_proposals WHERE pack_sha=?",(sha,)).fetchone()
        if not row:raise ValueError("Correction proposal unavailable")
        value=json.loads(row["payload"])
        validate_proposal(value)
        return row["state"],value

    def approve(self,sha,receipt):
        state,value=self.get(sha)
        if state not in {"review","approved"}:
            raise ValueError("Rejected correction cannot activate")
        pack=value["pack"]
        validate_receipt(receipt,pack)
        # Receipt is an explicit privileged operator attestation, never model input.
        with self.catalog.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT state FROM correction_proposals WHERE pack_sha=?",(sha,)).fetchone()
            if row[0] not in {"review","approved"}:
                raise ValueError("Correction changed during review")
            db.execute("UPDATE correction_proposals SET state='approved' WHERE pack_sha=?",(sha,))
            cursor=db.execute("""INSERT INTO correction_activations(pack_sha,payload,receipt,created_at,action)
               VALUES(?,?,?,?, 'approve_and_activate')""",
               (sha,canonical(pack).decode(),canonical(receipt).decode(),datetime.now(timezone.utc).isoformat()))
            revision=cursor.lastrowid
        return {"status":"active","revision":revision,"pack_sha256":sha}

    def reject(self,sha):
        self.get(sha)
        with self.catalog.db() as db:
            changed=db.execute("UPDATE correction_proposals SET state='rejected' WHERE pack_sha=? AND state='review'",(sha,)).rowcount
        if changed!=1:raise ValueError("Only an unapproved proposal may be rejected")
        return {"status":"rejected","pack_sha256":sha}

    def deactivate(self,expected_revision):
        with self.catalog.db() as db:
            db.execute("BEGIN IMMEDIATE")
            current=db.execute("SELECT coalesce(max(revision),0) FROM correction_activations").fetchone()[0]
            if current!=expected_revision:raise ValueError("Active revision changed")
            cursor=db.execute("""INSERT INTO correction_activations(created_at,action)
                VALUES(?,'deactivate')""",(datetime.now(timezone.utc).isoformat(),))
        return {"status":"disabled","revision":cursor.lastrowid}

    def active(self):
        with self.catalog.db() as db:
            row=db.execute("SELECT * FROM correction_activations ORDER BY revision DESC LIMIT 1").fetchone()
        result={"schema":ENVELOPE,"revision":row["revision"] if row else 0,"state":"disabled",
                "pack":None,"pack_sha256":None,"scanner_version":SCANNER_VERSION,
                "scanner_source_sha256":None,"contract_sha256":contract_digest(),"gate_revision":GATE_REVISION}
        if row and row["payload"]:
            try:
                pack=validate_pack(json.loads(row["payload"]))
                receipt=json.loads(row["receipt"])
                validate_receipt(receipt,pack,fresh=False)
                if receipt["contract_sha256"]!=contract_digest() or receipt["scanner_version"]!=SCANNER_VERSION:
                    raise ValueError("Stale scanner approval")
                result.update(state="active",pack=pack,pack_sha256=pack_digest(pack),
                              scanner_source_sha256=receipt["scanner_source_sha256"])
            except (ValueError,KeyError,TypeError):
                result["state"]="stale"
        return result

    def status(self):
        with self.catalog.db() as db:
            counts=dict(db.execute("SELECT state,count(*) FROM correction_proposals GROUP BY state"))
        active=self.active()
        return {"counts":counts,"active_revision":active["revision"],"active_state":active["state"],
                "model_access":False,"approval_interface":"trusted_local_cli_only","last_error":self.last_error}

    def run(self):
        while not self.stop_event.is_set():
            try:self.import_files()
            except Exception as error:self.last_error=type(error).__name__
            self.stop_event.wait(30)

    def close(self):
        self.stop_event.set()
        if self.thread.is_alive():self.thread.join(timeout=10)

def main():
    parser=argparse.ArgumentParser(description="Privileged local correction review; no network approval route")
    parser.add_argument("--db",type=Path,default=Path("/data/research.sqlite3"))
    parser.add_argument("--inbox",type=Path,default=Path("/research-inbox"))
    parser.add_argument("command",choices=["list","get","approve","reject","active","deactivate"])
    parser.add_argument("--sha",default="")
    parser.add_argument("--expected-revision",type=int,default=-1)
    args=parser.parse_args()
    store=CorrectionStore(Catalog(args.db,Path(__file__).with_name("sources.json")),args.inbox)
    store.import_files()
    if args.command=="approve":
        import sys
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536:raise ValueError("Receipt budget")
        result=store.approve(args.sha,json.loads(raw))
    elif args.command=="reject":result=store.reject(args.sha)
    elif args.command=="deactivate":result=store.deactivate(args.expected_revision)
    elif args.command=="active":result=store.active()
    elif args.command=="get":result=store.get(args.sha)[1]
    else:result=store.list()
    print(json.dumps(result))

if __name__=="__main__":
    main()
