"""One-way import of untrusted research files. No model/client/network calls."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import threading
from pathlib import Path

from .catalog import Catalog,STATUS
from .public_web import public_url
from .research_signals import SIGNALS,model_signals

SCHEMA="injecticide.scheduled-research.v1"


def validate_record(value):
    fields={"schema","run_id","day","generated_at","model","planning_model","signals",
            "sources","proposals","fetch_failures","verification","model_weights_updated"}
    if (not isinstance(value,dict) or set(value)!=fields or value["schema"]!=SCHEMA
            or not isinstance(value["run_id"],str) or not re.fullmatch(r"[a-f0-9]{32}",value["run_id"])
            or value["verification"]!=STATUS or value["model_weights_updated"] is not False
            or not isinstance(value["signals"],list) or any(x not in SIGNALS for x in value["signals"])
            or not isinstance(value["sources"],list) or not 1<=len(value["sources"])<=6
            or not isinstance(value["proposals"],list) or len(value["proposals"])>3):
        raise ValueError("Invalid scheduled research record")
    lookup={}
    for source in value["sources"]:
        if (not isinstance(source,dict) or set(source)!={"id","url","sha256","text"}
                or type(source["id"]) is not int or source["id"] in lookup
                or not isinstance(source["sha256"],str) or not re.fullmatch(r"[a-f0-9]{64}",source["sha256"])
                or not isinstance(source["text"],str) or len(source["text"])>1800):
            raise ValueError("Invalid public source")
        public_url(source["url"]);lookup[source["id"]]=source
    for item in value["proposals"]:
        if (not isinstance(item,dict) or set(item)!={"source_id","quote","summary"}
                or type(item["source_id"]) is not int or item["source_id"] not in lookup
                or not isinstance(item["quote"],str) or not 8<=len(item["quote"])<=200
                or item["quote"] not in lookup[item["source_id"]]["text"]
                or not isinstance(item["summary"],str) or not 1<=len(item["summary"])<=400):
            raise ValueError("Unsupported public research quote")
    return value


class ResearchInbox:
    def __init__(self,catalog,folder):
        self.catalog,self.folder=catalog,Path(folder)
        self.stop_event=threading.Event()
        self.thread=threading.Thread(target=self.run,name="research-inbox",daemon=True)
        self.last_error=None
        with catalog.db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS scheduled_research (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,sha256 TEXT UNIQUE NOT NULL,
                payload TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'review')""")

    def import_files(self):
        imported=0
        if not self.folder.is_dir() or self.folder.is_symlink():return {"imported":0}
        for path in sorted(self.folder.glob("*.json"))[:1000]:
            if not re.fullmatch(r"[a-f0-9]{64}\.json",path.name):continue
            try:
                if path.is_symlink() or path.stat().st_size>65536:raise ValueError("Unsafe inbox file")
                # O_NOFOLLOW closes the check/open race on the deployed Linux host.
                fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
                with os.fdopen(fd,"rb") as stream:raw=stream.read(65537)
                digest=hashlib.sha256(raw).hexdigest()
                if len(raw)>65536 or path.stem!=digest:raise ValueError("Inbox integrity")
                parsed=json.loads(raw)
                if isinstance(parsed,dict) and parsed.get("schema")=="injecticide.correction-proposal.v1":
                    continue
                value=validate_record(parsed)
                with self.catalog.db() as db:
                    if db.execute("SELECT count(*) FROM scheduled_research").fetchone()[0]>=1000:
                        raise ValueError("Retained research capacity")
                    imported+=db.execute("INSERT OR IGNORE INTO scheduled_research(sha256,payload) VALUES (?,?)",
                        (digest,json.dumps(value,ensure_ascii=True))).rowcount
            except Exception as error:self.last_error=type(error).__name__
        return {"imported":imported,"last_error":self.last_error}

    def list(self,after_id=0,limit=20,state=""):
        if type(after_id) is not int or after_id<0 or type(limit) is not int or not 1<=limit<=100 or state not in {"","review","approved","rejected"}:
            raise ValueError("Invalid research page")
        with self.catalog.db() as db:
            rows=db.execute("""SELECT * FROM scheduled_research WHERE seq>? AND (?='' OR state=?)
                ORDER BY seq LIMIT ?""",(after_id,state,state,limit)).fetchall()
        return {"authority":"unverified_public_research_not_active_rules","untrusted_content":True,"items":[
            {"sequence":r["seq"],"sha256":r["sha256"],"state":r["state"],"payload":json.loads(r["payload"])} for r in rows]}

    def status(self):
        with self.catalog.db() as db:
            counts={r[0]:r[1] for r in db.execute("SELECT state,count(*) FROM scheduled_research GROUP BY state")}
        return {"one_way":True,"model_access":False,"counts":counts,"last_error":self.last_error,
                "schedule":{"hour":2,"timezone":"America/Chicago"}}

    def review(self,sha256,state):
        if not re.fullmatch(r"[a-f0-9]{64}",sha256) or state not in {"approved","rejected"}:
            raise ValueError("Invalid trusted local review")
        with self.catalog.db() as db:
            changed=db.execute("UPDATE scheduled_research SET state=? WHERE sha256=? AND state='review'",(state,sha256)).rowcount
        if changed!=1:raise ValueError("Record changed or is unavailable")
        return {"sha256":sha256,"state":state}

    def training_examples(self):
        # Approved public sources only. No scan fields or active-session data exist here.
        examples=[]
        cursor=0
        while True:
            items=self.list(after_id=cursor,limit=100,state="approved")["items"]
            if not items:break
            for item in items:
                context=json.dumps(model_signals(item["payload"]["signals"]),sort_keys=True)
                for proposal in item["payload"]["proposals"]:
                    examples.append({"messages":[{"role":"user","content":"Technical categories: "+context+"; explain reviewed public evidence: "+proposal["quote"]},
                        {"role":"assistant","content":proposal["summary"]}],
                        "source_sha256":item["sha256"],"training_status":"curated_example_not_model_weights"})
            cursor=items[-1]["sequence"]
        return examples

    def run(self):
        while not self.stop_event.is_set():
            try:self.import_files()
            except Exception as error:self.last_error=type(error).__name__
            self.stop_event.wait(30)

    def close(self):
        self.stop_event.set()
        if self.thread.is_alive():self.thread.join(timeout=10)


def main():
    parser=argparse.ArgumentParser(description="Trusted local research review and offline dataset export")
    parser.add_argument("--db",type=Path,default=Path("/data/research.sqlite3"))
    parser.add_argument("--sources",type=Path,default=Path(__file__).with_name("sources.json"))
    parser.add_argument("--inbox",type=Path,default=Path("/research-inbox"))
    parser.add_argument("command",choices=["list","review","training-export"])
    parser.add_argument("--sha256",default="")
    parser.add_argument("--state",default="")
    args=parser.parse_args()
    inbox=ResearchInbox(Catalog(args.db,args.sources),args.inbox)
    if args.command=="training-export":
        for example in inbox.training_examples():print(json.dumps(example,ensure_ascii=True))
    else:print(json.dumps(inbox.review(args.sha256,args.state) if args.command=="review" else inbox.list(),ensure_ascii=True))


if __name__=="__main__":main()
