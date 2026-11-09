"""Trusted offline gate against actual scanner outcomes on shipped synthetic cases."""
from __future__ import annotations

import hashlib
from collections import Counter
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone

if __package__:
    from .correction_rules import contract_digest, evaluate_pack, load_cases, using_pack, validate_pack
    from .package_evidence import scanner_metadata
else:
    from correction_rules import contract_digest, evaluate_pack, load_cases, using_pack, validate_pack
    from package_evidence import scanner_metadata

RECEIPT_SCHEMA = "injecticide.correction-gate.v1"
GATE_REVISION = 2
MAX_PACK_BYTES = 65536


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON field")
        value[key] = item
    return value


def _reject_constant(value):
    raise ValueError("Nonfinite JSON value")


def read_pack(stream):
    raw = stream.read(MAX_PACK_BYTES + 1)
    if not raw or len(raw) > MAX_PACK_BYTES:
        raise ValueError("Correction pack budget")
    return validate_pack(json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant))


def _actionable_ids(findings):
    return sorted({item["id"] for item in findings
                   if isinstance(item, dict) and isinstance(item.get("id"), str)
                   and re.fullmatch(r"[a-z0-9_]{1,64}", item["id"])
                   and item.get("severity") in {"low", "medium", "high", "critical"}
                   and item.get("is_actionable", True) is not False})


def _outcomes(findings):
    return sorted(hashlib.sha256(canonical(item)).hexdigest() for item in findings)

def _native_findings(case,pack):
    if __package__:
        from .app import scan_upload
    else:
        from app import scan_upload
    raw=case["text"].encode("utf-8")
    if "database" in case:
        spec=case["database"]
        connection=sqlite3.connect(":memory:")
        try:
            columns=spec["columns"]
            connection.execute("CREATE TABLE facts ("+",".join('"'+c+'" TEXT' for c in columns)+")")
            connection.executemany("INSERT INTO facts VALUES ("+",".join("?" for c in columns)+")",spec["rows"])
            connection.commit()
            raw=connection.serialize()
        finally:
            connection.close()
    value=scan_upload(raw,case["path"],correction_pack=pack)
    findings=[]
    for entry in value["files"]:
        findings.extend(entry["findings"])
        if "database_profile" in entry:
            findings.append({"id":"database_profile","severity":"info","profile":entry["database_profile"]})
    return findings,value["correction_application"]["rules"]


def run_gate(pack, scanner=None):
    """Produce a content-free receipt; all acceptance labels belong to source."""
    validate_pack(pack)
    before_contract=contract_digest()
    interpretation = evaluate_pack(pack)
    native_scanner=scanner is None
    if scanner is None:
        if __package__:
            from .app import _scan_text_plain
        else:
            from app import _scan_text_plain
        scanner = _scan_text_plain
    before_identity = scanner_metadata()
    cases = []
    reductions = preserved = losses = 0
    verified=set()
    for case in load_cases():
        if native_scanner:
            baseline_findings,_=_native_findings(case,None)
            corrected_findings,applied=_native_findings(case,pack)
        else:
            with using_pack(None):
                baseline_findings=scanner(case["path"],case["text"],"active")
            with using_pack(pack,gate=False) as stats:
                corrected_findings=scanner(case["path"],case["text"],"active")
                applied=sorted(stats["rules"])
        baseline=_actionable_ids(baseline_findings)
        corrected=_actionable_ids(corrected_findings)
        original, updated = set(baseline), set(corrected)
        before_outcomes,after_outcomes=_outcomes(baseline_findings),_outcomes(corrected_findings)
        if case["expected"] == "keep":
            before_counter,after_counter=Counter(before_outcomes),Counter(after_outcomes)
            preserved += sum((before_counter & after_counter).values())
            losses += sum((before_counter - after_counter).values())
        elif any(rule["detector"] == case["detector"] and
                 case["feature"] in rule["all_features"] for rule in pack["rules"]):
            # Both removal and downgrade count only when an actionable target
            # actually existed. Already informational/absent cases count zero.
            reductions += int(case["detector"] in original - updated)
        if case["expected"]=="correct" and case["detector"] not in updated:
            verified.update((rule["id"],case["feature"]) for rule in pack["rules"]
                            if rule["id"] in applied and rule["detector"]==case["detector"]
                            and case["feature"] in rule["all_features"])
        cases.append({"applied_rules":applied,"id": case["id"], "baseline": baseline,
                      "corrected": corrected, "expected": case["expected"],
                      "baseline_outcomes":before_outcomes,"corrected_outcomes":after_outcomes})
    after_identity = scanner_metadata()
    identity_stable = (before_identity["engine_source_sha256"] == after_identity["engine_source_sha256"]
                       and before_identity["scanner_version"] == after_identity["scanner_version"]
                       and before_contract==contract_digest()==pack["contract_sha256"])
    return {"schema": RECEIPT_SCHEMA,
            "pack_sha256": hashlib.sha256(canonical(pack)).hexdigest(),
            "contract_sha256": contract_digest(),
            "scanner_source_sha256": after_identity["engine_source_sha256"],
            "scanner_version": after_identity["scanner_version"],
            "gate_revision": GATE_REVISION,
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "passed": interpretation.get("passed") is True and identity_stable
                      and reductions > 0 and preserved > 0 and losses == 0
                      and all((rule["id"],feature) in verified for rule in pack["rules"] for feature in rule["all_features"]),
            "fp_reductions": reductions, "protected_preserved": preserved,
            "protected_losses": losses, "cases": cases}


def main():
    try:
        receipt = run_gate(read_pack(sys.stdin.buffer))
        print(canonical(receipt).decode("utf-8"))
        return 0 if receipt["passed"] else 1
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as error:
        # Never echo a submitted pack, source excerpt, or exception message.
        print(json.dumps({"error": type(error).__name__, "passed": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
