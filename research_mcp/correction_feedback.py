"""Trusted reviewed corrections, represented solely by source-owned synthetic case IDs."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from .correction_rules import contract_digest, load_cases

SCHEMA = "injecticide.reviewed-correction.v1"

def cases():
    return {item["id"]: item for item in load_cases()}

def reviewable_cases():
    return {key: item for key, item in cases().items() if item["expected"] != "keep"}

def record_review(folder, case_id):
    root = Path(folder)
    if not root.is_dir() or root.is_symlink() or case_id not in reviewable_cases():
        raise ValueError("A trusted signal directory and known synthetic case are required")
    value = {"schema": SCHEMA, "case_id": case_id, "contract_sha256": contract_digest()}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(list(root.glob("*.json"))) >= 10000:
        raise OverflowError("Signal capacity reached")
    target = root / ("correction-review-" + hashlib.sha256(raw).hexdigest() + ".json")
    if not target.exists():
        temporary = root / ("." + uuid.uuid4().hex + ".tmp")
        with temporary.open("xb") as stream:
            stream.write(raw)
        os.replace(temporary, target)
    return {"status": "reviewed", "case_id": case_id, "private_content_retained": False}

def reviewed_ids(folder):
    root = Path(folder)
    result = set()
    if not root.is_dir():
        return []
    known = reviewable_cases()
    for path in sorted(root.glob("correction-review-*.json"))[:1000]:
        try:
            if path.is_symlink() or path.stat().st_size > 1024:
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
            if (set(value) == {"schema", "case_id", "contract_sha256"}
                    and value["schema"] == SCHEMA
                    and value["contract_sha256"] == contract_digest()
                    and value["case_id"] in known):
                result.add(value["case_id"])
        except (OSError, ValueError, TypeError):
            continue
    return sorted(result)

def model_examples(case_ids):
    # These texts are reconstructed from shipped synthetic fixtures, never scan evidence.
    selected = reviewable_cases()
    if any(key not in selected for key in case_ids):
        raise ValueError("Unknown reviewed correction")
    features = {selected[key]["feature"] for key in case_ids}
    result = []
    for item in load_cases():
        if item["feature"] not in features:
            continue
        text = re.sub(r"\d", "#", item["text"])
        text = re.sub(r"[\w.+-]+@[\w.-]+", "[synthetic-email-shape]", text)
        result.append({"case_id": item["id"], "feature": item["feature"],
                       "detector": item["detector"], "example_shape": text,
                       "expected": item["expected"], "source_owned_synthetic": True})
    return result

def main():
    parser = argparse.ArgumentParser(description="Trusted local review of source-owned synthetic corrections")
    parser.add_argument("--signals", type=Path,
                        default=Path(os.environ.get("INJECTICIDE_RESEARCH_SIGNALS_DIR", "/research-signals")))
    parser.add_argument("command", choices=["list", "record"])
    parser.add_argument("--case", default="")
    args = parser.parse_args()
    if args.command == "record":
        print(json.dumps(record_review(args.signals, args.case)))
    else:
        print(json.dumps({"available": sorted(reviewable_cases()), "reviewed": reviewed_ids(args.signals)}))

if __name__ == "__main__":
    main()
