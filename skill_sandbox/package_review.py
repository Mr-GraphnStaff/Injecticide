"""Offline review tools; explicitly invoked by an operator, never by an upload.

validate-update checks a candidate source/check registry and pinned schema hashes.
evaluate calls one administrator-installed isolated test runner. The runner must
provide its own container/VM isolation and return bounded scenario evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from datetime import date

from .package_formats import bounded_data
from .review_evidence import evaluation_status


def validate_update(directory):
    root = Path(directory)
    sources = bounded_data((root / "sources.json").read_text(encoding="utf-8"))
    checks = bounded_data((root / "proposed-checks.json").read_text(encoding="utf-8"))
    ids = [s["id"] for s in sources["sources"]] if isinstance(sources, dict) else [s["id"] for s in sources]
    source_items = sources["sources"] if isinstance(sources, dict) else sources
    if len(set(ids)) != len(ids) or not all(s.get("url", "").startswith("https://") and s.get("reviewed_on") for s in source_items):
        raise ValueError("Sources require unique IDs, HTTPS URLs and review dates")
    for source in source_items:
        if date.fromisoformat(source["reviewed_on"]) > date.today():
            raise ValueError("Source review date is in the future")
    check_ids = []
    for check in checks["checks"]:
        check_ids.append(check["id"])
        if not check.get("source_ids") or set(check["source_ids"]) - set(ids):
            raise ValueError("Check has missing or unknown sources")
    if len(set(check_ids)) != len(check_ids):
        raise ValueError("Duplicate check identifiers")
    schema_root = Path(__file__).parent / "schemas"
    provenance = json.loads((schema_root / "provenance.json").read_text())
    for item in provenance:
        path = schema_root / item["file"]
        if not path.resolve().is_relative_to(schema_root.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("Pinned schema fingerprint mismatch")
    return {"status": "candidate_validated_not_activated", "sources": len(ids), "checks": len(check_ids),
            "promotion": "Run regression corpus; review code and sources; human PR acceptance; versioned application release"}


def evaluate(artifact):
    runner = os.getenv("INJECTICIDE_EVALUATION_RUNNER")
    if not runner or not Path(runner).is_absolute() or not Path(runner).is_file():
        raise ValueError("Configure an absolute administrator-installed isolated evaluation runner")
    artifact = Path(artifact).resolve(strict=True)
    if not artifact.is_file() or artifact.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Evaluation input must be a file of at most 32 MiB")
    with tempfile.TemporaryDirectory(prefix="injecticide-eval-") as directory:
        output = Path(directory) / "evidence.json"
        subprocess.run([runner, "--artifact", str(artifact), "--sha256", hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "--output", str(output)], timeout=120, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
        if not output.is_file() or output.stat().st_size > 131072:
            raise ValueError("Runner output missing or exceeds evidence budget")
        evidence = bounded_data(output.read_text(encoding="utf-8"))
        if evaluation_status(evidence) == "insufficient_evidence":
            raise ValueError("Runner must report positive, negative, coexistence and bounded workflow cases")
        return {"artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "evaluation": evidence,
                "status": "runner_claim_requires_authenticated_issuer_envelope", "isolation": "operator_managed_not_verified_by_static_scanner"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate-update", "evaluate"))
    parser.add_argument("path")
    args = parser.parse_args()
    print(json.dumps(validate_update(args.path) if args.action == "validate-update" else evaluate(args.path), indent=2))


if __name__ == "__main__":
    main()
