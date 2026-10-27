"""Opt-in, local synthetic evaluation and hash-bound exported-report comparison.

This is regression evidence, not an independent benchmark or a safety score.
No uploaded scripts, LLMs or network requests are executed. The scanner may run
its reviewed bundled metadata-only format validators; nothing is fetched to run.
"""
from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "tests" / "fixtures" / "scanner_evaluation" / "manifest.json"
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_FIXTURE_BYTES = 2 * 1024 * 1024
MAX_REPORT_FILES = 4096
MAX_REPORT_FINDINGS = 50000
MAX_REPORT_OBSERVATIONS = 200000
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
SENSITIVE_RULE_IDS = {"pii_email_address", "pii_phone_number", "pii_ssn", "pii_date_of_birth",
                      "phi_medical_record_number", "phi_patient_record"}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys are not accepted")
        result[key] = value
    return result


def _load_json(path: Path, limit: int = MAX_REPORT_BYTES) -> dict:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"JSON input exceeds {limit} bytes")
    data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return data


def _artifact_hash(report: dict) -> str:
    evidence = report.get("governance_evidence", {})
    digest = evidence.get("artifact_sha256") if isinstance(evidence, dict) else None
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ValueError("Both reports require governance_evidence.artifact_sha256 (64 hex characters)")
    return digest.lower()


def _findings(report: dict) -> dict:
    """Keep observation locations, never echo sensitive samples or source content."""
    found = {}
    for entry in report.get("files", []):
        for finding in entry.get("findings", []):
            _add_finding(found, entry.get("path"), finding)
    for finding in report.get("package_analysis", {}).get("format_findings", []):
        _add_finding(found, finding.get("path"), finding)
    return found


def _add_finding(found: dict, path: str, finding: dict) -> None:
    identifier = finding.get("id")
    if not isinstance(path, str) or not isinstance(identifier, str):
        return
    key = (path.replace("\\", "/"), identifier)
    row = found.setdefault(key, {"locations": set(), "tiers": set(), "severities": set()})
    for observation in finding.get("observations", []):
        if isinstance(observation, dict) and type(observation.get("line")) is int:
            row["locations"].add(observation["line"])
    for field in ("source_start_line", "line"):
        if type(finding.get(field)) is int:
            row["locations"].add(finding[field])
    if isinstance(finding.get("tier"), str):
        row["tiers"].add(finding["tier"])
    if isinstance(finding.get("severity"), str):
        row["severities"].add(finding["severity"])


def _file(report: dict, path: str) -> dict:
    for collection in ("files", "inventory"):
        for item in report.get(collection, []):
            if item.get("path", "").replace("\\", "/") == path:
                return item
    return {}


@lru_cache(maxsize=1)
def _text_rule_ids():
    try:
        catalog = _load_json(ROOT / "skill_sandbox" / "rules" / "violations.json", 1024 * 1024)
        return frozenset(rule["id"] for rule in catalog.get("rules", [])
                         if isinstance(rule, dict) and isinstance(rule.get("id"), str))
    except (OSError, ValueError, TypeError):
        return frozenset()


def _absence_state(report: dict, path: str, identifier: str) -> str:
    entry = _file(report, path)
    state = entry.get("assessment_state")
    if state in {"unsupported", "binary_asset_inventory_only", "executable_not_analyzed", "rejected_unsafe_entry"}:
        return "not_inspected"
    matching = [item for collection in ("files", "inventory") for item in report.get(collection, [])
                if item.get("path", "").replace("\\", "/") == path]
    if state != "text_analyzed" or any(item.get("assessment_state") in {
            "limited_or_truncated", "structured_content_analyzed", "unsupported",
            "binary_asset_inventory_only", "executable_not_analyzed", "rejected_unsafe_entry"}
            or item.get("skipped") is True for item in matching):
        return "unknown"
    coverage = entry.get("analysis_coverage", {})
    matching_coverage = [item.get("analysis_coverage", {}) for item in matching]
    if any(item.get(stage, {}).get("status") in {"partial", "error", "not_performed"}
           for item in matching_coverage for stage in ("extraction", "result_display")):
        return "unknown"
    # Only a detector that can produce this particular rule is relevant. An
    # arbitrary complete stage (or complete extraction/display) proves nothing.
    detectors = set()
    if identifier in SENSITIVE_RULE_IDS:
        detectors.update(("sensitive_data", "text_patterns"))
    if identifier == "unverifiable_chunk_marker":
        detectors.add("creator_markers")
    if identifier in _text_rule_ids():
        detectors.add("text_patterns")
    if any(item.get(detector, {}).get("status") in {"partial", "error", "not_performed"}
           for item in matching_coverage for detector in detectors):
        return "unknown"
    if any(coverage.get(detector, {}).get("status") == "complete" for detector in detectors):
        return "not_detected"
    # complete_input means supplied input, not measured exhaustive traversal.
    return "unknown"


def _validate_report(report):
    """Reject malformed consumed fields before comparison; bound traversal work."""
    if not isinstance(report, dict):
        raise ValueError("Reports must be JSON objects")
    finding_count, observation_count = 0, 0

    def optional_text(value, field, maximum=4096):
        if value is not None and (not isinstance(value, str) or len(value) > maximum):
            raise ValueError(field + " must be bounded text or null")

    def validate_finding(finding):
        nonlocal finding_count, observation_count
        finding_count += 1
        if finding_count > MAX_REPORT_FINDINGS or not isinstance(finding, dict):
            raise ValueError("Findings must be bounded lists of objects")
        for field in ("id", "path", "tier", "severity"):
            optional_text(finding.get(field), "Finding " + field)
        observations = finding.get("observations", [])
        if not isinstance(observations, list):
            raise ValueError("Finding observations must be a list of objects")
        observation_count += len(observations)
        if observation_count > MAX_REPORT_OBSERVATIONS:
            raise ValueError("Report observation budget exceeded")
        for observation in observations:
            if not isinstance(observation, dict):
                raise ValueError("Finding observations must be objects")
            line = observation.get("line")
            if line is not None and (type(line) is not int or line < 1):
                raise ValueError("Observation lines must be positive integers or null")
        for field in ("line", "source_start_line"):
            if finding.get(field) is not None and (type(finding[field]) is not int or finding[field] < 1):
                raise ValueError("Finding source lines must be positive integers or null")

    for collection in ("files", "inventory"):
        items = report.get(collection, [])
        if not isinstance(items, list) or len(items) > MAX_REPORT_FILES:
            raise ValueError(collection + " must be a bounded list of objects")
        for entry in items:
            if not isinstance(entry, dict):
                raise ValueError(collection + " entries must be objects")
            optional_text(entry.get("path"), "File path")
            if "path" in entry and entry["path"] is None:
                raise ValueError("File path must be text when present")
            optional_text(entry.get("assessment_state"), "Assessment state", 128)
            if "skipped" in entry and type(entry["skipped"]) is not bool:
                raise ValueError("File skipped must be a boolean when present")
            coverage = entry.get("analysis_coverage", {})
            if not isinstance(coverage, dict) or len(coverage) > 100:
                raise ValueError("analysis_coverage must be a bounded object")
            for detector, details in coverage.items():
                optional_text(detector, "Detector name", 256)
                if not isinstance(details, dict):
                    raise ValueError("Each analysis_coverage detector must be an object")
                optional_text(details.get("status"), "Detector status", 128)
            mitigation = entry.get("creator_mitigation", {})
            if not isinstance(mitigation, dict):
                raise ValueError("creator_mitigation must be an object")
            optional_text(mitigation.get("status"), "Mitigation status", 128)
            if mitigation.get("satisfies_tagging_convention") is not None and type(mitigation["satisfies_tagging_convention"]) is not bool:
                raise ValueError("satisfies_tagging_convention must be a boolean")
            findings = entry.get("findings", [])
            if not isinstance(findings, list):
                raise ValueError("File findings must be a list")
            for finding in findings:
                validate_finding(finding)
    for field in ("governance_evidence", "package_analysis", "scanner_metadata"):
        if not isinstance(report.get(field, {}), dict):
            raise ValueError(field + " must be an object")
    analysis, metadata = report.get("package_analysis", {}), report.get("scanner_metadata", {})
    optional_text(analysis.get("target_runtime"), "Target runtime", 256)
    formats = analysis.get("format_findings", [])
    if not isinstance(formats, list):
        raise ValueError("format_findings must be a list of objects")
    for finding in formats:
        validate_finding(finding)
    for field in ("scanner_version", "adapter_version", "engine_source_sha256"):
        optional_text(metadata.get(field), field, 256)
    catalogs = metadata.get("catalogs")
    if catalogs is not None:
        if not isinstance(catalogs, list) or len(catalogs) > 1000:
            raise ValueError("Catalogs must be a bounded list of objects or null")
        for catalog in catalogs:
            if not isinstance(catalog, dict):
                raise ValueError("Each catalog must be an object")
            for field in ("name", "version", "sha256"):
                optional_text(catalog.get(field), "Catalog " + field, 256)


def _context(report: dict) -> dict:
    metadata = report.get("scanner_metadata", {})
    analysis = report.get("package_analysis", {})
    catalogs = metadata.get("catalogs")
    if isinstance(catalogs, list):
        catalogs = [{key: item.get(key) for key in ("name", "version", "sha256")}
                    for item in catalogs if isinstance(item, dict)]
    return {"scanner_version": metadata.get("scanner_version"),
            "adapter_version": metadata.get("adapter_version"),
            "engine_source_sha256": metadata.get("engine_source_sha256"),
            "catalogs": catalogs, "target_runtime": analysis.get("target_runtime")}


def compare_reports(left: dict, right: dict) -> dict:
    """Compare reports of identical bytes without appointing either ground truth."""
    for report in (left, right):
        _validate_report(report)
    digest = _artifact_hash(left)
    if digest != _artifact_hash(right):
        raise ValueError("Artifact hashes differ; these are not same-package reports")
    a, b = _findings(left), _findings(right)
    context_left, context_right = _context(left), _context(right)
    known_difference = any(context_left[k] is not None and context_right[k] is not None
                           and context_left[k] != context_right[k] for k in context_left)
    rows = []
    for key in sorted(a.keys() | b.keys()):
        path, identifier = key
        first, second = a.get(key), b.get(key)
        annotations = []
        if first and second:
            outcome = "location_difference" if (first["locations"] and second["locations"]
                                               and first["locations"] != second["locations"]) else "matched"
            if not first["locations"] or not second["locations"]:
                annotations.append("occurrence_alignment_unknown")
            if first["tiers"] != second["tiers"] or first["severities"] != second["severities"]:
                annotations.append("disposition_difference")
            missing_side = None
        else:
            missing_side = "right" if first else "left"
            outcome = _absence_state(right if first else left, path, identifier)
        for side, report in (("left", left), ("right", right)):
            mitigation = _file(report, path).get("creator_mitigation", {})
            if mitigation.get("status") == "verified" and mitigation.get("satisfies_tagging_convention") is True:
                annotations.append("creator_mitigation_verified_" + side)
        if known_difference:
            annotations.append("policy_or_rule_version_difference_possible")
        rows.append({"path": path, "id": identifier, "outcome": outcome, "missing_from": missing_side,
                     "left_locations": sorted(first["locations"]) if first else [],
                     "right_locations": sorted(second["locations"]) if second else [],
                     "annotations": annotations})
    return {"schema_version": 1, "artifact_sha256": digest, "same_artifact": True,
            "ground_truth": "neither_report_is_ground_truth", "left_context": context_left,
            "right_context": context_right, "comparisons": rows,
            "statement": "Differences are observations, not proof of a regression or malicious content. Unknown coverage stays unknown."}


def fixture_archive(case: dict) -> bytes:
    """Materialize bounded authored text fixtures in a reproducible ZIP in memory."""
    output, total = io.BytesIO(), 0
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in case["files"]:
            path = item["path"]
            parts = PurePosixPath(path)
            if parts.is_absolute() or ".." in parts.parts or "\\" in path:
                raise ValueError("Fixture paths must be relative package paths")
            count = item.get("padding_characters", 0)
            if type(count) is not int or not 0 <= count <= MAX_FIXTURE_BYTES:
                raise ValueError("Fixture padding is outside the bounded text budget")
            text = item.get("prefix", "") + item.get("text", "") + "x" * count + item.get("suffix", "")
            data = text.encode("utf-8")
            total += len(data)
            if total > 4 * MAX_FIXTURE_BYTES or len(data) > MAX_FIXTURE_BYTES:
                raise ValueError("Fixture exceeds the bounded package budget")
            info = zipfile.ZipInfo(path, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return output.getvalue()


def evaluate_corpus(manifest_path: Path = DEFAULT_CORPUS, scanner=None) -> dict:
    if scanner is None:
        sys.path.insert(0, str(ROOT))
        from skill_sandbox.app import scan_upload
        scanner = scan_upload
    manifest = _load_json(manifest_path, 256 * 1024)
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 100:
        raise ValueError("Corpus must have between 1 and 100 authored cases")
    rows, by_rule = [], {}
    for case in cases:
        raw = fixture_archive(case)
        report = scanner(raw, case["id"] + ".skill", target_runtime="generic")
        findings = _findings(report)
        observed = {identifier for _, identifier in findings}
        required, forbidden = set(case.get("required_findings", [])), set(case.get("forbidden_findings", []))
        partial = report.get("coverage", {}).get("status") != "complete_supported_content"
        missing, unexpected = required - observed, forbidden & observed
        unknown = sorted(missing) if partial else []
        blocks = sum("block" in item["tiers"] for item in findings.values())
        review = sum("review" in item["tiers"] for item in findings.values())
        failures = sorted(missing) if not partial else []
        observed_file_matches = {identifier: sum(key[1] == identifier for key in findings)
                                 for identifier in case.get("minimum_file_matches", {})}
        for identifier, minimum in case.get("minimum_file_matches", {}).items():
            if observed_file_matches[identifier] < minimum:
                if partial:
                    unknown.append(identifier + ":file_occurrences")
                else:
                    failures.append(identifier + ":file_occurrences")
        mitigation_results = []
        for expected in case.get("creator_mitigation_expectations", []):
            actual = _file(report, expected["path"]).get("creator_mitigation", {})
            matches = all(actual.get(key) == value for key, value in expected.items() if key != "path")
            mitigation_results.append({"path": expected["path"], "matched": matches,
                                       "observed_status": actual.get("status", "unknown")})
            if not matches:
                failures.append("creator_mitigation:" + expected["path"])
        if case.get("maximum_block_findings") is not None and blocks > case["maximum_block_findings"]:
            failures.append("maximum_block_findings_exceeded")
        coverage_expected = case.get("coverage_status")
        if coverage_expected and report.get("coverage", {}).get("status") != coverage_expected:
            failures.append("coverage_expectation_not_met")
        for identifier in required | forbidden:
            rule = by_rule.setdefault(identifier, {"expected_present_cases": 0, "detected_expected_cases": 0,
                "missing_in_inspected_cases": 0, "unknown_due_to_coverage": 0,
                "expected_absent_cases": 0, "unexpected_detection_cases": 0})
            if identifier in required:
                rule["expected_present_cases"] += 1
                rule["detected_expected_cases"] += identifier in observed
                rule["unknown_due_to_coverage"] += identifier in missing and partial
                rule["missing_in_inspected_cases"] += identifier in missing and not partial
            if identifier in forbidden:
                rule["expected_absent_cases"] += 1
                rule["unexpected_detection_cases"] += identifier in observed
        rows.append({"id": case["id"], "intent_label": case["intent_label"],
            "artifact_sha256": hashlib.sha256(raw).hexdigest(), "required_findings": sorted(required),
            "forbidden_findings": sorted(forbidden), "observed_findings": sorted(observed),
            "missing": sorted(missing), "unexpected": sorted(unexpected), "unknown_due_to_coverage": unknown,
            "observed_file_matches": observed_file_matches, "creator_mitigation_checks": mitigation_results,
            "contract_failures": failures, "status": "mismatch" if failures or unexpected else "incomplete" if unknown else "matched",
            "block_findings": blocks, "review_findings": review, "coverage": report.get("coverage", {}),
            "vendor_status": report.get("vendor_verification", {}).get("status", "unknown")})
    benign = [r for r in rows if r["intent_label"] == "benign_authored"]
    return {"schema_version": 1, "corpus_provenance": manifest["provenance"],
        "corpus_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(), "cases": rows,
        "per_rule": by_rule, "summary": {"case_count": len(rows),
            "mismatched_cases": sum(r["status"] == "mismatch" for r in rows),
            "incomplete_cases": sum(r["status"] == "incomplete" for r in rows),
            "benign_authored_cases": len(benign),
            "benign_cases_with_blocks": sum(r["block_findings"] > 0 for r in benign),
            "benign_review_findings": sum(r["review_findings"] for r in benign)},
        "statement": "Authored synthetic regression cases; not independently labeled, held out, or representative of real-world accuracy. No general safety score."}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    evaluation = commands.add_parser("evaluate", help="Run the opt-in authored synthetic corpus locally")
    evaluation.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    comparison = commands.add_parser("compare", help="Compare two JSON exports of the same artifact bytes")
    comparison.add_argument("left", type=Path)
    comparison.add_argument("right", type=Path)
    for command in (evaluation, comparison):
        command.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = evaluate_corpus(args.corpus) if args.command == "evaluate" else compare_reports(_load_json(args.left), _load_json(args.right))
    except (ValueError, KeyError, TypeError, OSError, RecursionError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, indent=2, ensure_ascii=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return int(args.command == "evaluate" and result["summary"]["mismatched_cases"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
