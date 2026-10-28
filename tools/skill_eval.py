"""Offline, provenance-bound external corpus diagnostics. Never execute samples.

Corpus labels retain their upstream authority; a security signal is not a malware
verdict. Holdout exposure requires an explicit caller-declared freeze identifier.
No downloads, tool installs, provider calls or arbitrary scanner commands occur.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.scanner_evaluation import _load_json, fixture_archive

PROFILES = {
    "security_block": "Actionable governance-counted security findings with tier=block.",
    "security_review": "Actionable governance-counted security findings with tier=review or block.",
}
COVERAGE_POLICY = {
    "version": "2",
    "complete_top_level_statuses": ["complete_supported_content"],
    "source": "skill_sandbox.package_evidence.coverage_report",
    "scope": "Supported static content only; not exhaustive security or runtime coverage.",
}
SECURITY_CATEGORIES = {"prompt", "code", "enterprise", "obfuscation", "sensitive_data"}
MAX_CASES, MAX_FILES, MAX_FILE_BYTES, MAX_CASE_BYTES = 1000, 128, 2 * 1024 * 1024, 8 * 1024 * 1024
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\Z")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read_manifest(path):
    manifest = _load_json(Path(path), 2 * 1024 * 1024)
    cases = manifest.get("cases")
    if manifest.get("schema_version") != 1 or not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("Invalid or oversized evaluation manifest")
    seen = set()
    for case in cases:
        identifier = case.get("id")
        if not isinstance(identifier, str) or not CASE_ID.fullmatch(identifier) or identifier in seen:
            raise ValueError("Case identities must be unique bounded identifiers")
        seen.add(identifier)
        if case.get("label") not in {"malicious", "benign", "unknown"} or not isinstance(case.get("label_origin"), str):
            raise ValueError("Every case needs a label and its actual origin")
        if case.get("split") not in {"development", "validation", "holdout"}:
            raise ValueError("Every case needs an explicit split")
        if case.get("input", {}).get("kind") not in {"raw", "package"}:
            raise ValueError("Unknown input view")
    return manifest


def input_bytes(case, corpus_root):
    """Verify immutable source bytes and preserve the declared artifact view."""
    files, total = [], 0
    entries = case["input"].get("files")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILES:
        raise ValueError("Invalid file inventory")
    seen = set()
    corpus_root = Path(corpus_root).resolve()
    for item in entries:
        package_path = item["path"]
        parts = PurePosixPath(package_path)
        if not package_path or parts.is_absolute() or ".." in parts.parts or str(parts) != package_path or any(c in package_path for c in ("\\", ":", "\x00")) or package_path in seen:
            raise ValueError("Unsafe or duplicated package path")
        seen.add(package_path)
        unresolved = corpus_root.joinpath(item["local_path"])
        location = unresolved.resolve()
        if not location.is_relative_to(corpus_root) or unresolved.is_symlink():
            raise ValueError("Source file escapes the corpus")
        with location.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
        total += len(raw)
        if len(raw) > MAX_FILE_BYTES or total > MAX_CASE_BYTES:
            raise ValueError("Source file budget exceeded")
        if not isinstance(item.get("sha256"), str) or not SHA256.fullmatch(item["sha256"]) or digest(raw) != item["sha256"]:
            raise ValueError("Source digest mismatch")
        files.append((package_path, raw))
    filename = case["input"].get("filename", case["id"] + ".skill")
    if not isinstance(filename, str) or len(filename) > 160 or PurePosixPath(filename).name != filename or any(c in filename for c in "\\:\x00"):
        raise ValueError("Invalid input filename")
    if case["input"]["kind"] == "raw":
        if len(files) != 1:
            raise ValueError("Raw input must have exactly one file")
        raw = files[0][1]
    else:
        # Reuse the existing reproducible ZIP convention. No source extraction
        # or normalization occurs; UTF-8 text round-trips byte-identically.
        raw = fixture_archive({"files": [{"path": path, "text": data.decode("utf-8")} for path, data in sorted(files)]})
    return raw, filename


def security_signals(report):
    findings = [finding for file in report.get("files", []) for finding in file.get("findings", [])]
    selected = [finding for finding in findings if finding.get("is_actionable") is True
                and finding.get("counts_for_governance") is True
                and finding.get("category") in SECURITY_CATEGORIES
                and not str(finding.get("id", "")).startswith(("pii_", "phi_"))]
    return {profile: sorted({finding["id"] for finding in selected
                            if finding.get("tier") in ({"block"} if profile == "security_block" else {"review", "block"})
                            and isinstance(finding.get("id"), str)}) for profile in PROFILES}


def security_unknowns(report):
    """Legacy/malformed policy fields cannot establish a clear negative."""
    reasons = {profile: set() for profile in PROFILES}
    for file in report.get("files", []):
        for finding in file.get("findings", []):
            if finding.get("category") not in SECURITY_CATEGORIES or str(finding.get("id", "")).startswith(("pii_", "phi_")):
                continue
            if finding.get("severity") == "info" or finding.get("tier") in {"info", "allow", "documented"}:
                continue
            if finding.get("is_actionable") is False or finding.get("counts_for_governance") is False:
                continue
            tier = finding.get("tier")
            for profile in PROFILES:
                if tier == "review" and profile == "security_block":
                    continue
                if tier not in {"review", "block"}:
                    reasons[profile].add("security_tier_unreported_or_invalid")
                if finding.get("is_actionable") is not True:
                    reasons[profile].add("actionability_unreported_or_invalid")
                if finding.get("counts_for_governance") is not True:
                    reasons[profile].add("governance_authority_unreported_or_invalid")
                if not isinstance(finding.get("id"), str) or not finding["id"]:
                    reasons[profile].add("security_finding_identity_unreported")
    return {profile: sorted(value) for profile, value in reasons.items()}


def summarize(records, profile):
    counts = Counter()
    for row in records:
        label = row["label"]
        decision = row["profiles"][profile]["decision"]
        counts[label + "_" + decision] += 1
    positive = sum(value for key, value in counts.items() if key.startswith("malicious_"))
    negative = sum(value for key, value in counts.items() if key.startswith("benign_"))
    tp, fp = counts["malicious_positive"], counts["benign_positive"]
    unresolved_positive = counts["malicious_abstain"] + counts["malicious_error"]
    unresolved_negative = counts["benign_abstain"] + counts["benign_error"]
    return {"profile": profile, "declared_threshold": PROFILES[profile], "total_cases": len(records),
            "upstream_positive_cases": positive, "upstream_negative_cases": negative,
            "unlabeled_cases": sum(row["label"] == "unknown" for row in records), "counts": dict(counts),
            "positive_signal_recall_lower_bound": tp / positive if positive else None,
            "positive_signal_recall_upper_bound": (tp + unresolved_positive) / positive if positive else None,
            "negative_signal_rate_lower_bound": fp / negative if negative else None,
            "negative_signal_rate_upper_bound": (fp + unresolved_negative) / negative if negative else None,
            "positive_label_fraction_among_signaled_cases": tp / (tp + fp) if tp + fp else None,
            "unresolved_positive_cases": unresolved_positive, "unresolved_negative_cases": unresolved_negative,
            "scope": "Relative to declared upstream labels; not a representative safety, accuracy or exploitability claim."}


def evaluate(manifest_path, *, split="development", freeze_id=None, scanner=None, artifacts=None):
    manifest_path = Path(manifest_path)
    manifest = read_manifest(manifest_path)
    if split == "holdout" and not freeze_id:
        raise ValueError("Holdout exposure requires a caller-declared frozen engine/runner identifier")
    cases = [case for case in manifest["cases"] if case["split"] == split]
    if not cases:
        raise ValueError("No cases in the requested split")
    if scanner is None:
        from skill_sandbox.app import scan_upload
        scanner = scan_upload
    records, contexts = [], {}
    if artifacts:
        Path(artifacts).mkdir(parents=True, exist_ok=True)
    for case in cases:
        row = {key: case.get(key) for key in ("id", "label", "label_origin", "category", "split", "source")}
        row.update(input_view=case["input"]["kind"], input_sha256=None, profiles={}, elapsed_seconds=None)
        start = time.perf_counter()
        try:
            raw, filename = input_bytes(case, manifest_path.parent)
            row["input_sha256"] = digest(raw)
            if artifacts:
                destination = Path(artifacts) / (case["id"] + (".bin" if case["input"]["kind"] == "raw" else ".skill"))
                with destination.open("xb") as handle:
                    handle.write(raw)
            report = scanner(raw, filename, target_runtime="generic")
            if report.get("governance_evidence", {}).get("artifact_sha256") != row["input_sha256"]:
                raise ValueError("Scanner report is not bound to the supplied artifact")
            coverage_complete = report.get("coverage", {}).get("status") in COVERAGE_POLICY["complete_top_level_statuses"]
            row["coverage"] = report.get("coverage", {}).get("status", "not_reported")
            signals = security_signals(report)
            unknowns = security_unknowns(report)
            row["profiles"] = {profile: {"decision": "positive" if signals[profile] else "negative" if coverage_complete and not unknowns[profile] else "abstain",
                                         "finding_ids": signals[profile],
                                         "unknown_reasons": unknowns[profile] + ([] if coverage_complete else ["scan_coverage_incomplete_or_unreported"])} for profile in PROFILES}
            metadata = report.get("scanner_metadata", {})
            context = {key: metadata.get(key) for key in ("scanner_version", "adapter_version", "engine_source_sha256")}
            contexts[json.dumps(context, sort_keys=True)] = context
        except Exception as error:
            row["error_type"] = type(error).__name__  # Never echo payloads or credential-bearing exceptions.
            row["profiles"] = {profile: {"decision": "error", "finding_ids": []} for profile in PROFILES}
        row["elapsed_seconds"] = round(time.perf_counter() - start, 6)
        records.append(row)
    return {"schema_version": 1, "corpus_id": manifest.get("corpus_id"), "manifest_sha256": digest(manifest_path.read_bytes()),
            "split": split, "freeze_id": freeze_id, "holdout_exposed": split == "holdout", "scanner": "injecticide",
            "scanner_contexts": list(contexts.values()), "runner_sha256": digest(Path(__file__).read_bytes()),
            "profiles": PROFILES, "coverage_policy": COVERAGE_POLICY, "records": records,
            "metrics": {profile: summarize(records, profile) for profile in PROFILES},
            "by_category": {str(category): {profile: summarize([row for row in records if row.get("category") == category], profile) for profile in PROFILES}
                            for category in sorted({row.get("category") for row in records}, key=str)},
            "status": "incomplete" if any(row["profiles"]["security_block"]["decision"] == "error" for row in records) else "diagnostic_complete",
            "statement": "Labels retain their stated origin. Missing coverage and errors stay visible; no sample code was executed. A freeze ID is caller-declared, not independently authenticated."}


def compare_runs(left, right):
    """Normalize external reports explicitly before using this same-input gate."""
    for value in (left, right):
        if value.get("schema_version") != 1 or not value.get("scanner") or not value.get("scanner_contexts"):
            raise ValueError("Comparator requires declared scanner identity/version context")
        if not isinstance(value.get("manifest_sha256"), str) or not SHA256.fullmatch(value["manifest_sha256"]):
            raise ValueError("Comparator needs a valid corpus digest")
        if not all(isinstance(context, dict) and isinstance(context.get("scanner_version"), str) and context["scanner_version"] for context in value["scanner_contexts"]):
            raise ValueError("Comparator scanner versions are not reported")
        if not isinstance(value.get("profiles"), dict) or any(not isinstance(value["profiles"].get(profile), str) or not value["profiles"][profile] for profile in PROFILES):
            raise ValueError("Comparator decision thresholds must be declared")
    if left.get("manifest_sha256") != right.get("manifest_sha256") or left.get("split") != right.get("split"):
        raise ValueError("Different corpus identity or split")
    if left.get("coverage_policy") != right.get("coverage_policy"):
        raise ValueError("Different coverage scoring policy; re-score both with the same adapter")
    def index(run):
        rows = run.get("records")
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_CASES:
            raise ValueError("Invalid comparison population")
        result = {}
        for row in rows:
            if row["id"] in result or not isinstance(row.get("input_sha256"), str) or not SHA256.fullmatch(row["input_sha256"]):
                raise ValueError("Comparison needs unique identities and actual artifact hashes")
            for profile in PROFILES:
                if row.get("profiles", {}).get(profile, {}).get("decision") not in {"positive", "negative", "abstain", "error"}:
                    raise ValueError("Comparator must explicitly map both decision profiles")
            result[row["id"]] = row
        return result
    a, b = index(left), index(right)
    if a.keys() != b.keys():
        raise ValueError("Comparator omitted or added cases; populations must match")
    differences = []
    for identifier in sorted(a):
        first, second = a[identifier], b[identifier]
        if first["input_sha256"] != second["input_sha256"] or first.get("input_view") != second.get("input_view"):
            raise ValueError("Comparator inputs differ")
        if first.get("label") != second.get("label") or first.get("label_origin") != second.get("label_origin"):
            raise ValueError("Comparator changed label authority")
        differences.append({"id": identifier, "input_sha256": first["input_sha256"],
                            "decisions": {profile: {"left": first["profiles"][profile]["decision"], "right": second["profiles"][profile]["decision"]} for profile in PROFILES}})
    return {"schema_version": 1, "same_inputs": True, "comparisons": differences,
            "left_thresholds": left["profiles"], "right_thresholds": right["profiles"],
            "left_metrics": {p: summarize(list(a.values()), p) for p in PROFILES},
            "right_metrics": {p: summarize(list(b.values()), p) for p in PROFILES},
            "statement": "Hash claims bind declared inputs; report authenticity and cross-tool threshold semantics require independent adapter review. Neither scanner supplies ground truth."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("manifest", type=Path)
    run.add_argument("--split", choices=("development", "validation", "holdout"), default="development")
    run.add_argument("--freeze-id")
    run.add_argument("--artifacts", type=Path)
    compare = commands.add_parser("compare")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    for command in (run, compare):
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise ValueError("Output already exists")
        result = evaluate(args.manifest, split=args.split, freeze_id=args.freeze_id, artifacts=args.artifacts) if args.command == "run" else compare_runs(_load_json(args.left), _load_json(args.right))
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2)
        return 1 if result.get("status") == "incomplete" else 0
    except (OSError, ValueError, TypeError, KeyError):
        print("Evaluation input/output rejected; inspect manifest, digests and permissions.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
