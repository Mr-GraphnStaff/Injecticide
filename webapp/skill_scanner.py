"""Utilities for scanning Claude .skill files or zip bundles for risky content."""

from __future__ import annotations

import io
import zipfile
from typing import Dict, List, Tuple

from skill_sandbox.behavior_analysis import analyze_behavior
from skill_sandbox.finding_enrichment import build_finding, classify_artifact_role, detect_special_findings
from skill_sandbox.governance import build_governance_profile
from skill_sandbox.scan_rules import compile_patterns, find_rule_matches

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_ZIP_FILES = 200
MAX_ZIP_TOTAL_BYTES = 25 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024

PATTERNS = compile_patterns()


def scan_upload(upload_bytes: bytes, filename: str) -> Dict[str, object]:
    if len(upload_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError("Upload exceeds size limit.")

    is_zip = filename.lower().endswith(".zip") or zipfile.is_zipfile(io.BytesIO(upload_bytes))
    if is_zip:
        return _scan_zip_bundle(upload_bytes, filename)

    return _scan_single_skill(upload_bytes, filename)


def _scan_zip_bundle(upload_bytes: bytes, filename: str) -> Dict[str, object]:
    results = []
    text_pairs: List[Tuple[str, str | None]] = []
    warnings = []
    total_uncompressed = 0

    with zipfile.ZipFile(io.BytesIO(upload_bytes)) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]

        if len(members) > MAX_ZIP_FILES:
            raise ValueError("Zip archive contains too many files.")

        for info in members:
            if info.file_size > MAX_FILE_BYTES:
                warnings.append(f"Skipped {info.filename}: file too large.")
                continue

            total_uncompressed += info.file_size
            if total_uncompressed > MAX_ZIP_TOTAL_BYTES:
                raise ValueError("Zip archive exceeds uncompressed size limit.")

            with archive.open(info) as handle:
                data = handle.read()

            entry, text = _scan_file_bytes(info.filename, data)
            results.append(entry)
            text_pairs.append((info.filename, text, entry["artifact_role"]))

    return _assemble_result(filename, "zip", results, warnings, _build_text_sources(text_pairs))


def _scan_single_skill(upload_bytes: bytes, filename: str) -> Dict[str, object]:
    entry, text = _scan_file_bytes(filename, upload_bytes)
    results = [entry]
    return _assemble_result(filename, "skill", results, [], _build_text_sources([(filename, text, entry["artifact_role"])]))


def _scan_file_bytes(path: str, data: bytes) -> Tuple[Dict[str, object], str | None]:
    entry = {
        "path": path,
        "size": len(data),
        "skipped": False,
        "reason": "",
        "artifact_role": "active",
        "findings": [],
    }

    if not _is_probably_text(data):
        entry["skipped"] = True
        entry["reason"] = "Binary or non-text content"
        return entry, None

    text = data.decode("utf-8", errors="replace")
    entry["artifact_role"] = classify_artifact_role(path, text)
    entry["findings"] = _scan_text(path, text, entry["artifact_role"])
    return entry, text


def _scan_text(path: str, text: str, artifact_role: str) -> List[Dict[str, object]]:
    findings = []
    scan_units = _iter_scan_units(path, text)

    for pattern in PATTERNS:
        matches = []
        for unit in scan_units:
            matches.extend(find_rule_matches(pattern, unit))
        if not matches:
            continue

        findings.append(build_finding(pattern, matches, artifact_role))

    findings.extend(detect_special_findings(path, text, artifact_role))
    return findings


def _assemble_result(
    filename: str,
    file_type: str,
    results: List[Dict[str, object]],
    warnings: List[str],
    text_sources: List[Dict[str, str]],
) -> Dict[str, object]:
    flagged_files = sum(
        1
        for item in results
        if any(finding.get("severity") != "info" for finding in item["findings"])
    )
    total_findings = sum(
        1
        for item in results
        for finding in item["findings"]
        if finding.get("severity") != "info"
    )
    info_findings = sum(
        1
        for item in results
        for finding in item["findings"]
        if finding.get("severity") == "info"
    )
    behavior_report = analyze_behavior(text_sources)
    governance_profile = build_governance_profile(results, behavior_report)

    return {
        "filename": filename,
        "file_type": file_type,
        "summary": {
            "total_files": len(results),
            "flagged_files": flagged_files,
            "total_findings": total_findings,
            "info_findings": info_findings,
        },
        "warnings": warnings,
        "files": results,
        **behavior_report,
        "governance_profile": governance_profile,
    }


def _is_probably_text(data: bytes) -> bool:
    if not data:
        return True

    if b"\x00" in data:
        return False

    sample = data[:4096]
    printable = sum(1 for byte in sample if 32 <= byte <= 126 or byte in (9, 10, 13))
    return printable / len(sample) >= 0.7


def _build_text_sources(text_pairs: List[Tuple[str, str | None, str]]) -> List[Dict[str, str]]:
    sources = []
    for path, text, artifact_role in text_pairs:
        if text:
            sources.append({"path": path, "text": text, "artifact_role": artifact_role})
    return sources


def _iter_scan_units(path: str, text: str) -> List[str]:
    lower_path = path.lower()
    if lower_path.endswith(".csv"):
        return [line for line in text.splitlines() if line.strip()]
    if lower_path.endswith((".md", ".skill", ".txt")):
        units = [
            " ".join(line.strip() for line in block.splitlines() if line.strip())
            for block in text.split("\n\n")
        ]
        return [unit for unit in units if unit]
    return [text]
