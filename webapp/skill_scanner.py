"""Utilities for scanning Claude .skill files or zip bundles for risky content."""

from __future__ import annotations

import io
import re
import zipfile
from typing import Dict, List, Tuple

from skill_sandbox.behavior_analysis import analyze_behavior

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_ZIP_FILES = 200
MAX_ZIP_TOTAL_BYTES = 25 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024

PROMPT_PATTERNS: Tuple[Dict[str, str], ...] = (
    {
        "id": "prompt_override",
        "category": "prompt",
        "severity": "high",
        "description": "Attempts to override or ignore higher-priority instructions.",
        "regex": r"\b(ignore|override|bypass)\s+(previous|prior|above|system|developer)\b",
    },
    {
        "id": "system_exfiltration",
        "category": "prompt",
        "severity": "high",
        "description": "Requests or leaks system/developer messages or hidden prompts.",
        "regex": r"\b(system|developer)\s+(prompt|message|instructions)\b|\breveal\s+the\s+system\s+prompt\b",
    },
    {
        "id": "secret_exfiltration",
        "category": "prompt",
        "severity": "medium",
        "description": "Requests secrets, tokens, or keys in prompt text.",
        "regex": r"\b(api\s*key|secret|token|password|credential|access\s+key)\b",
    },
    {
        "id": "tool_escape",
        "category": "prompt",
        "severity": "medium",
        "description": "Attempts to execute or escape to external tools or files.",
        "regex": r"\b(run|execute|shell|terminal|powershell|bash|cmd\.exe)\b",
    },
)

CODE_PATTERNS: Tuple[Dict[str, str], ...] = (
    {
        "id": "dynamic_exec",
        "category": "code",
        "severity": "high",
        "description": "Dynamic code execution helpers detected.",
        "regex": r"\b(exec|eval|compile)\s*\(",
    },
    {
        "id": "subprocess_spawn",
        "category": "code",
        "severity": "medium",
        "description": "Process execution via subprocess or os.system.",
        "regex": r"\b(subprocess\.run|subprocess\.Popen|os\.system)\b",
    },
    {
        "id": "network_calls",
        "category": "code",
        "severity": "medium",
        "description": "Network or HTTP request usage detected.",
        "regex": r"\b(requests\.|urllib\.|httpx\.|socket\.)\b",
    },
    {
        "id": "filesystem_access",
        "category": "code",
        "severity": "low",
        "description": "File system access or environment reads detected.",
        "regex": r"\b(open\(|pathlib\.|os\.environ|os\.listdir)\b",
    },
)


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
            text_pairs.append((info.filename, text))

    return _assemble_result(filename, "zip", results, warnings, _build_text_sources(text_pairs))


def _scan_single_skill(upload_bytes: bytes, filename: str) -> Dict[str, object]:
    entry, text = _scan_file_bytes(filename, upload_bytes)
    results = [entry]
    return _assemble_result(filename, "skill", results, [], _build_text_sources([(filename, text)]))


def _scan_file_bytes(path: str, data: bytes) -> Tuple[Dict[str, object], str | None]:
    entry = {
        "path": path,
        "size": len(data),
        "skipped": False,
        "reason": "",
        "findings": [],
    }

    if not _is_probably_text(data):
        entry["skipped"] = True
        entry["reason"] = "Binary or non-text content"
        return entry, None

    text = data.decode("utf-8", errors="replace")
    entry["findings"] = _scan_text(text)
    return entry, text


def _scan_text(text: str) -> List[Dict[str, object]]:
    findings = []

    for pattern in (*PROMPT_PATTERNS, *CODE_PATTERNS):
        regex = re.compile(pattern["regex"], re.IGNORECASE)
        matches = regex.findall(text)

        if not matches:
            continue

        normalized_matches = [match if isinstance(match, str) else " ".join(match) for match in matches]
        findings.append(
            {
                "id": pattern["id"],
                "category": pattern["category"],
                "severity": pattern["severity"],
                "description": pattern["description"],
                "count": len(matches),
                "samples": normalized_matches[:3],
            }
        )

    return findings


def _assemble_result(
    filename: str,
    file_type: str,
    results: List[Dict[str, object]],
    warnings: List[str],
    text_sources: List[Dict[str, str]],
) -> Dict[str, object]:
    flagged_files = sum(1 for item in results if item["findings"])
    total_findings = sum(len(item["findings"]) for item in results)
    behavior_report = analyze_behavior(text_sources)

    return {
        "filename": filename,
        "file_type": file_type,
        "summary": {
            "total_files": len(results),
            "flagged_files": flagged_files,
            "total_findings": total_findings,
        },
        "warnings": warnings,
        "files": results,
        **behavior_report,
    }


def _is_probably_text(data: bytes) -> bool:
    if not data:
        return True

    if b"\x00" in data:
        return False

    sample = data[:4096]
    printable = sum(1 for byte in sample if 32 <= byte <= 126 or byte in (9, 10, 13))
    return printable / len(sample) >= 0.7


def _build_text_sources(text_pairs: List[Tuple[str, str | None]]) -> List[Dict[str, str]]:
    sources = []
    for path, text in text_pairs:
        if text:
            sources.append({"path": path, "text": text})
    return sources
