"""Utilities for scanning Claude .skill files or zip bundles for risky content."""

from __future__ import annotations

import io
import os
import re
import zipfile
from typing import Dict, List, Tuple

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

            results.append(_scan_file_bytes(info.filename, data))

    return _assemble_result(filename, "zip", results, warnings)


def _scan_single_skill(upload_bytes: bytes, filename: str) -> Dict[str, object]:
    results = [_scan_file_bytes(filename, upload_bytes)]
    return _assemble_result(filename, "skill", results, [])


def _scan_file_bytes(path: str, data: bytes) -> Dict[str, object]:
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
        return entry

    text = data.decode("utf-8", errors="replace")
    entry["findings"] = _scan_text(text, path)
    return entry


def _scan_text(text: str, path: str) -> List[Dict[str, object]]:
    findings = []
    _, extension = os.path.splitext(path.lower())
    prompt_text = text if extension in (".md", ".markdown") else _strip_fenced_code_blocks(text)

    for pattern in PROMPT_PATTERNS:
        regex = re.compile(pattern["regex"], re.IGNORECASE)
        matches = regex.findall(prompt_text)

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

    for pattern in CODE_PATTERNS:
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
) -> Dict[str, object]:
    flagged_files = sum(1 for item in results if item["findings"])
    total_findings = sum(len(item["findings"]) for item in results)

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
    }


def _is_probably_text(data: bytes) -> bool:
    if not data:
        return True

    if b"\x00" in data:
        return False

    sample = data[:4096]
    printable = sum(1 for byte in sample if 32 <= byte <= 126 or byte in (9, 10, 13))
    return printable / len(sample) >= 0.7


def _strip_fenced_code_blocks(text: str) -> str:
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL)
