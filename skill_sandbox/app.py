from __future__ import annotations

import io
import tarfile
import tempfile
import zipfile
import hashlib
import threading
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Tuple

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool

if __package__:
    from .artifact_text import extract_scannable_text, looks_like_sqlite
    from .behavior_analysis import analyze_behavior
    from .contextual_rules import CONTEXTUAL_RULE_IDS, detect_contextual_findings
    from .finding_enrichment import build_finding, classify_artifact_role, detect_special_findings
    from .governance import build_governance_profile
    from .scan_rules import build_scan_units, compile_patterns, find_rule_matches
    from .package_analysis import enrich_result
    from .package_formats import bounded_data, RUNTIMES
else:
    from artifact_text import extract_scannable_text, looks_like_sqlite
    from behavior_analysis import analyze_behavior
    from contextual_rules import CONTEXTUAL_RULE_IDS, detect_contextual_findings
    from finding_enrichment import build_finding, classify_artifact_role, detect_special_findings
    from governance import build_governance_profile
    from scan_rules import build_scan_units, compile_patterns, find_rule_matches
    from package_analysis import enrich_result
    from package_formats import bounded_data, RUNTIMES

app = FastAPI(title="Injecticide Skill Sandbox", version="1.0.0")

MAX_UPLOAD_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_FILES = 200
MAX_ARCHIVE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_SQLITE_FILE_BYTES = 32 * 1024 * 1024
MAX_LARGE_ARTIFACT_BYTES = 64 * 1024 * 1024
LARGE_ASSET_EXTENSIONS = (".pptx", ".docx", ".xlsx")

PRIORITY_FILENAMES = (
    "skill.md",
    "readme.md",
)
PRIORITY_EXTENSIONS = (
    ".py",
    ".js",
    ".ts",
    ".sh",
    ".ps1",
    ".yaml",
    ".yml",
    ".json",
)

PATTERNS = compile_patterns()
SCAN_SLOT = threading.BoundedSemaphore(1)
MAX_TEXT_CHARS = 1024 * 1024


@app.post("/scan")
async def scan_skill(file: UploadFile = File(...), target_runtime: str = Form("auto"),
                     governance_evidence: str = Form("{}")) -> Dict[str, object]:
    if not file.filename:
        await file.close()
        raise HTTPException(status_code=400, detail="Missing filename")

    if not SCAN_SLOT.acquire(blocking=False):
        await file.close()
        raise HTTPException(status_code=429, detail="Another package scan is running. Retry after it finishes.")
    try:
        upload_bytes = await file.read(MAX_UPLOAD_BYTES + 1)
        evidence = bounded_data(governance_evidence)
        result = await run_in_threadpool(scan_upload, upload_bytes, file.filename, target_runtime, evidence)
        return result
    except (ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        SCAN_SLOT.release()
        await file.close()


def scan_upload(upload_bytes: bytes, filename: str, target_runtime="auto", governance_evidence=None) -> Dict[str, object]:
    if len(upload_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB size limit.")

    if target_runtime not in RUNTIMES:
        raise ValueError("Unsupported target runtime")
    lower_name = filename.lower()

    if lower_name.endswith(".zip") or zipfile.is_zipfile(io.BytesIO(upload_bytes)):
        return _scan_archive(upload_bytes, filename, archive_type="zip", target_runtime=target_runtime, governance_evidence=governance_evidence)

    if lower_name.endswith((".tar", ".tar.gz", ".tgz")):
        return _scan_archive(upload_bytes, filename, archive_type="tar", target_runtime=target_runtime, governance_evidence=governance_evidence)

    return _scan_single_file(upload_bytes, filename, target_runtime, governance_evidence)


def _scan_archive(upload_bytes: bytes, filename: str, archive_type: str, target_runtime="auto", governance_evidence=None) -> Dict[str, object]:
    warnings: List[str] = []
    excluded = []
    with tempfile.TemporaryDirectory() as temp_root:
        temp_path = Path(temp_root)
        if archive_type == "zip":
            extracted = _safe_extract_zip(upload_bytes, temp_path, warnings, excluded)
        elif archive_type == "tar":
            extracted = _safe_extract_tar(upload_bytes, temp_path, warnings, excluded)
        else:
            raise ValueError("Unsupported archive type.")

        results, text_sources = _scan_extracted_files(extracted)
        result = _assemble_result(filename, archive_type, results, warnings, text_sources)
        return enrich_result(result, text_sources, upload_bytes, target_runtime, governance_evidence, temp_path, excluded, _scan_text)


def _scan_single_file(upload_bytes: bytes, filename: str, target_runtime="auto", governance_evidence=None) -> Dict[str, object]:
    entry, text = _scan_file_bytes(filename, upload_bytes)
    results = [entry]
    text_sources = _build_text_sources([(filename, text, entry["artifact_role"])])
    return enrich_result(_assemble_result(filename, "skill", results, [], text_sources), text_sources,
                         upload_bytes, target_runtime, governance_evidence, rescan=_scan_text)


def _max_scannable_file_bytes(path: str, header: bytes = b"") -> int:
    if looks_like_sqlite(header):
        return MAX_SQLITE_FILE_BYTES
    if _is_large_scannable_artifact(path):
        return MAX_LARGE_ARTIFACT_BYTES
    return MAX_FILE_BYTES


def _is_large_scannable_artifact(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    anchored = f"/{normalized}"
    if "/references/" in anchored:
        return True
    return "/assets/" in anchored and normalized.endswith(LARGE_ASSET_EXTENSIONS)


def _safe_extract_zip(upload_bytes: bytes, root: Path, warnings: List[str], excluded=None) -> List[Tuple[str, Path]]:
    extracted: List[Tuple[str, Path]] = []
    total_uncompressed = 0
    seen_paths = set()

    with zipfile.ZipFile(io.BytesIO(upload_bytes)) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]

        if len(members) > MAX_ARCHIVE_FILES:
            raise ValueError("Zip archive contains too many files.")

        for info in members:
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_ARCHIVE_TOTAL_BYTES:
                raise ValueError("Zip archive exceeds uncompressed size limit.")

            if _zipinfo_is_symlink(info):
                _skip_entry(info.filename, info.file_size, "symlink entries are not allowed.", warnings, excluded)
                continue

            safe_name = _sanitize_member_name(info.filename)
            if not safe_name:
                _skip_entry(info.filename, info.file_size, "invalid path.", warnings, excluded)
                continue

            destination = _safe_join(root, safe_name)
            if destination is None:
                _skip_entry(info.filename, info.file_size, "invalid path.", warnings, excluded)
                continue

            if safe_name.casefold() in seen_paths:
                _skip_entry(safe_name, info.file_size, "duplicate or case-colliding path.", warnings, excluded)
                continue
            seen_paths.add(safe_name.casefold())
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source:
                header = source.read(16)
                limit = _max_scannable_file_bytes(safe_name, header)
                if info.file_size > limit:
                    _skip_entry(safe_name, info.file_size, "file too large.", warnings, excluded)
                    continue
                source.seek(0)
                with open(destination, "wb") as target:
                    _copy_limited(source, target, limit)

            extracted.append((safe_name, destination))

    return extracted


def _safe_extract_tar(upload_bytes: bytes, root: Path, warnings: List[str], excluded=None) -> List[Tuple[str, Path]]:
    extracted: List[Tuple[str, Path]] = []
    total_uncompressed = 0
    seen_paths = set()

    with tarfile.open(fileobj=io.BytesIO(upload_bytes), mode="r:*") as archive:
        members = [member for member in archive.getmembers() if not member.isdir()]

        if len(members) > MAX_ARCHIVE_FILES:
            raise ValueError("Tar archive contains too many files.")

        for member in members:
            total_uncompressed += member.size
            if total_uncompressed > MAX_ARCHIVE_TOTAL_BYTES:
                raise ValueError("Tar archive exceeds uncompressed size limit.")

            if member.issym() or member.islnk():
                _skip_entry(member.name, member.size, "link entries are not allowed.", warnings, excluded)
                continue

            safe_name = _sanitize_member_name(member.name)
            if not safe_name:
                _skip_entry(member.name, member.size, "invalid path.", warnings, excluded)
                continue

            destination = _safe_join(root, safe_name)
            if destination is None:
                _skip_entry(member.name, member.size, "invalid path.", warnings, excluded)
                continue

            if not member.isfile():
                _skip_entry(member.name, member.size, "special archive entries are not allowed.", warnings, excluded)
                continue
            source = archive.extractfile(member)
            if source is None:
                _skip_entry(member.name, member.size, "unable to read entry.", warnings, excluded)
                continue

            if safe_name.casefold() in seen_paths:
                _skip_entry(safe_name, member.size, "duplicate or case-colliding path.", warnings, excluded)
                continue
            seen_paths.add(safe_name.casefold())
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source:
                header = source.read(16)
                limit = _max_scannable_file_bytes(safe_name, header)
                if member.size > limit:
                    _skip_entry(safe_name, member.size, "file too large.", warnings, excluded)
                    continue
                source.seek(0)
                with open(destination, "wb") as target:
                    _copy_limited(source, target, limit)

            extracted.append((safe_name, destination))

    return extracted


def _scan_extracted_files(files: Iterable[Tuple[str, Path]]) -> Tuple[List[Dict[str, object]], List[Dict[str, str]]]:
    results = []
    text_pairs: List[Tuple[str, str | None, str]] = []
    sorted_files = sorted(files, key=_priority_key)
    for rel_path, path in sorted_files:
        data = path.read_bytes()
        entry, text = _scan_file_bytes(rel_path, data)
        results.append(entry)
        text_pairs.append((rel_path, text, entry["artifact_role"]))
    return results, _build_text_sources(text_pairs)


def _priority_key(item: Tuple[str, Path]) -> Tuple[int, str]:
    rel_path = item[0]
    name = Path(rel_path).name.lower()
    extension = Path(rel_path).suffix.lower()

    if name in PRIORITY_FILENAMES:
        return (0, name)
    if extension in PRIORITY_EXTENSIONS:
        return (1, rel_path.lower())
    return (2, rel_path.lower())


def _scan_file_bytes(path: str, data: bytes) -> Tuple[Dict[str, object], str | None]:
    entry = {
        "path": path,
        "size": len(data),
        "skipped": False,
        "reason": "",
        "artifact_role": classify_artifact_role(path),
        "findings": [],
        "sha256": hashlib.sha256(data).hexdigest(),
        "assessment_state": "unsupported",
        "required_component": Path(path).name in {"SKILL.md", "plugin.json", "gemini-extension.json", "openclaw.plugin.json", "mcp.json", ".mcp.json", "hooks.json", "manifest.json"},
    }

    magic = next((kind for prefix, kind in ((b"\x89PNG\r\n\x1a\n", "png"), (b"OTTO", "opentype_font"),
                    (b"\x00\x01\x00\x00", "truetype_font"), (b"MZ", "pe_executable"), (b"\x7fELF", "elf_executable"),
                    (b"SQLite format 3\x00", "sqlite"), (b"PK\x03\x04", "zip_container")) if data.startswith(prefix)), None)
    entry["detected_content_type"] = magic or "text_or_unknown"
    if magic and Path(path).suffix.lower() in {".md", ".txt", ".py", ".js"}:
        entry["content_extension_mismatch"] = True

    if data.startswith((b"MZ", b"\x7fELF")):
        entry.update(skipped=True, reason="Executable binary content is not analyzed.", assessment_state="executable_not_analyzed")
        return entry, None
    try:
        text, reason = extract_scannable_text(data)
    except ValueError as exc:
        entry.update(skipped=True, reason=str(exc), assessment_state="limited_or_truncated")
        return entry, None
    if text is None:
        entry["skipped"] = True
        entry["reason"] = reason
        entry["assessment_state"] = "binary_asset_inventory_only"
        return entry, None

    entry["reason"] = reason
    entry["assessment_state"] = "structured_content_analyzed" if reason else "text_analyzed"
    if reason:
        entry["analysis_scope"] = "Bounded text projection; binary contents and omitted records are not certified safe."
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]
        entry.update(assessment_state="limited_or_truncated", reason="Text analysis limited to 1 MiB characters.")
    entry["artifact_role"] = classify_artifact_role(path, text)
    entry["findings"] = _scan_text(path, text, entry["artifact_role"])
    return entry, text


def _scan_text(path: str, text: str, artifact_role: str) -> List[Dict[str, object]]:
    findings = []
    scan_units = build_scan_units(path, text)

    for pattern in PATTERNS:
        if pattern["id"] in CONTEXTUAL_RULE_IDS:
            continue
        matches = []
        for unit in scan_units:
            matches.extend(find_rule_matches(pattern, unit))
            if len(matches) >= 3:
                matches = matches[:3]
                break
        if not matches:
            continue

        findings.append(build_finding(pattern, matches, artifact_role))

    findings.extend(detect_contextual_findings(path, text, artifact_role, build_finding))
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


def _sanitize_member_name(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)

    if path.is_absolute() or ".." in path.parts or ":" in normalized or "\x00" in normalized:
        return None

    cleaned = "/".join(part for part in path.parts if part not in ("", "."))
    return cleaned or None


def _safe_join(root: Path, rel_posix: str) -> Path | None:
    root_resolved = root.resolve()
    target = root_resolved.joinpath(*PurePosixPath(rel_posix).parts)

    try:
        target_resolved = target.resolve()
    except FileNotFoundError:
        target_resolved = target.parent.resolve() / target.name

    if not target_resolved.is_relative_to(root_resolved):
        return None

    return target


def _zipinfo_is_symlink(info: zipfile.ZipInfo) -> bool:
    return (info.external_attr >> 16) & 0o170000 == 0o120000


def _copy_limited(source, target, limit: int) -> None:
    remaining = limit
    while remaining > 0:
        chunk = source.read(min(1024 * 1024, remaining))
        if not chunk:
            break
        target.write(chunk)
        remaining -= len(chunk)
    if remaining == 0 and source.read(1):
        raise ValueError("Archive member exceeds extraction byte budget")
def _build_text_sources(text_pairs: Iterable[Tuple[str, str | None, str]]) -> List[Dict[str, str]]:
    sources = []
    for path, text, artifact_role in text_pairs:
        if text:
            sources.append({"path": path, "text": text, "artifact_role": artifact_role})
    return sources


def _skip_entry(path, size, reason, warnings, excluded):
    warnings.append(f"Skipped {path}: {reason}")
    if excluded is not None:
        excluded.append({"path": path, "size": size, "sha256": None, "assessment_state": "limited_or_truncated" if "too large" in reason else "rejected_unsafe_entry", "reason": reason, "skipped": True, "findings": [], "required_component": Path(path).name in {"SKILL.md", "plugin.json", "hooks.json", "mcp.json", ".mcp.json", "manifest.json"}})
