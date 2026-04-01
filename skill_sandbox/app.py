from __future__ import annotations

import io
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Tuple

from fastapi import FastAPI, File, HTTPException, UploadFile

if __package__:
    from .artifact_text import extract_scannable_text
    from .behavior_analysis import analyze_behavior
    from .finding_enrichment import build_finding, classify_artifact_role, detect_special_findings
    from .governance import build_governance_profile
    from .scan_rules import compile_patterns, find_rule_matches
else:
    from artifact_text import extract_scannable_text
    from behavior_analysis import analyze_behavior
    from finding_enrichment import build_finding, classify_artifact_role, detect_special_findings
    from governance import build_governance_profile
    from scan_rules import compile_patterns, find_rule_matches

app = FastAPI(title="Injecticide Skill Sandbox", version="1.0.0")

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_FILES = 200
MAX_ARCHIVE_TOTAL_BYTES = 25 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024

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


@app.post("/scan")
async def scan_skill(file: UploadFile = File(...)) -> Dict[str, object]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    upload_bytes = await file.read()
    if len(upload_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Upload exceeds size limit.")

    try:
        result = scan_upload(upload_bytes, file.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip archive")
    except tarfile.TarError:
        raise HTTPException(status_code=400, detail="Invalid tar archive")

    return result


def scan_upload(upload_bytes: bytes, filename: str) -> Dict[str, object]:
    lower_name = filename.lower()

    if lower_name.endswith(".zip") or zipfile.is_zipfile(io.BytesIO(upload_bytes)):
        return _scan_archive(upload_bytes, filename, archive_type="zip")

    if lower_name.endswith((".tar", ".tar.gz", ".tgz")):
        return _scan_archive(upload_bytes, filename, archive_type="tar")

    return _scan_single_file(upload_bytes, filename)


def _scan_archive(upload_bytes: bytes, filename: str, archive_type: str) -> Dict[str, object]:
    warnings: List[str] = []
    with tempfile.TemporaryDirectory() as temp_root:
        temp_path = Path(temp_root)
        if archive_type == "zip":
            extracted = _safe_extract_zip(upload_bytes, temp_path, warnings)
        elif archive_type == "tar":
            extracted = _safe_extract_tar(upload_bytes, temp_path, warnings)
        else:
            raise ValueError("Unsupported archive type.")

        results, text_sources = _scan_extracted_files(extracted)

    return _assemble_result(filename, archive_type, results, warnings, text_sources)


def _scan_single_file(upload_bytes: bytes, filename: str) -> Dict[str, object]:
    entry, text = _scan_file_bytes(filename, upload_bytes)
    results = [entry]
    text_sources = _build_text_sources([(filename, text, entry["artifact_role"])])
    return _assemble_result(filename, "skill", results, [], text_sources)


def _safe_extract_zip(upload_bytes: bytes, root: Path, warnings: List[str]) -> List[Tuple[str, Path]]:
    extracted: List[Tuple[str, Path]] = []
    total_uncompressed = 0

    with zipfile.ZipFile(io.BytesIO(upload_bytes)) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]

        if len(members) > MAX_ARCHIVE_FILES:
            raise ValueError("Zip archive contains too many files.")

        for info in members:
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_ARCHIVE_TOTAL_BYTES:
                raise ValueError("Zip archive exceeds uncompressed size limit.")

            if info.file_size > MAX_FILE_BYTES:
                warnings.append(f"Skipped {info.filename}: file too large.")
                continue

            if _zipinfo_is_symlink(info):
                warnings.append(f"Skipped {info.filename}: symlink entries are not allowed.")
                continue

            safe_name = _sanitize_member_name(info.filename)
            if not safe_name:
                warnings.append(f"Skipped {info.filename}: invalid path.")
                continue

            destination = _safe_join(root, safe_name)
            if destination is None:
                warnings.append(f"Skipped {info.filename}: invalid path.")
                continue

            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, open(destination, "wb") as target:
                _copy_limited(source, target, MAX_FILE_BYTES)

            extracted.append((safe_name, destination))

    return extracted


def _safe_extract_tar(upload_bytes: bytes, root: Path, warnings: List[str]) -> List[Tuple[str, Path]]:
    extracted: List[Tuple[str, Path]] = []
    total_uncompressed = 0

    with tarfile.open(fileobj=io.BytesIO(upload_bytes), mode="r:*") as archive:
        members = [member for member in archive.getmembers() if not member.isdir()]

        if len(members) > MAX_ARCHIVE_FILES:
            raise ValueError("Tar archive contains too many files.")

        for member in members:
            total_uncompressed += member.size
            if total_uncompressed > MAX_ARCHIVE_TOTAL_BYTES:
                raise ValueError("Tar archive exceeds uncompressed size limit.")

            if member.size > MAX_FILE_BYTES:
                warnings.append(f"Skipped {member.name}: file too large.")
                continue

            if member.issym() or member.islnk():
                warnings.append(f"Skipped {member.name}: link entries are not allowed.")
                continue

            safe_name = _sanitize_member_name(member.name)
            if not safe_name:
                warnings.append(f"Skipped {member.name}: invalid path.")
                continue

            destination = _safe_join(root, safe_name)
            if destination is None:
                warnings.append(f"Skipped {member.name}: invalid path.")
                continue

            source = archive.extractfile(member)
            if source is None:
                warnings.append(f"Skipped {member.name}: unable to read entry.")
                continue

            destination.parent.mkdir(parents=True, exist_ok=True)
            with source, open(destination, "wb") as target:
                _copy_limited(source, target, MAX_FILE_BYTES)

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
    }

    text, reason = extract_scannable_text(data)
    if text is None:
        entry["skipped"] = True
        entry["reason"] = reason
        return entry, None

    entry["reason"] = reason
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


def _sanitize_member_name(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)

    if path.is_absolute() or ".." in path.parts:
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
def _build_text_sources(text_pairs: Iterable[Tuple[str, str | None, str]]) -> List[Dict[str, str]]:
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
