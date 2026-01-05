from __future__ import annotations

import io
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Tuple

from fastapi import FastAPI, File, HTTPException, UploadFile

from skill_sandbox.scan_rules import compile_patterns

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
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="Invalid zip archive") from exc
    except tarfile.TarError as exc:
        raise HTTPException(status_code=400, detail="Invalid tar archive") from exc

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

        results = _scan_extracted_files(extracted)
    return _assemble_result(filename, archive_type, results, warnings)


def _scan_single_file(upload_bytes: bytes, filename: str) -> Dict[str, object]:
    results = [_scan_file_bytes(filename, upload_bytes)]
    return _assemble_result(filename, "skill", results, [])


def _safe_extract_zip(
    upload_bytes: bytes,
    root: Path,
    warnings: List[str],
) -> List[Tuple[str, Path]]:
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


def _safe_extract_tar(
    upload_bytes: bytes,
    root: Path,
    warnings: List[str],
) -> List[Tuple[str, Path]]:
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


def _scan_extracted_files(files: Iterable[Tuple[str, Path]]) -> List[Dict[str, object]]:
    results = []
    sorted_files = sorted(files, key=_priority_key)
    for rel_path, path in sorted_files:
        data = path.read_bytes()
        results.append(_scan_file_bytes(rel_path, data))
    return results


def _priority_key(item: Tuple[str, Path]) -> Tuple[int, str]:
    rel_path = item[0]
    name = Path(rel_path).name.lower()
    extension = Path(rel_path).suffix.lower()

    if name in PRIORITY_FILENAMES:
        return (0, name)
    if extension in PRIORITY_EXTENSIONS:
        return (1, rel_path.lower())
    return (2, rel_path.lower())


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
    entry["findings"] = _scan_text(text)
    return entry


def _scan_text(text: str) -> List[Dict[str, object]]:
    findings = []

    for pattern in PATTERNS:
        matches = pattern["compiled"].findall(text)
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


def _sanitize_member_name(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)

    if path.is_absolute():
        return None

    if ".." in path.parts:
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
    while True:
        chunk = source.read(min(1024 * 1024, remaining))
        if not chunk:
            break
        target.write(chunk)
        remaining -= len(chunk)
        if remaining == 0:
            break


def _is_probably_text(data: bytes) -> bool:
    if not data:
        return True

    if b"\x00" in data:
        return False

    sample = data[:4096]
    printable = sum(1 for byte in sample if 32 <= byte <= 126 or byte in (9, 10, 13))
    return printable / len(sample) >= 0.7
