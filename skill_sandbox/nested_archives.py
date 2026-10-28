"""In-memory bounded nested ZIP inventory, without file writes or execution.

Sources: https://docs.python.org/3/library/zipfile.html and
https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT (ZIP 6.3.10).
Only stored/deflated, single-volume, non-ZIP64 inner archives are expanded.
Unsupported compression/containers remain explicit coverage gaps.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import io
from pathlib import PurePosixPath
import re
import stat
import struct
import zipfile
import zlib


@dataclass
class NestedArchiveBudget:
    """One instance per outer scan, reused across all sibling inner archives."""
    max_files: int = 200
    max_bytes: int = 64 * 1024 * 1024
    max_member_bytes: int = 5 * 1024 * 1024
    max_depth: int = 3
    files_used: int = 0
    bytes_used: int = 0
    seen_paths: set[str] = field(default_factory=set)


def is_nested_zip(data: bytes, path: str) -> bool:
    suffix = PurePosixPath(path.replace("\\", "/")).suffix.lower()
    if suffix in {".docx", ".pptx", ".xlsx", ".odt", ".ods", ".odp"}:
        return False
    return suffix == ".zip" or (suffix == ".skill" and data.startswith(b"PK")) or data.startswith((b"PK\x03\x04", b"PK\x05\x06"))


def _record(path: str, size: int, reason: str, state="rejected_unsafe_entry", **extra) -> dict:
    return {"path": path, "size": size, "skipped": True, "reason": reason,
            "assessment_state": state, "artifact_role": "reference", "findings": [], **extra}


def _preflight(data: bytes, remaining_files: int) -> tuple[str | None, int | None]:
    # Inspect EOCD before ZipFile materializes the whole central directory.
    start = max(0, len(data) - (65535 + 22))
    position = data.rfind(b"PK\x05\x06", start)
    if position < 0 or position + 22 > len(data):
        return "ZIP end-of-central-directory record is missing or truncated.", None
    disk, directory_disk, disk_count, total_count, directory_size, directory_offset, comment_size = struct.unpack_from("<HHHHIIH", data, position + 4)
    if position + 22 + comment_size != len(data):
        return "ZIP end record has inconsistent comment length or trailing bytes.", None
    if disk or directory_disk or disk_count != total_count:
        return "Multipart ZIP archives are not supported for nested inspection.", None
    if total_count == 0xffff or directory_size == 0xffffffff or directory_offset == 0xffffffff:
        return "ZIP64 inner archives are not supported for nested inspection.", None
    if directory_offset + directory_size > position:
        return "ZIP central-directory bounds exceed the end record.", None
    if total_count > max(0, remaining_files):
        return "Nested archive member count exceeds the remaining shared file budget.", total_count
    # A forged EOCD count must not make ZipFile allocate an unbounded list of
    # central records. Walk only fixed headers and lengths before construction.
    cursor, observed = directory_offset, 0
    directory_end = directory_offset + directory_size
    while cursor < directory_end:
        if observed >= total_count or cursor + 46 > directory_end or data[cursor:cursor + 4] != b"PK\x01\x02":
            return "ZIP central-directory record bounds or count are inconsistent.", None
        name_size, extra_size, member_comment_size = struct.unpack_from("<HHH", data, cursor + 28)
        cursor += 46 + name_size + extra_size + member_comment_size
        observed += 1
    if cursor != directory_end or observed != total_count:
        return "ZIP central-directory record bounds or count are inconsistent.", None
    return None, total_count


def _member_name(info: zipfile.ZipInfo) -> str | None:
    # Reject archive boundary delimiters to keep descendant identities unambiguous.
    original = info.orig_filename
    if (not original or len(original) > 4096 or "\x00" in original or "!" in original
            or "\\" in original or re.match(r"^[A-Za-z]:", original)):
        return None
    candidate = PurePosixPath(original)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        return None
    return str(candidate)


def inspect_nested_zip(data: bytes, path: str, budget: NestedArchiveBudget | None = None,
                       depth: int = 1) -> dict:
    """Return flat descendants and explicit exclusions under ``path!/member``.

    ``entries`` contain bytes for the caller's existing scanners. Nested container
    entries also carry ``container_inspection``. Bytes/files consumed by all
    recursive calls are charged to the same budget, including failed reads and
    rejected records. The root container's compressed bytes are already held by
    its caller; descendants are charged again at each expansion boundary.
    """
    budget = budget if budget is not None else NestedArchiveBudget()
    container = {"format": "zip", "status": "inspected", "depth": depth,
                 "checks": [], "limitations": [
                     "Container inspection does not establish descendant behavior or execution safety.",
                     "Only central-directory-declared members are expanded; archive comments, extra fields, prefixes and unreferenced bytes are not analyzed.",
                 ],
                 "members_seen": 0, "sha256": hashlib.sha256(data).hexdigest(),
                 "bytes_supplied": len(data)}
    result = {"container": container, "entries": [], "excluded": []}

    def incomplete(reason, state="limited_or_truncated", size=0, target=path, **extra):
        if container["status"] != "malformed":
            container["status"] = "partial"
        container["limitations"].append(reason)
        result["excluded"].append(_record(target, size, reason, state, **extra))

    if depth > budget.max_depth:
        incomplete("Nested archive depth budget reached.", size=len(data))
        return result
    # Bound the input used by ZipFile and the EOCD search independently of output.
    if len(data) > budget.max_member_bytes:
        incomplete("Nested archive input exceeds the member byte budget.", size=len(data))
        return result
    reason, declared_count = _preflight(data, budget.max_files - budget.files_used)
    if reason:
        if "missing or truncated" in reason or "inconsistent" in reason or "bounds" in reason:
            container["status"] = "malformed"
        incomplete(reason, size=len(data), unlisted_members=declared_count)
        return result
    container["checks"] = ["end_record", "directory_bounds", "member_names", "entry_types", "member_crc", "shared_expansion_budgets"]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) != declared_count:
                container["status"] = "malformed"
                incomplete("ZIP central-directory entry count disagrees with the end record.", size=len(data))
                return result
            local_names = set()
            for index, info in enumerate(members):
                if budget.files_used >= budget.max_files:
                    incomplete("Nested archive shared file budget reached.", unlisted_members=len(members) - index)
                    break
                budget.files_used += 1
                container["members_seen"] += 1
                safe_name = _member_name(info)
                display_name = info.orig_filename[:4096]
                member_path = f"{path}!/{safe_name if safe_name else display_name}"
                if safe_name is None:
                    incomplete("Unsafe or ambiguous nested archive member path.", "rejected_unsafe_entry", info.file_size, member_path)
                    continue
                identity = member_path.casefold()
                if identity in budget.seen_paths or safe_name.casefold() in local_names:
                    incomplete("Duplicate or case-colliding nested archive member path.", "rejected_unsafe_entry", info.file_size, member_path)
                    continue
                local_names.add(safe_name.casefold())
                budget.seen_paths.add(identity)
                mode = info.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if stat.S_ISLNK(mode) or file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    incomplete("Links and special nested archive entries are not allowed.", "rejected_unsafe_entry", info.file_size, member_path)
                    continue
                if info.flag_bits & 1:
                    incomplete("Encrypted nested archive entries cannot be inspected.", "unsupported", info.file_size, member_path)
                    continue
                if info.is_dir():
                    continue
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    incomplete("Nested archive compression method is unsupported.", "unsupported", info.file_size, member_path)
                    continue
                if info.file_size > budget.max_member_bytes:
                    incomplete("Nested archive member exceeds the per-member byte budget.", size=info.file_size, target=member_path)
                    continue
                if info.file_size > budget.max_bytes - budget.bytes_used:
                    incomplete("Nested archive member exceeds the remaining shared expanded byte budget.", size=info.file_size, target=member_path)
                    continue
                # Charge declared output before attempting decompression; corrupt
                # members cannot recycle work budgets across siblings.
                budget.bytes_used += info.file_size
                try:
                    with archive.open(info) as member:
                        raw = member.read(info.file_size + 1)
                    if len(raw) != info.file_size:
                        raise zipfile.BadZipFile("Expanded size disagrees with directory")
                except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, zlib.error):
                    incomplete("Nested archive member failed bounded decompression, size or CRC validation.", "malformed_archive_entry", info.file_size, member_path)
                    container["status"] = "malformed"
                    continue
                entry = {"path": member_path, "data": raw, "depth": depth,
                         "container_path": path, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
                result["entries"].append(entry)
                if is_nested_zip(raw, safe_name):
                    nested = inspect_nested_zip(raw, member_path, budget, depth + 1)
                    entry["container_inspection"] = nested["container"]
                    result["entries"].extend(nested["entries"])
                    result["excluded"].extend(nested["excluded"])
                    if nested["container"]["status"] != "inspected":
                        if container["status"] != "malformed":
                            container["status"] = "partial"
                        container["limitations"].append("At least one descendant archive has incomplete inspection.")
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, ValueError, struct.error):
        container["status"] = "malformed"
        incomplete("Nested ZIP central directory could not be parsed safely.", size=len(data))
    container["shared_files_used"] = budget.files_used
    container["shared_expanded_bytes_used"] = budget.bytes_used
    return result
