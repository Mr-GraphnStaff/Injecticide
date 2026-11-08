from __future__ import annotations

import io
import re
import zipfile
from typing import Iterable, Tuple
from xml.etree import ElementTree


SQLITE_HEADER = b"SQLite format 3\x00"
MAX_OFFICE_PARTS = 50
MAX_OFFICE_TEXT_CHARS = 100_000
MAX_OFFICE_PART_BYTES = 1024 * 1024
MAX_OFFICE_TOTAL_XML_BYTES = 5 * 1024 * 1024


def extract_scannable_text(data: bytes) -> Tuple[str | None, str]:
    if is_probably_text(data):
        return data.decode("utf-8", errors="replace"), ""

    if looks_like_sqlite(data):
        text = extract_sqlite_text(data)
        if text is None:
            return None, "Binary or non-text content"
        return text, "Scanned SQLite database content."

    if looks_like_zip(data):
        text = extract_office_document_text(data)
        if text is not None:
            return text, "Scanned Office document content."

    return None, "Binary or non-text content"


def is_probably_text(data: bytes) -> bool:
    if not data:
        return True

    if b"\x00" in data:
        return False

    sample = data[:4096]
    printable = sum(1 for byte in sample if 32 <= byte <= 126 or byte in (9, 10, 13))
    return printable / len(sample) >= 0.7


def looks_like_sqlite(data: bytes) -> bool:
    return data.startswith(SQLITE_HEADER)


def looks_like_zip(data: bytes) -> bool:
    return zipfile.is_zipfile(io.BytesIO(data))


def extract_sqlite_text(data: bytes) -> str | None:
    return extract_sqlite_projection(data)[0]


def extract_sqlite_projection(data: bytes):
    """Return (projection text, coverage evidence) from a complete, budgeted read.

    Every row of every table is read; long values are chunked, not truncated.
    Detection with table/column/row citations runs in
    database_analysis.scan_database_entry; this projection serves callers that
    only need text. The returned text is bounded for package-level analyses and
    the evidence states how much of the database was read.
    """
    try:
        from .database_analysis import project_database_text
    except ImportError:  # pragma: no cover - flat import layout used by the container
        from database_analysis import project_database_text
    return project_database_text(data)


def extract_office_document_text(data: bytes) -> str | None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = [info.filename for info in archive.infolist() if not info.is_dir()]
            part_names = _office_part_names(names)
            if not part_names:
                return None

            lines = []
            total_chars = 0
            total_xml_bytes = 0
            if len(part_names) > MAX_OFFICE_PARTS:
                raise ValueError("Office content exceeds XML part-count analysis limit.")
            for name in part_names[:MAX_OFFICE_PARTS]:
                try:
                    part = archive.getinfo(name)
                    total_xml_bytes += part.file_size
                    if part.file_size > MAX_OFFICE_PART_BYTES or total_xml_bytes > MAX_OFFICE_TOTAL_XML_BYTES:
                        raise ValueError("Office content exceeds decompressed XML analysis limit.")
                    xml_bytes = archive.read(name)
                except KeyError:
                    continue

                xml_text = _extract_xml_text(xml_bytes)
                if not xml_text:
                    continue

                line = f"part={name} text={xml_text}"
                lines.append(line)
                total_chars += len(line) + 1
                if total_chars >= MAX_OFFICE_TEXT_CHARS:
                    break

            if not lines:
                return None

            return "\n".join(lines)
    except (OSError, zipfile.BadZipFile, ElementTree.ParseError):
        return None


def _office_part_names(names: Iterable[str]) -> list[str]:
    normalized = [name.replace("\\", "/") for name in names]

    if any(name.startswith("ppt/") for name in normalized):
        prefixes = ("ppt/slides/", "ppt/notesSlides/", "ppt/comments/", "docProps/")
    elif any(name.startswith("word/") for name in normalized):
        prefixes = ("word/", "docProps/")
    elif any(name.startswith("xl/") for name in normalized):
        prefixes = ("xl/sharedStrings", "xl/worksheets/", "xl/comments", "docProps/")
    else:
        return []

    part_names = [
        name
        for name in normalized
        if name.endswith(".xml") and any(name.startswith(prefix) for prefix in prefixes)
    ]
    return sorted(part_names)


def _extract_xml_text(xml_bytes: bytes) -> str:
    if b"<!DOCTYPE" in xml_bytes.upper() or b"<!ENTITY" in xml_bytes.upper():
        raise ValueError("Office XML with DTD/entities is outside the safe parser profile.")
    root = ElementTree.fromstring(xml_bytes)
    text = " ".join(segment.strip() for segment in root.itertext() if segment and segment.strip())
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > 500:
        return text[:500].rstrip() + "..."
    return text
