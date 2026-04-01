from __future__ import annotations

import io
import os
import re
import sqlite3
import tempfile
import zipfile
from typing import Iterable, Tuple
from xml.etree import ElementTree


SQLITE_HEADER = b"SQLite format 3\x00"
MAX_SQLITE_TABLES = 25
MAX_SQLITE_ROWS_PER_TABLE = 50
MAX_SQLITE_TEXT_CHARS = 100_000
MAX_OFFICE_PARTS = 50
MAX_OFFICE_TEXT_CHARS = 100_000


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
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as handle:
        db_path = handle.name
        handle.write(data)

    try:
        return _read_sqlite_rows(db_path)
    except sqlite3.DatabaseError:
        return None
    finally:
        os.unlink(db_path)


def _read_sqlite_rows(db_path: str) -> str:
    lines = []
    total_chars = 0
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    try:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT ?",
                (MAX_SQLITE_TABLES,),
            )
        ]

        for table in tables:
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')]
            if not columns:
                continue

            lines.append(f"table={table} columns={', '.join(columns)}")
            total_chars += len(lines[-1]) + 1
            if total_chars >= MAX_SQLITE_TEXT_CHARS:
                break

            query = f'SELECT * FROM "{table}" LIMIT {MAX_SQLITE_ROWS_PER_TABLE}'
            for row in connection.execute(query):
                values = []
                for column, value in zip(columns, row):
                    rendered = _render_sqlite_value(value)
                    if rendered:
                        values.append(f"{column}={rendered}")
                if not values:
                    continue
                line = f"table={table} " + " ".join(values)
                lines.append(line)
                total_chars += len(line) + 1
                if total_chars >= MAX_SQLITE_TEXT_CHARS:
                    break
            if total_chars >= MAX_SQLITE_TEXT_CHARS:
                break
    finally:
        connection.close()

    return "\n".join(lines)


def _render_sqlite_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return ""

    text = re.sub(r"\s+", " ", str(value)).strip()
    if not text:
        return ""
    if len(text) > 200:
        return text[:200].rstrip() + "..."
    return text


def extract_office_document_text(data: bytes) -> str | None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = [info.filename for info in archive.infolist() if not info.is_dir()]
            part_names = _office_part_names(names)
            if not part_names:
                return None

            lines = []
            total_chars = 0
            for name in part_names[:MAX_OFFICE_PARTS]:
                try:
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
    root = ElementTree.fromstring(xml_bytes)
    text = " ".join(segment.strip() for segment in root.itertext() if segment and segment.strip())
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > 500:
        return text[:500].rstrip() + "..."
    return text
