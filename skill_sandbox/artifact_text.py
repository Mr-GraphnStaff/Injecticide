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
MAX_SQLITE_VALUE_CHARS = 4096
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
    """Return the bounded projection with measured sampling, never full-DB claims."""
    evidence = {"status": "partial", "tables": [], "table_limit": MAX_SQLITE_TABLES,
                "row_limit_per_table": MAX_SQLITE_ROWS_PER_TABLE,
                "text_character_limit": MAX_SQLITE_TEXT_CHARS,
                "value_character_limit": 200, "blob_values": "omitted",
                "scope": "Sampled row text only; original database bytes are not exhaustively analyzed."}
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as handle:
        db_path = handle.name
        handle.write(data)

    try:
        return _read_sqlite_rows(db_path, evidence), evidence
    except sqlite3.DatabaseError:
        evidence["reason"] = "SQLite projection unavailable within the safe parser and operation budget."
        return None, evidence
    finally:
        os.unlink(db_path)


def _read_sqlite_rows(db_path: str, evidence=None) -> str:
    lines = []
    total_chars = 0
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    operations = [0]
    def budget():
        operations[0] += 1
        return operations[0] > 5000
    connection.set_progress_handler(budget, 1000)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")

    try:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT ?",
                (MAX_SQLITE_TABLES,),
            )
        ]
        if evidence is not None:
            evidence["tables_seen"] = connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchone()[0]

        for table in tables:
            quoted_table = table.replace('"', '""')
            table_evidence = {"table": table, "sampled_rows": 0, "total_rows": None,
                              "total_rows_status": "not_measured"}
            if evidence is not None:
                evidence["tables"].append(table_evidence)
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{quoted_table}")')]
            if not columns:
                continue

            lines.append(f"table={table} columns={', '.join(columns)}")
            total_chars += len(lines[-1]) + 1
            if total_chars >= MAX_SQLITE_TEXT_CHARS:
                break

            # Slice TEXT inside SQLite so one large value is not copied into Python.
            # BLOBs remain inventory only, as in _render_sqlite_value.
            projections = []
            for column in columns:
                quoted_column = column.replace('"', '""')
                identifier = f'"{quoted_column}"'
                projections.append(
                    f"CASE WHEN typeof({identifier}) = 'text' "
                    f"THEN substr({identifier}, 1, {MAX_SQLITE_VALUE_CHARS}) "
                    f"WHEN typeof({identifier}) = 'blob' THEN NULL ELSE {identifier} END"
                )
            query = (f'SELECT {", ".join(projections)} FROM "{quoted_table}" '
                     f'LIMIT {MAX_SQLITE_ROWS_PER_TABLE}')
            for row in connection.execute(query):
                table_evidence["sampled_rows"] += 1
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
        if evidence is not None:
            # Counts are independently bounded; an expensive count does not erase
            # a successful projection or turn an unknown total into zero.
            operations[0] = 0
            for table_evidence in evidence["tables"]:
                quoted_table = table_evidence["table"].replace('"', '""')
                try:
                    table_evidence["total_rows"] = connection.execute(f'SELECT count(*) FROM "{quoted_table}"').fetchone()[0]
                    table_evidence["total_rows_status"] = "measured"
                except sqlite3.DatabaseError:
                    table_evidence["total_rows_status"] = "unavailable_within_budget"
            evidence["sampled_rows"] = sum(row["sampled_rows"] for row in evidence["tables"])
            evidence["projection_characters"] = len("\n".join(lines))
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
