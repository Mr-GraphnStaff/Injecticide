from __future__ import annotations

import os
import re
import sqlite3
import tempfile
from typing import Tuple


SQLITE_HEADER = b"SQLite format 3\x00"
MAX_SQLITE_TABLES = 25
MAX_SQLITE_ROWS_PER_TABLE = 50
MAX_SQLITE_TEXT_CHARS = 100_000


def extract_scannable_text(data: bytes) -> Tuple[str | None, str]:
    if is_probably_text(data):
        return data.decode("utf-8", errors="replace"), ""

    if looks_like_sqlite(data):
        text = extract_sqlite_text(data)
        if text is None:
            return None, "Binary or non-text content"
        return text, "Scanned SQLite database content."

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
