"""Complete, budgeted reading of SQLite databases packaged inside skills.

Every row of every table is read (streamed), long values are scanned in
overlapping chunks, BLOBs are typed by magic bytes, one encoding layer is
decoded, schema SQL is inspected, and bytes not holding live records (free
pages, unallocated page space, freeblocks, overflow tails) get a raw
printable-string pass. Each text value is supplied to the same detectors as a
plain file, and every database observation carries a table/column/rowid
citation. Coverage is measured, never assumed: anything not read is listed in
``coverage.unread`` with a reason.

Format source: SQLite database file format, https://www.sqlite.org/fileformat2.html
(header fields, freelist trunk/leaf pages, b-tree page header, cell layout,
overflow local-payload formulas). FTS shadow table names:
https://www.sqlite.org/fts5.html#fts5_table_creation_and_initialization and
https://www.sqlite.org/fts3.html#shadow_tables. Magic numbers: PE (MZ),
ELF (7F 45 4C 46), Mach-O (FEEDFACE/FEEDFACF/CAFEBABE and byte-swapped forms),
ZIP (PK 03 04), gzip (RFC 1952: 1F 8B), zlib (RFC 1950 CMF/FLG check).
"""
from __future__ import annotations

import base64
import binascii
import gzip
import math
import re
import sqlite3
import time
import zlib
from collections import Counter
from functools import lru_cache
from pathlib import PurePosixPath
from typing import Callable, Dict, List, Optional, Tuple

SCHEMA_ID = "injecticide-db-profile/v1"
SQLITE_HEADER = b"SQLite format 3\x00"
DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".db3", ".sdb", ".s3db", ".sl3"}

# Budgets: wall-clock and size, never a row cap.
DB_TIME_BUDGET_SECONDS = 90.0
PACKAGE_TIME_BUDGET_SECONDS = 60  # shared deadline across database members in one package
DB_TEXT_BUDGET_CHARS = 24 * 1024 * 1024  # projection characters supplied to detectors
VALUE_CHUNK_CHARS = 4096               # long values are scanned in chunks of this size
VALUE_CHUNK_OVERLAP = 256              # so a pattern spanning a chunk edge is still seen
DETECTOR_CHUNK_CHARS = 128 * 1024      # projection characters per detector call
MAX_DECODE_BYTES = 4 * 1024 * 1024     # bound on one decoded/decompressed value
MAX_SLACK_BYTES = 64 * 1024 * 1024     # bytes examined by the free-space string pass
MIN_FRAGMENT_CHARS = 8                 # shortest printable run treated as a text fragment
CONTACT_DIRECTORY_REVIEW_ABOVE = 200   # contact_directory: info up to this many records
MIN_DOMINANT_DOMAIN_EMAILS = 3
RETURNED_TEXT_CHARS = 1024 * 1024      # projection returned for package-level analyses
MAX_OBSERVATIONS = 10
DETECTOR_PATH_SUFFIX = ".csv"          # line-delimited scan units in scan_rules/contextual_rules

FTS_SHADOW_SUFFIXES = {
    "fts5": ("_data", "_idx", "_content", "_docsize", "_config"),
    "fts4": ("_content", "_segments", "_segdir", "_docsize", "_stat"),
    "fts3": ("_content", "_segments", "_segdir", "_docsize", "_stat"),
}

# Widely used consumer mailbox providers; an address here is personal, not organisational.
FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "outlook.com", "hotmail.com",
    "hotmail.co.uk", "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me",
    "protonmail.com", "pm.me", "gmx.com", "gmx.de", "gmx.net", "mail.com", "yandex.ru", "yandex.com",
    "zoho.com", "qq.com", "163.com", "126.com", "web.de", "fastmail.com", "tutanota.com", "hey.com",
}

CONTACT_CLASSES = ("business_contact_email", "work_phone", "person_name", "job_title", "department",
                   "manager_reference", "employee_id")
SENSITIVE_CLASSES = ("ssn", "date_of_birth", "home_address", "financial", "health", "credential")
DIRECTORY_TABLE_TOKENS = {"employee", "employees", "staff", "people", "person", "persons", "contact", "contacts",
                          "user", "users", "directory", "member", "members", "personnel", "team", "teams", "org",
                          "roster", "colleague", "colleagues", "worker", "workers", "hr", "phonebook"}

EMAIL_VALUE = re.compile(r"^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$")
EMAIL_ANY = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
PHONE_VALUE = re.compile(r"^\+?[\d\s().-]{7,22}(?:\s*(?:x|ext\.?)\s*\d{1,6})?$", re.I)
SSN_VALUE = re.compile(r"^\d{3}-\d{2}-\d{4}$")
BASE64_VALUE = re.compile(r"^[A-Za-z0-9+/_-]{20,}={0,2}$")
HEX_VALUE = re.compile(r"^(?:0x)?(?:[0-9a-fA-F]{2}){16,}$")
URL_IN_SQL = re.compile(r"\b(?:https?|ftp|wss?)://", re.I)
CODE_IN_SQL = re.compile(r"\b(?:eval|exec|popen|subprocess|powershell|cmd\.exe|bash\s+-c|curl|wget|os\.system|"
                         r"load_extension|readfile|writefile|edit|fts3_tokenizer)\s*\(|<script\b|\bimport\s+[a-z_]+|"
                         r"\b(?:curl|wget)\s+-", re.I)
SQL_LITERAL = re.compile(r"'((?:[^']|'')*)'")
INSTRUCTION_WORDS = re.compile(r"\b(?:ignore|disregard|assistant|instructions?|you\s+(?:must|should|are|will)|"
                               r"system\s+prompt|always|never|do\s+not|don't|forget|pretend|respond|reply|reveal|"
                               r"send|tell\s+the\s+user|model)\b", re.I)
# Remnant bytes concatenate record-header bytes and adjacent values without
# separators; a space is inserted before a capitalised word glued to a letter.
WORD_JOIN = re.compile(r"(?<=[A-Za-z])(?=[A-Z][a-z])")
PRINTABLE_RUN = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_FRAGMENT_CHARS)

TIER_RANK = {"block": 0, "review": 1, "info": 2}
MASKED_PII_PREFIXES = ("pii_", "phi_")


# --------------------------------------------------------------------------- utilities

class Budget:
    def __init__(self, seconds: float = None, chars: int = None):
        self.seconds = DB_TIME_BUDGET_SECONDS if seconds is None else seconds
        self.chars = DB_TEXT_BUDGET_CHARS if chars is None else chars
        self.deadline = time.monotonic() + self.seconds
        self.used_chars = 0

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline


def is_database_path(path: str) -> bool:
    return PurePosixPath(str(path).replace("\\", "/")).suffix.lower() in DATABASE_SUFFIXES


def _tokens(name: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name))
    return [token for token in re.split(r"[^a-z0-9]+", spaced.lower()) if token]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum(n / len(data) * math.log2(n / len(data)) for n in counts.values())


def _single_line(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def blob_kind(value: bytes) -> str:
    """Classify BLOB bytes by magic number; 'text' when they decode as readable text."""
    head = value[:8]
    if head.startswith(b"MZ"):
        return "pe_executable"
    if head.startswith(b"\x7fELF"):
        return "elf_executable"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho_executable"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip_archive"
    if head.startswith(b"\x1f\x8b"):
        return "gzip_archive"
    if head.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")):
        return "archive"
    if head.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM")) or (
            head.startswith(b"RIFF") and value[8:12] == b"WEBP"):
        return "image"
    if _zlib_header(value):
        return "zlib"
    if _bytes_to_text(value) is not None:
        return "text"
    return "opaque"


def _zlib_header(value: bytes) -> bool:
    return len(value) > 2 and value[0] & 0x0F == 8 and value[0] >> 4 <= 7 and ((value[0] << 8) | value[1]) % 31 == 0


def _bytes_to_text(value: bytes) -> Optional[str]:
    if not value:
        return None
    if value.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            text = value.decode("utf-16")
        except UnicodeDecodeError:
            return None
    else:
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    sample = text[:4096]
    printable = sum(1 for ch in sample if ch.isprintable() or ch in "\t\r\n")
    return text if printable / max(len(sample), 1) >= 0.85 else None


def _decompress_bounded(value: bytes, wbits: int) -> Optional[bytes]:
    try:
        decompressor = zlib.decompressobj(wbits)
        out = decompressor.decompress(value, MAX_DECODE_BYTES)
        return out
    except zlib.error:
        return None


def decode_one_layer(value: str) -> Tuple[Optional[str], Optional[str], bool]:
    """Return (decoded_text, encoding, looked_encoded) for one base64/hex/zlib layer."""
    stripped = value.strip()
    raw = None
    encoding = None
    if HEX_VALUE.match(stripped):
        try:
            raw = binascii.unhexlify(stripped[2:] if stripped.lower().startswith("0x") else stripped)
            encoding = "hex"
        except (binascii.Error, ValueError):
            raw = None
    elif BASE64_VALUE.match(stripped) and len(stripped.rstrip("=")) % 4 != 1 and (
            re.search(r"\d", stripped) or re.search(r"[+/=_-]", stripped)) and re.search(r"[A-Z]", stripped) \
            and re.search(r"[a-z]", stripped):
        padded = stripped + "=" * (-len(stripped) % 4)
        try:
            raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
            encoding = "base64"
        except (binascii.Error, ValueError):
            raw = None
    if raw is None:
        return None, None, False
    if _zlib_header(raw):
        # zlib inside base64/hex is a second layer: counted as opaque, not decoded.
        return None, encoding, True
    text = _bytes_to_text(raw[:MAX_DECODE_BYTES])
    return text, encoding, True


def mask_email(value: str) -> str:
    def repl(match):
        local, domain = match.group(0).split("@", 1)
        return (local[:1] or "*") + "***@" + domain
    return EMAIL_ANY.sub(repl, value)


def mask_work_emails(text: str, domain: Optional[str]) -> str:
    """Mask addresses at the organisation's own domain; contact_directory reports them."""
    if not domain or "@" not in text:
        return text

    def repl(match):
        if match.group(1).lower() != domain:
            return match.group(0)
        local, rest = match.group(0).split("@", 1)
        return (local[:1] or "*") + "***@" + rest
    return EMAIL_ANY.sub(repl, text)


def mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return "(***) ***-" + digits[-4:] if len(digits) >= 4 else "***"


def mask_sample(text: str, detector_id: str = "") -> str:
    """Mask personal data in a sample: j***@domain, (***) ***-1234, ***-**-6789."""
    text = mask_email(text)
    if detector_id == "pii_phone_number":
        return re.sub(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", lambda m: mask_phone(m.group(0)), text)
    if detector_id == "pii_ssn":
        return re.sub(r"\d{3}([- ]?)\d{2}([- ]?)(\d{4})", lambda m: f"***{m[1]}**{m[2]}{m[3]}", text)
    if detector_id.startswith(MASKED_PII_PREFIXES):
        return re.sub(r"\d", "*", text)
    return text


# --------------------------------------------------------------------------- column classes

def _name_classes(table: str, column: str) -> List[str]:
    tokens = _tokens(column)
    joined = "_".join(tokens)
    table_tokens = set(_tokens(table))
    directory_table = bool(table_tokens & DIRECTORY_TABLE_TOKENS)
    classes = []
    has = lambda *words: any(word in tokens for word in words)  # noqa: E731
    if has("ssn") or "social_security" in joined or "national_id" in joined or "national_insurance" in joined:
        classes.append("ssn")
    if has("dob", "birthday", "birthdate") or "birth" in joined:
        classes.append("date_of_birth")
    if (has("home", "street", "residential", "postcode", "zip", "zipcode") or joined in {
            "address", "addr", "address1", "address_1", "address_line1", "address_line_1", "address_line2",
            "address_line_2", "postal_code", "mailing_address"}) and not has(
            "email", "ip", "mac", "url", "web", "office", "work", "business"):
        classes.append("home_address")
    if has("salary", "wage", "wages", "compensation", "bonus", "bank", "iban", "swift", "routing", "cvv", "ccn") or any(
            phrase in joined for phrase in ("account_number", "acct_no", "credit_card", "card_number", "tax_id")):
        classes.append("financial")
    if has("diagnosis", "medical", "health", "medication", "medications", "prescription", "mrn", "allergy",
           "allergies", "disability", "treatment", "patient", "icd", "symptom", "symptoms"):
        classes.append("health")
    if has("password", "passwd", "pwd", "secret", "token", "apikey", "credential", "credentials") or any(
            phrase in joined for phrase in ("api_key", "private_key")):
        classes.append("credential")
    if has("manager", "supervisor") or "reports_to" in joined or "line_manager" in joined:
        classes.append("manager_reference")
    elif has("employee", "emp", "staff", "personnel", "badge", "worker") and has("id", "number", "no", "num", "code"):
        classes.append("employee_id")
    if joined in {"first_name", "last_name", "full_name", "given_name", "family_name", "display_name", "middle_name",
                  "firstname", "lastname", "fullname", "surname", "preferred_name", "employee_name", "contact_name",
                  "person_name"} or (joined == "name" and directory_table):
        classes.append("person_name")
    if joined in {"job_title", "jobtitle", "designation", "position_title"} or (
            joined in {"title", "position", "role"} and directory_table):
        classes.append("job_title")
    if has("department", "dept", "division") or joined in {"business_unit", "org_unit", "cost_center"} or (
            joined == "team" and directory_table):
        classes.append("department")
    if has("phone", "tel", "telephone", "mobile", "cell", "fax", "extension") and "home_address" not in classes:
        classes.append("work_phone" if not has("home", "personal", "private") else "home_address")
    if has("notes", "note", "comment", "comments", "description", "body", "content", "message", "text", "summary", "bio"):
        classes.append("free_text")
    return classes


@lru_cache(maxsize=1)
def _content_class_patterns():
    try:
        from .sensitive_data import SENSITIVE_DATA_RULES
    except ImportError:
        from sensitive_data import SENSITIVE_DATA_RULES
    classes = {"pii_ssn": "ssn", "pii_date_of_birth": "date_of_birth",
               "phi_medical_record_number": "health"}
    return [(rule["compiled_pattern"], classes[rule["id"]])
            for rule in SENSITIVE_DATA_RULES if rule["id"] in classes]


class ColumnState:
    def __init__(self, table: str, name: str, declared_type: str):
        self.name = name
        self.declared_type = declared_type
        self.name_classes = _name_classes(table, name)
        self.values = 0
        self.text_values = 0
        self.text_chars = 0
        self.opaque = 0
        self.emails = Counter()
        self.email_values = 0
        self.phones = 0
        self.ssns = 0
        self.classes: List[str] = []
        self.content_classes = set()
        self.content_email_domains = set()

    def observe_text(self, value: str):
        # Classify every value before bounded report observations are selected.
        self.content_email_domains.update(match.group(1).lower() for match in EMAIL_ANY.finditer(value))
        for pattern, data_class in _content_class_patterns():
            if pattern.search(value):
                self.content_classes.add(data_class)
        self.text_values += 1
        self.text_chars += len(value)
        stripped = value.strip()
        if len(stripped) <= 254:
            email = EMAIL_VALUE.match(stripped)
            if email:
                self.email_values += 1
                self.emails[email.group(1).lower()] += 1
                return
            if SSN_VALUE.match(stripped):
                self.ssns += 1
            elif PHONE_VALUE.match(stripped) and len(re.sub(r"\D", "", stripped)) >= 7:
                self.phones += 1

    def finalize(self, dominant_domain: Optional[str]):
        classes = list(self.name_classes) + sorted(self.content_classes)
        if any(domain != dominant_domain for domain in self.content_email_domains):
            classes.append("personal_email")
        base = max(self.text_values, 1)
        if self.email_values and self.email_values * 2 >= base:
            if dominant_domain and self.emails.get(dominant_domain):
                classes.append("business_contact_email")
            if any(domain in FREE_MAIL_DOMAINS for domain in self.emails):
                classes.append("personal_email")
            if "manager_reference" in classes and "business_contact_email" in classes:
                classes.remove("business_contact_email")
        if self.ssns and self.ssns * 2 >= base and "ssn" not in classes:
            classes.append("ssn")
        if self.phones and self.phones * 2 >= base and "work_phone" not in classes and "home_address" not in classes \
                and "employee_id" not in classes:
            classes.append("work_phone")
        if not classes and self.text_values and self.text_chars / self.text_values >= 40:
            classes.append("free_text")
        self.classes = list(dict.fromkeys(classes))
        return self.classes


# --------------------------------------------------------------------------- reading

class Line:
    __slots__ = ("text", "citation", "bucket", "table_index", "ordinal", "contact_key")

    def __init__(self, text, citation, table_index=None, ordinal=None, contact_key=None):
        self.text = text
        self.citation = citation
        self.bucket = "general"
        self.table_index = table_index
        self.ordinal = ordinal
        self.contact_key = contact_key  # (column index, kind) for routing decisions


def _open(data: bytes) -> sqlite3.Connection:
    raw = bytearray(data)
    if len(raw) > 19 and raw[18] == 2 and raw[19] == 2:
        # WAL-mode header: read the main file as a rollback-journal database.
        raw[18] = raw[19] = 1
    connection = sqlite3.connect(":memory:")
    if not hasattr(connection, "deserialize"):
        connection.close()
        raise sqlite3.NotSupportedError("This SQLite build cannot deserialize database assets; contents are unread.")
    for flag, value in (("SQLITE_DBCONFIG_DEFENSIVE", True), ("SQLITE_DBCONFIG_TRUSTED_SCHEMA", False),
                        ("SQLITE_DBCONFIG_ENABLE_TRIGGER", False), ("SQLITE_DBCONFIG_ENABLE_VIEW", True)):
        if hasattr(sqlite3, flag) and hasattr(connection, "setconfig"):
            try:
                connection.setconfig(getattr(sqlite3, flag), value)
            except sqlite3.Error:
                pass
    connection.deserialize(bytes(raw))
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA cell_size_check=ON")
    return connection


def _quote(identifier: str) -> str:
    return '"' + str(identifier).replace('"', '""') + '"'


class DatabaseReader:
    """Streams every row into detector lines and accumulates the profile."""

    def __init__(self, data: bytes, budget: Budget = None):
        self.data = data
        self.budget = budget or Budget()
        self.lines: List[Line] = []
        self.tables: List[Dict[str, object]] = []
        self.column_states: List[List[ColumnState]] = []
        self.schema_objects: List[Dict[str, object]] = []
        self.blobs = {"total": 0, "text_scanned": 0, "executables": 0, "archives": 0, "images": 0, "opaque": 0}
        self.blob_events: List[Dict[str, object]] = []
        self.unread: List[Dict[str, str]] = []
        self.root_pages: List[int] = []
        self.freelist_fragments = 0
        self.free_space = {"method": "ascii_printable_runs", "min_chars": MIN_FRAGMENT_CHARS, "bytes_examined": 0}
        self.dedupe = set()
        self.opaque_reason: Optional[str] = None
        self.text_budget_hit = False

    # -- helpers
    def _add_line(self, text: str, citation, table_index=None, ordinal=None, contact_key=None) -> bool:
        if self.budget.used_chars + len(text) > self.budget.chars:
            self.text_budget_hit = True
            return False
        self.budget.used_chars += len(text) + 1
        self.lines.append(Line(text, citation, table_index, ordinal, contact_key))
        return True

    def _progress(self):
        return 1 if self.budget.expired() else 0

    # -- entry
    def read(self):
        try:
            connection = _open(self.data)
        except (sqlite3.DatabaseError, ValueError, OverflowError, MemoryError) as exc:
            self.opaque_reason = f"SQLite could not open the database ({type(exc).__name__}: {exc})."
            return self
        try:
            connection.set_progress_handler(self._progress, 5000)
            try:
                master = connection.execute(
                    "SELECT type, name, tbl_name, rootpage, sql FROM sqlite_master").fetchall()
            except sqlite3.DatabaseError as exc:
                self.opaque_reason = f"The schema could not be read ({exc}); the file is encrypted or corrupt."
                return self
            self._read_schema(connection, master)
            self._read_tables(connection, master)
        finally:
            connection.close()
        return self

    def _read_schema(self, connection, master):
        for kind, name, table, rootpage, sql in master:
            if isinstance(rootpage, int) and rootpage > 0:
                self.root_pages.append(rootpage)
            if not sql:
                continue
            obj_type = {"trigger": "trigger", "view": "view", "index": "index"}.get(kind)
            if obj_type:
                self._schema_object(obj_type, name, sql)
            elif kind == "table":
                if re.search(r"\bCHECK\s*\(", sql, re.I):
                    self._schema_object("check", name, sql)
                else:
                    self._add_line(f"schema={_single_line(sql)}", {"table": name, "column": None, "row": None,
                                                                  "schema_object": "table"})
        for kind, name, _table, _root, _sql in master:
            if kind != "table":
                continue
            try:
                info = connection.execute(f"PRAGMA table_info({_quote(name)})").fetchall()
            except sqlite3.DatabaseError:
                continue
            for column in info:
                default = column[4]
                if default is not None and str(default).upper() not in {"NULL", "0", "1", "''", "CURRENT_TIMESTAMP",
                                                                        "CURRENT_DATE", "CURRENT_TIME"}:
                    self._schema_object("default", f"{name}.{column[1]}", str(default),
                                        table=name, column=column[1])

    def _schema_object(self, obj_type, name, sql, table=None, column=None):
        reasons = []
        if URL_IN_SQL.search(sql):
            reasons.append("url")
        if CODE_IN_SQL.search(sql):
            reasons.append("code")
        for literal in SQL_LITERAL.findall(sql):
            literal = literal.replace("''", "'")
            if len(literal.split()) >= 5 and INSTRUCTION_WORDS.search(literal):
                reasons.append("instruction_text")
                break
        record = {"type": obj_type, "name": name, "flagged": bool(reasons), "reasons": reasons}
        self.schema_objects.append(record)
        citation = {"table": table or name, "column": column, "row": None, "schema_object": obj_type}
        self._add_line(f"schema={_single_line(sql)}", citation)

    def _shadow_tables(self, master) -> Dict[str, str]:
        shadows = {}
        for kind, name, _t, _r, sql in master:
            if kind != "table" or not sql:
                continue
            match = re.search(r"\bUSING\s+(fts[345])\b", sql, re.I)
            if not match:
                continue
            for suffix in FTS_SHADOW_SUFFIXES[match.group(1).lower()]:
                shadows[(name + suffix).lower()] = name
        return shadows

    def _read_tables(self, connection, master):
        shadows = self._shadow_tables(master)
        names = [name for kind, name, *_ in master if kind == "table" and not name.startswith("sqlite_")]
        virtual = {name for kind, name, _t, _r, sql in master
                   if kind == "table" and sql and re.match(r"\s*CREATE\s+VIRTUAL\s+TABLE", sql, re.I)}
        readable_virtual = set()
        # Virtual (FTS) tables first, so shadow tables are skipped only when their text was read.
        ordered = sorted(names, key=lambda name: (name not in virtual, name.lower()))
        for name in ordered:
            parent = shadows.get(name.lower())
            table = {"name": name, "row_count": None, "rows_read": 0, "skipped_reason": None, "columns": []}
            self.tables.append(table)
            self.column_states.append([])
            if parent and parent in readable_virtual:
                table["skipped_reason"] = "fts_shadow"
                table["shadow_of"] = parent
                continue
            ok = self._read_table(connection, len(self.tables) - 1, name)
            if ok and name in virtual:
                readable_virtual.add(name)

    def _read_table(self, connection, index, name) -> bool:
        table = self.tables[index]
        quoted = _quote(name)
        try:
            info = connection.execute(f"PRAGMA table_xinfo({quoted})").fetchall()
        except sqlite3.DatabaseError as exc:
            self.unread.append({"what": f"table {name}", "reason": f"column list unavailable: {exc}"})
            table["skipped_reason"] = "unreadable"
            return False
        columns = [row[1] for row in info if len(row) < 7 or row[6] in (0, 2, 3)]
        states = [ColumnState(name, row[1], row[2] or "") for row in info if len(row) < 7 or row[6] in (0, 2, 3)]
        self.column_states[index] = states
        try:
            table["row_count"] = connection.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0]
        except sqlite3.DatabaseError as exc:
            if self.budget.expired():
                table["skipped_reason"] = "budget"
                self.unread.append({"what": f"table {name}", "reason": "time budget reached before the table was read"})
                return False
            table["row_count"] = None
            count_error = str(exc)
        else:
            count_error = None
        selected = ", ".join(_quote(column) for column in columns) or "NULL"
        rowid_expr = None
        lowered = {column.lower() for column in columns}
        for candidate in ("rowid", "_rowid_", "oid"):
            if candidate in lowered:
                continue
            try:
                connection.execute(f"SELECT {candidate} FROM {quoted} LIMIT 0")
                rowid_expr = candidate
                break
            except sqlite3.DatabaseError:
                continue
        query = f"SELECT {rowid_expr or 'NULL'}, {selected} FROM {quoted}"
        if rowid_expr:
            query += f" ORDER BY {rowid_expr}"
        if not rowid_expr:
            table["row_citation"] = "ordinal"
        rows_read = 0
        stopped = None
        try:
            cursor = connection.execute(query)
            for row in cursor:
                if rows_read % 256 == 0 and self.budget.expired():
                    stopped = "time_budget"
                    break
                rows_read += 1
                rowid = row[0] if rowid_expr else rows_read
                if not self._read_row(index, name, columns, states, rowid, rows_read, row[1:]):
                    stopped = "text_budget"
                    break
        except sqlite3.OperationalError as exc:
            stopped = "time_budget" if self.budget.expired() else f"read error: {exc}"
        except sqlite3.DatabaseError as exc:
            stopped = f"read error: {exc}"
        table["rows_read"] = rows_read
        if stopped:
            total = table["row_count"]
            remaining = f"rows after {rows_read}" + (f" of {total}" if total is not None else "")
            if stopped == "time_budget":
                reason = f"time budget ({self.budget.seconds:g} s) reached"
            elif stopped == "text_budget":
                reason = f"projection size budget ({self.budget.chars} characters) reached"
            else:
                reason = stopped
            table["skipped_reason"] = "budget" if stopped in {"time_budget", "text_budget"} else "unreadable"
            self.unread.append({"what": f"table {name}: {remaining}", "reason": reason})
            if table["row_count"] is None:
                table["row_count"] = None
            return False
        if table["row_count"] is None:
            table["row_count"] = rows_read
            if count_error:
                table["row_count_status"] = "counted_while_reading"
        return True

    def _read_row(self, index, table, columns, states, rowid, ordinal, values) -> bool:
        for position, (column, state, value) in enumerate(zip(columns, states, values)):
            if value is None:
                continue
            state.values += 1
            citation = {"table": table, "column": column, "row": rowid}
            if isinstance(value, bytes):
                if not self._read_blob(index, ordinal, column, position, state, value, citation):
                    return False
                continue
            text = str(value)
            if isinstance(value, str):
                state.observe_text(value)
            if not self._add_value(index, ordinal, column, position, text, citation):
                return False
            if isinstance(value, str) and len(value) >= 20:
                decoded, encoding, looked = decode_one_layer(value)
                if decoded is not None:
                    if not self._add_value(index, ordinal, column, position, decoded,
                                           {**citation, "decoded": encoding}, decoded=True):
                        return False
                elif looked:
                    state.opaque += 1
        return True

    def _add_value(self, index, ordinal, column, position, text, citation, decoded=False) -> bool:
        flat = _single_line(text)
        if not flat:
            return True
        decoded = decoded or bool(citation.get("blob"))
        key = (index, position, flat if len(flat) <= 256 else hash(flat), decoded)
        if key in self.dedupe:
            return True  # identical value already supplied to detectors for this column
        self.dedupe.add(key)
        if len(flat) <= VALUE_CHUNK_CHARS:
            return self._add_line(f"{column}={flat}", citation, index, ordinal, position)
        step = VALUE_CHUNK_CHARS - VALUE_CHUNK_OVERLAP
        for part, start in enumerate(range(0, len(flat), step)):
            chunk = flat[start:start + VALUE_CHUNK_CHARS]
            if not self._add_line(f"{column}={chunk}", {**citation, "chunk": part + 1, "offset": start},
                                  index, ordinal, position):
                return False
            if start + VALUE_CHUNK_CHARS >= len(flat):
                break
        return True

    def _read_blob(self, index, ordinal, column, position, state, value, citation) -> bool:
        self.blobs["total"] += 1
        kind = blob_kind(value)
        event = {"kind": kind, "bytes": len(value), "citation": citation}
        if kind.endswith("_executable"):
            self.blobs["executables"] += 1
            self.blob_events.append(event)
            return True
        if kind in {"zip_archive", "gzip_archive", "archive"}:
            self.blobs["archives"] += 1
            self.blob_events.append(event)
            if kind == "gzip_archive":
                inner = _decompress_bounded(value, 16 + zlib.MAX_WBITS)
                text = _bytes_to_text(inner) if inner else None
                if text is not None:
                    self.blobs["text_scanned"] += 1
                    return self._add_value(index, ordinal, column, position, text, {**citation, "decoded": "gzip"},
                                           decoded=True)
            return True
        if kind == "image":
            self.blobs["images"] += 1
            return True
        if kind == "zlib":
            inner = _decompress_bounded(value, zlib.MAX_WBITS)
            text = _bytes_to_text(inner) if inner else None
            if text is None:
                self.blobs["opaque"] += 1
                state.opaque += 1
                return True
            self.blobs["text_scanned"] += 1
            return self._add_value(index, ordinal, column, position, text, {**citation, "decoded": "zlib"}, decoded=True)
        if kind == "text":
            self.blobs["text_scanned"] += 1
            text = _bytes_to_text(value)
            state.observe_text(text)
            return self._add_value(index, ordinal, column, position, text, {**citation, "blob": True})
        self.blobs["opaque"] += 1
        state.opaque += 1
        return True

    # -- free space
    def read_free_space(self):
        try:
            regions, pages = free_space_regions(self.data, self.root_pages)
        except ValueError as exc:
            self.unread.append({"what": "free pages and deleted-record remnants",
                                "reason": f"page structure could not be parsed reliably: {exc}"})
            self.free_space["status"] = "unread"
            return
        examined = 0
        seen = set()
        for page, start, end in regions:
            if examined >= MAX_SLACK_BYTES:
                self.unread.append({"what": "free-space bytes beyond the examined limit",
                                    "reason": f"free-space string pass bounded at {MAX_SLACK_BYTES} bytes"})
                break
            end = min(end, start + (MAX_SLACK_BYTES - examined))
            examined += max(0, end - start)
            for match in PRINTABLE_RUN.finditer(self.data, start, end):
                fragment = WORD_JOIN.sub(" ", _single_line(match.group(0).decode("ascii")))
                if not fragment:
                    continue
                self.freelist_fragments += 1
                if fragment in seen:
                    continue  # identical remnant already supplied to detectors
                seen.add(fragment)
                if not self._add_line(f"free_space={fragment}",
                                      {"table": None, "column": None, "row": None, "page": page,
                                       "free_space": True}):
                    self.unread.append({"what": "free-space text fragments",
                                        "reason": "projection size budget reached"})
                    return
        self.free_space.update(status="read", bytes_examined=examined, pages=pages)


# --------------------------------------------------------------------------- page structure

def _u16(data, offset):
    return int.from_bytes(data[offset:offset + 2], "big")


def _u32(data, offset):
    return int.from_bytes(data[offset:offset + 4], "big")


def _varint(data, offset):
    value = 0
    for index in range(9):
        byte = data[offset + index]
        if index == 8:
            return (value << 8) | byte, offset + 9
        value = (value << 7) | (byte & 0x7F)
        if byte < 0x80:
            return value, offset + index + 1
    raise ValueError("bad varint")


def free_space_regions(data: bytes, root_pages: List[int]):
    """Byte ranges that hold no live record content, per the SQLite file format.

    Returns ([(page, start, end)], page_summary). Raises ValueError on any
    structural inconsistency so callers record the pass as unread.
    """
    if len(data) < 100 or not data.startswith(SQLITE_HEADER):
        raise ValueError("missing SQLite header")
    page_size = _u16(data, 16)
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise ValueError("invalid page size")
    usable = page_size - data[20]
    if usable < 480:
        raise ValueError("invalid reserved space")
    page_count = len(data) // page_size
    header_pages = _u32(data, 28)
    if 0 < header_pages <= page_count and _u32(data, 24) == _u32(data, 92):
        page_count = header_pages
    regions: List[Tuple[int, int, int]] = []
    accounted = set()

    def base(page):
        if page < 1 or page > page_count:
            raise ValueError(f"page {page} out of range")
        return (page - 1) * page_size

    # Freelist: trunk pages list leaf pages; all leaf bytes and unused trunk bytes are free.
    trunk, guard = _u32(data, 32), 0
    while trunk:
        guard += 1
        if trunk in accounted or guard > page_count:
            raise ValueError("freelist cycle")
        accounted.add(trunk)
        offset = base(trunk)
        leaves = _u32(data, offset + 4)
        if leaves > usable // 4 - 2:
            raise ValueError("freelist trunk leaf count")
        for position in range(leaves):
            leaf = _u32(data, offset + 8 + 4 * position)
            base(leaf)
            if leaf in accounted:
                raise ValueError("freelist leaf repeated")
            accounted.add(leaf)
            regions.append((leaf, base(leaf), base(leaf) + page_size))
        regions.append((trunk, offset + 8 + 4 * leaves, offset + page_size))
        trunk = _u32(data, offset)
    free_pages = len(accounted)

    btree, overflow = set(), set()
    stack = [1] + [page for page in root_pages if page != 1]
    while stack:
        page = stack.pop()
        if page in btree:
            continue
        if page in accounted:
            raise ValueError(f"page {page} referenced twice")
        btree.add(page)
        accounted.add(page)
        offset = base(page)
        header = offset + (100 if page == 1 else 0)
        kind = data[header]
        if kind not in (2, 5, 10, 13):
            raise ValueError(f"page {page} is not a b-tree page")
        first_freeblock, cells, content_start = _u16(data, header + 1), _u16(data, header + 3), _u16(data, header + 5)
        content_start = 65536 if content_start == 0 else content_start
        header_length = 12 if kind in (2, 5) else 8
        pointers = header + header_length
        pointer_end = pointers + 2 * cells
        if pointer_end - offset > content_start or content_start > usable:
            raise ValueError(f"page {page} cell layout")
        if pointer_end < offset + content_start:
            regions.append((page, pointer_end, offset + content_start))
        block, steps = first_freeblock, 0
        while block:
            steps += 1
            size = _u16(data, offset + block + 2)
            if steps > page_size // 4 or block + size > usable or size < 4:
                raise ValueError(f"page {page} freeblock chain")
            regions.append((page, offset + block + 4, offset + block + size))
            next_block = _u16(data, offset + block)
            if next_block and next_block <= block:
                raise ValueError(f"page {page} freeblock order")
            block = next_block
        if kind in (2, 5):
            stack.append(_u32(data, header + 8))
        for position in range(cells):
            cell = offset + _u16(data, pointers + 2 * position)
            if cell < offset + content_start or cell >= offset + usable:
                raise ValueError(f"page {page} cell pointer")
            cursor = cell
            if kind in (2, 5):
                stack.append(_u32(data, cursor))
                cursor += 4
            if kind == 5:
                continue
            payload, cursor = _varint(data, cursor)
            if kind == 13:
                _rowid, cursor = _varint(data, cursor)
            max_local = usable - 35 if kind == 13 else ((usable - 12) * 64 // 255) - 23
            if payload <= max_local:
                continue
            min_local = ((usable - 12) * 32 // 255) - 23
            local = min_local + ((payload - min_local) % (usable - 4))
            local = local if local <= max_local else min_local
            remaining = payload - local
            next_page, hops = _u32(data, cursor + local), 0
            while remaining > 0:
                hops += 1
                if not next_page or next_page in accounted or hops > page_count:
                    raise ValueError("overflow chain")
                accounted.add(next_page)
                overflow.add(next_page)
                page_offset = base(next_page)
                take = min(remaining, usable - 4)
                remaining -= take
                if remaining == 0:
                    regions.append((next_page, page_offset + 4 + take, page_offset + usable))
                next_page = _u32(data, page_offset)
    # The lock-byte page (offset 1 GiB) holds no data; any other page not
    # accounted for (pointer-map pages, orphans) gets the raw pass in full.
    lock_page = 1073741824 // page_size + 1
    unaccounted = [page for page in range(1, page_count + 1) if page not in accounted and page != lock_page]
    for page in unaccounted:
        regions.append((page, base(page), base(page) + page_size))
    if len(data) > page_count * page_size:
        regions.append((None, page_count * page_size, len(data)))
    summary = {"page_size": page_size, "page_count": page_count, "btree_pages": len(btree),
               "overflow_pages": len(overflow), "free_pages": free_pages, "unaccounted_pages": len(unaccounted)}
    return regions, summary


# --------------------------------------------------------------------------- analysis

class DatabaseAnalysis:
    def __init__(self, path: str, data: bytes, reader: Optional[DatabaseReader], opaque_reason: Optional[str]):
        self.path = path
        self.data = data
        self.reader = reader
        self.opaque_reason = opaque_reason
        self.dominant_domain: Optional[str] = None
        self.directory_tables: Dict[int, List[str]] = {}
        self.work_email_tables: Dict[int, Tuple[int, List[str]]] = {}
        self.contact_records = 0
        self.detector_cutoff: Optional[int] = None
        self.profile: Dict[str, object] = {}

    @property
    def opaque(self) -> bool:
        return self.opaque_reason is not None


def _opaque_reason_for_bytes(data: bytes) -> str:
    if data.startswith(SQLITE_HEADER):
        return "SQLite header present but the database could not be parsed (corrupt or truncated)."
    entropy = _entropy(data[:65536])
    if entropy >= 7.5:
        return (f"No SQLite header and the bytes are near-random ({entropy:.2f} bits/byte); "
                "the database is likely encrypted (for example SQLCipher).")
    return "No SQLite header; the database format is unrecognized or corrupt."


def analyze_database(path: str, data: bytes, budget: Budget = None) -> DatabaseAnalysis:
    """Read the whole database into detector lines and a profile (no detection yet)."""
    budget = budget or Budget()
    if not data.startswith(SQLITE_HEADER):
        analysis = DatabaseAnalysis(path, data, None, _opaque_reason_for_bytes(data))
        analysis.profile = _opaque_profile(analysis.opaque_reason)
        return analysis
    reader = DatabaseReader(data, budget).read()
    if reader.opaque_reason:
        analysis = DatabaseAnalysis(path, data, reader, reader.opaque_reason)
        analysis.profile = _opaque_profile(reader.opaque_reason)
        return analysis
    reader.read_free_space()
    analysis = DatabaseAnalysis(path, data, reader, None)
    _classify(analysis)
    analysis.profile = _build_profile(analysis)
    return analysis


def _opaque_profile(reason: str) -> Dict[str, object]:
    return {"schema": SCHEMA_ID, "tables": [], "schema_objects": [],
            "blobs": {"total": 0, "text_scanned": 0, "executables": 0, "archives": 0, "images": 0, "opaque": 0},
            "freelist_text_fragments": 0,
            "coverage": {"status": "opaque", "rows_read": 0, "rows_total": None,
                         "unread": [{"what": "entire database", "reason": reason}]}}


def _classify(analysis: DatabaseAnalysis):
    reader = analysis.reader
    domains = Counter()
    for states in reader.column_states:
        for state in states:
            for domain, count in state.emails.items():
                if domain not in FREE_MAIL_DOMAINS:
                    domains[domain] += count
    if domains:
        domain, count = domains.most_common(1)[0]
        if count >= MIN_DOMINANT_DOMAIN_EMAILS and count * 2 >= sum(domains.values()):
            analysis.dominant_domain = domain
    for index, states in enumerate(reader.column_states):
        classes = [state.finalize(analysis.dominant_domain) for state in states]
        flat = {cls for column in classes for cls in column}
        contact = flat & set(CONTACT_CLASSES)
        # A table is a contact directory only when it holds business contact data
        # and none of the sensitive personal classes.
        if (len(contact) >= 2 and contact & {"business_contact_email", "work_phone", "person_name"}
                and not flat & set(SENSITIVE_CLASSES)):
            analysis.directory_tables[index] = [state.name for state, column in zip(states, classes)
                                                if set(column) & set(CONTACT_CLASSES)]
            analysis.contact_records += reader.tables[index]["rows_read"]
    if analysis.dominant_domain:
        rows, seen = Counter(), set()
        for line in reader.lines:
            if line.table_index is None or line.table_index in analysis.directory_tables or "@" not in line.text:
                continue
            if (line.table_index, line.ordinal) in seen:
                continue
            if any(match.group(1).lower() == analysis.dominant_domain for match in EMAIL_ANY.finditer(line.text)):
                seen.add((line.table_index, line.ordinal))
                rows[line.table_index] += 1
        for index, count in rows.items():
            columns = [state.name for state in reader.column_states[index] if state.emails.get(analysis.dominant_domain)]
            analysis.work_email_tables[index] = (count, columns or ["(free text)"])
            analysis.contact_records += count
    # Route business contact values in directory tables away from the generic
    # email/phone PII detectors; contact_directory reports them instead.
    for line in reader.lines:
        if line.table_index not in analysis.directory_tables or line.contact_key is None or line.contact_key < 0:
            continue
        state = reader.column_states[line.table_index][line.contact_key]
        value = line.text.split("=", 1)[1] if "=" in line.text else line.text
        if line.citation.get("decoded") or line.citation.get("chunk") or line.citation.get("blob"):
            continue
        email = EMAIL_VALUE.match(value)
        if email and email.group(1).lower() == analysis.dominant_domain and (
                "business_contact_email" in state.classes or "manager_reference" in state.classes):
            line.bucket = "contact"
        elif "work_phone" in state.classes and PHONE_VALUE.match(value):
            line.bucket = "contact"


def _build_profile(analysis: DatabaseAnalysis) -> Dict[str, object]:
    reader = analysis.reader
    tables = []
    for table, states in zip(reader.tables, reader.column_states):
        tables.append({
            "name": table["name"], "row_count": table["row_count"], "rows_read": table["rows_read"],
            "skipped_reason": table["skipped_reason"],
            "columns": [{"name": state.name, "declared_type": state.declared_type, "data_classes": state.classes,
                         "values_scanned": state.values, "opaque_values": state.opaque} for state in states],
            **({"shadow_of": table["shadow_of"]} if table.get("shadow_of") else {}),
            **({"row_citation": table["row_citation"]} if table.get("row_citation") else {}),
        })
    return {"schema": SCHEMA_ID, "tables": tables, "schema_objects": reader.schema_objects,
            "blobs": dict(reader.blobs), "freelist_text_fragments": reader.freelist_fragments,
            "free_space_scan": reader.free_space,
            "dominant_organisation_domain": analysis.dominant_domain,
            "contact_records": analysis.contact_records,
            "coverage": _coverage(analysis)}


def _coverage(analysis: DatabaseAnalysis) -> Dict[str, object]:
    reader = analysis.reader
    counted = [table for table in reader.tables if table["skipped_reason"] != "fts_shadow"]
    rows_total = None if any(table["row_count"] is None for table in counted) else sum(
        table["row_count"] for table in counted)
    rows_read = sum(table["rows_read"] for table in counted)
    unread = list(reader.unread)
    if reader.text_budget_hit and not any("size budget" in item["reason"] for item in unread):
        unread.append({"what": "values beyond the projection size budget",
                       "reason": f"projection size budget ({reader.budget.chars} characters) reached"})
    complete = not unread and rows_total is not None and rows_read == rows_total
    return {"status": "complete" if complete else "partial", "rows_read": rows_read, "rows_total": rows_total,
            "unread": unread}


# --------------------------------------------------------------------------- detection

def _lazy_imports():
    try:
        from .finding_enrichment import build_finding
        from .evidence_redaction import redact_result
        from .inspection_evidence import creator_mitigation
        from .text_projections import decoded_projections
    except ImportError:  # pragma: no cover - flat import layout used by the container
        from finding_enrichment import build_finding
        from evidence_redaction import redact_result
        from inspection_evidence import creator_mitigation
        from text_projections import decoded_projections
    return build_finding, redact_result, creator_mitigation, decoded_projections


def _merge_into(merged: Dict[Tuple, Dict], finding: Dict[str, object]):
    key = (finding.get("id"), finding.get("evidence_scope"))
    existing = merged.get(key)
    if existing is None:
        merged[key] = dict(finding, observations=list(finding.get("observations", []))[:MAX_OBSERVATIONS])
        return
    existing["count"] = int(existing.get("count") or 0) + int(finding.get("count") or 0)
    stronger = TIER_RANK.get(finding.get("tier"), 9) < TIER_RANK.get(existing.get("tier"), 9)
    if stronger:
        for field in ("tier", "severity", "disposition", "is_actionable", "counts_for_governance", "action_state",
                      "description", "display_kind", "finding_category"):
            if field in finding:
                existing[field] = finding[field]
        existing["observations"] = list(finding.get("observations", [])) + list(existing.get("observations", []))
    else:
        existing["observations"] = list(existing.get("observations", [])) + list(finding.get("observations", []))
    existing["observations"] = existing["observations"][:MAX_OBSERVATIONS]
    if isinstance(existing.get("secret_kinds"), dict) and isinstance(finding.get("secret_kinds"), dict):
        kinds = Counter(existing["secret_kinds"])
        kinds.update(finding["secret_kinds"])
        existing["secret_kinds"] = dict(sorted(kinds.items()))
    if isinstance(existing.get("contact_context"), dict) and isinstance(finding.get("contact_context"), dict):
        for field in ("role_alias_matches", "individual_or_unknown_matches"):
            existing["contact_context"][field] = (existing["contact_context"].get(field, 0)
                                                  + finding["contact_context"].get(field, 0))
        if existing["contact_context"]["individual_or_unknown_matches"]:
            existing["contact_context"]["classification"] = "individual_or_unknown_contact"
    if isinstance(existing.get("observation_display"), dict):
        existing["observation_display"]["retained"] = len(existing["observations"])
        existing["observation_display"]["total_matches"] = existing["count"]


def _cite(findings, citations: List[Dict[str, object]]):
    for finding in findings:
        for observation in finding.get("observations", []):
            line = observation.get("line")
            if isinstance(line, int) and 1 <= line <= len(citations):
                observation["citation"] = dict(citations[line - 1])
                observation["projection_line"] = line
                observation["line"] = None


def _sample(observation: Dict[str, object], detector_id: str) -> str:
    text = mask_sample(str(observation.get("text", "")), detector_id)
    citation = observation.get("citation")
    if not citation:
        return text
    if citation.get("free_space"):
        return f"free space (page {citation.get('page')}): {text}"
    where = citation.get("table") or "database"
    if citation.get("column"):
        where += f".{citation['column']}"
    if citation.get("row") is not None:
        where += f" row {citation['row']}"
    return f"{where}: {text}"


def _detector_line_text(line, dominant_domain):
    text = mask_work_emails(line.text, dominant_domain)
    if line.citation.get("free_space"):
        # Raw slack can concatenate an address and the next SQLite value.
        # Such overlong DNS labels are not valid addresses (RFC1035 section2.3.4):
        # https://www.rfc-editor.org/rfc/rfc1035#section-2.3.4
        # Keep every character for instruction scanning, marking only the invalid @.
        text = EMAIL_ANY.sub(lambda m: m.group(0).replace("@", "[invalid-at]", 1)
                             if any(len(label) > 63 for label in m.group(1).split(".")) else m.group(0), text)
    return text


def run_detectors(analysis: DatabaseAnalysis, scan_text: Callable, artifact_role: str) -> List[Dict[str, object]]:
    """Supply every projection line to the shared file detectors, chunked and cited."""
    _build_finding, redact_result, _cm, _dp = _lazy_imports()
    reader = analysis.reader
    merged: Dict[Tuple, Dict] = {}
    buffers = {"general": [], "contact": []}
    sizes = {"general": 0, "contact": 0}
    first_pending = {"general": None, "contact": None}
    cutoff = None

    def flush(bucket) -> bool:
        lines = buffers[bucket]
        if not lines:
            return True
        if reader.budget.expired():
            return False
        text = "\n".join(_detector_line_text(line, analysis.dominant_domain) for line in lines)
        # One value per line, scanned as line-delimited records so every match
        # keeps its own line and therefore its own table/column/row citation.
        findings = scan_text(analysis.path + DETECTOR_PATH_SUFFIX, text, artifact_role, observation_limit=None)
        redact_result({"findings": findings}, {analysis.path: text})
        if bucket == "contact":
            findings = [item for item in findings if item.get("id") not in {"pii_email_address", "pii_phone_number"}]
        _cite(findings, [line.citation for line in lines])
        for finding in findings:
            data_class = {"hardcoded_secret": "credential", "pii_email_address": "personal_email",
                          "pii_ssn": "ssn", "pii_date_of_birth": "date_of_birth",
                          "phi_medical_record_number": "health", "phi_patient_record": "health"}.get(finding.get("id"))
            if data_class:
                _mark_detected_columns(analysis, finding, data_class)
            _merge_into(merged, finding)
        buffers[bucket], sizes[bucket], first_pending[bucket] = [], 0, None
        return True

    for sequence, line in enumerate(reader.lines):
        bucket = line.bucket
        if first_pending[bucket] is None:
            first_pending[bucket] = sequence
        buffers[bucket].append(line)
        sizes[bucket] += len(line.text) + 1
        if sizes[bucket] >= DETECTOR_CHUNK_CHARS and not flush(bucket):
            cutoff = min(value for value in first_pending.values() if value is not None)
            break
    if cutoff is None:
        for bucket in ("general", "contact"):
            if not flush(bucket):
                pending = [value for value in first_pending.values() if value is not None]
                cutoff = min(pending) if pending else None
                break
    if cutoff is not None:
        _apply_detector_cutoff(analysis, cutoff)
    findings = list(merged.values())
    for finding in findings:
        finding["evidence_scope"] = finding.get("evidence_scope") or "database_values"
        finding["samples"] = list(dict.fromkeys(_sample(item, str(finding.get("id")))
                                                for item in finding.get("observations", [])))[:3]
        if str(finding.get("id", "")).startswith(MASKED_PII_PREFIXES):
            for observation in finding.get("observations", []):
                observation["text"] = mask_sample(str(observation.get("text", "")), str(finding["id"]))
    return findings


def _mark_detected_columns(analysis, finding, data_class):
    reader = analysis.reader
    for observation in finding.get("observations", []):
        citation = observation.get("citation") or {}
        for table, states in zip(reader.tables, reader.column_states):
            if table["name"] != citation.get("table"):
                continue
            for state in states:
                if state.name == citation.get("column") and data_class not in state.classes:
                    state.classes.append(data_class)
    analysis.profile["tables"] = _build_profile(analysis)["tables"]


def _apply_detector_cutoff(analysis: DatabaseAnalysis, cutoff: int):
    """Rows whose lines were not supplied to detectors are not counted as read."""
    reader = analysis.reader
    line = reader.lines[cutoff]
    analysis.detector_cutoff = cutoff
    if line.table_index is None:
        stop_table, stop_ordinal = (len(reader.tables), None) if line.citation.get("free_space") else (0, None)
    else:
        stop_table, stop_ordinal = line.table_index, line.ordinal
    for index, table in enumerate(reader.tables):
        if table["skipped_reason"] == "fts_shadow" or index < stop_table:
            continue
        before = table["rows_read"]
        table["rows_read"] = max(0, (stop_ordinal or 1) - 1) if index == stop_table else 0
        if table["rows_read"] < before or (table["row_count"] or 0) > table["rows_read"]:
            table["skipped_reason"] = table["skipped_reason"] or "budget"
    reader.unread.append({"what": f"projection lines {cutoff + 1}-{len(reader.lines)} (rows and fragments after the cut)",
                          "reason": f"time budget ({reader.budget.seconds:g} s) reached during detection"})
    analysis.profile = _build_profile(analysis)


def database_findings(analysis: DatabaseAnalysis, artifact_role: str) -> List[Dict[str, object]]:
    """Findings that describe the database itself (contract section 1).

    Disposition uses the 'active' role: a role override for documentation must
    not turn an executable BLOB or unread data into an informational note. The
    file's real role is restored on each finding afterwards.
    """
    findings = _database_findings(analysis)
    for finding in findings:
        finding["artifact_role"] = artifact_role
        finding["evidence_scope"] = "database_structure"
    return findings


def _database_findings(analysis: DatabaseAnalysis) -> List[Dict[str, object]]:
    build_finding, *_ = _lazy_imports()
    artifact_role = "active"
    findings = []
    if analysis.opaque:
        finding = build_finding({
            "id": "opaque_database", "category": "data", "finding_category": "coverage",
            "subject": "database", "action_state": "unreadable", "status": "verified",
            "description": ("Database content could not be read, so nothing inside it was checked: "
                            + analysis.opaque_reason + " Obtain a readable copy or confirm what it holds."),
            "sources": [{"name": "SQLite", "ref": "Database file format", "url": "https://www.sqlite.org/fileformat2.html"}],
        }, [{"text": analysis.opaque_reason, "line": None, "context_tag": "pattern_match", "confidence": "high"}],
            artifact_role)
        return [finding]
    profile = analysis.profile
    coverage = profile["coverage"]
    reader = analysis.reader
    if coverage["status"] == "partial":
        observations = [{"text": f"{item['what']}: {item['reason']}", "line": None, "context_tag": "pattern_match",
                         "confidence": "high"} for item in coverage["unread"][:MAX_OBSERVATIONS]]
        total = coverage["rows_total"]
        finding = build_finding({
            "id": "database_not_cleared", "category": "coverage", "finding_category": "coverage",
            "subject": "database", "action_state": "partially_read", "status": "verified",
            "description": (f"Only part of this database was checked ({coverage['rows_read']} of "
                            f"{total if total is not None else 'an unknown number of'} rows read; "
                            f"{len(coverage['unread'])} area(s) unread). Unread content is not cleared."),
            "sources": [],
        }, observations, artifact_role)
        finding["count"] = len(coverage["unread"])
        findings.append(finding)
    if reader.blob_events:
        observations = []
        for event in reader.blob_events[:MAX_OBSERVATIONS]:
            executable = event["kind"].endswith("_executable")
            observations.append({"text": f"{event['kind'].replace('_', ' ')} BLOB ({event['bytes']} bytes)",
                                 "line": None, "context_tag": "executable_blob" if executable else "archive_blob",
                                 "confidence": "high"})
        finding = build_finding({
            "id": "embedded_executable_blob", "category": "execution", "finding_category": "format_integrity",
            "subject": "database_blob", "action_state": "present", "status": "verified",
            "description": (f"Database holds {reader.blobs['executables']} executable and {reader.blobs['archives']} "
                            "archive BLOB(s), identified by magic bytes. Their contents were not unpacked or run. "
                            "Executables in a skill's data are blocked; archives need review."),
            "sources": [{"name": "SQLite", "ref": "Database file format", "url": "https://www.sqlite.org/fileformat2.html"}],
        }, observations, artifact_role)
        for observation, event in zip(finding["observations"], reader.blob_events):
            observation["citation"] = dict(event["citation"])
        finding["samples"] = [_sample(item, "") for item in finding["observations"][:3]]
        finding["count"] = len(reader.blob_events)
        findings.append(finding)
    flagged = [item for item in reader.schema_objects if item["flagged"]]
    if flagged:
        observations = [{"text": f"{item['type']} {item['name']}: {', '.join(item['reasons'])}", "line": None,
                         "context_tag": "pattern_match", "confidence": "medium"} for item in flagged[:MAX_OBSERVATIONS]]
        finding = build_finding({
            "id": "suspicious_schema_object", "category": "injection", "finding_category": "signal",
            "subject": "database_schema", "action_state": "present", "status": "verified",
            "description": ("Database schema (trigger, view, index, default or CHECK constraint) contains a URL, "
                            "code or instruction-like text. Schema SQL runs inside the database engine; review why "
                            "it is there."),
            "sources": [{"name": "SQLite", "ref": "PRAGMA trusted_schema",
                         "url": "https://www.sqlite.org/pragma.html#pragma_trusted_schema"}],
        }, observations, artifact_role)
        for observation, item in zip(finding["observations"], flagged):
            observation["citation"] = {"table": item["name"], "column": None, "row": None,
                                       "schema_object": item["type"]}
        finding["count"] = len(flagged)
        findings.append(finding)
    if analysis.contact_records:
        findings.append(_contact_directory(analysis, artifact_role, build_finding))
    return findings


def _contact_directory(analysis, artifact_role, build_finding):
    reader = analysis.reader
    records = analysis.contact_records
    tag = "contact_directory_large" if records > CONTACT_DIRECTORY_REVIEW_ABOVE else "contact_directory_small"
    described = []
    for index, columns in analysis.directory_tables.items():
        described.append(f"{reader.tables[index]['name']} ({', '.join(columns)})")
    for index, (count, columns) in analysis.work_email_tables.items():
        described.append(f"{reader.tables[index]['name']} ({', '.join(columns)}; {count} rows with work email)")
    samples = []
    domain = analysis.dominant_domain
    for line in reader.lines:
        if len(samples) >= 3:
            break
        value = line.text.split("=", 1)[1] if "=" in line.text else line.text
        if line.bucket == "contact":
            masked = mask_email(value) if "@" in value else mask_phone(value)
        elif line.table_index in analysis.work_email_tables and domain:
            match = next((m for m in EMAIL_ANY.finditer(value) if m.group(1).lower() == domain), None)
            if not match:
                continue
            masked = mask_email(match.group(0))
        else:
            continue
        samples.append({"text": masked, "line": None, "context_tag": tag, "confidence": "high",
                        "_citation": line.citation})
    if not samples:
        samples = [{"text": f"{records} contact records", "line": None, "context_tag": tag, "confidence": "high"}]
    finding = build_finding({
        "id": "contact_directory", "category": "data", "finding_category": "data_presence",
        "subject": "business_contact_data", "action_state": "present", "status": "verified",
        "description": (f"Business contact directory: {records} records in {'; '.join(described)}"
                        + (f", at the organisation's own domain {domain}" if domain else "")
                        + ". This is business contact data, not sensitive personal data; confirm the skill needs it "
                          "and that sharing it with the model is approved."
                        + (" More than 200 records: review." if records > CONTACT_DIRECTORY_REVIEW_ABOVE else "")),
        "sources": [],
    }, [{key: value for key, value in item.items() if key != "_citation"} for item in samples], artifact_role)
    for observation, item in zip(finding["observations"], samples):
        if item.get("_citation"):
            observation["citation"] = dict(item["_citation"])
    finding["samples"] = [_sample(item, "") for item in finding["observations"][:3]]
    finding["count"] = records
    finding["contact_directory"] = {"records": records, "tables": [
        {"table": reader.tables[index]["name"], "columns": columns} for index, columns in analysis.directory_tables.items()]
        + [{"table": reader.tables[index]["name"], "columns": columns, "rows_with_work_email": count}
           for index, (count, columns) in analysis.work_email_tables.items()],
        "organisation_domain": domain}
    return finding


def returned_projection(analysis: DatabaseAnalysis) -> str:
    """Bounded projection for package-level analyses (footprint, behaviour, redaction)."""
    if analysis.opaque or analysis.reader is None:
        return ""
    parts, size = [], 0
    for line in analysis.reader.lines:
        if size + len(line.text) + 1 > RETURNED_TEXT_CHARS:
            break
        parts.append(mask_work_emails(line.text, analysis.dominant_domain))
        size += len(line.text) + 1
    return "\n".join(parts)


def legacy_sampling(analysis: DatabaseAnalysis) -> Dict[str, object]:
    """Shape kept for analysis_coverage.extraction.sampling consumers."""
    coverage = analysis.profile.get("coverage", {})
    tables = [{"table": table["name"], "sampled_rows": table["rows_read"], "total_rows": table["row_count"],
               "total_rows_status": "measured" if table["row_count"] is not None else "unavailable_within_budget"}
              for table in analysis.profile.get("tables", []) if table.get("skipped_reason") != "fts_shadow"]
    return {"status": coverage.get("status"), "tables": tables, "table_limit": None, "row_limit_per_table": None,
            "time_budget_seconds": DB_TIME_BUDGET_SECONDS, "text_character_budget": DB_TEXT_BUDGET_CHARS,
            "value_chunk_characters": VALUE_CHUNK_CHARS, "blob_values": "typed_by_magic_bytes; text-like scanned",
            "sampled_rows": coverage.get("rows_read"), "rows_total": coverage.get("rows_total"),
            "scope": ("Every row of every table read and supplied to detectors." if coverage.get("status") == "complete"
                      else "Database partly read; see database_profile.coverage.unread.")}


# --------------------------------------------------------------------------- entry point used by app.py

def scan_database_entry(entry: Dict[str, object], data: bytes, scan_text: Callable,
                        budget: Budget = None) -> Tuple[Dict[str, object], Optional[str]]:
    """Fill a file entry for a database (SQLite header or database suffix) and return (entry, text)."""
    _bf, _rr, creator_mitigation, decoded_projections = _lazy_imports()
    path = entry["path"]
    role = entry.get("artifact_role", "reference")
    analysis = analyze_database(path, data, budget)
    entry["database_profile"] = analysis.profile
    if analysis.opaque:
        entry.update(skipped=True, reason="Binary or non-text content", assessment_state="binary_asset_inventory_only")
        entry["analysis_coverage"]["extraction"].update(status="not_performed", reason=analysis.opaque_reason)
        entry["findings"] = database_findings(analysis, role)
        return entry, None
    started = time.monotonic()
    value_findings = run_detectors(analysis, scan_text, role)
    entry["findings"] = value_findings + database_findings(analysis, role)
    entry["database_profile"] = analysis.profile
    coverage = analysis.profile["coverage"]
    text = returned_projection(analysis)
    complete = coverage["status"] == "complete"
    entry["reason"] = "Scanned SQLite database content."
    entry["assessment_state"] = "structured_content_analyzed"
    entry["analysis_scope"] = ("Every row, schema object and free-space text fragment was supplied to detectors; "
                               "BLOB images and archive contents are typed, not inspected."
                               if complete else
                               "Database partly read; unread areas are listed in database_profile.coverage and are "
                               "not certified safe.")
    entry["creator_mitigation"] = creator_mitigation(path, None)
    entry["analysis_coverage"]["creator_markers"] = {
        "status": "not_performed", "total_characters": None, "inspected_characters": None,
        "reason": entry["creator_mitigation"]["reason"],
        "scope": "Database projections cannot verify original binary EOF markers."}
    total_characters = analysis.reader.budget.used_chars
    entry["analysis_coverage"]["extraction"] = {
        "status": "complete" if complete else "partial", "extracted_characters": total_characters,
        "reason": entry["reason"], "original_binary_security_analysis": "free_space_strings_only",
        "sampling": legacy_sampling(analysis)}
    entry["analysis_coverage"]["text_patterns"] = {
        "status": "complete_input" if complete else "partial", "total_characters": total_characters,
        "supplied_characters": total_characters if analysis.detector_cutoff is None else sum(
            len(line.text) + 1 for line in analysis.reader.lines[:analysis.detector_cutoff]),
        "inspected_characters": None,
        "reason": "Every projected database value supplied to deterministic rules in cited chunks.",
        "detector_seconds": round(time.monotonic() - started, 3)}
    entry["analysis_coverage"]["decoded_text"] = decoded_projections(text)[1]
    entry["analysis_coverage"]["result_display"] = {"status": "complete", "findings_before_limit": len(entry["findings"]),
                                                     "findings_displayed": len(entry["findings"]),
                                                     "reason": "No file finding display limit reached."}
    return entry, text


def project_database_text(data: bytes, budget: Budget = None) -> Tuple[Optional[str], Dict[str, object]]:
    """Projection without detection, for artifact_text.extract_sqlite_projection."""
    analysis = analyze_database("database.db", data, budget)
    if analysis.opaque:
        return None, {"status": "opaque", "reason": analysis.opaque_reason, "tables": []}
    return returned_projection(analysis), legacy_sampling(analysis)
