"""Bounded text extraction. Office coverage names its exact supported scope."""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import io
import re
import time
import zipfile
from pathlib import PurePosixPath
from typing import Iterable, Tuple
from xml.etree import ElementTree
if __package__:
    from .nested_archives import NestedArchiveBudget, inspect_nested_zip
else:
    from nested_archives import NestedArchiveBudget, inspect_nested_zip
SQLITE_HEADER = b'SQLite format 3\x00'
MAX_OFFICE_PARTS = 1024
MAX_OFFICE_TEXT_CHARS = 1024 * 1024
MAX_OFFICE_PART_BYTES = 1024 * 1024
MAX_OFFICE_TOTAL_XML_BYTES = 5 * 1024 * 1024
OFFICE_SUFFIXES = {'.docx', '.pptx', '.xlsx'}
XML_SUFFIXES = {'.xml', '.rels', '.vml', '.svg'}
OFFICE_SCOPE = ('ElementTree-exposed XML element text/tails and attribute values in XML/.rels/.vml/.svg and embedded OOXML, plus bounded container checks; no binary runtime analysis, rendered pixels, OCR, XML comments, processing instructions, namespace declarations or unreferenced ZIP bytes.')
@dataclass
class OfficeBudget:
    """One object shared across every Office asset in a package scan."""
    archive: NestedArchiveBudget = field(default_factory=lambda: NestedArchiveBudget(max_files=2000, max_bytes=50 * 1024 * 1024, max_member_bytes=8 * 1024 * 1024, max_depth=3))
    xml_parts_used: int = 0
    xml_bytes_used: int = 0
    text_chars_used: int = 0
    seconds_used: float = 0.0
    active_started: float | None = None
    max_seconds: float = 10.0
class OfficeProjectionError(ValueError):
    def __init__(self, code: str, message: str, profile: dict | None = None):
        super().__init__(message)
        self.code = code
        self.profile = profile or {}
def is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    if b'\x00' in data:
        return False
    sample = data[:4096]
    printable = sum(1 for byte in sample if 32 <= byte <= 126 or byte in (9, 10, 13))
    return printable / len(sample) >= 0.7
def looks_like_sqlite(data: bytes) -> bool:
    return data.startswith(SQLITE_HEADER)
def looks_like_zip(data: bytes) -> bool:
    return zipfile.is_zipfile(io.BytesIO(data))
def extract_scannable_text(data: bytes) -> Tuple[str | None, str]:
    if is_probably_text(data):
        return data.decode('utf-8', errors='replace'), ''
    if looks_like_sqlite(data):
        text = extract_sqlite_text(data)
        return (text, 'Scanned SQLite database content.') if text is not None else (None, 'Binary or non-text content')
    if looks_like_zip(data):
        text = extract_office_document_text(data)
        if text is not None:
            return text, 'Scanned Office document content.'
    return None, 'Binary or non-text content'
def extract_sqlite_text(data: bytes) -> str | None:
    return extract_sqlite_projection(data)[0]
def extract_sqlite_projection(data: bytes):
    try:
        from .database_analysis import project_database_text
    except ImportError:
        from database_analysis import project_database_text
    return project_database_text(data)
def _office_part_names(names: Iterable[str]) -> list[str]:
    return sorted(name for name in names if PurePosixPath(name).suffix.lower() in XML_SUFFIXES)
class _NoDTDTreeBuilder(ElementTree.TreeBuilder):
    def doctype(self, name, pubid, system):
        raise OfficeProjectionError('office_xml_dtd', 'Office XML DTDs/entities are unsupported.')
def _extract_xml_text(xml_bytes: bytes) -> str:
    if b'\x00' in xml_bytes:
        raise OfficeProjectionError('office_xml_encoding', 'NUL-containing Office XML encoding is unsupported.')
    upper = xml_bytes.upper()
    if b'<!DOCTYPE' in upper or b'<!ENTITY' in upper:
        raise OfficeProjectionError('office_xml_dtd', 'Office XML DTDs/entities are unsupported.')
    try:
        parser = ElementTree.XMLParser(target=_NoDTDTreeBuilder())
        root = ElementTree.fromstring(xml_bytes, parser=parser)
    except (ElementTree.ParseError, LookupError, UnicodeError) as error:
        raise OfficeProjectionError('office_xml_malformed', 'Office XML is malformed.') from error
    chunks = []
    for node in root.iter():
        if node.text and node.text.strip():
            chunks.append(node.text.strip())
        for key, value in sorted(node.attrib.items()):
            if value.strip():
                chunks.append(key + '=' + value.strip())
        if node.tail and node.tail.strip():
            chunks.append(node.tail.strip())
    return re.sub(r'\s+', ' ', ' '.join(chunks)).strip()
def extract_office_document_text(data: bytes) -> str | None:
    projected = extract_office_projection(data)
    return projected[0] if projected is not None else None
def _office_time_guard(budget):
    active = 0.0 if budget.active_started is None else time.monotonic() - budget.active_started
    if budget.seconds_used + active > budget.max_seconds:
        raise OfficeProjectionError('office_time_limit', 'Office shared analysis time budget exceeded.')
def extract_office_projection(data, path='document', budget=None, depth=1):
    budget = budget if budget is not None else OfficeBudget()
    outer = budget.active_started is None
    if outer:
        budget.active_started = time.monotonic()
    try:
        _office_time_guard(budget)
        return _extract_office_projection_impl(data, path, budget, depth)
    finally:
        if outer:
            budget.seconds_used += time.monotonic() - budget.active_started
            budget.active_started = None
def _extract_office_projection_impl(data: bytes, path: str, budget: OfficeBudget, depth: int):
    """Incomplete structure, XML parsing or work budgets never become complete."""
    profile = {'schema': 'injecticide.office-projection.v1', 'sha256': hashlib.sha256(data).hexdigest(), 'structure_status': 'not_inspected', 'scope': OFFICE_SCOPE, 'coverage': {'status': 'not_performed', 'xml_parts_total': 0, 'xml_parts_read': 0, 'omitted': []}, 'binary_members': 0, 'embedded_office_documents': 0}
    def fail(code, message):
        profile['coverage']['status'] = 'partial'
        profile['coverage']['omitted'].append({'code': code})
        raise OfficeProjectionError(code, message, profile)
    expanded = inspect_nested_zip(data, path, budget.archive, depth)
    _office_time_guard(budget)
    container = expanded['container']
    profile['container_inspection'] = container
    profile['excluded_member_count'] = len(expanded['excluded'])
    if container['status'] != 'inspected' or expanded['excluded']:
        profile['structure_status'] = container['status']
        fail('office_container_incomplete', 'Office ZIP structure inspection is incomplete or exceeded its safety budget.')
    profile['structure_status'] = 'inspected'
    immediate = [entry for entry in expanded['entries'] if entry['container_path'] == path]
    names = {entry['path'][len(path) + 2:]: entry for entry in immediate}
    cores = [(kind, required) for kind, required in (('docx', 'word/document.xml'), ('pptx', 'ppt/presentation.xml'), ('xlsx', 'xl/workbook.xml')) if required in names]
    if not cores:
        if PurePosixPath(path).suffix.lower() in OFFICE_SUFFIXES:
            fail('office_required_parts', 'Office container lacks its supported document core.')
        return None
    if len(cores) != 1 or '[Content_Types].xml' not in names:
        fail('office_required_parts', 'Office container has ambiguous or missing required core parts.')
    profile['format'] = cores[0][0]
    if any('container_inspection' in entry for entry in immediate):
        fail('office_embedded_container', 'Embedded non-Office archives are unsupported.')
    xml_names = _office_part_names(names)
    profile['coverage']['xml_parts_total'] = len(xml_names)
    if budget.xml_parts_used + len(xml_names) > MAX_OFFICE_PARTS:
        fail('office_xml_parts_limit', 'Office XML part count exceeds the shared 1024-part limit.')
    lines = []
    for name in sorted(names):
        _office_time_guard(budget)
        entry = names[name]
        raw = entry['data']
        suffix = PurePosixPath(name).suffix.lower()
        if suffix in OFFICE_SUFFIXES:
            try:
                child = extract_office_projection(raw, entry['path'], budget, depth + 1)
            except OfficeProjectionError as error:
                fail(error.code, str(error))
            if child is None:
                fail('office_embedded_container', 'Embedded Office document lacks a supported core.')
            child_text, child_profile = child
            profile['embedded_office_documents'] += 1 + child_profile['embedded_office_documents']
            profile['binary_members'] += child_profile['binary_members']
            profile['coverage']['xml_parts_total'] += child_profile['coverage']['xml_parts_total']
            profile['coverage']['xml_parts_read'] += child_profile['coverage']['xml_parts_read']
            lines.append(child_text)
            continue
        if raw.startswith((b'PK\x03\x04', b'PK\x05\x06', b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', b'\x1f\x8b', b'7z\xbc\xaf\x27\x1c', b'Rar!', b'BZh', b'\xfd7zXZ')) or raw[257:262] == b'ustar':
            fail('office_embedded_container', 'Embedded unsupported archive or OLE container prevents complete supported inspection.')
        if suffix not in XML_SUFFIXES:
            profile['binary_members'] += 1
            continue
        budget.xml_parts_used += 1
        if budget.xml_parts_used > MAX_OFFICE_PARTS:
            fail('office_xml_parts_limit', 'Office XML part count exceeds the shared 1024-part limit.')
        budget.xml_bytes_used += len(raw)
        if len(raw) > MAX_OFFICE_PART_BYTES or budget.xml_bytes_used > MAX_OFFICE_TOTAL_XML_BYTES:
            fail('office_xml_bytes_limit', 'Office XML exceeds per-part 1 MiB or shared 5 MiB byte limits.')
        try:
            text = _extract_xml_text(raw)
        except OfficeProjectionError as error:
            fail(error.code, str(error))
        _office_time_guard(budget)
        line = 'part=' + entry['path'] + ' text=' + text
        budget.text_chars_used += len(line) + 1
        if budget.text_chars_used > MAX_OFFICE_TEXT_CHARS:
            fail('office_text_limit', 'Office projection exceeds the shared 1 MiB character limit.')
        lines.append(line)
        profile['coverage']['xml_parts_read'] += 1
    _office_time_guard(budget)
    profile['coverage']['status'] = 'complete'
    profile['coverage']['omitted'] = []
    profile['shared_work'] = {'members': budget.archive.files_used, 'expanded_bytes': budget.archive.bytes_used, 'xml_parts': budget.xml_parts_used, 'xml_bytes': budget.xml_bytes_used, 'projection_characters': budget.text_chars_used}
    return '\n'.join(lines), profile
