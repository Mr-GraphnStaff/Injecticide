"""Bounded deterministic package editing; uploads are never extracted or executed."""
from __future__ import annotations
import hashlib
import io
import posixpath
import re
import stat
import struct
import unicodedata
import zipfile
import zlib
import yaml
from urllib.parse import unquote
MAX_ARCHIVE = 50 * 1024 * 1024
MAX_TOTAL = 50 * 1024 * 1024
MAX_FILE = 25 * 1024 * 1024
MAX_ENTRIES = 500
MAX_TEXT = 128 * 1024
MAX_PREVIEW = 512 * 1024
MAX_RATIO = 200
OPENAI_MAX_FILE_BYTES = 25_000_000
CLAUDE_MAX_TOTAL_BYTES = 30_000_000
PROFILES = frozenset(('generic-agent-skills', 'claude-ai', 'claude-code', 'claude-api', 'openai-codex', 'openai-api', 'gemini-cli'))
SOURCES = [
 {'title': 'Agent Skills specification', 'url': 'https://agentskills.io/specification'},
 {'title': 'Claude custom skills', 'url': 'https://support.claude.com/en/articles/12512198-how-to-create-custom-skills'},
 {'title': 'Claude API skills guide', 'url': 'https://platform.claude.com/docs/en/build-with-claude/skills-guide'},
 {'title': 'Claude Code skills', 'url': 'https://code.claude.com/docs/en/skills'},
 {'title': 'OpenAI API skills', 'url': 'https://developers.openai.com/api/docs/guides/tools-skills'},
 {'title': 'Codex skills', 'url': 'https://learn.chatgpt.com/docs/build-skills'},
 {'title': 'Gemini CLI creating skills', 'url': 'https://geminicli.com/docs/cli/creating-skills/'},
 {'title': 'Gemini CLI using skills', 'url': 'https://geminicli.com/docs/cli/using-agent-skills/'},
]
ARCHIVE_SUFFIXES = ('.zip', '.skill', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.tgz')
TEXT_SUFFIXES = frozenset(('.md', '.txt', '.rst', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.csv', '.tsv', '.xml', '.html', '.css', '.js', '.ts', '.jsx', '.tsx', '.py', '.sh', '.ps1', '.bat', '.cmd', '.sql', '.r', '.rb', '.go', '.java', '.c', '.h', '.cpp', '.rs', '.svg', '.gitignore', '.env.example'))
class PackageEditError(ValueError):
    def __init__(self, message: str, validation: dict | None = None):
        super().__init__(message)
        self.validation = validation

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _path(path: str) -> str:
    if not isinstance(path, str) or not path or len(path) > 1024:
        raise PackageEditError('Archive paths must be nonempty strings of at most 1024 characters')
    if '\\' in path or path.startswith('/') or ':' in path:
        raise PackageEditError('Absolute, drive, UNC, and backslash paths are forbidden')
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise PackageEditError('Control characters in archive paths are forbidden')
    parts = path.split('/')
    if any(p in ('', '.', '..') or p.endswith((' ', '.')) for p in parts):
        raise PackageEditError('Empty, traversal, and ambiguous path components are forbidden')
    for part in parts:
        if re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', part):
            raise PackageEditError('Device names in archive paths are forbidden')
    return path

def _text(path: str, data: bytes) -> str | None:
    suffix = posixpath.splitext(path)[1].lower()
    if len(data) > MAX_TEXT or (suffix and suffix not in TEXT_SUFFIXES):
        return None
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 32 and c not in '\r\n\t' for c in text):
        return None
    return text


def _zip_preflight(data: bytes, max_entries: int) -> None:
    """Bound central-directory allocation before constructing stdlib ZipFile.

    ZIP64, multipart ZIPs and central directories over 2 MiB are outside
    this local editor safety profile, even if another consumer supports them.
    """
    if len(data) < 22:
        raise PackageEditError('Truncated ZIP footer')
    footer = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
    if footer < 0 or footer + 22 > len(data):
        raise PackageEditError('Missing ZIP footer')
    _, disk, directory_disk, disk_count, count, size, offset, comment = struct.unpack_from('<4sHHHHIIH', data, footer)
    if footer + 22 + comment != len(data):
        raise PackageEditError('Ambiguous ZIP footer or trailing data')
    if disk or directory_disk or disk_count != count:
        raise PackageEditError('Multipart ZIP archives are unsupported')
    if footer >= 20 and data[footer - 20:footer - 16] == b'PK\x06\x07':
        raise PackageEditError('ZIP64 locator is outside the local editor safety profile')
    if count == 65535 or size == 0xffffffff or offset == 0xffffffff:
        raise PackageEditError('ZIP64 is outside the local editor safety profile')
    if not 1 <= count <= max_entries:
        raise PackageEditError('ZIP entry count exceeds the local safety limit')
    if size > 2 * 1024 * 1024:
        raise PackageEditError('ZIP central directory exceeds the 2 MiB safety limit')
    if offset + size != footer:
        raise PackageEditError('ZIP central-directory bounds are inconsistent')
    cursor = offset
    actual = 0
    while cursor < footer:
        if cursor + 46 > footer or data[cursor:cursor + 4] != b'PK\x01\x02':
            raise PackageEditError('Malformed ZIP central directory')
        compressed, expanded = struct.unpack_from('<II', data, cursor + 20)
        name_length, extra_length, comment_length, start_disk = struct.unpack_from('<HHHH', data, cursor + 28)
        local_offset = struct.unpack_from('<I', data, cursor + 42)[0]
        if compressed == 0xffffffff or expanded == 0xffffffff or local_offset == 0xffffffff or start_disk:
            raise PackageEditError('ZIP64 or multipart entries are unsupported')
        cursor += 46 + name_length + extra_length + comment_length
        actual += 1
        if actual > max_entries or cursor > footer or not name_length:
            raise PackageEditError('ZIP directory exceeds count or byte bounds')
    if cursor != footer or actual != count:
        raise PackageEditError('ZIP directory count or size mismatch')

def _read(data: bytes, filename: str) -> tuple[dict[str, bytes], str, str]:
    if not isinstance(data, bytes) or not data or len(data) > MAX_ARCHIVE:
        raise PackageEditError('Archive must contain 1 to 50 MiB of bytes')
    if not isinstance(filename, str):
        raise PackageEditError('Filename must be a string')
    extension = posixpath.splitext(filename.replace('\\', '/'))[1].lower()
    if extension not in ('.zip', '.skill'):
        raise PackageEditError('Only .zip and .skill ZIP archives are supported')
    if not data.startswith(b'PK\x03\x04'):
        raise PackageEditError('Input is not a ZIP archive; renaming another format is unsupported')
    files = {}
    seen = set()
    directories = set()
    spellings = {}
    total = 0
    office_budget = [0, 0]
    try:
        _zip_preflight(data, MAX_ENTRIES)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ENTRIES:
                raise PackageEditError('Archive entry count must be between 1 and 500')
            for entry in infos:
                if entry.orig_filename != entry.filename:
                    raise PackageEditError('Truncated or NUL-containing ZIP filename')
                path = _path(entry.filename[:-1] if entry.is_dir() else entry.filename)
                key = unicodedata.normalize('NFC', path).casefold()
                if key in seen:
                    raise PackageEditError('Duplicate or Unicode/case-colliding archive paths')
                seen.add(key)
                parts = path.split('/')
                for index in range(1, len(parts) + 1):
                    prefix = '/'.join(parts[:index])
                    canonical = unicodedata.normalize('NFC', prefix).casefold()
                    if canonical in spellings and spellings[canonical] != prefix:
                        raise PackageEditError('Unicode/case-colliding path components')
                    spellings[canonical] = prefix
                mode = entry.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise PackageEditError('Symlinks and special archive entries are forbidden')
                if entry.flag_bits & 1:
                    raise PackageEditError('Encrypted archives are unsupported')
                if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise PackageEditError('Only stored/deflated ZIP entries are supported')
                if entry.is_dir():
                    if entry.file_size:
                        raise PackageEditError('Directory entries cannot contain data')
                    directories.add(key)
                    continue
                if kind == stat.S_IFDIR:
                    raise PackageEditError('File marked as directory')
                total += entry.file_size
                if entry.file_size > MAX_FILE or total > MAX_TOTAL:
                    raise PackageEditError('Expanded archive exceeds the 25 MiB file / 50 MiB package limits')
                if entry.file_size > max(entry.compress_size, 1) * MAX_RATIO:
                    raise PackageEditError('Archive compression ratio exceeds the safety limit')
                with archive.open(entry) as stream:
                    content = stream.read(min(MAX_FILE, entry.file_size) + 1)
                if len(content) != entry.file_size:
                    raise PackageEditError('ZIP entry size mismatch')
                office = _office_asset(path, content, office_budget)
                if not office and _nested_archive(path, content):
                    raise PackageEditError('Nested archives are unsupported')
                files[path] = content
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, NotImplementedError, ValueError, zlib.error) as error:
        if isinstance(error, PackageEditError):
            raise
        raise PackageEditError('Malformed or unsupported ZIP archive') from error
    if not files:
        raise PackageEditError('Archive contains no files')
    file_keys = {unicodedata.normalize('NFC', p).casefold() for p in files}
    for key in seen:
        for index in range(1, len(key.split('/'))):
            if '/'.join(key.split('/')[:index]) in file_keys:
                raise PackageEditError('A file conflicts with an archive directory')
    if file_keys & directories:
        raise PackageEditError('A file conflicts with an archive directory')
    roots = {p.split('/')[0] for p in files}
    if len(roots) != 1 or any('/' not in p for p in files):
        raise PackageEditError('Package must contain one top-level skill folder')
    root = next(iter(roots))
    canonical_root = unicodedata.normalize('NFC', root).casefold()
    if any(d != canonical_root and not d.startswith(canonical_root + '/') for d in directories):
        raise PackageEditError('Directory outside the single skill root')
    skill_paths = [p for p in files if posixpath.basename(p).casefold() == 'skill.md']
    if skill_paths != [root + '/SKILL.md']:
        raise PackageEditError('Package must contain exactly one root SKILL.md with that exact casing')
    return files, root, extension[1:]

def _nested_archive(path: str, content: bytes) -> bool:
    return (path.lower().endswith(ARCHIVE_SUFFIXES)
        or content.startswith((b'PK\x03\x04', b'PK\x05\x06', b'\x1f\x8b', b'7z\xbc\xaf\x27\x1c', b'Rar!', b'BZh', b'\xfd7zXZ'))
        or content[257:262] == b'ustar')

def _office_asset(path: str, data: bytes, budget: list, depth: int = 0) -> bool:
    """Bounded Office container checks; semantic/document safety is rescanned separately."""
    required = {'.docx': 'word/document.xml', '.pptx': 'ppt/presentation.xml', '.xlsx': 'xl/workbook.xml'}
    suffix = posixpath.splitext(path)[1].lower()
    if suffix not in required:
        return False
    if depth > 3:
        raise PackageEditError('Office nesting exceeds three levels')
    try:
        _zip_preflight(data, 2000 - budget[1])
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            entries = package.infolist()
            budget[1] += len(entries)
            if budget[1] > 2000:
                raise PackageEditError('Office assets exceed shared 2000-entry budget')
            names = set()
            for entry in entries:
                name = _path(entry.filename[:-1] if entry.is_dir() else entry.filename)
                canonical = unicodedata.normalize('NFC', name).casefold()
                if canonical in names or entry.orig_filename != entry.filename:
                    raise PackageEditError('Office asset has duplicate or ambiguous paths')
                names.add(canonical)
                if entry.flag_bits & 1 or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise PackageEditError('Office asset contains encrypted or special entries')
                if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise PackageEditError('Unsupported Office compression')
                budget[0] += entry.file_size
                if budget[0] > MAX_TOTAL or entry.file_size > MAX_FILE or entry.file_size > max(entry.compress_size, 1) * MAX_RATIO:
                    raise PackageEditError('Office assets exceed shared expanded size or ratio budget')
                if entry.is_dir():
                    if entry.file_size:
                        raise PackageEditError('Office directory contains data')
                    continue
                with package.open(entry) as stream:
                    content = stream.read(entry.file_size + 1)
                if len(content) != entry.file_size:
                    raise PackageEditError('Office asset size mismatch')
                office = _office_asset(name, content, budget, depth + 1)
                if not office and _nested_archive(name, content):
                    raise PackageEditError('Nested non-Office archives inside Office assets are unsupported')
            if '[content_types].xml' not in names or required[suffix] not in names:
                raise PackageEditError('Office asset is missing required container members')
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, NotImplementedError, ValueError, zlib.error) as error:
        if isinstance(error, PackageEditError):
            raise
        raise PackageEditError('Malformed Office asset') from error
    return True

def inspect_package(data: bytes, filename: str) -> dict:
    files, root, extension = _read(data, filename)
    entries = []
    remaining = MAX_PREVIEW
    for path, content in sorted(files.items(), key=lambda pair: (pair[0] != root + '/SKILL.md', pair[0])):
        text = _text(path, content)
        entry = {'path': path, 'sha256': _sha(content), 'size': len(content), 'editable': False, 'editable_reason': 'binary_or_oversized'}
        if text is not None and len(content) <= remaining:
            entry['text'] = text
            entry['editable'] = True
            entry.pop('editable_reason', None)
            remaining -= len(content)
        if text is not None and 'text' not in entry:
            entry['editable_reason'] = 'preview_budget_exceeded'
        entries.append(entry)
    entries.sort(key=lambda entry: entry['path'])
    return {'sha256': _sha(data), 'filename': filename, 'input_format': extension,
            'skill_root': root, 'entries': entries,
            'total_uncompressed_size': sum(map(len, files.values())), 'sources': SOURCES}

class _UniqueLoader(yaml.SafeLoader):
    """SafeLoader with duplicate mapping keys rejected, including merged keys."""

def _mapping(loader, node):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise PackageEditError('Frontmatter mapping keys must be unique strings')
        result[key] = loader.construct_object(value_node)
    return result
_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)

def _frontmatter(content: bytes) -> tuple[dict, str]:
    if len(content) > MAX_TEXT:
        raise PackageEditError('SKILL.md exceeds the 128 KiB editor limit')
    text = content.decode('utf-8')
    lines = text.splitlines()
    if not lines or lines[0] != '---':
        raise PackageEditError('SKILL.md must begin with YAML frontmatter')
    try:
        end = lines.index('---', 1)
    except ValueError as error:
        raise PackageEditError('SKILL.md frontmatter has no closing delimiter') from error
    raw = '\n'.join(lines[1:end])
    depth = 0
    for event in yaml.parse(raw, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.events.AliasEvent) or getattr(event, 'anchor', None):
            raise PackageEditError('YAML anchors and aliases are unsupported')
        if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
            depth += 1
            if depth > 16:
                raise PackageEditError('Frontmatter nesting exceeds 16 levels')
        if isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
            depth -= 1
    metadata = yaml.load(raw, Loader=_UniqueLoader)
    if not isinstance(metadata, dict):
        raise PackageEditError('Frontmatter must be a mapping')
    return metadata, '\n'.join(lines[end + 1:])

def _validate(files: dict[str, bytes], root: str, profile: str, removed: set[str]) -> dict:
    result = {'status': 'pass', 'target_profile': profile, 'errors': [], 'warnings': [], 'sources': SOURCES}
    def issue(kind, code, message, source=0, path=None):
        if len(result[kind]) >= MAX_ENTRIES:
            return
        item = {'code': code, 'message': message, 'source': SOURCES[source]['url']}
        if path:
            item['path'] = path
        result[kind].append(item)
    skill = root + '/SKILL.md'
    if skill not in files:
        issue('errors', 'missing_skill', 'SKILL.md cannot be removed')
    else:
        try:
            metadata, body = _frontmatter(files[skill])
        except (PackageEditError, yaml.YAMLError, UnicodeError, RecursionError) as error:
            issue('errors', 'frontmatter', str(error), path=skill)
        else:
            name = metadata.get('name')
            description = metadata.get('description')
            normalized_name = unicodedata.normalize('NFKC', name) if isinstance(name, str) else ''
            if (not normalized_name or len(normalized_name) > 64
                or normalized_name != normalized_name.lower()
                or not all(c.isalnum() or c == '-' for c in normalized_name)
                or normalized_name.startswith('-') or normalized_name.endswith('-') or '--' in normalized_name):
                issue('errors', 'name', 'Name must be 1-64 lowercase alphanumeric characters with single internal hyphens')
            elif name != root:
                issue('errors', 'root_name', 'Root folder must exactly match frontmatter name')
            if not isinstance(description, str) or not description.strip() or len(description) > 1024:
                issue('errors', 'description', 'Description must be a nonempty string of at most 1024 characters')
            compatibility = metadata.get('compatibility')
            if compatibility is not None and (not isinstance(compatibility, str) or not 1 <= len(compatibility) <= 500):
                issue('errors', 'compatibility', 'Compatibility must be a string of 1 to 500 characters')
            meta = metadata.get('metadata')
            if meta is not None and (not isinstance(meta, dict)
                or any(not isinstance(k, str) or not isinstance(v, str) for k, v in meta.items())):
                issue('errors', 'metadata', 'Metadata must map strings to strings')
            for field in ('license', 'allowed-tools'):
                if field in metadata and not isinstance(metadata[field], str):
                    issue('errors', 'field_type', field + ' must be a string')
            portable = {'name', 'description', 'license', 'compatibility', 'metadata', 'allowed-tools'}
            extra = sorted(set(metadata) - portable)
            if extra and profile != 'claude-code':
                issue('errors' if profile in ('generic-agent-skills', 'claude-ai', 'claude-api') else 'warnings', 'extra_frontmatter',
                      'Additional frontmatter is preserved; target support is unverified: ' + ', '.join(extra))
            if profile == 'claude-ai' and isinstance(description, str) and len(description) > 200:
                issue('warnings', 'claude_ai_description',
                      'Claude.ai help specifies 200 characters while API documentation specifies 1024; shorten for Claude.ai compatibility', 1)
            if profile == 'claude-api':
                if isinstance(name, str) and any(x in name for x in ('anthropic', 'claude')):
                    issue('errors', 'reserved_name', 'Claude API disallows reserved name words anthropic and claude', 2)
                if any(isinstance(v, str) and ('<' in v or '>' in v) for v in (name, description)):
                    issue('errors', 'xml_metadata', 'Claude API name and description cannot contain XML tags', 2)
            if len(body.splitlines()) > 500:
                issue('warnings', 'long_skill', 'Skill body exceeds the 500-line recommendation')
            if len(body) > 20000:
                issue('warnings', 'token_budget',
                      'Body exceeds 20000 characters; review the approximately 5000-token recommendation (tokens were not measured)')
    if profile == 'claude-api' and sum(map(len, files.values())) >= CLAUDE_MAX_TOTAL_BYTES:
        issue('errors', 'claude_size', 'Claude API requires total uncompressed package size below 30 MB', 2)
    if profile == 'openai-api' and any(len(content) > OPENAI_MAX_FILE_BYTES for content in files.values()):
        issue('errors', 'openai_file_size', 'OpenAI API permits at most 25 MB per uncompressed file', 4)
    if profile in ('claude-code', 'openai-codex', 'gemini-cli'):
        source = {'claude-code': 3, 'openai-codex': 5, 'gemini-cli': 7}[profile]
        issue('warnings', 'install_unverified',
              'Archive structure checked; installation and execution in the selected CLI have not been verified', source)
    for path, content in files.items():
        if not path.lower().endswith('.md'):
            continue
        text = _text(path, content)
        if text is None:
            continue
        text = re.sub(r'(?ms)^([ \t]*)(?:\x60{3,}|~{3,}).*?^[ \t]*(?:\x60{3,}|~{3,})[^\n]*', '', text)
        text = re.sub(r'(?<!\x60)(\x60+)(?!\x60).*?(?<!\x60)\1(?!\x60)', '', text, flags=re.S)
        for target in re.findall(r'!?\[[^\]\n]*\]\(\s*<?([^()\s>]+)>?(?:\s+[^)]*)?\)', text):
            target = unquote(target.split('#', 1)[0].split('?', 1)[0])
            if not target or re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target) or target.startswith('/'):
                continue
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
            if resolved in removed:
                issue('errors', 'removed_reference', 'Markdown link references removed file: ' + resolved, path=path)
    result['status'] = 'error' if result['errors'] else 'warn' if result['warnings'] else 'pass'
    return result

def build_package(data: bytes, filename: str, changes: list, target_profile: str, output_format: str) -> dict:
    if target_profile not in PROFILES:
        raise PackageEditError('Unsupported target profile')
    if output_format not in ('zip', 'skill'):
        raise PackageEditError('Output format must be zip or skill')
    files, root, _ = _read(data, filename)
    if not isinstance(changes, list) or len(changes) > MAX_ENTRIES:
        raise PackageEditError('Changes must be a list with at most 500 entries')
    summary = []
    changed = set()
    removed = set()
    for change in changes:
        if not isinstance(change, dict):
            raise PackageEditError('Each change must be an object')
        path = _path(change.get('path'))
        if path in changed:
            raise PackageEditError('Duplicate change path')
        changed.add(path)
        if path not in files:
            raise PackageEditError('Change refers to an unknown file')
        if change.get('original_sha256') != _sha(files[path]):
            raise PackageEditError('Stale original file hash for ' + path)
        action = change.get('action')
        item = {'path': path, 'action': action, 'original_sha256': _sha(files[path])}
        if action == 'remove':
            del files[path]
            removed.add(path)
        elif action == 'replace':
            if _text(path, files[path]) is None:
                raise PackageEditError('Binary or oversized files cannot be rewritten')
            content = change.get('content')
            if not isinstance(content, str):
                raise PackageEditError('Replacement content must be UTF-8 text')
            try:
                replacement = content.encode('utf-8')
            except UnicodeError as error:
                raise PackageEditError('Replacement is not valid UTF-8') from error
            if _text(path, replacement) is None:
                raise PackageEditError('Replacement must be safe text of at most 128 KiB')
            files[path] = replacement
            item['sha256'] = _sha(replacement)
        else:
            raise PackageEditError('Change action must be replace or remove')
        summary.append(item)
    if sum(map(len, files.values())) > MAX_TOTAL:
        raise PackageEditError('Edited archive exceeds uncompressed size limit')
    validation = _validate(files, root, target_profile, removed)
    if validation['errors']:
        raise PackageEditError('Package validation failed', validation)
    if output_format == 'skill' and target_profile in ('claude-ai', 'claude-api', 'openai-api'):
        validation['warnings'].append({'code': 'documented_zip_upload', 'message': 'This destination documents ZIP uploads. The .skill file is ZIP-format, but direct acceptance of this extension was not tested; choose .zip for its documented upload path.', 'source': SOURCES[4 if target_profile == 'openai-api' else 2 if target_profile == 'claude-api' else 1]['url']})
        validation['status'] = 'warn'
    # Keep ordinary executable-script behavior while stripping privileged bits.
    with zipfile.ZipFile(io.BytesIO(data)) as original:
        executables = {entry.filename for entry in original.infolist()
                       if entry.create_system == 3 and (entry.external_attr >> 16) & 0o111}
    if any(path.lower().endswith(('.sig', '.asc')) for path in files):
        validation['warnings'].append({'code': 'signature_revalidation_required',
            'message': 'A signature-like file is retained; verify any publisher signatures separately for the rebuilt artifact. Export does not establish authenticity.',
            'source': SOURCES[0]['url']})
        validation['status'] = 'warn'
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for path, content in sorted(files.items()):
            entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | (0o755 if path in executables else 0o644)) << 16
            entry.compress_type = zipfile.ZIP_STORED
            archive.writestr(entry, content)
    package = output.getvalue()
    if len(package) > MAX_ARCHIVE:
        raise PackageEditError('Edited archive exceeds output size limit')
    return {'bytes': package, 'filename': root + '.' + output_format, 'sha256': _sha(package), 'validation': validation, 'changes': summary}
