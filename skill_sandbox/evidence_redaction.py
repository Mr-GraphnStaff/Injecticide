"""Redact reflected credential literals after detection, never before decisions.

This is report hygiene, not a claim to discover every possible secret. Contact
addresses and ordinary data-presence evidence remain visible unless explicitly
used as a credential literal. No source text or package hashes are modified.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
MAX_SECRET_VALUES = 128
MAX_SECRET_CHARACTERS = 32768
MAX_RESULT_NODES = 1_000_000
MAX_SOURCE_CHARACTERS = 1024 * 1024
MAX_SOURCE_FILES = 200
URL_RE = re.compile(r"(?:https?|wss?)://[^\s<>\"'`]+", re.I)
SENSITIVE_KEY = re.compile(r"(?:api[-_]?key|(?:access|refresh|session|auth)[-_]?token|authorization|password|passwd|secret|credential|private[-_]?key|signature|bearer)", re.I)
DECLARATION = re.compile(
    r'''(?ix)["']?\b(?:api[-_]?key|(?:access|refresh|session|auth)[-_]?token|authorization|password|passwd|(?:client[-_]?)?secret|private[-_]?key)\b["']?\s*[:=]\s*["']([^"'\r\n]{1,8192})["']''')
AUTHORIZATION = re.compile(r"(?i)\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{4,8192})")
TRUSTED_FIELDS = {
    "id", "rule_id", "status", "severity", "tier", "category", "finding_category", "subject",
    "action_state", "disposition", "display_kind", "decision", "execution_tier", "policy_capabilities",
    "required_capabilities", "sha256", "artifact_sha256", "engine_source_sha256", "reviewed_sha256",
    "scanner_version", "adapter_version", "catalog_version", "version", "source_ids", "source_url",
    "format", "kind", "runtime", "target_runtime", "assessment_state", "convention", "verification",
    "validation", "format_compatibility", "vendor_compatibility", "authority", "policy_scope",
}
EVIDENCE_FIELDS = {
    "samples", "text", "match", "instruction", "external_dependencies", "metadata",
    "detail", "message", "purpose", "intended_purpose", "filename", "path",
    "source", "target", "root", "manifest", "value", "url", "endpoint", "command",
    "provided_issuer", "issuer", "audience", "author", "owner", "evidence_excerpt",
    "script", "script_candidate", "external_script", "package_declarations",
    "dependencies", "requires_python",
    "reachable_paths", "unreferenced_paths", "entrypoints",
}


class RedactionBudgetExceeded(ValueError):
    """Fail closed rather than returning unsanitized evidence after a budget hit."""


def _remember(values, value):
    if not value or "${" in value or "{{" in value or value == REDACTED:
        return
    values.add(value)
    # Header schemes are not secrets; their literal credential portion is.
    match = AUTHORIZATION.fullmatch(value.strip())
    if match:
        values.add(match[1])
    if len(values) > MAX_SECRET_VALUES or sum(map(len, values)) > MAX_SECRET_CHARACTERS:
        raise RedactionBudgetExceeded("Credential evidence exceeds the report redaction budget")


def _url_credentials(raw, values):
    try:
        parsed = urlsplit(raw)
        if parsed.password:
            _remember(values, unquote(parsed.password))
        for section in (parsed.query, parsed.fragment if "=" in parsed.fragment else ""):
            for key, value in parse_qsl(section, keep_blank_values=True, max_num_fields=4096):
                if SENSITIVE_KEY.search(key):
                    _remember(values, value)
    except RedactionBudgetExceeded:
        raise
    except ValueError:
        # Malformed URLs are still handled by the bounded text sanitizer below.
        return


def _redact_url(match):
    raw = match[0]
    try:
        parsed = urlsplit(raw)
        netloc = parsed.netloc.rsplit("@", 1)[-1]
        if "@" in parsed.netloc:
            netloc = REDACTED + "@" + netloc
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=4096)
        fragment_pairs = parse_qsl(parsed.fragment, keep_blank_values=True, max_num_fields=4096) if "=" in parsed.fragment else []
        query_sensitive = any(SENSITIVE_KEY.search(key) for key, _ in pairs)
        fragment_sensitive = any(SENSITIVE_KEY.search(key) for key, _ in fragment_pairs)
        if "@" not in parsed.netloc and not query_sensitive and not fragment_sensitive:
            return raw
        query = urlencode([(key, REDACTED if SENSITIVE_KEY.search(key) else value) for key, value in pairs], safe="[]") if query_sensitive else parsed.query
        fragment = urlencode([(key, REDACTED if SENSITIVE_KEY.search(key) else value) for key, value in fragment_pairs], safe="[]") if fragment_sensitive else parsed.fragment
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))
    except ValueError:
        # Never echo a malformed URL whose credential boundaries are ambiguous.
        return "[URL OMITTED: credential boundaries unavailable]"


def redact_result(result, texts):
    """Sanitize returned evidence in place, after all detection and policy work."""
    if len(texts) > MAX_SOURCE_FILES:
        raise ValueError("Source inventory exceeds the report redaction budget")
    values = set()
    for text in texts.values():
        bounded = text[:MAX_SOURCE_CHARACTERS]
        for match in DECLARATION.finditer(bounded):
            _remember(values, match[1])
        for match in URL_RE.finditer(bounded):
            _url_credentials(match[0], values)
    # Longest-first prevents a shorter credential hiding part of a longer one.
    secrets = sorted(values, key=len, reverse=True)
    replacements = set()
    for secret in secrets:
        replacements.update((secret, quote(secret, safe="")))
    def token_expression(value):
        literal = re.escape(value)
        # A one-character password must not erase letters from email addresses,
        # source paths or unrelated evidence. Short literals require boundaries.
        return literal if len(value) >= 8 else r"(?<![\w@])" + literal + r"(?![\w@])"
    token_pattern = re.compile("|".join(token_expression(s) for s in sorted(replacements, key=len, reverse=True))) if replacements else None

    def sanitize(text):
        def replace_value(match):
            start, end = match.start(1) - match.start(), match.end(1) - match.start()
            return match[0][:start] + REDACTED + match[0][end:]
        text = URL_RE.sub(_redact_url, text)
        text = DECLARATION.sub(replace_value, text)
        text = AUTHORIZATION.sub(replace_value, text)
        return token_pattern.sub(lambda match: REDACTED, text) if token_pattern else text

    pending = [(result, None, None, ())]
    count = 0
    while pending:
        node, parent, key, path = pending.pop()
        count += 1
        if count > MAX_RESULT_NODES:
            raise ValueError("Returned evidence exceeds the report redaction work budget")
        if isinstance(node, dict):
            if "metadata" in path:
                for name in list(node):
                    redacted_name = sanitize(name) if isinstance(name, str) else name
                    if redacted_name != name:
                        # Metadata keys are upload data, not report-schema keys.
                        node[redacted_name] = node.pop(name)
            pending.extend((value, node, name, path + (name,)) for name, value in node.items())
        elif isinstance(node, list):
            pending.extend((value, node, index, path + (index,)) for index, value in enumerate(node))
        elif isinstance(node, str) and parent is not None:
            user_metadata = "metadata" in path
            semantic_key = next((part for part in reversed(path) if isinstance(part, str)), "")
            # Machine decisions, rule identities and hash bindings are computed
            # before redaction and must never be changed by an attacker choosing
            # a credential equal to 'blocked', 'prompt_override' or one hex digit.
            if semantic_key in TRUSTED_FIELDS and not user_metadata:
                continue
            evidence_bearing = user_metadata or semantic_key in EVIDENCE_FIELDS
            if not evidence_bearing:
                continue
            if user_metadata and isinstance(key, str) and SENSITIVE_KEY.search(key):
                parent[key] = REDACTED
            else:
                parent[key] = sanitize(node)
    result["evidence_redaction"] = {
        "status": "applied", "scope": "Evidence fields: reflected literal credentials, authorization values, URL userinfo and sensitive query/fragment values. Computed decisions and hash bindings are preserved.",
        "detection_order": "after_detection_and_policy_decisions", "contact_data": "preserved_unless_explicit_credential_literal",
        "secret_detection_completeness": "not_guaranteed"}
    return result
