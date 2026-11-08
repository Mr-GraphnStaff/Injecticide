"""Organisation AI policy (``injecticide-org-policy/v1``): validation and evaluation.

The policy is data. It is parsed with the bounded JSON parser, checked against a
strict schema and evaluated with fixed, deterministic conditions over the
finished scan result. No policy value is compiled as a regular expression,
imported or executed. Matching is exact identifier comparison, case-folded
substring comparison for connector names and a single leading ``*.`` wildcard
for host names.

The policy result sits beside the scanner verdict. It never removes or
downgrades a finding: an ``allow`` rule only marks matching findings with
``policy_disposition: "allowed_by_policy"``. An ``advisory`` rule cannot produce
an effective block; a triggered advisory block is reported as advisory.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import json
import re
from datetime import date
from functools import lru_cache
from pathlib import Path, PurePosixPath

try:
    from .package_formats import bounded_data, frontmatter
    from .governance import (CODE_EXECUTION_RULES, NETWORK_RULES, FILESYSTEM_RULES, ENTERPRISE_WRITE_RULES,
                             SENSITIVE_HANDLING_RULES, REGULATED_DATA_RULES)
except ImportError:
    from package_formats import bounded_data, frontmatter
    from governance import (CODE_EXECUTION_RULES, NETWORK_RULES, FILESYSTEM_RULES, ENTERPRISE_WRITE_RULES,
                            SENSITIVE_HANDLING_RULES, REGULATED_DATA_RULES)

POLICY_SCHEMA = "injecticide-org-policy/v1"
RESULT_SCHEMA = "injecticide-policy-results/v1"

MAX_POLICY_CHARS = 128 * 1024   # bounded_data enforces the same budget
MAX_RULES = 200
MAX_SOURCES = 100
MAX_NOTES = 200
MAX_CONDITION_DEPTH = 6
MAX_CONDITION_NODES = 64       # per rule
MAX_LIST_VALUES = 100
MAX_ID_CHARS = 64
MAX_TEXT_CHARS = 4000
MAX_ERRORS = 100
MAX_EVIDENCE = 50              # per rule

EFFECTS = ("block", "require_approval", "warn", "allow")
ENFORCEMENTS = ("mandatory", "advisory")
RISK_LEVELS = ("low", "medium", "high")
COVERAGE_VALUES = ("partial", "opaque")
CONDITION_KEYS = ("finding", "capability", "data_class", "external_origin", "connector_mentioned",
                  "frontmatter_missing", "risk_at_least", "coverage", "all", "any")

TOP_REQUIRED = ("schema", "organization", "policy_name", "compiled_date", "sources", "rules")
TOP_OPTIONAL = ("not_statically_checkable", "verification_notes")
SOURCE_REQUIRED = ("id", "title")
SOURCE_OPTIONAL = ("version", "date", "owner", "url", "notes")
RULE_REQUIRED = ("id", "title", "source", "requirement", "when", "effect", "enforcement")
RULE_OPTIONAL = ("section", "approver", "rationale")
NSC_FIELDS = ("source", "section", "requirement", "reason")

# Policy capability names come from governance.policy_capabilities and
# behavior_analysis required_capabilities; both are read at evaluation time.
CAPABILITIES = ("code_execution", "credential_handling", "enterprise_access", "file_write", "network",
                "read_only", "regulated_data", "state_persistence", "html_generation",
                "external_content_embedding", "auto_open")
CAPABILITY_FINDINGS = {
    "code_execution": CODE_EXECUTION_RULES,
    "file_write": FILESYSTEM_RULES | ENTERPRISE_WRITE_RULES,
    "network": NETWORK_RULES,
    "credential_handling": SENSITIVE_HANDLING_RULES,
    "regulated_data": REGULATED_DATA_RULES,
    "enterprise_access": ENTERPRISE_WRITE_RULES,
}

# Data classes from the database-profile contract (injecticide-db-profile/v1).
DATA_CLASSES = ("business_contact_email", "work_phone", "person_name", "job_title", "department",
                "manager_reference", "employee_id", "personal_email", "ssn", "date_of_birth", "home_address",
                "financial", "health", "credential", "free_text")
# Fixed finding -> data class mapping for text (non-database) evidence. A
# finding that carries its own ``data_classes`` list uses that list instead.
FINDING_DATA_CLASSES = {
    "pii_ssn": ("ssn",),
    "pii_date_of_birth": ("date_of_birth",),
    "phi_medical_record_number": ("health",),
    "phi_patient_record": ("health",),
    "hardcoded_secret": ("credential",),
    "literal_credential_declaration": ("credential",),
    "contact_directory": ("business_contact_email",),
}

# Finding ids named in the 0.16.0 shared contract that other modules add. They
# are accepted before those modules land so a policy does not go stale.
CONTRACT_FINDING_IDS = frozenset({"database_not_cleared", "opaque_database", "embedded_executable_blob",
                                  "contact_directory"})
# Plain-language names people use for a finding, mapped to the real id. Used
# only to suggest a correction; the policy must still name the real id.
FINDING_ALIASES = {
    "secret_in_file": "hardcoded_secret", "secret_present": "hardcoded_secret", "hardcoded_credential": "hardcoded_secret",
    "hardcoded_password": "hardcoded_secret", "api_key": "hardcoded_secret", "api_key_in_file": "hardcoded_secret",
    "credential_in_file": "hardcoded_secret", "embedded_secret": "hardcoded_secret", "secret": "hardcoded_secret",
    "prompt_injection": "prompt_override", "jailbreak": "prompt_override", "ignore_instructions": "prompt_override",
    "system_prompt_leak": "system_exfiltration", "email_address": "pii_email_address", "email": "pii_email_address",
    "phone_number": "pii_phone_number", "phone": "pii_phone_number", "ssn": "pii_ssn",
    "disguised_script": "executable_packaged_as_document", "shell_exec": "subprocess_spawn",
}
SECRET_DISCLOSURE_WARNING = (
    "'secret_exfiltration' means an instruction asking the model to disclose or send secrets. It does not fire "
    "when a secret is merely stored in a file. To act on secrets present in the package, use 'hardcoded_secret'.")

_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{2,63}")
_RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_FIELD_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_NON_FINDING_PREFIXES = ("plan_", "step_", "area_", "node_", "edge_")
_EXCLUDED_SOURCES = {"org_policy.py", "fix_summary.py"}


# --------------------------------------------------------------------------
# Finding id discovery
# --------------------------------------------------------------------------

@lru_cache(maxsize=1)
def known_finding_ids() -> frozenset:
    """Every finding id the scanner can emit, discovered from catalogs and code.

    Sources: rules/violations.json, rules/dispositions.json,
    rules/obsession_signatures.json, rules/finding-labels.json when present, and
    the scanner's own Python sources read with ``ast`` (never imported here):
    ``{"id": "<literal>"}`` dictionaries, ``finding("<id>", ...)`` /
    ``_finding(result, "<id>", ...)`` calls. Catalog-driven detectors are covered
    by the JSON catalogs above.
    """
    base = Path(__file__).resolve().parent
    found = set(CONTRACT_FINDING_IDS)
    rules = base / "rules"

    def load(name):
        try:
            return json.loads((rules / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    found.update(r.get("id") for r in load("violations.json").get("rules", []) if isinstance(r, dict))
    found.update(r.get("detector_id") for r in load("dispositions.json").get("rules", []) if isinstance(r, dict))
    found.update(s.get("id") for s in load("obsession_signatures.json").get("signatures", []) if isinstance(s, dict))
    labels = load("finding-labels.json")
    if isinstance(labels, dict):
        found.update(k for k in labels if not k.startswith("_"))
    for source in sorted(base.glob("*.py")):
        if source.name in _EXCLUDED_SOURCES:
            continue
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and key.value == "id":
                        # ``"id": "a" if condition else "b"`` names two ids.
                        options = [value.body, value.orelse] if isinstance(value, ast.IfExp) else [value]
                        found.update(option.value for option in options
                                     if isinstance(option, ast.Constant) and isinstance(option.value, str))
            elif isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
                if name in {"finding", "_finding"}:
                    for arg in node.args[:2]:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            found.add(arg.value)
                            break
    return frozenset(item for item in found if isinstance(item, str) and _IDENTIFIER.fullmatch(item)
                     and not item.startswith(_NON_FINDING_PREFIXES))


def _closest(value, choices):
    if not isinstance(value, str):
        return None
    match = difflib.get_close_matches(value.casefold(), list(choices), n=1, cutoff=0.5)
    return match[0] if match else None


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

class _Report:
    def __init__(self):
        self.errors, self.warnings = [], []

    def error(self, path, message, suggestion=None):
        if len(self.errors) < MAX_ERRORS:
            self.errors.append({"path": path, "message": message, "suggestion": suggestion})

    def warn(self, path, message, suggestion=None):
        if len(self.warnings) < MAX_ERRORS:
            self.warnings.append({"path": path, "message": message, "suggestion": suggestion})


def _public_keys(obj):
    return [key for key in obj if not (isinstance(key, str) and key.startswith("_"))]


def _check_keys(obj, required, optional, path, label, report):
    allowed = tuple(required) + tuple(optional)
    for key in _public_keys(obj):
        if key not in allowed:
            close = _closest(key, allowed)
            report.error(f"{path}.{key}" if path else key,
                         f"{label}: unknown field '{key}'" + (f"; did you mean '{close}'?" if close else
                         "; fields starting with '_' are ignored and can hold comments."), close)
    for key in required:
        if key not in obj:
            report.error(f"{path}.{key}" if path else key, f"{label}: missing required field '{key}'.")


def _text(obj, key, path, label, report, *, limit=MAX_TEXT_CHARS, required=True):
    value = obj.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        if key in obj or required:
            report.error(f"{path}.{key}" if path else key, f"{label}: '{key}' must be a non-empty string.")
        return None
    if len(value) > limit:
        report.error(f"{path}.{key}" if path else key, f"{label}: '{key}' exceeds {limit} characters.")
        return None
    return value


def _string_list(value, path, label, key, report, *, allow_object=False):
    """Normalise a string or list of strings. Returns None on error."""
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values:
        report.error(path, f"{label}: '{key}' must be a string or a non-empty list of strings.")
        return None
    if len(values) > MAX_LIST_VALUES:
        report.error(path, f"{label}: '{key}' lists more than {MAX_LIST_VALUES} values.")
        return None
    if not all(isinstance(item, str) and item.strip() and len(item) <= 200 for item in values):
        report.error(path, f"{label}: every '{key}' value must be a non-empty string of at most 200 characters.")
        return None
    return list(dict.fromkeys(values))


def _host_pattern(raw):
    """Return (pattern, error, suggestion). Only a leading '*.' wildcard is allowed."""
    value = raw.strip().casefold()
    if "://" in value or "/" in value or "@" in value or ":" in value:
        candidate = value.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
        return None, f"'{raw}' must be a host name such as 'api.example.test' or '*.example.test', not a URL.", candidate or None
    wildcard = value.startswith("*.")
    host = value[2:] if wildcard else value
    labels = host.split(".")
    if "*" in host or not host or len(host) > 253 or not all(_HOST_LABEL.fullmatch(label) for label in labels):
        return None, (f"'{raw}' is not a valid host pattern. Only a leading '*.' wildcard is supported "
                      "(for example '*.example.test')."), None
    return ("*." + host if wildcard else host), None, None


def _validate_condition(node, path, label, report, budget, depth=0):
    budget[0] += 1
    if budget[0] > MAX_CONDITION_NODES:
        if budget[0] == MAX_CONDITION_NODES + 1:
            report.error(path, f"{label}: condition has more than {MAX_CONDITION_NODES} parts.")
        return None
    if depth > MAX_CONDITION_DEPTH:
        report.error(path, f"{label}: conditions are nested deeper than {MAX_CONDITION_DEPTH} levels.")
        return None
    if not isinstance(node, dict):
        report.error(path, f"{label}: a condition must be an object with one key such as {{\"finding\": \"hardcoded_secret\"}}.")
        return None
    keys = _public_keys(node)
    if len(keys) != 1:
        report.error(path, f"{label}: a condition must have exactly one key (found {len(keys)}); combine conditions with 'all' or 'any'.")
        return None
    key = keys[0]
    value = node[key]
    here = f"{path}.{key}"
    if key not in CONDITION_KEYS:
        close = _closest(key, CONDITION_KEYS)
        report.error(here, f"{label}: unknown condition '{key}'" + (f"; did you mean '{close}'?" if close else "."), close)
        return None
    if key in {"all", "any"}:
        if not isinstance(value, list) or not value:
            report.error(here, f"{label}: '{key}' must be a non-empty list of conditions.")
            return None
        if len(value) > MAX_LIST_VALUES:
            report.error(here, f"{label}: '{key}' lists more than {MAX_LIST_VALUES} conditions.")
            return None
        children = [_validate_condition(child, f"{here}[{index}]", label, report, budget, depth + 1)
                    for index, child in enumerate(value)]
        return None if any(child is None for child in children) else {key: children}
    if key == "finding":
        include_info = False
        ids_value = value
        if isinstance(value, dict):
            _check_keys(value, ("ids",), ("include_info",), here, label, report)
            include_info = value.get("include_info", False)
            if not isinstance(include_info, bool):
                report.error(f"{here}.include_info", f"{label}: 'include_info' must be true or false.")
                return None
            ids_value = value.get("ids")
            here_ids = f"{here}.ids"
        else:
            here_ids = here
        ids = _string_list(ids_value, here_ids, label, "finding", report)
        if ids is None:
            return None
        known = known_finding_ids()
        bad = False
        for item in ids:
            if item not in known:
                close = FINDING_ALIASES.get(item.casefold()) or _closest(item, known)
                report.error(here_ids, f"{label}: unknown finding '{item}'" + (f"; did you mean '{close}'?" if close else
                             ". Use a finding id the scanner emits (see docs/org-policy.md)."), close)
                bad = True
        if "secret_exfiltration" in ids and "hardcoded_secret" not in ids:
            report.warn(here_ids, f"{label}: {SECRET_DISCLOSURE_WARNING}", "hardcoded_secret")
        return None if bad else {"finding": {"ids": ids, "include_info": include_info}}
    if key in {"capability", "data_class"}:
        allowed = CAPABILITIES if key == "capability" else DATA_CLASSES
        values = _string_list(value, here, label, key, report)
        if values is None:
            return None
        bad = False
        for item in values:
            if item not in allowed:
                close = _closest(item, allowed)
                report.error(here, f"{label}: unknown {key.replace('_', ' ')} '{item}'" + (f"; did you mean '{close}'?" if close else
                             f". Valid values: {', '.join(allowed)}."), close)
                bad = True
        return None if bad else {key: values}
    if key == "external_origin":
        mode, raw = "matches", value
        if isinstance(value, dict):
            _check_keys(value, ("outside",), (), here, label, report)
            mode, raw = "outside", value.get("outside")
        values = _string_list(raw, here + (".outside" if mode == "outside" else ""), label, "external_origin", report)
        if values is None:
            return None
        patterns, bad = [], False
        for item in values:
            pattern, problem, suggestion = _host_pattern(item)
            if problem:
                report.error(here, f"{label}: {problem}", suggestion)
                bad = True
            else:
                patterns.append(pattern)
        return None if bad else {"external_origin": {"mode": mode, "patterns": patterns}}
    if key == "connector_mentioned":
        values = _string_list(value, here, label, key, report)
        return None if values is None else {key: [item.strip().casefold() for item in values]}
    if key == "frontmatter_missing":
        values = _string_list(value, here, label, key, report)
        if values is None:
            return None
        bad = [item for item in values if not _FIELD_NAME.fullmatch(item)]
        for item in bad:
            report.error(here, f"{label}: '{item}' is not a frontmatter field name.")
        return None if bad else {key: values}
    if key == "risk_at_least":
        if value not in RISK_LEVELS:
            close = _closest(value, RISK_LEVELS)
            report.error(here, f"{label}: risk_at_least must be one of {', '.join(RISK_LEVELS)}" +
                         (f"; did you mean '{close}'?" if close else "."), close)
            return None
        return {key: value}
    if key == "coverage":
        if value not in COVERAGE_VALUES:
            close = _closest(value, COVERAGE_VALUES)
            report.error(here, f"{label}: coverage must be 'partial' or 'opaque'" +
                         (f"; did you mean '{close}'?" if close else "."), close)
            return None
        return {key: value}
    return None  # unreachable: every CONDITION_KEYS entry is handled above


def validate_policy(policy):
    """Validate a parsed policy object. Returns (normalised policy or None, errors, warnings)."""
    report = _Report()
    if not isinstance(policy, dict):
        report.error("", "Policy: the policy must be a JSON object.")
        return None, report.errors, report.warnings
    _check_keys(policy, TOP_REQUIRED, TOP_OPTIONAL, "", "Policy", report)
    schema = policy.get("schema")
    if "schema" in policy and schema != POLICY_SCHEMA:
        report.error("schema", f"Policy: schema must be '{POLICY_SCHEMA}' (found {json.dumps(schema)[:80]}).", POLICY_SCHEMA)
    organization = _text(policy, "organization", "", "Policy", report, limit=200)
    name = _text(policy, "policy_name", "", "Policy", report, limit=200)
    compiled = _text(policy, "compiled_date", "", "Policy", report, limit=10)
    if compiled is not None:
        try:
            if not _DATE.fullmatch(compiled):
                raise ValueError
            date.fromisoformat(compiled)
        except ValueError:
            report.error("compiled_date", "Policy: compiled_date must be a calendar date written YYYY-MM-DD.")

    source_ids = set()
    sources = policy.get("sources")
    clean_sources = []
    if "sources" in policy:
        if not isinstance(sources, list) or not sources:
            report.error("sources", "Policy: 'sources' must be a non-empty list of source documents.")
        elif len(sources) > MAX_SOURCES:
            report.error("sources", f"Policy: more than {MAX_SOURCES} sources.")
        else:
            for index, source in enumerate(sources):
                path = f"sources[{index}]"
                if not isinstance(source, dict):
                    report.error(path, "Policy: each source must be an object with 'id' and 'title'.")
                    continue
                _check_keys(source, SOURCE_REQUIRED, SOURCE_OPTIONAL, path, f"Source {index + 1}", report)
                sid = _text(source, "id", path, f"Source {index + 1}", report, limit=MAX_ID_CHARS)
                title = _text(source, "title", path, f"Source {index + 1}", report, limit=300)
                for key in SOURCE_OPTIONAL:
                    _text(source, key, path, f"Source {index + 1}", report, limit=500, required=False)
                if sid is not None:
                    if sid in source_ids:
                        report.error(f"{path}.id", f"Source {index + 1}: duplicate source id '{sid}'.")
                    source_ids.add(sid)
                    clean_sources.append({"id": sid, "title": title})

    rules = policy.get("rules")
    clean_rules = []
    if "rules" in policy:
        if not isinstance(rules, list) or not rules:
            report.error("rules", "Policy: 'rules' must be a non-empty list.")
            rules = []
        elif len(rules) > MAX_RULES:
            report.error("rules", f"Policy: more than {MAX_RULES} rules.")
            rules = []
        seen = set()
        for index, rule in enumerate(rules):
            path = f"rules[{index}]"
            if not isinstance(rule, dict):
                report.error(path, f"Rule {index + 1}: each rule must be an object.")
                continue
            raw_id = rule.get("id")
            label = f"Rule {raw_id}" if isinstance(raw_id, str) and _RULE_ID.fullmatch(raw_id) else f"Rule {index + 1}"
            before = len(report.errors)
            _check_keys(rule, RULE_REQUIRED, RULE_OPTIONAL, path, label, report)
            rid = _text(rule, "id", path, label, report, limit=MAX_ID_CHARS)
            if rid is not None and not _RULE_ID.fullmatch(rid):
                report.error(f"{path}.id", f"{label}: rule id may use letters, digits, '.', '_' and '-' only.")
            elif rid is not None:
                if rid in seen:
                    report.error(f"{path}.id", f"{label}: duplicate rule id '{rid}'.")
                seen.add(rid)
            title = _text(rule, "title", path, label, report, limit=300)
            source = _text(rule, "source", path, label, report, limit=MAX_ID_CHARS)
            if source is not None and source_ids and source not in source_ids:
                close = _closest(source, source_ids)
                report.error(f"{path}.source", f"{label}: source '{source}' is not listed in 'sources'" +
                             (f"; did you mean '{close}'?" if close else "."), close)
            requirement = _text(rule, "requirement", path, label, report)
            section = _text(rule, "section", path, label, report, limit=200, required=False)
            approver = _text(rule, "approver", path, label, report, limit=200, required=False)
            rationale = _text(rule, "rationale", path, label, report, required=False)
            effect = rule.get("effect")
            if "effect" in rule and effect not in EFFECTS:
                close = _closest(effect, EFFECTS)
                report.error(f"{path}.effect", f"{label}: unknown effect {json.dumps(effect)[:60]}" +
                             (f"; did you mean '{close}'?" if close else f". Use one of {', '.join(EFFECTS)}."), close)
            enforcement = rule.get("enforcement")
            if "enforcement" in rule and enforcement not in ENFORCEMENTS:
                close = _closest(enforcement, ENFORCEMENTS)
                report.error(f"{path}.enforcement", f"{label}: enforcement must be 'mandatory' or 'advisory'" +
                             (f"; did you mean '{close}'?" if close else "."), close)
            if effect == "require_approval" and approver is None:
                report.error(f"{path}.approver", f"{label}: a require_approval rule must name its approver.")
            when = None
            if "when" in rule:
                when = _validate_condition(rule["when"], f"{path}.when", label, report, [0])
            if len(report.errors) == before and when is not None:
                clean_rules.append({"id": rid, "title": title, "source": source, "section": section,
                                    "requirement": requirement, "when": when, "effect": effect,
                                    "enforcement": enforcement, "approver": approver, "rationale": rationale})

    def notes(key, objects):
        value = policy.get(key, [])
        if not isinstance(value, list):
            report.error(key, f"Policy: '{key}' must be a list.")
            return []
        if len(value) > MAX_NOTES:
            report.error(key, f"Policy: '{key}' has more than {MAX_NOTES} entries.")
            return []
        cleaned = []
        for index, item in enumerate(value):
            path = f"{key}[{index}]"
            if isinstance(item, str) and item.strip() and len(item) <= MAX_TEXT_CHARS:
                cleaned.append(item)
            elif objects and isinstance(item, dict):
                _check_keys(item, ("requirement",), tuple(f for f in NSC_FIELDS if f != "requirement"), path, f"Entry {index + 1}", report)
                entry = {}
                for field in NSC_FIELDS:
                    text = _text(item, field, path, f"Entry {index + 1}", report, required=field == "requirement")
                    if text is not None:
                        entry[field] = text
                cleaned.append(entry)
            else:
                report.error(path, f"Policy: each '{key}' entry must be a non-empty string" +
                             (" or an object with a 'requirement'." if objects else "."))
        return cleaned
    nsc = notes("not_statically_checkable", True)
    verification = notes("verification_notes", False)

    if report.errors:
        return None, report.errors, report.warnings
    return ({"organization": organization, "policy_name": name, "compiled_date": compiled, "sources": clean_sources,
             "rules": clean_rules, "not_statically_checkable": nsc, "verification_notes": verification},
            report.errors, report.warnings)


def parse_policy(raw):
    """Parse policy text or an already-parsed object. Returns (object|None, sha256|None, errors)."""
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            return None, hashlib.sha256(bytes(raw)).hexdigest(), [{"path": "", "message": "Policy: the policy file must be UTF-8 text.", "suggestion": None}]
    if isinstance(raw, str):
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if len(raw) > MAX_POLICY_CHARS:
            return None, digest, [{"path": "", "message": f"Policy: the policy exceeds the {MAX_POLICY_CHARS // 1024} KiB size limit.", "suggestion": None}]
        try:
            return bounded_data(raw.lstrip("﻿")), digest, []
        except json.JSONDecodeError as exc:
            return None, digest, [{"path": "", "message": f"Policy: not valid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}.", "suggestion": None}]
        except (ValueError, RecursionError) as exc:
            message = str(exc)[:200] if isinstance(exc, ValueError) else "nesting too deep"
            return None, digest, [{"path": "", "message": f"Policy: could not be read within the parser limits ({message}).", "suggestion": None}]
    try:
        canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError):
        return None, None, [{"path": "", "message": "Policy: the policy must be JSON data.", "suggestion": None}]
    # Re-parse through the bounded parser so in-process callers get the same limits.
    return parse_policy(canonical)[0], hashlib.sha256(canonical.encode("utf-8")).hexdigest(), []


def is_empty_policy(raw):
    return raw is None or (isinstance(raw, (str, bytes, bytearray)) and not raw.strip())


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def _actionable(finding):
    tier = finding.get("tier")
    if tier in {"review", "block"}:
        return True
    if tier == "info":
        return False
    return finding.get("severity") not in {None, "info"}


def _host_matches(host, pattern):
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def _origin_host(url):
    if not isinstance(url, str):
        return None
    rest = url.split("://", 1)[-1]
    host = rest.split("/", 1)[0].rsplit("@", 1)[-1]
    if host.startswith("["):
        return host.split("]", 1)[0] + "]"
    return host.split(":", 1)[0].casefold() or None


class _Facts:
    """Read-only view of the finished scan result. Absent keys are tolerated."""

    def __init__(self, result, text_sources=None):
        self.findings = []  # (path, finding dict, actionable)
        for entry in result.get("files") or []:
            if not isinstance(entry, dict):
                continue
            path = entry.get("path")
            for finding in entry.get("findings") or []:
                if isinstance(finding, dict) and isinstance(finding.get("id"), str):
                    self.findings.append((path, finding, _actionable(finding)))
        analysis = result.get("package_analysis") or {}
        for issue in analysis.get("format_findings") or []:
            # Format findings carry severity error|warning, not a tier.
            if isinstance(issue, dict) and isinstance(issue.get("id"), str):
                self.findings.append((issue.get("path"), None, issue.get("severity") == "error", issue["id"]))
        governance = result.get("governance_profile") or {}
        behaviour = result.get("behavioral_summary") or {}
        self.capabilities = set(governance.get("policy_capabilities") or []) | set(behaviour.get("required_capabilities") or [])
        self.risk = (result.get("risk_classification") or {}).get("overall_risk")
        self.result_coverage = (result.get("coverage") or {}).get("status")

        self.data_classes = {}  # class -> {path: count}
        self.db_coverage = {}   # path -> status
        for entry in result.get("files") or []:
            profile = entry.get("database_profile") if isinstance(entry, dict) else None
            if not isinstance(profile, dict):
                continue
            path = entry.get("path")
            status = (profile.get("coverage") or {}).get("status")
            if isinstance(status, str):
                self.db_coverage[path] = status
            for table in profile.get("tables") or []:
                for column in (table.get("columns") or []) if isinstance(table, dict) else []:
                    for data_class in (column.get("data_classes") or []) if isinstance(column, dict) else []:
                        if isinstance(data_class, str):
                            bucket = self.data_classes.setdefault(data_class, {})
                            bucket[path] = bucket.get(path, 0) + 1
        for item in self.findings:
            if len(item) != 3:
                continue
            path, finding, _ = item
            classes = finding.get("data_classes")
            classes = classes if isinstance(classes, list) else FINDING_DATA_CLASSES.get(finding["id"], ())
            for data_class in classes:
                if isinstance(data_class, str):
                    bucket = self.data_classes.setdefault(data_class, {})
                    bucket[path] = bucket.get(path, 0) + 1

        self.hosts = {}  # host -> {path: count}
        graph = analysis.get("relationship_graph") or {}
        for reference in graph.get("external_references") or []:
            if isinstance(reference, dict):
                host = _origin_host(reference.get("url"))
                if host:
                    bucket = self.hosts.setdefault(host, {})
                    source = reference.get("source")
                    bucket[source] = bucket.get(source, 0) + 1
        overview = (result.get("process_diagram") or {}).get("overview") or {}
        self.connector_text = []  # (path, casefolded text)
        for system in overview.get("external_systems") or []:
            if not isinstance(system, dict):
                continue
            label = system.get("label")
            evidence = system.get("evidence") or [{}]
            path = evidence[0].get("path") if isinstance(evidence[0], dict) else None
            if system.get("kind") == "web":
                host = _origin_host(label) if isinstance(label, str) and "://" in label else (label.casefold() if isinstance(label, str) and "." in label and " " not in label else None)
                if host:
                    bucket = self.hosts.setdefault(host, {})
                    bucket[path] = bucket.get(path, 0) + 1
            elif system.get("kind") in {"tool", "mcp"} and isinstance(label, str):
                self.connector_text.append((path, label.casefold()))
        for permission in analysis.get("permissions") or []:
            if isinstance(permission, dict) and permission.get("allowed_tools"):
                self.connector_text.append((permission.get("path"), str(permission["allowed_tools"])[:4000].casefold()))

        # Frontmatter is removed from the returned result (it can hold secrets),
        # so field presence and compatibility are read from the scanned text.
        self.frontmatter = {}  # SKILL.md path -> set of present field names (top level and metadata)
        for skill in analysis.get("skills") or []:
            if isinstance(skill, dict) and isinstance(skill.get("path"), str):
                self.frontmatter[skill["path"]] = set((skill.get("metadata") or {}).keys())
        for source in text_sources or []:
            path = source.get("path") if isinstance(source, dict) else None
            if not isinstance(path, str) or PurePosixPath(path).name != "SKILL.md":
                continue
            fields = self.frontmatter.setdefault(path, set())
            try:
                data = frontmatter(source.get("text") or "")
            except ValueError:
                continue
            fields.update(str(key) for key in data)
            metadata = data.get("metadata")
            if isinstance(metadata, dict):
                fields.update(str(key) for key in metadata)
            for key in ("compatibility", "allowed-tools"):
                if data.get(key):
                    self.connector_text.append((path, str(data[key])[:4000].casefold()))
        self.texts_supplied = text_sources is not None


def _finding_items(facts):
    for item in facts.findings:
        if len(item) == 3:
            path, finding, actionable = item
            yield path, finding["id"], actionable, finding
        else:
            path, _, actionable, finding_id = item
            yield path, finding_id, actionable, None


def _evaluate(node, facts):
    """Return (triggered, evidence rows, matched finding dicts)."""
    key, value = next(iter(node.items()))
    if key in {"all", "any"}:
        results = [_evaluate(child, facts) for child in value]
        triggered = all(r[0] for r in results) if key == "all" else any(r[0] for r in results)
        if not triggered:
            return False, [], []
        chosen = [r for r in results if r[0]]
        return True, [row for r in chosen for row in r[1]], [f for r in chosen for f in r[2]]
    evidence, matched = [], []
    if key == "finding":
        ids = set(value["ids"])
        for path, finding_id, actionable, finding in _finding_items(facts):
            if finding_id in ids and (actionable or value["include_info"]):
                evidence.append({"path": path, "finding_id": finding_id, "count": 1})
                if finding is not None:
                    matched.append(finding)
    elif key == "capability":
        for capability in value:
            if capability not in facts.capabilities:
                continue
            related = CAPABILITY_FINDINGS.get(capability, set())
            rows = [{"path": path, "finding_id": fid, "count": 1} for path, fid, actionable, _ in _finding_items(facts)
                    if fid in related and actionable]
            evidence.extend(rows or [{"path": None, "finding_id": None, "count": 1, "signal": "capability:" + capability}])
    elif key == "data_class":
        for data_class in value:
            for path, count in sorted((facts.data_classes.get(data_class) or {}).items(), key=lambda kv: str(kv[0])):
                evidence.append({"path": path, "finding_id": None, "count": count, "signal": "data_class:" + data_class})
    elif key == "external_origin":
        for host in sorted(facts.hosts):
            hit = any(_host_matches(host, pattern) for pattern in value["patterns"])
            if hit == (value["mode"] == "matches"):
                for path, count in sorted(facts.hosts[host].items(), key=lambda kv: str(kv[0])):
                    evidence.append({"path": path, "finding_id": None, "count": count, "signal": "external_origin:" + host})
    elif key == "connector_mentioned":
        for name in value:
            for path, text in facts.connector_text:
                if name in text:
                    evidence.append({"path": path, "finding_id": None, "count": 1, "signal": "connector:" + name})
    elif key == "frontmatter_missing":
        skills = facts.frontmatter or {None: set()}
        for path in sorted(skills, key=str):
            for field in value:
                if field not in skills[path]:
                    evidence.append({"path": path, "finding_id": None, "count": 1, "signal": "frontmatter_missing:" + field})
    elif key == "risk_at_least":
        if facts.risk in RISK_LEVELS and RISK_LEVELS.index(facts.risk) >= RISK_LEVELS.index(value):
            evidence.append({"path": None, "finding_id": None, "count": 1, "signal": "overall_risk:" + facts.risk})
    elif key == "coverage":
        wanted = {"opaque"} if value == "opaque" else {"partial", "opaque"}
        for path, status in sorted(facts.db_coverage.items(), key=lambda kv: str(kv[0])):
            if status in wanted:
                evidence.append({"path": path, "finding_id": None, "count": 1, "signal": "database_coverage:" + status})
        coverage_findings = {"opaque_database"} if value == "opaque" else {"opaque_database", "database_not_cleared"}
        for path, finding_id, _, finding in _finding_items(facts):
            if finding_id in coverage_findings:
                evidence.append({"path": path, "finding_id": finding_id, "count": 1})
        if value == "partial" and facts.result_coverage == "partial":
            evidence.append({"path": None, "finding_id": None, "count": 1, "signal": "analysis_coverage:partial"})
    return bool(evidence), evidence, matched


def _merge_evidence(rows):
    merged = {}
    for row in rows:
        key = (row.get("path") or "", row.get("finding_id") or "", row.get("signal") or "")
        if key in merged:
            merged[key]["count"] += row.get("count", 1)
        else:
            merged[key] = dict(row)
    ordered = [merged[key] for key in sorted(merged)]
    for row in ordered:
        if row.get("signal") is None:
            row.pop("signal", None)
    return ordered


def _empty(status, *, policy=None, errors=(), warnings=()):
    return {"schema": RESULT_SCHEMA, "status": status, "policy": policy, "errors": list(errors),
            "warnings": list(warnings), "rules": [], "not_statically_checkable": [], "verification_notes": [],
            "effect_summary": {"block": 0, "require_approval": 0, "warn": 0, "allow": 0, "advisory_block": 0},
            "decision": "not_evaluated",
            "scope": "Static evaluation of the supplied organisation policy against this scan. It is not tenant "
                     "enforcement, legal advice or compliance certification; the scanner's own verdict is unchanged."}


def evaluate_policy(raw_policy, result, text_sources=None):
    """Build ``result["policy_evaluation"]``. Never raises for bad policy input."""
    if is_empty_policy(raw_policy):
        return _empty("none")
    parsed, digest, errors = parse_policy(raw_policy)
    policy_info = {"name": None, "organization": None, "sha256": digest}
    if errors:
        return _empty("invalid", policy=policy_info, errors=errors)
    if isinstance(parsed, dict):
        for key, out in (("policy_name", "name"), ("organization", "organization")):
            if isinstance(parsed.get(key), str):
                policy_info[out] = parsed[key][:200]
    policy, errors, warnings = validate_policy(parsed)
    if policy is None:
        return _empty("invalid", policy=policy_info, errors=errors, warnings=warnings)
    policy_info["compiled_date"] = policy["compiled_date"]

    facts = _Facts(result, text_sources)
    output = _empty("applied", policy=policy_info, warnings=warnings)
    output["not_statically_checkable"] = policy["not_statically_checkable"]
    output["verification_notes"] = policy["verification_notes"]
    summary = output["effect_summary"]
    for rule in policy["rules"]:
        triggered, evidence, matched = _evaluate(rule["when"], facts)
        evidence = _merge_evidence(evidence)
        effective = rule["effect"]
        if rule["effect"] == "block" and rule["enforcement"] == "advisory":
            effective = "advisory_block"
        row = {"id": rule["id"], "title": rule["title"], "effect": rule["effect"], "enforcement": rule["enforcement"],
               "approver": rule["approver"], "triggered": triggered, "evidence": evidence[:MAX_EVIDENCE],
               "effective_effect": effective if triggered else None, "source": rule["source"],
               "section": rule["section"], "requirement": rule["requirement"], "rationale": rule["rationale"]}
        if len(evidence) > MAX_EVIDENCE:
            row["evidence_omitted"] = len(evidence) - MAX_EVIDENCE
        output["rules"].append(row)
        if not triggered:
            continue
        summary[effective] += 1
        if rule["effect"] == "allow":
            for finding in matched:
                # The finding stays in place with its tier and severity.
                if finding.get("policy_disposition") != "allowed_by_policy":
                    finding["policy_disposition"] = "allowed_by_policy"
                    finding["policy_rule"] = rule["id"]
    output["decision"] = ("block" if summary["block"] else "require_approval" if summary["require_approval"]
                          else "warn" if summary["warn"] or summary["advisory_block"]
                          else "allow" if summary["allow"] else "no_rule_triggered")
    if not facts.texts_supplied:
        output["limits"] = ["Scanned text was not supplied; frontmatter fields and compatibility were read from the result only."]
    return output
