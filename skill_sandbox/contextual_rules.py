from __future__ import annotations

import re
import json
from bisect import bisect_right
from pathlib import Path
from typing import Dict, Iterable, List

if __package__:
    from .scan_rules import load_rule_catalog
else:
    from scan_rules import load_rule_catalog


CONTEXTUAL_RULE_IDS = {
    "secret_exfiltration",
    "tool_escape",
    "autonomous_authoritative_write",
    "bulk_enterprise_modification",
    "workflow_manipulation",
    "cross_system_automation",
}

MARKDOWN_LIKE_EXTENSIONS = (".md", ".skill", ".txt")
SENTENCE_SPLIT_REGEX = re.compile(r"(?<=[.!?])\s+|;\s+")
LEADING_MARKUP_REGEX = re.compile(r"^[#>*\-\d.\s`|]+")

DISCLOSURE_VERB_REGEX = re.compile(
    r"\b(show|reveal|dump|return|expose|output|extract|leak|disclose|send|share|display|print|read|fetch)\b",
    re.IGNORECASE,
)
HIGH_CONFIDENCE_DISCLOSURE_VERB_REGEX = re.compile(
    r"\b(show|reveal|dump|return|expose|output|extract|leak|disclose|send|share)\b",
    re.IGNORECASE,
)
SECRET_TARGET_REGEX = re.compile(
    r"\b(api\s*key|access\s+token|bearer\s+token|password|credential|secret|access\s+key|private\s+key|ssh\s+key|pem)\b",
    re.IGNORECASE,
)
POLICY_SECRET_CONTEXT_REGEX = re.compile(
    r"\b(confidential(?:ity| information)?|trade\s+secrets?|proprietary\s+information|non-public information)\b",
    re.IGNORECASE,
)
AUTHENTICATION_CONTEXT_REGEX = re.compile(
    r"\b(temporary|initial|your|my|change|reset|enter|login|log in|sign in|username|single sign-on|sso)\b",
    re.IGNORECASE,
)
SAFE_SECRET_DISCUSSION_REGEX = re.compile(
    r"\b(token\s+lifecycle|credential\s+exposure|key\s+management|risk\s+statements?|control\s+gap|governance\s+artifacts?|threat\s+model(?:ing)?|security\s+architecture|best\s+practices?)\b",
    re.IGNORECASE,
)
NEGATED_DISCLOSURE_REGEX = re.compile(
    r"\b(do\s+not|don't|never|must\s+not|should\s+not|not\s+allowed\s+to)\b",
    re.IGNORECASE,
)

EXECUTION_VERB_REGEX = re.compile(r"\b(run|execute|launch|invoke|use|open)\b", re.IGNORECASE)
EXECUTION_CONTEXT_REGEX = re.compile(
    r"\b(shell|terminal|powershell|bash|cmd(?:\.exe)?|python|docker|script|command)\b",
    re.IGNORECASE,
)
STRONG_EXECUTION_CONTEXT_REGEX = re.compile(
    r"\b(shell|terminal|powershell|bash|cmd(?:\.exe)?|python|docker)\b",
    re.IGNORECASE,
)
EXECUTION_FALSE_POSITIVE_REGEX = re.compile(
    r"\b(open communication|open to feedback|open enrollment|open house|office space|program/script/command)\b",
    re.IGNORECASE,
)

ENTERPRISE_SERVICE_REGEX = re.compile(
    r"\b(jira|confluence|servicenow|github|gitlab|salesforce|sharepoint)\b",
    re.IGNORECASE,
)
ENTERPRISE_MUTATION_REGEX = re.compile(
    r"\b(create|update|modify|delete|transition|comment|worklog|close|reassign|merge|approve|write)\b",
    re.IGNORECASE,
)
ENTERPRISE_AUTONOMY_REGEX = re.compile(
    r"\b(autonom(?:ous|ously)|automatic(?:ally)?|when\s+triggered|without\s+human\s+review|single\s+command|will\s+(?:create|update|modify|delete|transition|comment|worklog|close|reassign|merge|approve))\b",
    re.IGNORECASE,
)
ENTERPRISE_BULK_REGEX = re.compile(
    r"\b(batch|bulk|mass\s+update|multiple|all\s+issues|every\s+issue|entire\s+project|across\s+all)\b",
    re.IGNORECASE,
)
ENTERPRISE_AUTHORITY_REGEX = re.compile(
    r"\b(systems?\s+of\s+record|authoritative\s+systems?|authoritative\s+data)\b",
    re.IGNORECASE,
)
WORKFLOW_ACTION_REGEX = re.compile(
    r"\b(transition|workflow|status\s+change|move\s+to\s+done|reopen|close\s+ticket|change\s+assignee|add\s+watchers?|approve|merge)\b",
    re.IGNORECASE,
)
SYNC_ACTION_REGEX = re.compile(
    r"\b(sync|synchronize|mirror|propagate|copy|write\s+back|push\s+updates|create\s+records\s+in\s+both|cross-system)\b",
    re.IGNORECASE,
)


def detect_contextual_findings(
    path: str,
    text: str,
    artifact_role: str,
    build_finding,
) -> List[Dict[str, object]]:
    units = _iter_context_units(path, text, artifact_role)
    if not units:
        return []

    catalog = {rule["id"]: rule for rule in load_rule_catalog().get("rules", [])}
    findings: List[Dict[str, object]] = []

    matches = _match_secret_exfiltration(units, artifact_role)
    if matches:
        findings.append(build_finding(catalog["secret_exfiltration"], matches, artifact_role))

    matches = _match_tool_escape(units, artifact_role)
    if matches:
        findings.append(build_finding(catalog["tool_escape"], matches, artifact_role))

    matches = _match_autonomous_authoritative_write(units)
    if matches:
        findings.append(build_finding(catalog["autonomous_authoritative_write"], matches, artifact_role))

    matches = _match_bulk_enterprise_modification(units)
    if matches:
        findings.append(build_finding(catalog["bulk_enterprise_modification"], matches, artifact_role))

    matches = _match_workflow_manipulation(units)
    if matches:
        findings.append(build_finding(catalog["workflow_manipulation"], matches, artifact_role))

    matches = _match_cross_system_automation(units)
    if matches:
        findings.append(build_finding(catalog["cross_system_automation"], matches, artifact_role))

    return findings


def _match_secret_exfiltration(units: Iterable[Dict[str, object]], artifact_role: str) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    reference_like = artifact_role in {"reference", "reference_template"}

    for unit in units:
        text = str(unit.get("text", ""))
        line = unit.get("line") if isinstance(unit.get("line"), int) else None
        target_match = SECRET_TARGET_REGEX.search(text)
        if not target_match:
            continue

        if POLICY_SECRET_CONTEXT_REGEX.search(text):
            continue

        if SAFE_SECRET_DISCUSSION_REGEX.search(text):
            matches.append(
                {
                    "text": text,
                    "line": line,
                    "context_tag": "topic_discussion",
                    "confidence": "medium",
                }
            )
            continue

        if target_match.group(0).lower() == "password" and AUTHENTICATION_CONTEXT_REGEX.search(text):
            continue

        if reference_like:
            verb_match = HIGH_CONFIDENCE_DISCLOSURE_VERB_REGEX.search(text)
        else:
            verb_match = DISCLOSURE_VERB_REGEX.search(text)

        if not verb_match:
            continue

        following_target = SECRET_TARGET_REGEX.search(text, verb_match.end())
        reverse_link = text[target_match.end():verb_match.start()] if target_match.end() <= verb_match.start() else None
        if following_target and following_target.start() - verb_match.end() <= 100:
            target_match = following_target
        elif reverse_link is None or not re.fullmatch(r"\s*(?:(?:must|should|will|can)\s+(?:be\s+)?)?[:,]?\s*", reverse_link, re.I):
            continue
        sample = _source_span(text, verb_match, target_match)
        context_tag = "topic_discussion" if NEGATED_DISCLOSURE_REGEX.search(text) else "imperative_disclosure"
        if not any(match["text"] == sample and match.get("line") == line for match in matches):
            matches.append(
                {
                    "text": sample,
                    "line": line,
                    "context_tag": "test_fixture" if unit.get("test_fixture") else context_tag,
                    "confidence": "high" if context_tag == "imperative_disclosure" else "medium",
                }
            )
        if len(matches) >= 3:
            break

    return matches


def _match_tool_escape(units: Iterable[Dict[str, object]], artifact_role: str) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    reference_like = artifact_role in {"reference", "reference_template"}

    for unit in units:
        text = str(unit.get("text", ""))
        line = unit.get("line") if isinstance(unit.get("line"), int) else None
        if EXECUTION_FALSE_POSITIVE_REGEX.search(text):
            continue

        verb_match = EXECUTION_VERB_REGEX.search(text)
        context_match = EXECUTION_CONTEXT_REGEX.search(text)
        if not verb_match or not context_match:
            continue

        if not _are_matches_close(verb_match, context_match, 48):
            continue

        if reference_like and not STRONG_EXECUTION_CONTEXT_REGEX.search(text):
            continue

        sample = _source_span(text, verb_match, context_match)
        if not any(match["text"] == sample and match.get("line") == line for match in matches):
            matches.append(
                {
                    "text": sample,
                    "line": line,
                    "context_tag": "pattern_match",
                    "confidence": "medium",
                }
            )
        if len(matches) >= 3:
            break

    return matches


def _match_autonomous_authoritative_write(units: Iterable[str]) -> List[str]:
    return _match_enterprise_rule(
        units,
        required_patterns=(
            ENTERPRISE_SERVICE_REGEX,
            ENTERPRISE_MUTATION_REGEX,
            ENTERPRISE_AUTONOMY_REGEX,
            ENTERPRISE_AUTHORITY_REGEX,
        ),
    )


def _match_bulk_enterprise_modification(units: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    return _match_enterprise_rule(
        units,
        required_patterns=(
            ENTERPRISE_SERVICE_REGEX,
            ENTERPRISE_MUTATION_REGEX,
            ENTERPRISE_BULK_REGEX,
            ENTERPRISE_AUTONOMY_REGEX,
        ),
    )


def _match_workflow_manipulation(units: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    return _match_enterprise_rule(
        units,
        required_patterns=(
            ENTERPRISE_SERVICE_REGEX,
            WORKFLOW_ACTION_REGEX,
            ENTERPRISE_AUTONOMY_REGEX,
        ),
    )


def _match_cross_system_automation(units: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    for unit in units:
        text = _enterprise_action_text(str(unit.get("text", "")))
        line = unit.get("line") if isinstance(unit.get("line"), int) else None
        services = [match for match in ENTERPRISE_SERVICE_REGEX.finditer(text)]
        if len({service.group(0).lower() for service in services}) < 2:
            continue
        sync_match = SYNC_ACTION_REGEX.search(text)
        autonomy_match = ENTERPRISE_AUTONOMY_REGEX.search(text)
        if not sync_match or not autonomy_match:
            continue

        evidence = services + [sync_match, autonomy_match]
        sample = text[min(m.start() for m in evidence):max(m.end() for m in evidence)].strip()
        if not any(match["text"] == sample and match.get("line") == line for match in matches):
            matches.append(
                {
                    "text": sample,
                    "line": line,
                    "context_tag": "test_fixture" if unit.get("test_fixture") else "pattern_match",
                    "confidence": "medium",
                }
            )
        if len(matches) >= 3:
            break

    return matches


def _match_enterprise_rule(
    units: Iterable[Dict[str, object]],
    required_patterns: Iterable[re.Pattern[str]],
) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []

    for unit in units:
        text = _enterprise_action_text(str(unit.get("text", "")))
        line = unit.get("line") if isinstance(unit.get("line"), int) else None
        unit_matches = [pattern.search(text) for pattern in required_patterns]
        if not all(unit_matches):
            continue

        sample = text[min(m.start() for m in unit_matches):max(m.end() for m in unit_matches)].strip()
        if not any(match["text"] == sample and match.get("line") == line for match in matches):
            matches.append(
                {
                    "text": sample,
                    "line": line,
                    "context_tag": "test_fixture" if unit.get("test_fixture") else "pattern_match",
                    "confidence": "medium",
                }
            )
        if len(matches) >= 3:
            break

    return matches


def _enterprise_action_text(text: str) -> str:
    # Offering a UI step is different from executing the step. Remove only the
    # offer/autonomy phrase; independent execution instructions remain visible.
    offer = r"(?:offer(?:ed)?|suggest(?:ed)?|propos(?:e|ed)|present(?:ed)?|recommend(?:ed)?)"
    text = re.sub(rf"\b{offer}\s+automatically\b|\bautomatically\s+{offer}\b", "", text, flags=re.I)
    return text


def _json_context_units(path: str, text: str) -> List[Dict[str, object]]:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    try:
        data = json.loads(text, object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        # Invalid JSON is still scanned, with line boundaries rather than a
        # synthetic whole-file sentence that combines unrelated instructions.
        return [{"text": line, "line": n} for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    newline_positions = [i for i, char in enumerate(text) if char == "\n"]
    units = []
    cursor = 0
    evaluation_file = "evals" in Path(path.replace("\\", "/")).parts
    assertion_types = {"tool_call_forbidden", "tool_call_requires_precondition", "content_diff_forbidden", "scope_check"}
    def walk(value, fixture=False, depth=0):
        nonlocal cursor
        if depth > 64:
            raise ValueError("JSON nesting exceeds context budget")
        if isinstance(value, dict):
            assertion = value.get("assertion")
            test_case = evaluation_file and isinstance(value.get("trigger_prompt"), str) and isinstance(assertion, dict) and assertion.get("type") in assertion_types
            for key, item in value.items():
                # Keys are also untrusted strings; do not hide instructions there.
                walk(key, fixture, depth+1)
                walk(item, fixture or (test_case and key in {"trigger_prompt", "assertion"}), depth+1)
        elif isinstance(value, list):
            for item in value:
                walk(item, fixture, depth+1)
        elif isinstance(value, str):
            tokens = [json.dumps(value, ensure_ascii=False), json.dumps(value, ensure_ascii=True)]
            positions = [(text.find(token, cursor), len(token)) for token in tokens]
            positions = [(position, length) for position, length in positions if position >= 0]
            position, length = min(positions) if positions else (cursor, 0)
            line = bisect_right(newline_positions, position)+1 if positions else None
            cursor = position + length
            # Do not combine independent scalar values or separate test cases.
            for segment in SENTENCE_SPLIT_REGEX.split(value):
                if segment.strip():
                    units.append({"text": segment.strip(), "line": line, "test_fixture": fixture})
    try:
        walk(data)
    except ValueError:
        return [{"text": line, "line": n} for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    return units


def _iter_context_units(path: str, text: str, artifact_role: str) -> List[Dict[str, object]]:
    lower_path = Path(path.lower()).suffix
    if lower_path == ".json":
        return _json_context_units(path, text)
    if lower_path == ".csv":
        return [
            {"text": line.strip(), "line": index}
            for index, line in enumerate(text.splitlines(), start=1)
            if line.strip()
        ]

    if lower_path in MARKDOWN_LIKE_EXTENSIONS:
        base_units = _markdown_context_units(text)
        if artifact_role == "active":
            return _with_active_windows(base_units)
        return base_units

    return [{"text": text, "line": 1}]


def _markdown_context_units(text: str) -> List[Dict[str, object]]:
    units: List[Dict[str, object]] = []

    current_lines: List[tuple[int, str]] = []
    paragraphs: List[List[tuple[int, str]]] = []
    for index, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            if current_lines:
                paragraphs.append(current_lines)
                current_lines = []
            continue
        current_lines.append((index, line))
    if current_lines:
        paragraphs.append(current_lines)

    for paragraph_id, paragraph in enumerate(paragraphs):
        stripped = "\n".join(line for _, line in paragraph).strip()
        if not stripped:
            continue

        lines = [(line_number, line.strip()) for line_number, line in paragraph if line.strip()]
        for line_number, line in lines:
            cleaned = _clean_markdown_text(line)
            if not cleaned:
                continue
            segments = [segment for segment in SENTENCE_SPLIT_REGEX.split(cleaned) if segment.strip()]
            if not segments:
                segments = [cleaned]
            for segment in segments:
                normalized = re.sub(r"\s+", " ", segment).strip()
                if normalized:
                    units.append({"text": normalized, "line": line_number, "paragraph": paragraph_id,
                                  "context_boundary": bool(re.match(r"^ {0,3}(?:#{1,6}\s|`{3,}|~{3,})", line))})

    return _unique(units)


def _with_active_windows(units: List[Dict[str, object]]) -> List[Dict[str, object]]:
    expanded = list(units)
    for index in range(len(units) - 1):
        left, right = units[index], units[index + 1]
        if (left.get("paragraph") != right.get("paragraph")
                or left.get("context_boundary") or right.get("context_boundary")
                or right.get("line", 0) - left.get("line", 0) > 1):
            continue
        combined = f"{units[index]['text']} {units[index + 1]['text']}"
        expanded.append({"text": combined, "line": units[index].get("line")})
    return _unique(expanded)


def _clean_markdown_text(text: str) -> str:
    text = LEADING_MARKUP_REGEX.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def _are_matches_close(left: re.Match[str], right: re.Match[str], max_gap: int) -> bool:
    if left.start() <= right.start():
        gap = right.start() - left.end()
    else:
        gap = left.start() - right.end()
    return gap <= max_gap


def _source_span(text: str, left: re.Match[str], right: re.Match[str]) -> str:
    start = min(left.start(), right.start())
    end = max(left.end(), right.end())
    return text[start:end].strip()


def _unique(values: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    seen = set()
    output = []
    for value in values:
        key = (str(value.get("text", "")).lower(), value.get("line"))
        if key in seen:
            continue
        seen.add(key)
        output.append(value)
    return output
