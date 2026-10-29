from __future__ import annotations

import re
import json
from bisect import bisect_right
from pathlib import Path
from typing import Dict, Iterable, List

if __package__:
    from .scan_rules import load_rule_catalog, _disclosure_clauses, _disclosure_context_tag, DISCLOSURE_VERBS
    from .speech_acts import annotate_observation_facts, prepare_observation_context, observation_fact_priority
else:
    from scan_rules import load_rule_catalog, _disclosure_clauses, _disclosure_context_tag, DISCLOSURE_VERBS
    from speech_acts import annotate_observation_facts, prepare_observation_context, observation_fact_priority


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
    r"\b(?:" + DISCLOSURE_VERBS + r")\b",
    re.IGNORECASE,
)
HIGH_CONFIDENCE_DISCLOSURE_VERB_REGEX = re.compile(
    r"\b(?:" + DISCLOSURE_VERBS + r")\b",
    re.IGNORECASE,
)
SECRET_TARGET_REGEX = re.compile(
    r"\b(api\s*key|access\s+token|bearer\s+token|passwords?|credentials?|secrets?|access\s+key|private\s+key|ssh\s+key|pem|env(?:ironment)?\s+(?:vars?|variables))\b",
    re.IGNORECASE,
)
SAFE_SECRET_DISCUSSION_REGEX = re.compile(
    r"\b(token\s+lifecycle|credential\s+exposure|key\s+management|risk\s+statements?|control\s+gap|governance\s+artifacts?|threat\s+model(?:ing)?|security\s+architecture|best\s+practices?)\b",
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
    def units():
        return _iter_context_units(path, text, artifact_role)

    catalog = {rule["id"]: rule for rule in load_rule_catalog().get("rules", [])}
    findings: List[Dict[str, object]] = []

    matches = _match_secret_exfiltration(units(), artifact_role, text)
    if matches:
        findings.append(build_finding(catalog["secret_exfiltration"], matches, artifact_role))

    matches = _match_tool_escape(units(), artifact_role)
    if matches:
        escape = [item for item in matches if item["context_tag"] == "boundary_escape_instruction"]
        invocation = [item for item in matches if item["context_tag"] != "boundary_escape_instruction"]
        if escape:
            findings.append(build_finding(catalog["tool_escape"], escape, "active"))
        if invocation:
            capability_rule = {**catalog["tool_escape"], "id": "declared_tool_execution",
                               "description": "Declares shell, interpreter or script invocation; execution and boundary escape are not established.",
                               "finding_category": "capability_observation", "subject": "code_execution",
                               "action_state": "declared"}
            findings.append(build_finding(capability_rule, invocation, "active"))

    matches = _match_autonomous_authoritative_write(units(), text)
    if matches:
        findings.append(build_finding(catalog["autonomous_authoritative_write"], matches, artifact_role))

    matches = _match_bulk_enterprise_modification(units(), text)
    if matches:
        findings.append(build_finding(catalog["bulk_enterprise_modification"], matches, artifact_role))

    matches = _match_workflow_manipulation(units(), text)
    if matches:
        findings.append(build_finding(catalog["workflow_manipulation"], matches, artifact_role))

    matches = _match_cross_system_automation(units(), text)
    if matches:
        findings.append(build_finding(catalog["cross_system_automation"], matches, artifact_role))

    return findings


def _match_secret_exfiltration(units: Iterable[Dict[str, object]], artifact_role: str, source_text=None) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    reference_like = artifact_role in {"reference", "reference_template"}
    prepared_context = None
    for unit in units:
        line = unit.get("line") if isinstance(unit.get("line"), int) else None
        for text in _disclosure_clauses(str(unit.get("text", ""))):
            target_match = SECRET_TARGET_REGEX.search(text)
            if not target_match:
                continue
            verbs = HIGH_CONFIDENCE_DISCLOSURE_VERB_REGEX if reference_like else DISCLOSURE_VERB_REGEX
            linked_action = False
            for verb_match in verbs.finditer(text):
                following_target = SECRET_TARGET_REGEX.search(text, verb_match.end())
                reverse_link = text[target_match.end():verb_match.start()] if target_match.end() <= verb_match.start() else None
                subject_predicate = False
                if following_target and following_target.start() - verb_match.end() <= 100:
                    linked_target = following_target
                elif reverse_link is not None and re.fullmatch(r"\s*(?:(?:must|should|shall|will|needs?\s+to)\s+be\s+|is\s+|[:,]\s*)", reverse_link, re.I):
                    linked_target = target_match
                elif reverse_link is not None and not reverse_link.strip():
                    # Subject + predicate ("credentials show expired") is a
                    # detectable mention, not an object-directed disclosure.
                    linked_target, subject_predicate = target_match, True
                else:
                    continue
                # A topic phrase elsewhere in this clause cannot exempt a direct
                # disclosure request. Summaries/evidence about credentials remain
                # topic observations when the verb is not directed at the secret.
                gap = text[verb_match.end():linked_target.start()] if following_target else ""
                discussion = verb_match.group(0).lower() in {"return", "output", "show", "display"} and bool(re.search(
                    r"\b(?:summary|report|analysis|evidence|statements?)\b[^.;!?]{0,30}\b(?:about|of|on)\s*$", gap, re.I)) and bool(re.match(
                    r"(?:credential\s+exposure|token\s+lifecycle|key\s+management)\b", text[linked_target.start():], re.I))
                # A secret-qualified policy topic is not the secret value itself.
                # Retain the complete clause as evidence; explicit value/content
                # requests and independent later actions keep their own context.
                topic_object = bool(re.match(
                    r"\s+(?:storage|transmission|rotation|management|lifecycle|changing|complexity|aging|requirements?|polic(?:y|ies)|protection|controls?|hygiene|exposure|handling|security|practices|guidance|configuration)\b",
                    text[linked_target.end():], re.I)) and not re.search(
                    r"\b(?:values?|contents?|plaintext|unredacted)\b", text[linked_target.end():], re.I)
                context = ("descriptive_security_language" if subject_predicate else
                           "topic_discussion" if discussion or topic_object else _disclosure_context_tag(text[:verb_match.end()]))
                if unit.get("activated_quote") and context == "quoted_or_fenced":
                    context = "imperative_disclosure"
                if unit.get("attack_catalog") and _is_catalog_description(text):
                    context = "documented_attack_pattern"
                sample = text if context in {"descriptive_security_language", "documented_attack_pattern", "ambiguous_disclosure", "topic_discussion"} else _source_span(text, verb_match, linked_target)
                observation = {"text": sample, "line": line,
                               "context_tag": "test_fixture" if unit.get("test_fixture") else context,
                               "confidence": "high" if context == "imperative_disclosure" else "medium",
                               "candidate_context": text[:verb_match.end()][-1024:],
                               "structured_value": bool(unit.get("structured_value")), "fixture_id": unit.get("fixture_id"), "line_end": unit.get("line_end"), "context_limit": unit.get("context_limit")}
                if source_text is not None:
                    if prepared_context is None:
                        prepared_context = prepare_observation_context(source_text)
                    observation = annotate_observation_facts("secret_exfiltration", [observation], prepared_context=prepared_context)[0]
                if observation not in matches:
                    matches.append(observation)
                linked_action = True
            if not linked_action and SAFE_SECRET_DISCUSSION_REGEX.search(text):
                observation = {"text": text, "line": line, "context_tag": "topic_discussion", "confidence": "medium"}
                if observation not in matches:
                    matches.append(observation)
            # Keep the strongest evidence even after many benign observations.
            matches.sort(key=lambda item: observation_fact_priority(item) if item.get("speech_act") else {"imperative_disclosure": 0, "ambiguous_disclosure": 1, "test_fixture": 2}.get(item["context_tag"], 3))
            del matches[3:]
    return matches


def _match_tool_escape(units: Iterable[Dict[str, object]], artifact_role: str) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    for unit in units:
        text = str(unit.get("text", ""))
        line = unit.get("line") if isinstance(unit.get("line"), int) else None
        for verb_match in EXECUTION_VERB_REGEX.finditer(text):
            # Execution requires a verb governing the tool/command, rather than
            # arbitrary proximity to a Python/SDK mention earlier in the line.
            following = text[verb_match.end():]
            invocation = re.match(
                r"\s+(?:(?:the|a|an|this|that|packaged|bundled|extraction)\s+){0,3}"
                r"(?P<tool>shell|terminal|powershell|bash|cmd(?:\.exe)?|python(?:3)?|docker|script|command)\b", following, re.I)
            if not invocation:
                continue
            tool = invocation["tool"].lower()
            rest = following[invocation.end():]
            if tool == "python" and re.match(r"(?:-pptx|\s+(?:SDK|API|documentation|reference))\b", rest, re.I):
                continue
            if re.search(r"\b(?:do\s+not|don't|never|must\s+not|cannot|can't)\s*$", text[:verb_match.start()], re.I):
                continue
            boundary = bool(re.search(r"\b(?:escape|bypass|outside|disable)\b[^.;!?]{0,60}\b(?:sandbox|restriction|isolation|policy|permission|boundary)\b", text, re.I))
            sample = text if boundary else text[verb_match.start():verb_match.end()+invocation.end()].strip()
            observation = {"text": sample, "line": line,
                           "context_tag": "boundary_escape_instruction" if boundary else "execution_capability",
                           "confidence": "medium"}
            if observation not in matches:
                matches.append(observation)
        # Retain explicit escape instructions before the bounded capability list.
        matches.sort(key=lambda item: item["context_tag"] != "boundary_escape_instruction")
        del matches[3:]
    return matches


def _is_catalog_description(text):
    # A locally structured attack/control catalog can document an adversary
    # action. Agent addressing, live outputs, destinations and imperative
    # control phrases override that context even inside the same catalog.
    if re.search(r"\b(?:assistant|agent|you|your|operator|please|now|must|shall|should|ignore|override|response|output|send|share|reveal|show|print|return|display|current|live|actual|runtime|session|save|paste|upload|write|store|persist|collect|copy|dump)\b|https?://|[~`]|/\w", text, re.I):
        return False
    if re.search(r"\b(?:to|into|in)\s+(?:(?:a|an|the|this|that)\s+)?(?:file|response|message|payload|report|log|database|endpoint|url)\b", text, re.I):
        return False
    return bool(re.match(r"(?:extract\b|(?:compromised|attacker|adversary|malware)\b)", text, re.I))


def _match_autonomous_authoritative_write(units: Iterable[str], source_text=None) -> List[str]:
    return _match_enterprise_rule(
        units,
        detector_id="autonomous_authoritative_write", source_text=source_text,
        required_patterns=(
            ENTERPRISE_SERVICE_REGEX,
            ENTERPRISE_MUTATION_REGEX,
            ENTERPRISE_AUTONOMY_REGEX,
            ENTERPRISE_AUTHORITY_REGEX,
        ),
    )


def _match_bulk_enterprise_modification(units: Iterable[Dict[str, object]], source_text=None) -> List[Dict[str, object]]:
    return _match_enterprise_rule(
        units,
        detector_id="bulk_enterprise_modification", source_text=source_text,
        required_patterns=(
            ENTERPRISE_SERVICE_REGEX,
            ENTERPRISE_MUTATION_REGEX,
            ENTERPRISE_BULK_REGEX,
            ENTERPRISE_AUTONOMY_REGEX,
        ),
    )


def _match_workflow_manipulation(units: Iterable[Dict[str, object]], source_text=None) -> List[Dict[str, object]]:
    return _match_enterprise_rule(
        units,
        detector_id="workflow_manipulation", source_text=source_text,
        required_patterns=(
            ENTERPRISE_SERVICE_REGEX,
            WORKFLOW_ACTION_REGEX,
            ENTERPRISE_AUTONOMY_REGEX,
        ),
    )


def _match_cross_system_automation(units: Iterable[Dict[str, object]], source_text=None) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    prepared_context = None
    detector_id = "cross_system_automation"
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
            observation = {"text": sample, "line": line,
                           "context_tag": "test_fixture" if unit.get("test_fixture") else "pattern_match",
                           "confidence": "medium", "candidate_context": text[:1024],
                           "structured_value": bool(unit.get("structured_value")), "fixture_id": unit.get("fixture_id"), "line_end": unit.get("line_end"), "context_limit": unit.get("context_limit")}
            if source_text is not None:
                if prepared_context is None:
                    prepared_context = prepare_observation_context(source_text)
                observation = annotate_observation_facts(detector_id, [observation], prepared_context=prepared_context)[0]
            matches.append(observation)
        matches.sort(key=observation_fact_priority)
        del matches[3:]

    return matches


def _match_enterprise_rule(
    units: Iterable[Dict[str, object]],
    required_patterns: Iterable[re.Pattern[str]],
    *, detector_id, source_text=None,
) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    prepared_context = None

    for unit in units:
        text = _enterprise_action_text(str(unit.get("text", "")))
        line = unit.get("line") if isinstance(unit.get("line"), int) else None
        unit_matches = [pattern.search(text) for pattern in required_patterns]
        if not all(unit_matches):
            continue

        sample = text[min(m.start() for m in unit_matches):max(m.end() for m in unit_matches)].strip()
        if not any(match["text"] == sample and match.get("line") == line for match in matches):
            observation = {"text": sample, "line": line,
                           "context_tag": "test_fixture" if unit.get("test_fixture") else "pattern_match",
                           "confidence": "medium", "candidate_context": text[:1024],
                           "structured_value": bool(unit.get("structured_value")), "fixture_id": unit.get("fixture_id"), "line_end": unit.get("line_end"), "context_limit": unit.get("context_limit")}
            if source_text is not None:
                if prepared_context is None:
                    prepared_context = prepare_observation_context(source_text)
                observation = annotate_observation_facts(detector_id, [observation], prepared_context=prepared_context)[0]
            matches.append(observation)
        matches.sort(key=observation_fact_priority)
        del matches[3:]

    return matches


def _enterprise_action_text(text: str) -> str:
    # Offering a UI step is different from executing the step. Remove only the
    # offer/autonomy phrase; independent execution instructions remain visible.
    offer = r"(?:offer(?:ed)?|suggest(?:ed)?|propos(?:e|ed)|present(?:ed)?|recommend(?:ed)?)"
    text = re.sub(rf"\b{offer}\s+automatically\b|\bautomatically\s+{offer}\b", "", text, flags=re.I)
    return text


def _json_fallback_units(text):
    # A failed/duplicate-key object must not discard earlier string values.
    # Tokenize complete JSON strings as data without claiming a valid object;
    # keep raw lines too so malformed unquoted instructions remain inspectable.
    newlines = [index for index, char in enumerate(text) if char == "\n"]
    units = []
    for match in re.finditer(r'"(?:\\.|[^"\\])*"', text):
        try:
            value = json.loads(match.group(0))
        except ValueError:
            continue
        if value.strip():
            units.append({"text": value, "line": bisect_right(newlines, match.start())+1,
                          "structured_value": True})
    units.extend({"text": line, "line": n, "structured_value": True}
                 for n, line in enumerate(text.splitlines(), 1) if line.strip())
    return units


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
        return _json_fallback_units(text)
    newline_positions = [i for i, char in enumerate(text) if char == "\n"]
    units = []
    cursor = 0
    assertion_types = {"tool_call_forbidden", "tool_call_requires_precondition", "content_diff_forbidden", "scope_check"}
    assertion_fields = {"description", "expected", "expected_result", "tool_name", "precondition", "condition"}
    fixture_counter = 0
    def walk(value, fixture=False, depth=0, assertion_scope=False, fixture_id=None):
        nonlocal cursor, fixture_counter
        if depth > 64:
            raise ValueError("JSON nesting exceeds context budget")
        if isinstance(value, dict):
            assertion = value.get("assertion")
            test_case = isinstance(value.get("trigger_prompt"), str) and isinstance(assertion, dict) and assertion.get("type") in assertion_types
            if test_case:
                fixture_counter += 1
                fixture_id = fixture_counter
            for key, item in value.items():
                # Keys are also untrusted strings; do not hide instructions there.
                walk(key, False, depth+1)
                if test_case and key == "assertion":
                    walk(item, False, depth+1, assertion_scope=True, fixture_id=fixture_id)
                else:
                    child_fixture = (test_case and key == "trigger_prompt" and isinstance(item, str)) or (assertion_scope and key in assertion_fields and isinstance(item, str))
                    walk(item, child_fixture, depth+1, fixture_id=fixture_id if child_fixture else None)
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
                    units.append({"text": segment.strip(), "line": line, "test_fixture": fixture, "structured_value": True, "fixture_id": fixture_id if fixture else None})
    try:
        walk(data)
    except ValueError:
        return _json_fallback_units(text)
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
        return _with_active_windows(base_units)

    return [{"text": text, "line": 1}]


def _markdown_context_units(text):
    """Stream participating lines; do not allocate one dict per input line."""
    source_lines = text.splitlines()
    # A target/service/tool anchor plus its adjacent physical lines preserves
    # the existing two-line continuation contract. Bare pronouns and unrelated
    # prose cannot participate in any contextual detector.
    anchor = re.compile("|".join((SECRET_TARGET_REGEX.pattern, EXECUTION_CONTEXT_REGEX.pattern,
                                  ENTERPRISE_SERVICE_REGEX.pattern, WORKFLOW_ACTION_REGEX.pattern,
                                  SYNC_ACTION_REGEX.pattern, ENTERPRISE_AUTHORITY_REGEX.pattern)), re.I)
    relevant = [bool(anchor.search(line)) for line in source_lines]

    def paragraph_units(start, end, paragraph_id):
        stripped = "\n".join(source_lines[start:end]).strip()
        activated_quote = _activates_quoted_request(stripped)
        # A syntactic condition governs its own contiguous list, not arbitrary
        # neighboring prose or metadata. Keep the declared order and source
        # range; runtime triggering, permissions and approval remain unverified.
        for header in range(start, end):
            heading = source_lines[header].strip()
            if not re.fullmatch(r"(?:When|If)\b[^:]{0,160}\b(?:Claude|ChatGPT|the\s+assistant|this\s+assistant|the\s+agent|this\s+agent|the\s+model|this\s+model)\s+(?:will|must|shall)\s*:", heading, re.I):
                continue
            items = []
            last = header
            characters = len(heading)
            group_limit = None
            for offset in range(header+1, min(end, header+17)):
                line = source_lines[offset]
                if re.match(r"^\s*(?:[-+*]|\d+[.)])\s+", line):
                    if len(items) >= 8 or characters+len(line)>4096:
                        group_limit = "condition_list_item_budget_exceeded" if len(items)>=8 else "condition_list_character_budget_exceeded"
                        break
                    items.append(re.sub(r"^\s*(?:[-+*]|\d+[.)])\s+", "", line).strip())
                elif items and re.match(r"^\s{2,}\S", line):
                    if characters+len(line)>4096:
                        group_limit = "condition_list_character_budget_exceeded"
                        break
                    items[-1] += " " + line.strip()
                else:
                    break
                characters += len(line)
                last = offset
            if items and group_limit is None and last+1<end and last>=header+16 and re.match(r"^\s*(?:[-+*]|\d+[.)])\s+|^\s{2,}\S", source_lines[last+1]):
                group_limit = "condition_list_line_budget_exceeded"
            if items:
                yield {"text": heading+" "+" ".join(items), "line": header+1, "line_end": last+1,
                       "paragraph": paragraph_id, "context_boundary": True,
                       "structured_condition_list": True, "context_limit": group_limit, "attack_catalog": False,
                       "activated_quote": activated_quote}
        for offset in range(start, end):
            if not (relevant[offset] or (offset > start and relevant[offset-1])
                    or (offset+1 < end and relevant[offset+1])):
                continue
            line = source_lines[offset].strip()
            cleaned = _clean_markdown_text(line)
            if not cleaned:
                continue
            attack_catalog = _local_attack_catalog(source_lines, offset+1)
            segments = [segment for segment in SENTENCE_SPLIT_REGEX.split(cleaned) if segment.strip()]
            for segment in segments or [cleaned]:
                normalized = re.sub(r"\s+", " ", segment).strip()
                if normalized:
                    yield {"text": normalized, "line": offset+1, "paragraph": paragraph_id,
                           "context_boundary": bool(re.match(r"^ {0,3}(?:#{1,6}\s|`{3,}|~{3,})", line)),
                           "attack_catalog": attack_catalog, "activated_quote": activated_quote}

    start, paragraph_id = 0, 0
    for offset, line in enumerate(source_lines):
        if not line.strip():
            if offset > start:
                yield from paragraph_units(start, offset, paragraph_id)
                paragraph_id += 1
            start = offset+1
    if start < len(source_lines):
        yield from paragraph_units(start, len(source_lines), paragraph_id)


def _activates_quoted_request(text):
    for match in re.finditer(r"\b(?:follow|execute|obey|apply|perform)\s+(?:that|this|the)\s+(?:request|instruction|command|example)\b", text, re.I):
        if not re.search(r"\b(?:do not|don't|never|must not)\s*$", text[:match.start()], re.I):
            return True
    return False


def _local_attack_catalog(lines, line_number):
    index = line_number - 1
    # Both a scenario label and nearby mitigation context are required. Merely
    # naming a file/heading "reference" or "attack patterns" grants no exemption.
    before = " ".join(lines[max(0, index-12):index])
    after = " ".join(lines[index+1:index+17])
    return bool(re.search(r"(?:attack patterns|adversary behaviors|attack techniques)\s*(?:\*\*)?[:.]", before, re.I)
                and re.search(r"(?:key controls|mitigations|defensive controls)\s*(?:\*\*)?:", after, re.I))


def _with_active_windows(units):
    previous = None
    for current in units:
        yield current
        if previous is not None and not (previous.get("paragraph") != current.get("paragraph")
                or previous.get("context_boundary") or current.get("context_boundary")
                or current.get("line", 0)-previous.get("line", 0)>1):
            yield {"text": f"{previous['text']} {current['text']}", "line": previous.get("line"),
                   "attack_catalog": bool(previous.get("attack_catalog") and current.get("attack_catalog")),
                   "activated_quote": bool(previous.get("activated_quote") or current.get("activated_quote"))}
        previous = current


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
