"""Bounded English speech-act facts, independent of channel or policy decisions.

Uploaded examples, labels and quoted authorities never grant permissions. Facts
retain candidate commands inside examples; governance consumes facts separately.
This parser does not claim arbitrary-language or complete discourse understanding.
"""
from __future__ import annotations

import re
import json
from bisect import bisect_right
from typing import Iterable

ENTERPRISE_FACT_DETECTORS = {"autonomous_authoritative_write", "bulk_enterprise_modification", "workflow_manipulation", "cross_system_automation"}
ENTERPRISE_ACTIONS = r"create|update|modify|delete|transition|comment|worklog|close|reassign|merge|approve|write|sync|synchronize|copy|propagate"
FACT_DETECTORS = {"prompt_override", "system_exfiltration", "secret_exfiltration"} | ENTERPRISE_FACT_DETECTORS
ACTION = r"(?:show|reveal|dump|print|return|expose|output|extract|leak|disclose|send|share|display|read|fetch|include|ignore|override|create|update|modify|delete|transition|comment|worklog|close|reassign|merge|approve|write|sync|synchronize|copy|propagate)"
EXAMPLE_TAGS = {"quoted_or_fenced", "educational_example", "test_fixture"}
DESCRIPTIVE_TAGS = {"descriptive_security_language", "topic_discussion", "protective_language", "negated_or_defined"}


def _activation(text):
    pattern = r"\b(?:do|act\s+on|follow|execute|obey|apply|perform|carry\s+out)\s+(?:(?:that|this|the|above|previous)\s+){0,2}(?:request|instruction|command|example|quote|quoted\s+text|fenced\s+(?:text|block))\b"
    for match in re.finditer(pattern, text, re.I):
        opening = re.search(r"(?:^|[ :])([\"'])", text[:match.start()])
        if opening and len(re.findall(r"(?<!\\)" + re.escape(opening[1]), text[opening.end()-1:match.start()])) % 2:
            continue
        if not re.search(r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|cannot|can't)\s*$", text[:match.start()], re.I):
            return True
    return False


def _narrative_frame(text):
    return bool((re.search(r"\b(?:story|novel|fiction|dialogue|character)\b", text, re.I)
                 and re.search(r"\b(?:[A-Z][a-z]+)\s+(?:says|said|asks|asked|tells|told)\b", text))
                or re.search(r"\b[A-Z][a-z]+\s+(?:tells|told|asks|asked)\s+[A-Z][a-z]+\b", text)
                or re.search(r"\b(?:attacker|adversary|character|intruder)\s+(?:said|says|saying|asked|asks|asking|told|tells)\b", text, re.I))



def _json_fixture_activations(text):
    if not text.lstrip().startswith(("{", "[")):
        return {}
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    try:
        data = json.loads(text, object_pairs_hook=unique)
    except (ValueError, RecursionError):
        return {}
    assertion_types = {"tool_call_forbidden", "tool_call_requires_precondition", "content_diff_forbidden", "scope_check"}
    assertion_fields = {"description", "expected", "expected_result", "tool_name", "precondition", "condition"}
    counter, references = 0, 0
    recent = []
    output = {}
    def walk(value, path="$", protected=False, assertion_scope=False, depth=0):
        nonlocal counter, references
        if depth > 64:
            return
        if isinstance(value, dict):
            assertion = value.get("assertion")
            case = isinstance(value.get("trigger_prompt"), str) and isinstance(assertion, dict) and assertion.get("type") in assertion_types
            identifier = None
            if case:
                counter += 1
                identifier = counter
            for key, child in value.items():
                child_path = path + "." + key
                if case and key == "trigger_prompt":
                    recent.append(identifier)
                    recent[:] = recent[-64:]
                    walk(child, child_path, protected=True, depth=depth+1)
                elif case and key == "assertion":
                    walk(child, child_path, assertion_scope=True, depth=depth+1)
                else:
                    own_protected = assertion_scope and key in assertion_fields and isinstance(child, str)
                    walk(child, child_path, protected=own_protected, depth=depth+1)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, path+"["+str(index)+"]", depth=depth+1)
        elif isinstance(value, str) and not protected and recent and _activation(value):
            references += 1
            if references > 256:
                output["_limit"] = True
                return
            encoded = json.dumps(value, ensure_ascii=False)
            position = text.find(encoded)
            line = text.count("\n", 0, position)+1 if position >= 0 else None
            specific = bool(re.search(r"\b(?:above|previous|last)\b", value, re.I))
            output.setdefault(recent[-1], []).append({"line": line, "text": value[:512],
                "kind": "structured_example_activation", "json_path": path,
                "reference_resolution": "ambiguous" if len(recent)>1 and not specific else "single_candidate"})
    walk(data)
    return output


def _source_contexts(text, projected_candidate_lines=()):
    projected_lines = set(projected_candidate_lines)
    lines = text.splitlines()
    contexts = {}
    fence = None
    fence_example = False
    frame_start = None
    previous = ""
    recent_examples = []
    activations = []
    activation_limited = False
    example_ranges = []
    omitted_range = None
    record_limit = False
    for number, line in enumerate(lines, 1):
        structural = re.sub(r"^\s*(?:>\s*)+", "", line)
        marker = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", structural)
        example_label = bool(re.search(r"\b(?:examples?|sample|illustration|quoted\s+(?:request|instruction)|unsafe\s+request)\b", previous, re.I))
        quote = bool(re.match(r"\s*>\s*", line))
        in_example = bool(fence and fence_example) or (quote and example_label)
        if marker:
            if fence and re.fullmatch(r" {0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*", structural):
                if fence_example:
                    if len(example_ranges) < 8192:
                        example_ranges.append((frame_start, number))
                    else:
                        omitted_range = (omitted_range[0] if omitted_range else frame_start, number)
                fence = None
                in_example = fence_example or quote
            elif not fence:
                fence = marker[1]
                fence_example = example_label
                frame_start = number
                in_example = fence_example
        inline_example = (example_label or bool(re.search(r"\b(?:example\s+of|unsafe\s+request|attack\s+example)\b", line, re.I))) and bool(re.search(r"[\"']", line))
        direct_address = bool(re.search(r"(?:^|[,;:])\s*(?:assistant|agent|you)\b", structural, re.I))
        # Narrative actor resolution is local to this line, never inherited
        # from a nearby story paragraph that could mask a separate instruction.
        narrative = _narrative_frame(structural) and not direct_address
        example = in_example
        local_context = {"example": example, "narrative": narrative,
                            "example_id": frame_start if in_example and frame_start else number,
                            "candidate": (example or inline_example or narrative or bool(re.match(r"\s*[\"']", line))) and (_contained_imperative(line) or number in projected_lines),
                            "direct_address": direct_address, "illustrative_frame": fence_example if fence else example_label}
        # Ordinary lines need no per-line dictionary. Preserve state only for
        # candidate/frame/activation-relevant lines; the complete source still
        # goes to detectors under their ordinary budgets.
        special_context = not in_example and (narrative or inline_example or
                          (direct_address and _contained_imperative(line)) or number in projected_lines)
        if special_context:
            if len(contexts) < 8192:
                contexts[number] = local_context
            else:
                record_limit = True
        if local_context["candidate"]:
            identifier = local_context["example_id"]
            if not recent_examples or recent_examples[-1] != identifier:
                recent_examples.append(identifier)
                recent_examples[:] = recent_examples[-64:]
        vague = bool(re.search(r"\b(?:do|perform|execute)\s+(?:that|this)\s*(?:now)?[.!]?\s*$", line, re.I)) and not re.search(r"\b(?:do not|don't|never|must not)\s+(?:do|perform|execute)\b", line, re.I)
        if recent_examples and not local_context["example"] and (_activation(line[:2048]) or vague):
            if len(activations) < 256:
                specific = bool(re.search(r"\b(?:above|previous|last)\b", line, re.I))
                activations.append({"line": number, "text": line[:512],
                                    "kind": "quoted_instruction_activation",
                                    "target_example_id": recent_examples[-1],
                                    "reference_resolution": "ambiguous" if vague or (len(recent_examples)>1 and not specific) else "single_candidate"})
            else:
                activation_limited = True
        if line.strip():
            previous = line[:512]
    if fence and fence_example:
        if len(example_ranges) < 8192:
            example_ranges.append((frame_start, len(lines)))
        else:
            omitted_range = (omitted_range[0] if omitted_range else frame_start, len(lines))
    contexts["_example_ranges"] = example_ranges
    contexts["_range_starts"] = [start for start, _ in example_ranges]
    contexts["_omitted_example_range"] = omitted_range
    contexts["_record_limit"] = record_limit
    contexts["_activations"] = activations
    contexts["_activation_limited"] = activation_limited
    contexts["_json_activations"] = _json_fixture_activations(text)
    return lines, contexts



def _open_literal_span(text):
    opened = None
    for match in re.finditer(r"`+|[\"']", text):
        token = match.group(0)
        pos = match.start()
        if token == "'" and pos and pos+1<len(text) and text[pos-1].isalnum() and text[pos+1].isalnum():
            continue
        if opened is None:
            opened = (token, pos)
        elif opened[0] == token:
            opened = None
    return opened


def _contained_imperative(text):
    # Only syntax of the candidate is tested; an example can contain this fact.
    cleaned = re.sub(r"^[\s>*#\-\d.\"'`]+", "", text)
    return bool(re.match(r"(?:please\s+)?" + ACTION + r"\b", cleaned, re.I)
                or re.search(r"\b(?:must|shall|should)\s+(?:be\s+)?" + ACTION + r"", cleaned, re.I)
                or re.search(r"[\"'`: ]" + ACTION + r"\b", cleaned, re.I))


def prepare_observation_context(text, projected_candidate_lines=()):
    return _source_contexts(text, projected_candidate_lines)


def source_observation_frame(prepared_context, line):
    """Framing facts at an original source line (e.g. decoded provenance)."""
    return _lookup_context(prepared_context, line)


def _lookup_context(prepared_context, line):
    lines, contexts = prepared_context
    local = dict(contexts.get(line, {}))
    if isinstance(line, int):
        index = bisect_right(contexts.get("_range_starts", []), line)-1
        ranges = contexts.get("_example_ranges", [])
        if index >= 0 and line <= ranges[index][1]:
            local.update(example=True, illustrative_frame=True, example_id=ranges[index][0])
        missing = contexts.get("_omitted_example_range")
        if missing and missing[0] <= line <= missing[1] and not local.get("example"):
            local["context_limit"] = "illustrative_frame_budget_exceeded"
    return local


def observation_fact_priority(row):
    speech = row.get("speech_act")
    if speech == "request" and row.get("imperative_evidence"):
        return 0 if row.get("target") == "model_or_system" else 1
    return {"ambiguous": 2, "example": 3, "described_risk": 4}.get(speech, 2)


def annotate_observation_facts(detector_id: str, observations: Iterable[dict], text: str | None = None, *, prepared_context=None):
    """Return observation copies with candidate facts; never choose disposition.

    Source context is optional. Without it, existing exact context tags and the
    supplied evidence remain usable, while unsupported discourse stays unknown.
    """
    rows = [dict(item) for item in observations]
    if detector_id not in FACT_DETECTORS:
        return rows
    lines, contexts = prepared_context if prepared_context is not None else (_source_contexts(text) if text is not None else ([], {}))
    for row in rows:
        tag = row.get("context_tag", "pattern_match")
        sample = str(row.get("text", ""))
        candidate_context = str(row.get("candidate_context", sample))
        if detector_id in ({"prompt_override"} | ENTERPRISE_FACT_DETECTORS) and tag == "pattern_match":
            # Reuse the same bounded grammatical classifier for override
            # verbs without declaring them credential-disclosure verbs.
            if __package__:
                from .scan_rules import _disclosure_context_tag
            else:
                from scan_rules import _disclosure_context_tag
            action_pattern = ENTERPRISE_ACTIONS if detector_id in ENTERPRISE_FACT_DETECTORS else r"ignore|override|disregard|forget|bypass"
            action = re.search(r"\b(?:" + action_pattern + r")\b", sample, re.I)
            if action:
                all_actions = list(re.finditer(r"\b(?:" + action_pattern + r")\b", candidate_context, re.I))
                if all_actions:
                    action_tags = [_disclosure_context_tag(candidate_context[:item.end()], action_pattern) for item in all_actions]
                    tag = min(action_tags, key=lambda value: {"imperative_disclosure": 0, "ambiguous_disclosure": 1, "quoted_or_fenced": 2}.get(value, 3))
                    row["context_tag"] = tag
        number = row.get("line")
        local = _lookup_context((lines, contexts), number)
        example = tag in EXAMPLE_TAGS or local.get("example", False)
        literal = _open_literal_span(candidate_context)
        if literal and not row.get("structured_value"):
            wrapper = candidate_context[:literal[1]]
            operative_wrapper = bool(re.search(r"\b(?:execute|run|follow|obey|apply|perform|use)\s+(?:(?:this|that|the)\s+)?(?:(?:instruction|request|command|example)\s*)?[: ]*\s*$|\b(?:admin(?:istrator)?|developer|system|manager)\s+(?:says|said|asks|instructs)\s*[: ]*\s*$|(?:^|[,;:])\s*(?:assistant|agent|you)\s*[: ]*\s*$", wrapper, re.I))
            if not operative_wrapper:
                example = True
        narrative = _narrative_frame(candidate_context) if row.get("candidate_context") else local.get("narrative", False)
        direct_address = (bool(re.search(r"(?:^|[,;:])\s*(?:assistant|agent|you)\b", candidate_context, re.I))
                          if row.get("candidate_context") else local.get("direct_address", False))
        if narrative:
            example = True
        if direct_address and not local.get("illustrative_frame"):
            example, narrative = False, False
        imperative = tag == "imperative_disclosure" or (detector_id == "prompt_override" and tag == "pattern_match")
        if example and tag not in DESCRIPTIVE_TAGS:
            imperative = imperative or _contained_imperative(sample)
        # Catalogs retain the candidate adversary action instead of erasing it.
        if tag == "documented_attack_pattern":
            example = True
            imperative = _contained_imperative(sample)
            narrative = True
        activation = []
        if example and isinstance(number, int) and lines:
            identifier = local.get("example_id", number)
            for item in contexts.get("_activations", []):
                if item["line"] >= number and item["target_example_id"] == identifier:
                    activation = [{**item, "example_line": number}]
                    break
        if row.get("fixture_id") is not None:
            structured = contexts.get("_json_activations", {}).get(row["fixture_id"], [])
            if structured:
                activation = [{**structured[0], "example_line": number}]
        if activation and activation[0]["reference_resolution"] == "ambiguous":
            speech_act, imperative = "ambiguous", True
        elif activation:
            speech_act, imperative = "request", True
        elif local.get("context_limit"):
            speech_act = "ambiguous"
        elif example and (contexts.get("_activation_limited") or contexts.get("_json_activations", {}).get("_limit")):
            speech_act = "ambiguous"
        elif example:
            speech_act = "example"
        elif tag in DESCRIPTIVE_TAGS:
            speech_act = "described_risk"
        elif imperative:
            speech_act = "request"
        else:
            speech_act = "ambiguous"
        if activation or (imperative and not narrative):
            target = "model_or_system"
        elif narrative or tag in {"descriptive_security_language", "documented_attack_pattern"}:
            target = "third_party"
        else:
            target = "unspecified"
        row.update(speech_act=speech_act, imperative_evidence=bool(imperative), target=target,
                   confidence="high" if imperative or tag in DESCRIPTIVE_TAGS else "medium",
                   language_scope="bounded_english_patterns")
        if activation:
            row["activation_evidence"] = activation
        if local.get("context_limit"):
            row["context_limit"] = local["context_limit"]
        elif contexts.get("_record_limit"):
            row["context_limit"] = "source_context_record_budget_exceeded"
            if not row.get("candidate_context") and not local:
                row["speech_act"] = "ambiguous"
        if contexts.get("_activation_limited"):
            row["context_limit"] = "activation_reference_budget_exceeded"
    return rows
