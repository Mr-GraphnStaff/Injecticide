from __future__ import annotations

import re
from typing import Dict, Iterable, List, Tuple

URL_REGEX = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)

PURPOSE_PATTERNS = (
    (
        re.compile(
            r"^(?:#+\s*)?(purpose|goal|overview|description|about)\s*[:\-]\s*(.+)$",
            re.IGNORECASE | re.MULTILINE,
        ),
        2,
    ),
    (
        re.compile(
            r"\b(this\s+(skill|tool|assistant)\s+(is|provides|helps|allows)\s+[^.\n]+)",
            re.IGNORECASE,
        ),
        1,
    ),
)

HTML_REGEX = re.compile(r"\b(html|doctype|<html|<body|<div|<script|<style)\b", re.IGNORECASE)
FILE_WRITE_REGEX = re.compile(
    r"\b(create|generate|write|save|export)\b[^.\n]{0,80}\b(file|report|dashboard|html|csv|pdf)\b",
    re.IGNORECASE,
)
EXTERNAL_EMBED_REGEX = re.compile(
    r"\b(iframe|<iframe|embed|<img|<script|youtube|vimeo|cdn|remote content)\b",
    re.IGNORECASE,
)
AUTO_OPEN_REGEX = re.compile(
    r"\b(auto[- ]?open|open\s+in\s+(browser|tab)|launch\s+dashboard|open\s+the\s+file|auto[- ]?launch)\b",
    re.IGNORECASE,
)
UX_MANIPULATION_REGEX = re.compile(r"\b(rickroll|prank|surprise|autoplay|pop[- ]?up|fullscreen)\b", re.IGNORECASE)
PERSISTENCE_REGEX = re.compile(r"\b(persist|persistent|store|cache|remember|stateful|session)\b", re.IGNORECASE)
CREDENTIAL_REGEX = re.compile(r"\b(api\s*key|token|credential|password|secret|oauth)\b", re.IGNORECASE)

ENTERPRISE_SERVICES = (
    "jira",
    "slack",
    "confluence",
    "salesforce",
    "github",
    "gitlab",
    "google drive",
    "gdrive",
    "sharepoint",
    "okta",
    "servicenow",
)
ENTERPRISE_REGEX = re.compile(r"\b(" + "|".join(re.escape(item) for item in ENTERPRISE_SERVICES) + r")\b", re.IGNORECASE)
VAGUE_ACTION_REGEX = re.compile(r"\b(analyze|summarize|report|review|audit|monitor|scan)\b", re.IGNORECASE)
READ_ONLY_REGEX = re.compile(r"\b(read[- ]only|view|summarize|analyze|extract)\b", re.IGNORECASE)


def analyze_behavior(text_sources: Iterable[Dict[str, str]]) -> Dict[str, object]:
    sources = list(text_sources)
    combined_text = "\n\n".join(source["text"] for source in sources if source.get("text"))

    declared_purpose = _extract_declared_purpose(sources)
    behaviors, capabilities, dependencies, ux_manipulation, capability_flags = _infer_capabilities(combined_text)
    instruction_risks, overall_risk, recommendation = _classify_instructions(sources, capability_flags)
    inconsistencies = _find_inconsistencies(declared_purpose, capability_flags)

    return {
        "behavioral_summary": {
            "declared_purpose": declared_purpose,
            "observed_behaviors": behaviors,
            "required_capabilities": capabilities,
            "external_dependencies": dependencies,
            "ux_manipulation": ux_manipulation,
            "inconsistencies": inconsistencies,
        },
        "risk_classification": {
            "overall_risk": overall_risk,
            "instruction_risks": instruction_risks,
            "recommendation": recommendation,
        },
    }


def _extract_declared_purpose(text_sources: Iterable[Dict[str, str]]) -> str:
    for source in text_sources:
        text = source.get("text", "")
        if not text:
            continue
        for pattern, group_index in PURPOSE_PATTERNS:
            match = pattern.search(text)
            if match:
                return _clean_sentence(match.group(group_index))
    return "Unknown"


def _infer_capabilities(text: str) -> Tuple[List[str], List[str], List[str], bool, Dict[str, bool]]:
    observed_behaviors: List[str] = []
    required_capabilities: List[str] = []
    external_dependencies: List[str] = []

    flags = {
        "html": bool(HTML_REGEX.search(text)),
        "file_write": bool(FILE_WRITE_REGEX.search(text)),
        "external_embed": bool(EXTERNAL_EMBED_REGEX.search(text)),
        "auto_open": bool(AUTO_OPEN_REGEX.search(text)),
        "ux_manipulation": bool(UX_MANIPULATION_REGEX.search(text)),
        "persistence": bool(PERSISTENCE_REGEX.search(text)),
        "credentials": bool(CREDENTIAL_REGEX.search(text)),
        "enterprise_access": bool(ENTERPRISE_REGEX.search(text)),
    }

    if flags["html"]:
        observed_behaviors.append("Generates HTML or markup output.")
        required_capabilities.append("html_generation")
    if flags["file_write"]:
        observed_behaviors.append("Writes user-visible files or dashboards.")
        required_capabilities.append("file_write")
    if flags["external_embed"]:
        observed_behaviors.append("Embeds external content (iframes, images, scripts, videos).")
        required_capabilities.append("external_content_embedding")
    if flags["auto_open"]:
        observed_behaviors.append("Auto-opens or launches generated content.")
        required_capabilities.append("auto_open")
    if flags["persistence"]:
        observed_behaviors.append("Persists state across invocations.")
        required_capabilities.append("state_persistence")
    if flags["credentials"]:
        observed_behaviors.append("Handles credentials or secrets.")
        required_capabilities.append("credential_handling")
    if flags["enterprise_access"]:
        observed_behaviors.append("Claims access to enterprise systems.")
        required_capabilities.append("enterprise_access")

    ux_manipulation = flags["auto_open"] or flags["ux_manipulation"]

    external_dependencies.extend(_unique_preserve_order(URL_REGEX.findall(text)))
    if flags["enterprise_access"]:
        external_dependencies.extend(_unique_preserve_order(_find_enterprise_services(text)))

    return (
        observed_behaviors,
        _unique_preserve_order(required_capabilities),
        _unique_preserve_order(external_dependencies),
        ux_manipulation,
        flags,
    )


def _classify_instructions(
    text_sources: Iterable[Dict[str, str]],
    capability_flags: Dict[str, bool],
) -> Tuple[List[Dict[str, str]], str, str]:
    instruction_blocks = _extract_instruction_blocks(text_sources)
    instruction_risks: List[Dict[str, str]] = []

    any_bad = False
    any_risky = False
    any_unknown = False

    for block in instruction_blocks:
        classification, reason = _classify_block(block)
        instruction_risks.append(
            {
                "instruction": block,
                "classification": classification,
                "reason": reason,
            }
        )
        if classification == "bad":
            any_bad = True
        elif classification == "risky":
            any_risky = True
        elif classification == "unknown":
            any_unknown = True

    if capability_flags.get("credentials"):
        any_bad = True
    if any_bad:
        overall_risk = "high"
    elif any_risky or any_unknown or capability_flags.get("external_embed") or capability_flags.get("auto_open"):
        overall_risk = "medium"
    else:
        overall_risk = "low"

    recommendation = _recommend_action(overall_risk, capability_flags)
    return instruction_risks, overall_risk, recommendation


def _classify_block(block: str) -> Tuple[str, str]:
    if CREDENTIAL_REGEX.search(block):
        return "bad", "Handles credentials or secrets."

    risky_reasons = []
    if EXTERNAL_EMBED_REGEX.search(block):
        risky_reasons.append("Embeds external iframe or media content.")
    if AUTO_OPEN_REGEX.search(block):
        risky_reasons.append("Auto-opens or launches generated content.")
    if UX_MANIPULATION_REGEX.search(block):
        risky_reasons.append("Manipulates user experience (auto-play or pop-ups).")
    if HTML_REGEX.search(block):
        risky_reasons.append("Generates HTML or markup output.")
    if FILE_WRITE_REGEX.search(block):
        risky_reasons.append("Writes user-visible files or dashboards.")

    if risky_reasons:
        return "risky", " ".join(risky_reasons[:2])

    if ENTERPRISE_REGEX.search(block) and VAGUE_ACTION_REGEX.search(block):
        return "unknown", "Mentions enterprise system access without enforceable integration details."

    if READ_ONLY_REGEX.search(block):
        return "good", "Read-only analysis or safe transformation."

    return "unknown", "No clear safe or risky indicators."


def _recommend_action(overall_risk: str, capability_flags: Dict[str, bool]) -> str:
    if overall_risk == "high":
        return "block_by_default"
    if overall_risk == "medium":
        if capability_flags.get("external_embed") or capability_flags.get("auto_open") or capability_flags.get("ux_manipulation"):
            return "require_admin_approval"
        return "allow_with_warnings"
    return "allow"


def _extract_instruction_blocks(text_sources: Iterable[Dict[str, str]]) -> List[str]:
    blocks: List[str] = []
    for source in text_sources:
        text = source.get("text", "")
        if not text:
            continue
        for block in re.split(r"\n\s*\n", text):
            cleaned = _clean_sentence(" ".join(line.strip() for line in block.splitlines()))
            if len(cleaned.split()) < 5:
                continue
            if len(cleaned) > 1000:
                cleaned = cleaned[:1000].rstrip() + "…"
            blocks.append(cleaned)
    return blocks


def _find_inconsistencies(declared_purpose: str, capability_flags: Dict[str, bool]) -> List[str]:
    inconsistencies: List[str] = []
    if declared_purpose != "Unknown" and READ_ONLY_REGEX.search(declared_purpose):
        if capability_flags.get("html") or capability_flags.get("auto_open") or capability_flags.get("external_embed"):
            inconsistencies.append(
                "Declared read-only intent but observed output generation or UX manipulation indicators."
            )
    return inconsistencies


def _find_enterprise_services(text: str) -> List[str]:
    matches = ENTERPRISE_REGEX.findall(text)
    return [match if isinstance(match, str) else match[0] for match in matches]


def _unique_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    output = []
    for item in items:
        normalized = item.strip()
        if not normalized or normalized.lower() in seen:
            continue
        seen.add(normalized.lower())
        output.append(normalized)
    return output


def _clean_sentence(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()
