from __future__ import annotations

import json
import re
import tokenize
from itertools import islice
from functools import lru_cache
from io import StringIO
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

if __package__:
    from .obsession_signatures import load_rules as load_obsession_rules
else:
    from obsession_signatures import load_rules as load_obsession_rules


RULE_CATALOG_PATH = Path(__file__).resolve().parent / "rules" / "violations.json"


@lru_cache(maxsize=1)
def load_rule_catalog() -> Dict[str, object]:
    """Load the local structured rule catalog used for skill scanning."""

    with RULE_CATALOG_PATH.open("r", encoding="utf-8") as handle:
        catalog = json.load(handle)
    catalog["rules"].extend(load_obsession_rules())
    return catalog


def compile_patterns() -> Tuple[Dict[str, object], ...]:
    """Compile the local rule catalog into regex-backed matcher definitions."""

    catalog = load_rule_catalog()
    compiled: List[Dict[str, object]] = []

    for rule in catalog.get("rules", []):
        compiled.append(
            {
                **rule,
                "compiled_patterns": tuple(
                    re.compile(pattern, re.IGNORECASE)
                    for pattern in rule.get("patterns", [])
                ),
                "compiled_excludes": tuple(
                    re.compile(pattern, re.IGNORECASE)
                    for pattern in rule.get("exclude_patterns", [])
                ),
            }
        )

    return tuple(compiled)


SAFE_RUNTIME_PACKAGES = {
    "pillow",
    "python-pptx",
    "markitdown",
    "pptxgenjs",
    "jellyfish",
    "rapidfuzz",
    "openpyxl",
    "python-docx",
    "reportlab",
    "pypdf",
    "pdfplumber",
}

DISCLOSURE_VERBS = r"show|reveal|dump|print|return|expose|output|extract|leak|disclose|send|share|display|read|fetch"
SYSTEM_TARGETS = r"(?:system|developer)\s+(?:prompt|message|instructions)"


def find_rule_matches(rule: Dict[str, object], unit: object) -> List[Dict[str, object]]:
    """Return normalized match samples when a compiled rule applies."""

    text, line_number = _unit_text_and_line(unit)
    if isinstance(unit, dict) and unit.get("context_tag") == "educational_example" and rule.get("id") in {"prompt_override", "system_exfiltration", "secret_exfiltration"}:
        matches = find_rule_matches(rule, {"text": text, "line": line_number})
        for match in matches:
            # An authored example still needs review; it is not an exemption.
            match["context_tag"] = "educational_example"
        return matches

    if rule.get("id") == "unicode_deception":
        return _find_unicode_deception_matches(text, line_number)
    if rule.get("id") == "system_exfiltration":
        return _find_system_exfiltration_matches(text, line_number)
    if rule.get("id") == "secret_exfiltration":
        return _find_secret_exfiltration_matches(text, line_number)
    if rule.get("id") == "sensitive_topic":
        matches = []
        for clause in _disclosure_clauses(text):
            protective = _protective_prefix(clause)
            if not protective and any(pattern.search(clause) for pattern in rule.get("compiled_excludes", ())):
                continue
            for pattern in rule.get("compiled_patterns", ()):
                matches.extend(_observations_for_pattern(pattern, clause, line_number,
                               "protective_language" if protective else "pattern_match"))
        return matches[:3]
    if rule.get("id") == "dynamic_exec":
        if isinstance(unit, dict) and "source_text" in unit:
            text = str(unit["source_text"])
        return _find_dynamic_exec_matches(text, line_number, prose=isinstance(unit, dict) and "source_text" in unit and not unit.get("code_fence"))
    if rule.get("id") == "runtime_dependency_install":
        return _find_runtime_dependency_matches(text, line_number)

    if any(pattern.search(text) for pattern in rule.get("compiled_excludes", ())):
        return []

    compiled_patterns = rule.get("compiled_patterns", ())
    if not compiled_patterns:
        return []

    mode = rule.get("match_mode", "any")

    if mode == "all":
        grouped_matches: List[Dict[str, object]] = []
        for pattern in compiled_patterns:
            matches = _observations_for_pattern(pattern, text, line_number)
            if not matches:
                return []
            grouped_matches.extend(matches[:1])
        return grouped_matches[:3]

    positive_matches: List[Dict[str, object]] = []
    for pattern in compiled_patterns:
        positive_matches.extend(_observations_for_pattern(pattern, text, line_number))

    return positive_matches[:3]


def build_scan_units(path: str, text: str) -> List[Dict[str, object]]:
    """Split text into units that reduce unrelated cross-line keyword matches."""

    lower_path = path.lower()
    if lower_path.endswith(".csv"):
        return [
            {"text": line.strip(), "line": index}
            for index, line in enumerate(text.splitlines(), start=1)
            if line.strip()
        ]
    if lower_path.endswith((".md", ".skill", ".txt")):
        return _markdown_scan_units(text)
    if lower_path.endswith((".py", ".pyw")):
        stripped = _strip_python_comments_and_strings(text)
        return [
            {"text": line.strip(), "line": index}
            for index, line in enumerate(stripped.splitlines(), start=1)
            if line.strip()
        ]
    return [{"text": text, "line": 1}]


def _markdown_scan_units(text: str) -> List[Dict[str, object]]:
    units: List[Dict[str, object]] = []
    current_lines: List[str] = []
    current_start = 1
    fence = None
    example = False
    previous_paragraph = ""
    fenced_lines = []
    fenced_start = 1

    def flush_fenced():
        if fenced_lines:
            unit = {"text": " ".join(fenced_lines), "line": fenced_start, "code_fence": True}
            if example:
                unit["context_tag"] = "educational_example"
            units.append(unit)
            fenced_lines.clear()

    for index, line in enumerate(text.splitlines(), start=1):
        marker = re.fullmatch(r" {0,3}(`{3,}|~{3,})([^\r\n]*)", line)
        if fence:
            if re.fullmatch(r" {0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*", line):
                flush_fenced()
                fence = None
            elif line.strip():
                if not fenced_lines:
                    fenced_start = index
                fenced_lines.append(line.strip())
            else:
                flush_fenced()
            continue
        if marker:
            preceding = " ".join(current_lines) or previous_paragraph
            if current_lines:
                units.append({"text": " ".join(item.strip() for item in current_lines), "line": current_start})
                current_lines = []
            example = bool(re.search(r"\b(?:attack example|example (?:of|prompt)|sample (?:attack|injection))\b", preceding, re.I)
                           and re.search(r"\b(?:never|do not|don't|not an instruction|reject)\b", preceding, re.I))
            fence = marker[1]
            current_start = index + 1
            continue
        if re.match(r"^ {0,3}>\s*", line):
            if current_lines and not re.match(r"^ {0,3}>", current_lines[0]):
                units.append({"text": " ".join(item.strip() for item in current_lines), "line": current_start})
                current_lines = []
            if current_lines:
                current_lines.append(re.sub(r"^ {0,3}>\s?", "", line))
            else:
                current_lines = [line]
                current_start = index
            continue
        if re.match(r"^ {0,3}(?:#{1,6}\s|[-+*]\s|\d+[.)]\s)", line):
            if current_lines:
                units.append({"text": " ".join(item.strip() for item in current_lines), "line": current_start})
                current_lines = []
            if re.match(r"^ {0,3}#{1,6}\s", line):
                units.append({"text": line.strip(), "line": index})
            else:
                # Keep an item's continuation with its start. A following item
                # or blank line flushes it, avoiding unrelated-list joins.
                current_lines = [line]
            current_start = index + 1
            if current_lines:
                current_start = index
            continue
        if not line.strip():
            if current_lines:
                previous_paragraph = " ".join(current_lines)
                units.append(
                    {
                        "text": " ".join(item.strip() for item in current_lines if item.strip()),
                        "line": current_start,
                    }
                )
                current_lines = []
            current_start = index + 1
            continue
        if not current_lines:
            current_start = index
        current_lines.append(line)

    flush_fenced()
    if current_lines:
        units.append(
            {
                "text": " ".join(item.strip() for item in current_lines if item.strip()),
                "line": current_start,
            }
        )

    for index, unit in enumerate(units):
        if (index and re.match(r"^\s*>\s*\S", unit["text"])
                and re.search(r"\b(?:quoted attack example|attack example)\b", units[index - 1]["text"], re.I)
                and re.search(r"\b(?:for review only|never|do not|reject)\b", units[index - 1]["text"], re.I)):
            unit["context_tag"] = "educational_example"
    # Retain the original line layout for detectors that cite individual calls.
    # Other matchers still receive the paragraph projection for wrapped prose.
    original_lines = text.splitlines()
    for index, unit in enumerate(units):
        start = int(unit["line"]) - 1
        end = int(units[index + 1]["line"]) - 1 if index + 1 < len(units) else len(original_lines)
        unit["source_text"] = "\n".join(original_lines[start:end])
    return [unit for unit in units if unit["text"]]


def _find_unicode_deception_matches(text: str, line_number: int | None) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    for index, char in enumerate(text):
        if not _is_unicode_control_signal(char):
            continue
        context_tag = _unicode_context_tag(text, index, char)
        if not any(match["text"] == char and match["context_tag"] == context_tag for match in matches):
            matches.append(
                _observation(
                    _unicode_sample(char),
                    line_number,
                    context_tag,
                    "high" if context_tag in {"bidi_override", "invisible_mid_instruction"} else "medium",
                )
            )
        if len(matches) >= 3:
            break
    return matches


def _find_system_exfiltration_matches(text: str, line_number: int | None) -> List[Dict[str, object]]:
    patterns = (
        re.compile(
            rf"\b({DISCLOSURE_VERBS})\b"
            r"[^.\n]{0,80}"
            rf"\b{SYSTEM_TARGETS}\b",
            re.IGNORECASE,
        ),
        re.compile(
            rf"\b{SYSTEM_TARGETS}\b"
            r"[^.\n]{0,80}"
            rf"\b({DISCLOSURE_VERBS})\b",
            re.IGNORECASE,
        ),
    )
    return _disclosure_matches(patterns, text, line_number)


def _find_secret_exfiltration_matches(text: str, line_number: int | None) -> List[Dict[str, object]]:
    patterns = (
        re.compile(
            rf"\b({DISCLOSURE_VERBS})\b"
            r"[^.\n]{0,80}"
            r"\b(api\s*key|access\s+token|bearer\s+token|password|credential|secret|access\s+key|private\s+key|ssh\s+key|pem)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(api\s*key|access\s+token|bearer\s+token|password|credential|secret|access\s+key|private\s+key|ssh\s+key|pem)\b"
            r"[^.\n]{0,80}"
            rf"\b({DISCLOSURE_VERBS})\b",
            re.IGNORECASE,
        ),
    )
    return _disclosure_matches(patterns, text, line_number)


def _disclosure_clauses(text):
    # Contrast, sequence and independently commanded conjunctions end negation
    # scope. This is a bounded syntax convention, not a natural-language proof.
    return re.split(r"[.;!?\n]|\b(?:but|however|then)\b|(?:,\s*|\b(?:and|or)\s+)(?=(?:please\s+)?(?:" + DISCLOSURE_VERBS + r")\b)", text, flags=re.I)


def _protective_prefix(text):
    for verb in re.finditer(r"\b(?:" + DISCLOSURE_VERBS + r")\b", text, re.I):
        if _disclosure_context_tag(text[:verb.end()]) == "negated_or_defined":
            return True
    return False


def _disclosure_matches(patterns, text, line_number):
    matches = []
    for clause in _disclosure_clauses(text):
        for pattern in patterns:
            for match in pattern.finditer(clause):
                verb = re.search(r"\b(?:" + DISCLOSURE_VERBS + r")\b", match.group(0), re.I)
                action_end = match.start() + verb.end()
                context = _disclosure_context_tag(clause[:action_end])
                observation = _observation(match.group(0), line_number, context, "high")
                if observation not in matches:
                    matches.append(observation)
                # Protective prefixes must never consume the display budget
                # before a later disclosure instruction in the same paragraph.
                matches.sort(key=lambda item: item["context_tag"] != "imperative_disclosure")
                del matches[3:]
    return matches


def _find_dynamic_exec_matches(text: str, line_number: int | None, *, prose=False) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    execution_context = "decoded_or_fetched_exec" if _has_decoded_or_fetched_context(text) else "direct_dynamic_exec"
    empty_arguments = re.compile(r"\s*\)")
    previous_offset, line_offset = 0, 0
    for match in re.finditer(r"\b(exec|eval|compile)\s*\(", text, re.IGNORECASE):
        line_offset += text.count("\n", previous_offset, match.start())
        previous_offset = match.start()
        previous = match.start() - 1
        if previous >= 0 and (text[previous].isalnum() or text[previous] == "_"):
            continue
        cursor = previous
        while cursor >= 0 and text[cursor].isspace():
            cursor -= 1
        if cursor >= 0 and text[cursor] == ".":
            continue
        context_tag = execution_context
        # Bare API names such as `eval()/exec()` are mentions, not executable
        # calls with a payload. Keep the observation without asserting use.
        if prose and empty_arguments.match(text, match.end()):
            context_tag = "prose_mention"
        match_line = line_number + line_offset if isinstance(line_number, int) else None
        matches.append(_observation(match.group(0), match_line, context_tag, "high"))
        # Display budgets must not let early mentions suppress a later call.
        matches.sort(key=lambda item: {"decoded_or_fetched_exec": 0, "direct_dynamic_exec": 1, "prose_mention": 2}.get(item["context_tag"], 3))
        del matches[3:]
    return matches


def _find_runtime_dependency_matches(text: str, line_number: int | None) -> List[Dict[str, object]]:
    pattern = re.compile(
        r"\b(?:(pip|pip3)\s+install|python\s+-m\s+pip\s+install|npm\s+install|npm\s+add|yarn\s+add|apt(?:-get)?\s+install)\s+([^\n;&|]+)",
        re.IGNORECASE,
    )
    matches: List[Dict[str, object]] = []
    for match in pattern.finditer(text):
        command = match.group(0).strip()
        package_spec = match.group(2).strip().split()[0] if match.lastindex and match.group(2) else ""
        context_tag = _dependency_context_tag(package_spec)
        confidence = "high" if context_tag == "url_or_vcs_dependency" else "medium"
        matches.append(_observation(command, line_number, context_tag, confidence))
        if len(matches) >= 3:
            break
    return matches


def _strip_python_comments_and_strings(text: str) -> str:
    try:
        tokens = tokenize.generate_tokens(StringIO(text).readline)
    except tokenize.TokenError:
        return text

    output_lines = [[] for _ in text.splitlines()]
    for token in tokens:
        token_type = token.type
        token_text = token.string
        start_line, _ = token.start

        if token_type in {tokenize.COMMENT, tokenize.STRING}:
            continue
        if token_type in {tokenize.ENCODING, tokenize.ENDMARKER, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}:
            continue
        if 1 <= start_line <= len(output_lines):
            output_lines[start_line - 1].append(token_text)

    return "\n".join(" ".join(parts) for parts in output_lines)


def _observations_for_pattern(
    pattern: re.Pattern[str],
    text: str,
    line_number: int | None,
    context_tag: str = "pattern_match",
    confidence: str = "medium",
) -> List[Dict[str, object]]:
    return [
        _observation(match.group(0), line_number, context_tag, confidence)
        for match in islice(pattern.finditer(text), 3)
    ]


def _observation(
    text: str,
    line_number: int | None,
    context_tag: str,
    confidence: str,
) -> Dict[str, object]:
    return {
        "text": re.sub(r"\s+", " ", text).strip(),
        "line": line_number,
        "context_tag": context_tag,
        "confidence": confidence,
    }


def _unit_text_and_line(unit: object) -> Tuple[str, int | None]:
    if isinstance(unit, dict):
        line = unit.get("line")
        return str(unit.get("text", "")), line if isinstance(line, int) else None
    return str(unit), None


def _disclosure_context_tag(text: str) -> str:
    opening = re.match(r"^\s*(?:>\s*)?([\"'`])", text)
    # An unrelated completed quote before an instruction is not its context.
    if opening and len(re.findall(r"(?<!\\)" + re.escape(opening[1]), text)) % 2:
        return "quoted_or_fenced"
    # Only a guard that directly governs this action changes its disposition.
    # Earlier unrelated prohibitions cannot immunize a later disclosure verb.
    if re.search(r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|not\s+allowed\s+to|cannot|can't|will\s+not)\s+(?:ever\s+)?(?:(?:ask|instruct|tell)\s+(?:the\s+)?(?:user|agent|operator)\s+to\s+)?(?:" + DISCLOSURE_VERBS + r")\s*$", text, re.I):
        return "negated_or_defined"
    if re.search(r"\b(?:refuse|decline)\s+to\s+(?:" + DISCLOSURE_VERBS + r")\s*$", text, re.I) and not re.search(r"\b(?:not|never|don't)\s+(?:refuse|decline)\b", text, re.I):
        return "negated_or_defined"
    return "imperative_disclosure"


def _dependency_context_tag(package_spec: str) -> str:
    lowered = package_spec.lower()
    if lowered.startswith(("http://", "https://", "git+", "svn+", "hg+")):
        return "url_or_vcs_dependency"
    package_name = re.split(r"[<>=~!@\[]", lowered, maxsplit=1)[0].strip()
    package_name = package_name.replace("_", "-")
    if package_name in SAFE_RUNTIME_PACKAGES:
        return "allowlisted_dependency"
    return "unknown_dependency"


def _has_decoded_or_fetched_context(text: str) -> bool:
    return bool(
        re.search(r"\b(base64|b64decode|decode|requests\.get|urllib|fetch|curl|wget)\b", text, re.IGNORECASE)
    )


def _unicode_context_tag(text: str, index: int, char: str) -> str:
    codepoint = ord(char)
    if 0x202A <= codepoint <= 0x202E or 0x2066 <= codepoint <= 0x2069:
        return "bidi_override"
    if char == "\u200d" and _is_emoji_joiner(text, index):
        return "emoji_joiner"
    if char in {"\u200b", "\u200c"} and _is_self_documented_spacer(text):
        return "self_documented_spacer"
    if _is_mid_instruction(text, index):
        return "invisible_mid_instruction"
    return "invisible_character"


def _unicode_sample(char: str) -> str:
    return f"U+{ord(char):04X}"


def _is_self_documented_spacer(text: str) -> bool:
    return bool(re.search(r"\b(spacer|zero-width|zwnj|zwsp|non-joiner)\b", text, re.IGNORECASE))


def _is_mid_instruction(text: str, index: int) -> bool:
    before = text[max(0, index - 40):index]
    after = text[index + 1:index + 41]
    return bool(re.search(r"[A-Za-z0-9]$", before) and re.search(r"^[A-Za-z0-9]", after))


def _is_unicode_control_signal(char: str) -> bool:
    codepoint = ord(char)
    return (
        0x202A <= codepoint <= 0x202E
        or 0x2066 <= codepoint <= 0x2069
        or 0x200B <= codepoint <= 0x200D
        or codepoint == 0xFEFF
    )


def _is_emoji_joiner(text: str, index: int) -> bool:
    previous_char = _previous_non_variation_char(text, index)
    next_char = _next_non_variation_char(text, index)
    return bool(previous_char and next_char and _is_emoji_like(previous_char) and _is_emoji_like(next_char))


def _previous_non_variation_char(text: str, index: int) -> str:
    cursor = index - 1
    while cursor >= 0 and ord(text[cursor]) == 0xFE0F:
        cursor -= 1
    return text[cursor] if cursor >= 0 else ""


def _next_non_variation_char(text: str, index: int) -> str:
    cursor = index + 1
    while cursor < len(text) and ord(text[cursor]) == 0xFE0F:
        cursor += 1
    return text[cursor] if cursor < len(text) else ""


def _is_emoji_like(char: str) -> bool:
    codepoint = ord(char)
    return (
        0x1F000 <= codepoint <= 0x1FAFF
        or 0x2600 <= codepoint <= 0x27BF
    )


def _normalize_matches(matches: List[object]) -> List[str]:
    normalized: List[str] = []
    for match in matches:
        if isinstance(match, tuple):
            text = " ".join(str(item) for item in match if item)
        else:
            text = str(match)
        text = re.sub(r"\s+", " ", text).strip()
        if text:
            normalized.append(text)
    return normalized
