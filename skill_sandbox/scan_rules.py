from __future__ import annotations

import json
import re
import tokenize
from functools import lru_cache
from io import StringIO
from pathlib import Path
from typing import Dict, List, Tuple


RULE_CATALOG_PATH = Path(__file__).resolve().parent / "rules" / "violations.json"


@lru_cache(maxsize=1)
def load_rule_catalog() -> Dict[str, object]:
    """Load the local structured rule catalog used for skill scanning."""

    with RULE_CATALOG_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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


def find_rule_matches(rule: Dict[str, object], text: str) -> List[str]:
    """Return normalized match samples when a compiled rule applies."""

    if rule.get("id") == "unicode_deception":
        return _find_unicode_deception_matches(text)
    if rule.get("id") == "secret_exfiltration":
        return _find_secret_exfiltration_matches(text)
    if rule.get("id") == "dynamic_exec":
        return _find_dynamic_exec_matches(text)

    if any(pattern.search(text) for pattern in rule.get("compiled_excludes", ())):
        return []

    compiled_patterns = rule.get("compiled_patterns", ())
    if not compiled_patterns:
        return []

    mode = rule.get("match_mode", "any")

    if mode == "all":
        grouped_matches: List[str] = []
        for pattern in compiled_patterns:
            matches = _normalize_matches(pattern.findall(text))
            if not matches:
                return []
            grouped_matches.extend(matches[:1])
        return grouped_matches[:3]

    positive_matches: List[str] = []
    for pattern in compiled_patterns:
        positive_matches.extend(_normalize_matches(pattern.findall(text)))

    return positive_matches[:3]


def build_scan_units(path: str, text: str) -> List[str]:
    """Split text into units that reduce unrelated cross-line keyword matches."""

    lower_path = path.lower()
    if lower_path.endswith(".csv"):
        return [line for line in text.splitlines() if line.strip()]
    if lower_path.endswith((".md", ".skill", ".txt")):
        units = [
            " ".join(line.strip() for line in block.splitlines() if line.strip())
            for block in text.split("\n\n")
        ]
        return [unit for unit in units if unit]
    if lower_path.endswith((".py", ".pyw")):
        stripped = _strip_python_comments_and_strings(text)
        return [line for line in stripped.splitlines() if line.strip()]
    return [text]


def _find_unicode_deception_matches(text: str) -> List[str]:
    matches: List[str] = []
    for index, char in enumerate(text):
        if not _is_unicode_control_signal(char):
            continue
        if char == "\u200d" and _is_emoji_joiner(text, index):
            continue
        if char not in matches:
            matches.append(char)
        if len(matches) >= 3:
            break
    return matches


def _find_secret_exfiltration_matches(text: str) -> List[str]:
    patterns = (
        re.compile(
            r"\b(show|reveal|dump|print|return|expose|display|output|extract|leak)\b"
            r"[^.\n]{0,80}"
            r"\b(api\s*key|access\s+token|bearer\s+token|password|credential|secret|access\s+key|private\s+key|ssh\s+key|pem)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(api\s*key|access\s+token|bearer\s+token|password|credential|secret|access\s+key|private\s+key|ssh\s+key|pem)\b"
            r"[^.\n]{0,80}"
            r"\b(show|reveal|dump|print|return|expose|display|output|extract|leak)\b",
            re.IGNORECASE,
        ),
    )
    matches: List[str] = []
    for pattern in patterns:
        matches.extend(_normalize_matches(pattern.findall(text)))
    return matches[:3]


def _find_dynamic_exec_matches(text: str) -> List[str]:
    matches: List[str] = []
    for match in re.finditer(r"\b(exec|eval|compile)\s*\(", text, re.IGNORECASE):
        previous = match.start() - 1
        if previous >= 0 and (text[previous].isalnum() or text[previous] == "_"):
            continue
        cursor = previous
        while cursor >= 0 and text[cursor].isspace():
            cursor -= 1
        if cursor >= 0 and text[cursor] == ".":
            continue
        matches.append(match.group(0))
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
