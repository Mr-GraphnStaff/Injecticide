"""Creator reading conventions are evidence, never instructions or scanner exemptions.

These are local author conventions, not vendor-mandated file size requirements.
The complete extracted text is used only to verify the declaration and true EOF;
ordinary detector budgets remain unchanged.
"""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

HEADER_CHARACTERS = 8192
HEADER_LINES = 128
MAX_MARKER_CHARACTERS = 2 * 1024 * 1024


def _outside_fences(text):
    """Keep offsets while removing fenced content, including unclosed fences."""
    result, fence = [], None
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        candidate = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", content)
        if fence:
            closing = r" {0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*"
            if re.fullmatch(closing, content):
                fence = None
            result.append(" " * len(line.rstrip("\r\n")) + line[len(line.rstrip("\r\n")):])
        elif candidate and not (candidate[1][0] == "`" and "`" in candidate[2]):
            fence = candidate[1]
            result.append(" " * len(line.rstrip("\r\n")) + line[len(line.rstrip("\r\n")):])
        else:
            result.append(line)
    return "".join(result)


def creator_mitigation(path, text):
    result = {"status": "absent", "convention": None, "start_marker_found": False,
              "end_marker_found": False, "eof_verified": False,
              "satisfies_tagging_convention": False,
              "large_file_tagged_chunked_reference": False,
              "policy_scope": "creator_large_file_reading_convention",
              "target_runtime_reading": "unknown",
              "reason": "No recognized creator reading convention found near the file header.",
              "effect": "Does not change detector coverage, security findings or vendor compatibility."}
    if text is None:
        result.update(status="unverifiable", reason="No complete extracted text available for marker verification.")
        return result
    # Most files have no claim. Never split/mask their complete contents merely
    # to discover that fact, especially large references allowed by extraction.
    header_input = "".join(text[:HEADER_CHARACTERS].splitlines(keepends=True)[:HEADER_LINES])
    header = _outside_fences(header_input)
    basename = PurePosixPath(path).name
    if basename.lower().endswith(".json"):
        # A duplicate-key or malformed object can claim a marker, but cannot
        # establish which declaration a consumer would see.
        claimed = bool(re.search(r'"_review_tag"\s*:', text[:HEADER_CHARACTERS]))
        if not claimed:
            return result
        unclaimed_result = dict(result)
        result.update(start_marker_found=True, convention="B", status="unverifiable")
        if len(text) > MAX_MARKER_CHARACTERS:
            result["reason"] = "Claimed JSON convention exceeds the 2 MiB marker-parser budget; completeness was not verified."
            return result
        def unique(pairs):
            output = {}
            for key, value in pairs:
                if key in output:
                    raise ValueError("Duplicate JSON key")
                output[key] = value
            return output
        def reject_constant(value):
            raise ValueError("Nonstandard JSON numeric constant")
        try:
            data = json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)
            if not isinstance(data, dict) or "_review_tag" not in data:
                return unclaimed_result
            tag = data["_review_tag"]
            if not isinstance(tag, str) or not re.search(r"large[- ]file", tag, re.I) or not re.search(r"chunk", tag, re.I):
                result.update(status="invalid", reason="Top-level _review_tag does not declare the large-file chunk-reading convention.")
                return result
            # True EOF is the final structural property in a fully parsed object.
            result["end_marker_found"] = "_end_of_file" in data
            result["eof_verified"] = (list(data)[-1:] == ["_end_of_file"]
                                      and (data["_end_of_file"] is True or isinstance(data["_end_of_file"], str) and bool(data["_end_of_file"].strip())))
        except (ValueError, RecursionError):
            result["reason"] = "Claimed JSON convention could not be verified: malformed, duplicate-key or excessively nested JSON."
            return result
    else:
        declaration = re.search(r'''(?im)^ {0,3}(?:[#;/*][#;/* \t]*|<!--[ \t]*)?read_pattern:[ \t]*(?:chunked-reference|'chunked-reference'|"chunked-reference")[ \t]*(?:\#[^\r\n]*|-->|\*/)?[ \t]*$''', header)
        comment_claim = re.search(r"(?m)^ {0,3}<!--\s*REVIEW TAG:\s*large-file\b", header, re.I)
        comment = re.search(r"(?m)^ {0,3}<!--\s*REVIEW TAG:\s*large-file\b(.*?)-->", header, re.I | re.S)
        if not declaration and not comment_claim:
            return result
        result.update(start_marker_found=True, convention="A" if declaration else "B", status="unverifiable")
        if not declaration and not comment:
            result["reason"] = "Large-file header tag is incomplete within the bounded header recognition region."
            return result
        if comment and not declaration and not (re.search(r"chunk", comment[1], re.I) and re.search(r"END OF FILE", comment[1], re.I)):
            result["reason"] = "Large-file tag is present but does not declare chunk reading through an EOF marker."
            return result
        if len(text) > MAX_MARKER_CHARACTERS:
            result["reason"] = "Claimed convention exceeds the 2 MiB marker-verification budget; fenced-content and EOF completeness were not verified."
            return result
        if re.search(r"(?m)^[ \t]*(?:(?:>[ \t]*)|(?:[-+*]|\d+[.)])[ \t]+)+(?:`{3,}|~{3,})", text):
            result["reason"] = "Container-prefixed code fences require unsupported Markdown context; creator-tag and EOF placement are unverifiable."
            return result
        visible = _outside_fences(text)
        end = re.compile(r"<!--\s*END OF FILE:\s*" + re.escape(basename) + r"\s*-->")
        result["end_marker_found"] = bool(end.search(visible))
        # Require the marker in original text too: a fenced marker cannot verify
        # EOF and trailing executable/prose content cannot be hidden by masking.
        result["eof_verified"] = bool(re.search(r"(?m)^ {0,3}" + end.pattern + r"\s*\Z", text)
                                      and re.search(r"(?m)^ {0,3}" + end.pattern + r"\s*\Z", visible))
    verified = result["eof_verified"]
    result.update(status="verified" if verified else "unverifiable",
                  satisfies_tagging_convention=verified,
                  large_file_tagged_chunked_reference=verified,
                  reason="Creator chunk-reading convention and true EOF marker verified; runtime reading and detector completeness remain separate." if verified
                  else "Creator claims chunk reading but a matching marker at true EOF could not be confirmed.")
    return result


def mitigation_finding(evidence):
    if not evidence["start_marker_found"] or evidence["status"] == "verified":
        return []
    return [{"id": "unverifiable_chunk_marker", "severity": "medium", "tier": "review",
             "category": "coverage", "finding_category": "creator_mitigation",
             "description": evidence["reason"], "subject": "creator_reading_convention",
             "action_state": "declared_unverified", "disposition": "review",
             "count": 1, "samples": [], "observations": [],
             "counts_for_governance": False, "status": "unverified",
             "is_actionable": True, "display_kind": "actionable_finding"}]


def initial_coverage():
    return {name: {"status": "not_performed", "inspected_characters": None,
                   "reason": "No supported text supplied to this stage."}
            for name in ("extraction", "text_patterns", "embedded_code", "result_display")}
