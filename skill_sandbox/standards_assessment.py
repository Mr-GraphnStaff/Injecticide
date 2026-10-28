"""Measured Agent Skills conformance; vendor, security and runtime remain separate.

Run before the common report redactor. Source excerpts are intentionally avoided:
only fixed explanations, measured counts, paths and exact field lines are emitted.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path, PurePosixPath

try:
    from .package_formats import BASE_FIELDS, ParserLimitError, frontmatter, portable_skill_checks
except ImportError:
    from package_formats import BASE_FIELDS, ParserLimitError, frontmatter, portable_skill_checks

MAX_SKILLS = 200
MAX_ROWS = 6000
UNKNOWN = "STATUS: UNKNOWN — UNVERIFIED"


@lru_cache(maxsize=1)
def load_standards_catalog():
    return json.loads((Path(__file__).parent / "rules" / "skill_standards.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _source_catalog():
    return json.loads((Path(__file__).parent / "rules" / "standards_sources.json").read_text(encoding="utf-8"))


def _layout(text):
    """Return exact top-level field lines and unrestricted Markdown body bounds."""
    lines = text.splitlines()
    positions, close = {}, None
    if lines and lines[0].strip() == "---":
        for index, line in enumerate(lines[1:], 2):
            if line.strip() == "---":
                close = index
                break
            match = re.match(r"^([A-Za-z][A-Za-z0-9_-]*):", line)
            if match:
                positions[match[1]] = index
    return positions, close, max(0, len(lines) - close) if close else None


def build_standards_assessment(result, text_sources):
    catalog = load_standards_catalog()
    source = dict(catalog["source"])
    definitions = {row["id"]: row for row in catalog["requirements"]}
    analysis = result.get("package_analysis") or {}
    target = analysis.get("target_runtime", "auto")
    texts = {s["path"]: s["text"] for s in text_sources
             if isinstance(s, dict) and isinstance(s.get("path"), str) and isinstance(s.get("text"), str)}
    inventory = {}
    for entry in list(result.get("files") or []) + list(result.get("inventory") or []):
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            inventory.setdefault(entry["path"], entry)
    paths = [path for path in inventory if PurePosixPath(path).name.lower() == "skill.md"]
    rows, limits = [], []
    omitted_rows = 0

    def add(rule_id, status, message, path=None, line=None, applicability="applicable", **details):
        nonlocal omitted_rows
        if len(rows) >= MAX_ROWS:
            omitted_rows += 1
            return
        definition = definitions[rule_id]
        row = {**definition, "status": status, "applicability": applicability,
               "path": path, "line": line, "message": message,
               "evidence": [{"path": path, "line": line, "text": message}] if path else [],
               "sources": [{"url": source["url"], "title": source.get("title", "Agent Skills specification"),
                            "section": definition["section"], "revision": source.get("revision"),
                            "source_sha256": source.get("source_sha256")}], **details}
        # The specification is not an authority for security/runtime validation;
        # those rows expose unsupported areas rather than invented standards.
        if definition["category"] in {"security", "runtime_evaluation"} or rule_id == "vendor_runtime_compatibility":
            row["sources"] = []
        rows.append(row)

    archive = result.get("file_type") in {"zip", "tar"}
    supplied_skill_dirs = {str(PurePosixPath(path).parent) for path in paths}
    collection_hints = {}
    for path in inventory:
        if any(directory == "." or path.startswith(directory.rstrip("/") + "/") for directory in supplied_skill_dirs):
            continue
        parts = PurePosixPath(path).parts
        for index, part in enumerate(parts[:-1]):
            if part == "skills" and index + 2 < len(parts):
                collection_hints.setdefault("/".join(parts[:index + 2]), path)
                if len(collection_hints) > MAX_SKILLS:
                    break
        if len(collection_hints) > MAX_SKILLS:
            limits.append({"kind": "standards_collection_hint_count"})
            break
    for directory, evidence_path in list(collection_hints.items())[:MAX_SKILLS]:
        add("skill_collection_intent", "not_assessed", "A directory named skills is not proof that its child directories are skills. Collection intent and any missing entrypoint remain unverified.", evidence_path)
    if not paths:
        incomplete_inventory = any(e.get("skipped") or (e.get("analysis_coverage", {}).get("format_validation") or {}).get("status") == "partial" for e in inventory.values()) or result.get("coverage", {}).get("status") == "partial"
        missing = archive and target == "generic" and not analysis.get("packages") and not incomplete_inventory
        add("skill_entrypoint", "fail" if missing else "not_assessed" if not analysis.get("packages") else "not_applicable",
            "The supplied portable skill archive lacks SKILL.md." if missing else "No skill entrypoint was identified; package intent or complete directory structure is unavailable.",
            applicability="applicable" if not analysis.get("packages") else "not_applicable")
    if len(paths) > MAX_SKILLS:
        limits.append({"kind": "standards_skill_count", "omitted_skills": len(paths) - MAX_SKILLS})
    for path in paths[:MAX_SKILLS]:
        entry, text = inventory[path], texts.get(path)
        add("skill_entrypoint", "pass" if PurePosixPath(path).name == "SKILL.md" else "fail",
            "Required SKILL.md filename is present." if PurePosixPath(path).name == "SKILL.md" else "Skill entrypoint filename must be exactly SKILL.md.", path)
        positions, close, body_lines = _layout(text) if text is not None else ({}, None, None)
        parsed, parse_status = None, "not_assessed"
        parse_message = "Skill content was not supplied to the format parser."
        if text is not None:
            try:
                parsed = frontmatter(text)
                parse_status, parse_message = "pass", "YAML frontmatter is a mapping under the local bounded parser."
            except ParserLimitError:
                parse_message = "A local parser safety limit prevents assessment; this does not establish invalid portable format."
            except ValueError:
                parse_status, parse_message = "fail", "Missing, unterminated, non-mapping or invalid YAML frontmatter."
        add("yaml_frontmatter", parse_status, parse_message, path, 1 if text is not None else None)
        checks = portable_skill_checks(parsed, path) if parsed is not None else [
            {"id": rule_id, "status": "not_assessed", "message": "Field constraints cannot be assessed without parsed frontmatter."}
            for rule_id in ("name_required", "name_length", "name_characters", "name_hyphens", "name_directory_match", "description_required", "description_length", "compatibility_value", "metadata_value", "allowed_tools_value")]
        for check in checks:
            key = "name" if check["id"].startswith("name_") else "description" if check["id"].startswith("description_") else check["id"].removesuffix("_value").replace("_", "-")
            add(check["id"], check["status"], check["message"], path, positions.get(key),
                applicability="not_applicable" if check["status"] == "not_applicable" else "applicable")
        add("markdown_body", "pass" if parsed is not None else "not_assessed",
            "The body has no additional portable format restrictions; instructional completeness and quality are not assessed.", path, close)
        license_present = parsed is not None and "license" in parsed
        license_string = license_present and isinstance(parsed["license"], str)
        add("license_value", "pass" if license_string else "not_assessed" if license_present or parsed is None else "not_applicable",
            "License text is present; legal meaning and bundled license references are not verified." if license_string else "License representation is not assessed; the shared specification does not provide a complete normative type/validity rule.",
            path, positions.get("license"), applicability="applicable" if license_present or parsed is None else "not_applicable")
        extras = parsed is not None and bool(set(parsed) - BASE_FIELDS)
        add("frontmatter_extensions", "not_assessed" if extras or parsed is None else "not_applicable",
            "Additional frontmatter fields do not automatically invalidate portable base constraints; vendor support and unknown extension semantics are unverified.", path,
            applicability="applicable" if extras or parsed is None else "not_applicable")
        coverage = entry.get("analysis_coverage") or {}
        incomplete = any((coverage.get(stage) or {}).get("status") == "partial" for stage in ("extraction", "text_patterns"))
        complete_lines = len(text.splitlines()) if text is not None and not incomplete else None
        line_status = "not_assessed" if body_lines is None or complete_lines is None else "pass" if complete_lines < 500 else "fail"
        add("body_line_guidance", line_status,
            "Authoring recommendation: keep SKILL.md under 500 lines. Count is unavailable for incomplete input." if line_status == "not_assessed" else f"Authoring recommendation: keep SKILL.md under 500 lines; measured complete file contains {complete_lines} lines.",
            path, measured_lines=complete_lines)
        add("body_token_guidance", "not_assessed", "Fewer than 5000 instruction tokens is recommended. Token count is unavailable; no tokenizer was run.", path, token_measurement="not_available")
        add("description_trigger_quality", "not_assessed", "Whether the description communicates when to use the skill requires semantic and behavioral evaluation.", path, positions.get("description"))
    add("vendor_runtime_compatibility", "not_assessed", "Portable syntax does not establish acceptance by the selected vendor, installed version or managed environment.")
    add("security_coverage", "not_assessed", "Measured security findings are reported separately. These detectors do not establish complete OWASP coverage, absence of malicious behavior or safe execution.")
    for rule_id, message in (
        ("trigger_accuracy", "Trigger precision and recall require a labeled runtime evaluation; none was performed."),
        ("output_quality", "Output quality requires representative runtime tasks and reviewed results; none was performed."),
        ("script_behavior", "Script behavior and environment compatibility were not executed or verified."),
        ("runtime_control_enforcement", "Runtime permissions, approvals and enforcement were not verified."),
    ):
        add(rule_id, "not_assessed", message)
    if omitted_rows:
        limits.append({"kind": "standards_requirement_rows", "omitted_rows": omitted_rows})
    mandatory = [r for r in rows if r["category"] == "format" and r["requirement_level"] == "mandatory" and r["status"] != "not_applicable"]
    counts = Counter(r["status"] for r in mandatory)
    provenance_verified = bool(source.get("source_sha256") and source.get("revision"))
    overall = "fail" if counts["fail"] else "not_assessed" if counts["not_assessed"] or limits or not provenance_verified else "pass" if mandatory else "not_applicable"
    guidance = dict(_source_catalog()["security_guidance"])
    observed = {f["id"] for e in result.get("files", []) for f in e.get("findings", []) if isinstance(f, dict) and isinstance(f.get("id"), str)}
    guidance["risks"] = [{**risk, "status": "not_assessed", "risk_exploitability": "not_assessed", "runtime_enforcement": "not_assessed",
                          "observed_detector_ids": sorted(observed.intersection(risk["related_detector_ids"])),
                          "observation_scope": "Detector relevance only; not verified risk, coverage or compliance."} for risk in guidance["risks"]]
    return {"schema_version": 1, "standard": catalog["standard"], "source": source,
            "profile_scope": "Explicit portable profile" if target == "generic" else "Portable observations; selected vendor acceptance is separate",
            "overall_status_scope": "applicable_mandatory_portable_format_checks_only", "overall_status": overall,
            "summary": {"mandatory_pass": counts["pass"], "mandatory_fail": counts["fail"], "mandatory_not_assessed": counts["not_assessed"],
                        "recommendations_attention": sum(r["requirement_level"] == "recommendation" and r["status"] in {"fail", "not_assessed"} for r in rows),
                        "skills_assessed": min(len(paths), MAX_SKILLS), "omitted_skills": max(0, len(paths) - MAX_SKILLS), "omitted_rows": omitted_rows},
            "requirements": rows, "limits": limits, "security_guidance": guidance,
            "limitations": ["A pass applies only to the listed measured portable format constraints, not vendor compatibility, security or runtime behavior.",
                            "Static syntax cannot establish trigger accuracy, output quality, script behavior or permission enforcement.",
                            "A source-content SHA-256 identifies the reviewed snapshot; it is not an upstream release version."]}
