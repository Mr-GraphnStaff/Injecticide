"""Bounded packaged-text footprint, not observed model or billing usage.

Loading stages: https://agentskills.io/specification#progressive-disclosure
Request/tokenizer limits: https://developers.openai.com/api/docs/guides/token-counting
No provider calls, tokenizer downloads, uploaded execution or source reflection.
"""
from __future__ import annotations

import math
import posixpath
import re

try:
    from .package_formats import frontmatter
except ImportError:
    from package_formats import frontmatter

MAX_FILES = 500
MAX_CHARACTERS = 2 * 1024 * 1024
MAX_SKILLS = 100
MAX_TOP_FILES = 20


def _measure(text):
    characters = len(text)
    non_ascii = sum(ord(character) > 127 for character in text)
    suitable = (not characters or non_ascii / characters <= .05) and not re.search(r"[A-Za-z0-9+/=]{512,}", text)
    return {"characters": characters, "utf8_bytes": len(text.encode("utf-8")),
            "lines": len(text.splitlines()), "exact_tokens": None,
            "estimated_tokens": math.ceil(characters / 4) if suitable else None,
            "estimate_method": "illustrative_four_characters_per_token" if suitable else "not_assessed",
            "estimate_reason": "Rough mostly-ASCII text proxy; not a tokenizer measurement or guaranteed bound." if suitable else "Language or encoded-content mix makes the text proxy unsuitable."}


def _sum_measures(rows):
    return {key: sum(row[key] for row in rows) for key in ("characters", "utf8_bytes", "lines")} | {
        "exact_tokens": None,
        "estimated_tokens": sum(row["estimated_tokens"] for row in rows) if all(row["estimated_tokens"] is not None for row in rows) else None,
        "estimate_method": "sum_of_per_file_text_proxies", "file_count": len(rows)}


def build_token_footprint(text_sources, inventory=None, relationship_graph=None):
    files, texts, limits = [], {}, []
    extraction_by_path = {row.get("path"): row.get("analysis_coverage", {}).get("extraction", {})
                          for row in inventory or []}
    remaining = MAX_CHARACTERS
    for index, source in enumerate(text_sources):
        if index >= MAX_FILES:
            limits.append({"kind": "footprint_file_budget"})
            break
        path, text = source.get("path"), source.get("text")
        if not isinstance(path, str) or not isinstance(text, str) or path in texts:
            continue
        supplied = text[:remaining]
        remaining -= len(supplied)
        if len(supplied) != len(text):
            limits.append({"kind": "footprint_character_budget", "path": path})
        texts[path] = supplied
        extraction = extraction_by_path.get(path, {})
        projection_complete = len(supplied) == len(text)
        source_complete = extraction.get("status") not in {"partial", "not_performed"}
        files.append({"path": path, "complete_text": projection_complete and source_complete,
                      "complete_extracted_projection": projection_complete,
                      "source_extraction_status": extraction.get("status", "not_reported"), **_measure(supplied)})
        if not source_complete:
            limits.append({"kind": "partial_source_extraction", "path": path})
        if remaining == 0:
            limits.append({"kind": "footprint_character_budget"})
            break
    by_path = {row["path"]: row for row in files}
    inventory_paths = {row.get("path") for row in inventory or [] if isinstance(row.get("path"), str)}
    missing = inventory_paths - texts.keys()
    if missing:
        limits.append({"kind": "inventory_without_extracted_text", "file_count": len(missing)})
    skills = []
    entrypoints = sorted(path for path in texts if posixpath.basename(path) == "SKILL.md")
    for path in entrypoints[:MAX_SKILLS]:
        text = texts[path]
        root = posixpath.dirname(path)
        boundary = path.rsplit("!/", 1)[0] + "!/" if "!/" in path else ""
        metadata = None
        try:
            data = frontmatter(text)
            if isinstance(data.get("name"), str) and isinstance(data.get("description"), str):
                metadata = _measure(data["name"] + "\n" + data["description"])
        except (ValueError, RecursionError):
            pass
        references = set()
        for edge in (relationship_graph or {}).get("edges", [])[:2000]:
            target = edge.get("target")
            if (edge.get("source") == path and edge.get("status") == "resolved"
                    and edge.get("kind") in {"document_reference", "resource_reference", "prose_resource_reference"}
                    and target in by_path and target != path):
                references.add(target)
        prefix = root + "/" if root else boundary
        descendant_roots = [posixpath.dirname(other) for other in entrypoints if other != path
                            and posixpath.dirname(other) != root and posixpath.dirname(other).startswith(prefix)
                            and other.count("!/") == path.count("!/")]
        supporting = [row for row in files if row["path"] != path
                      and row["path"].startswith(root + "/" if root else boundary)
                      and row["path"].count("!/") == path.count("!/")
                      and not any(row["path"].startswith(other_root + "/") for other_root in descendant_roots)]
        skills.append({"path": path, "metadata_discovery": metadata,
                       "main_instructions": by_path[path],
                       "directly_referenced_text": _sum_measures([by_path[target] for target in sorted(references)]),
                       "packaged_supporting_text": _sum_measures(supporting),
                       "reference_paths": sorted(references),
                       "scenario_scope": "Each listed text loaded once; supporting files are optional and may never enter model context. Main instructions include the supplied frontmatter.",
                       "guidance": ["Consider moving supporting detail into on-demand references while retaining essential instructions."] if by_path[path]["lines"] >= 500 else []})
    if len(entrypoints) > MAX_SKILLS:
        limits.append({"kind": "footprint_skill_budget", "omitted_skills": len(entrypoints) - MAX_SKILLS})
    return {"schema_version": 1, "status": "partial" if limits else "complete_extracted_text" if files else "not_assessed",
            "measurement": "extracted_text_characters_and_utf8_bytes", "tokenizer": None,
            "runtime_usage": "not_assessed", "model": None, "skills": skills,
            "extracted_text_total": _sum_measures(files),
            "largest_text_files": sorted(files, key=lambda row: (-row["characters"], row["path"]))[:MAX_TOP_FILES],
            "limits": limits, "sources": ["https://agentskills.io/specification#progressive-disclosure",
                                            "https://developers.openai.com/api/docs/guides/token-counting"],
            "limitations": ["Token figures are illustrative text proxies, not exact tokenizer counts or a forecast of per-run usage.",
                            "No universal token-hunger grade: model, language, loading choices and the task change usage.",
                            "Tool output, retries, generated output, reasoning, message wrappers, caching and external material are not measured.",
                            "Binary assets, inaccessible or omitted text and OCR/vision tokenization are not included."]}
