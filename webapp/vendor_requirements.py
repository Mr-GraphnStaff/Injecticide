"""Per-scan vendor evidence check through Research MCP; uploads stay local."""
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

RUNTIMES = {"openai", "openai-mcp-import", "claude-code", "claude-upload", "gemini", "copilot"}
HOSTS = {"developers.openai.com", "code.claude.com", "support.claude.com",
         "geminicli.com", "docs.github.com"}
UNKNOWN = "STATUS: UNKNOWN — UNVERIFIED"


def unknown(runtime, reason):
    return {"status": "unknown", "verification": UNKNOWN, "runtime": runtime,
            "reason": reason, "live_check": False, "runtime_tested": False,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "requirements": [], "documents": [], "compatibility": "unknown"}


def _validate(data, runtime):
    if (not isinstance(data, dict) or data.get("runtime") != runtime
            or data.get("status") not in {"unknown", "current_documented_requirements"}
            or not isinstance(data.get("requirements"), list)
            or not isinstance(data.get("documents"), list)
            or len(data["requirements"]) > 20 or len(data["documents"]) > 5):
        raise ValueError("Invalid vendor evidence")
    checked = datetime.fromisoformat(data["checked_at"])
    if not 0 <= (datetime.now(timezone.utc) - checked).total_seconds() <= 120:
        raise ValueError("Evidence response is not from this run")
    for item in data["documents"] + data["requirements"]:
        if not isinstance(item, dict):
            raise ValueError("Invalid vendor evidence entry")
        url = urlsplit(item.get("url", item.get("source_url", "")))
        if (url.scheme != "https" or url.hostname not in HOSTS or url.username
                or url.password or url.port not in (None, 443)):
            raise ValueError("Vendor evidence URL is outside selected vendors")
    for rule in data["requirements"]:
        if (not isinstance(rule.get("field"), str) or not isinstance(rule.get("note"), str)
                or rule.get("status") not in {"unknown", "vendor_documented"}
                or not (rule.get("value") is None or type(rule["value"]) is int
                        or isinstance(rule["value"], str)
                        or isinstance(rule["value"], list) and all(isinstance(v, str) for v in rule["value"]))):
            raise ValueError("Invalid documented requirement")
    if data["status"] == "current_documented_requirements" and (
            data.get("live_check") is not True or not data["documents"]
            or any(d.get("state") != "unchanged" for d in data["documents"])):
        raise ValueError("Live vendor evidence is incomplete")
    return data


def check_vendor(runtime):
    if runtime not in RUNTIMES:
        return unknown(runtime, "Select OpenAI, Claude Code, Claude upload, Gemini or Copilot for vendor verification.")
    origin = os.environ.get("RESEARCH_MCP_URL", "").rstrip("/")
    if not origin:
        return unknown(runtime, "Research MCP is not configured; vendor compatibility is unverified.")
    try:
        with requests.Session() as session:
            session.trust_env = False
            # Only runtime is sent: no filenames, package bytes, findings or credentials.
            with session.post(origin + "/requirements/check", json={"runtime": runtime},
                              timeout=(2, 8), stream=True, allow_redirects=False) as response:
                if response.status_code != 200:
                    raise ValueError("Research MCP unavailable")
                chunks, size, started = [], 0, time.monotonic()
                for block in response.iter_content(8192):
                    size += len(block)
                    if size > 65536 or time.monotonic() - started > 3:
                        raise ValueError("Research evidence exceeds budget")
                    chunks.append(block)
                return _validate(json.loads(b"".join(chunks)), runtime)
    except (requests.RequestException, ValueError, TypeError, KeyError, OverflowError):
        return unknown(runtime, "Live vendor check unavailable, timed out or returned invalid evidence; no cached pass was substituted.")


def attach_vendor_check(result):
    analysis = result.get("package_analysis", {})
    runtime = analysis.get("target_runtime", "auto")
    if runtime == "auto":
        candidates = {item["runtime"] for item in analysis.get("runtime_targets", [])}
        # Ambiguous/generic packages must not silently inherit one vendor's rules.
        runtime = next(iter(candidates)) if len(candidates) == 1 else "auto"
    evidence = check_vendor(runtime)
    checks = []
    for rule in evidence.get("requirements", []):
        field = rule.get("field")
        if evidence.get("status") != "current_documented_requirements" or rule.get("status") != "vendor_documented":
            continue
        limit = rule.get("value")
        if type(limit) is not int or not 0 < limit <= 100000000:
            continue
        def add(path, observed, complete=True):
            checks.append({"field": field, "path": path, "maximum": limit,
                "observed": observed, "status": "unknown" if observed is None else "fail" if observed > limit else "pass" if complete else "unknown",
                "source_url": rule["source_url"]})
        complete_inventory = result.get("coverage", {}).get("status") == "complete_supported_content"
        if field == "import_max_skills":
            add("package", len(analysis.get("skills", [])), complete_inventory)
        for skill in analysis.get("skills", []):
            if field in {"name_max_characters", "description_max_characters", "compatibility_max_characters"}:
                key = field.removesuffix("_max_characters")
                add(skill["path"], skill.get("field_lengths", {}).get(key))
                continue
            root = skill.get("root", "").rstrip("/")
            if root == ".":
                root = ""
            inventory = [item for item in result.get("inventory", [])
                         if not root or item["path"].startswith(root + "/")]
            sizes = [item.get("size") for item in inventory]
            complete_sizes = bool(sizes) and all(type(size) is int and size >= 0 for size in sizes)
            if field == "skill_max_files":
                add(skill["path"], len(inventory) if inventory else None, complete_inventory)
            elif field == "skill_resources_max_bytes":
                add(skill["path"], sum(sizes) if complete_sizes else None, complete_inventory)
            elif field in {"skill_md_max_bytes", "supporting_file_max_bytes"}:
                for item in inventory:
                    if (item["path"] == skill["path"]) == (field == "skill_md_max_bytes"):
                        add(item["path"], item.get("size"))
        if field in {"generated_archives_max_bytes", "catalog_max_pages"}:
            add("MCP import process (not executed by static scan)", None)
    evidence["checks"] = checks
    evidence["compatibility"] = "fails_documented_requirement" if any(c["status"] == "fail" for c in checks) else "unknown"
    # Never certify all assets/outputs/size limits based on a metadata-only check.
    evidence["statement"] = "Vendor evidence and individual checks are separate from static security findings. Overall runtime acceptance is not verified."
    result["vendor_verification"] = evidence
    result.setdefault("readiness", {})["vendor_compatibility"] = evidence["compatibility"]
    return result
