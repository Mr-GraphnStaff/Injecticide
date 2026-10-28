"""Explicit, read-only comparison of reviewed standards source fingerprints.

No package data is accepted or transmitted. This command never activates rules,
changes catalog files, installs dependencies or executes downloaded content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

import requests

CATALOG = Path(__file__).resolve().parents[1] / "skill_sandbox/rules/standards_sources.json"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCES = 40
HOSTS = {"agentskills.io", "learn.chatgpt.com", "code.claude.com", "peps.python.org",
         "docs.astral.sh", "owasp.org", "owasp.github.io", "pipx.pypa.io",
         "docs.npmjs.com", "docs.deno.com", "bun.sh", "docs.python.org", "raw.githubusercontent.com"}


def check_sources(catalog=None, session=None):
    catalog = catalog if catalog is not None else json.loads(CATALOG.read_text(encoding="utf-8"))
    if session is None:
        with requests.Session() as client:
            client.trust_env = False
            return check_sources(catalog, client)
    results = []
    for source in catalog.get("sources", [])[:MAX_SOURCES]:
        item = {"id": source["id"], "source_url": source["url"],
                "reviewed_sha256": source["source_sha256"], "status": "unknown_unverified"}
        try:
            parsed = urlsplit(source["url"])
            if (parsed.scheme != "https" or parsed.hostname not in HOSTS or parsed.username
                    or parsed.password or parsed.port not in (None, 443) or parsed.query or parsed.fragment):
                raise ValueError("Source URL is outside the reviewed retrieval profile")
            digest, size = hashlib.sha256(), 0
            with session.get(source["url"], timeout=(3, 10), stream=True, allow_redirects=False) as response:
                if response.status_code != 200:
                    raise ValueError("Source unavailable or redirected; requires review")
                for chunk in response.iter_content(8192):
                    size += len(chunk)
                    if size > MAX_SOURCE_BYTES:
                        raise ValueError("Source exceeds retrieval budget")
                    digest.update(chunk)
            item.update(observed_sha256=digest.hexdigest(), observed_bytes=size)
            item["status"] = ("unchanged_reviewed_snapshot" if digest.hexdigest() == source["source_sha256"]
                              else "changed_review_required")
        except (requests.RequestException, ValueError, TypeError):
            item["reason"] = "Source could not be compared within the reviewed retrieval profile. No cached pass substituted."
        results.append(item)
    omitted = max(0, len(catalog.get("sources", [])) - MAX_SOURCES)
    return {"scope": "Source-byte comparison only; change does not establish semantic incompatibility.",
            "automatic_rule_activation": False, "results": results, "omitted_sources": omitted,
            "review_required": not results or any(r["status"] != "unchanged_reviewed_snapshot" for r in results) or bool(omitted)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional new JSON file; existing files are never overwritten")
    args = parser.parse_args(argv)
    if args.output and args.output.exists():
        parser.error("Output already exists")
    result = check_sources()
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        print(rendered, end="")
    return 2 if not result["results"] or result["omitted_sources"] or any(r["status"] == "unknown_unverified" for r in result["results"]) else 1 if result["review_required"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
