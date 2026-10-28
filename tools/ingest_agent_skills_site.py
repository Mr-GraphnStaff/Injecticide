"""Capture Agent Skills' complete published documentation and its direct links.

Run explicitly; never called by an uploaded-package scan. Downloaded content is
research data, never imported/executed or used to activate detector rules.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urldefrag, urlsplit, urljoin
from xml.etree import ElementTree

from research_mcp.catalog import Catalog, now
from research_mcp.collector import project, PageParser
from research_mcp.fetch import fetch

SITE = "https://agentskills.io/"
ROOT = Path(__file__).resolve().parents[1]
# The site's reviewed outbound domains, not destinations supplied by uploads.
REFERENCE_HOSTS = {
    "agentskills.io", "bun.sh", "bun.com", "code.visualstudio.com", "deno.com",
    "discord.gg", "discord.com", "docs.astral.sh", "docs.deno.com",
    "docs.npmjs.com", "github.com", "marketplace.visualstudio.com",
    "peps.python.org", "pipx.pypa.io", "pkg.go.dev", "platform.claude.com",
    "rubygems.org", "specifications.freedesktop.org", "www.anthropic.com",
    "raw.githubusercontent.com", "code.claude.com",
}
MAX_DOCUMENTS = 100
MAX_REFERENCES = 200
FULL_TEXT_PREFIXES = (
    SITE,
    "https://raw.githubusercontent.com/agentskills/agentskills/69ef37e9424c0a7ea9dd2293b559e43ec8176379/",
    "https://raw.githubusercontent.com/anthropics/skills/ca45fc496a3436251f191354091d557da31c15b5/skills/skill-creator/",
)


def links(text):
    """Distinct document URLs; preserve fragments separately from fetch identity."""
    return sorted(set(re.findall(r"https://[^\s<>\"')\]`{}]+", text)))


def index_documents(text):
    urls = []
    for raw in links(text):
        url = urldefrag(raw)[0]
        parsed = urlsplit(url)
        if parsed.netloc != "agentskills.io" or parsed.query or not parsed.path.endswith(".md"):
            raise ValueError("Unexpected documentation index destination; review before ingesting")
        urls.append(url)
    if not urls or len(urls) > MAX_DOCUMENTS:
        raise ValueError("Documentation index is empty or exceeds the review budget")
    return sorted(set(urls))


def capture(url, directory, fetcher=fetch):
    record = {"url": url, "retrieved_at": now(), "status": "unknown_unverified"}
    try:
        parsed = urlsplit(url)
        if parsed.hostname not in REFERENCE_HOSTS:
            raise ValueError("New outbound host needs explicit source review")
        # Cross-host redirects are rejected by the existing bounded fetcher.
        response = fetcher(url, ["https://" + parsed.hostname + "/"], max_bytes=2 * 1024 * 1024)
        record.update(http_status=response.status, resolved_url=response.url)
        if response.status != 200:
            raise ValueError("Reference did not return HTTP 200")
        digest = hashlib.sha256(response.body).hexdigest()
        filename = hashlib.sha256(url.encode()).hexdigest()[:24]
        text, _ = project(response)
        (directory / (filename + ".source")).write_bytes(response.body)
        (directory / (filename + ".txt")).write_text(text, encoding="utf-8")
        record.update(status="retrieved", sha256=digest, bytes=len(response.body),
                      media=response.headers.get("content-type", ""),
                      raw_file=filename + ".source", text_file=filename + ".txt")
        return record, text, response
    except (OSError, ValueError, TimeoutError) as error:
        record["reason"] = str(error)
        return record, None, None


def ingest(output, fetcher=fetch):
    output.mkdir(parents=True, exist_ok=False)
    snapshots = output / "snapshots"
    snapshots.mkdir()
    index_row, index, _ = capture(SITE + "llms.txt", snapshots, fetcher)
    sitemap_row, sitemap, _ = capture(SITE + "sitemap.xml", snapshots, fetcher)
    if index is None or sitemap is None:
        raise ValueError("Cannot establish site coverage without both index and sitemap")
    documents = index_documents(index)
    tree = ElementTree.fromstring(sitemap)
    sitemap_urls = {node.text for node in tree.findall("{*}url/{*}loc")}
    indexed_urls = {url.removesuffix(".md") for url in documents}
    if sitemap_urls != indexed_urls:
        raise ValueError("Index and sitemap differ; review omitted or additional pages")
    # Explicit approved seeds keep discovery from silently enabling new sources.
    catalog = Catalog(output / "research.sqlite3", ROOT / "research_mcp/sources.json")
    records, edges, html_edges = [index_row, sitemap_row], [], []
    texts = {}
    for url in documents:
        row, text, response = capture(url, snapshots, fetcher)
        records.append(row)
        if text is not None:
            texts[url] = text
            catalog.record({"source": "agent-skills", "url": url}, response, text, [])
            edges.extend({"source": url, "target": target, "fetch_url": urldefrag(target)[0]}
                         for target in links(text))
        html_url = url.removesuffix(".md")
        html_row, _, html_response = capture(html_url, snapshots, fetcher)
        html_row["role"] = "site_html_representation"
        records.append(html_row)
        if html_response is not None:
            parser = PageParser()
            parser.feed(html_response.body.decode("utf-8", errors="replace"))
            html_edges.extend({"source": html_url, "target": urljoin(html_url, target),
                               "fetch_url": urldefrag(urljoin(html_url, target))[0]}
                              for target in parser.links
                              if urlsplit(urljoin(html_url, target)).scheme == "https")
    references = sorted({edge["fetch_url"] for edge in edges} - set(documents) - {SITE + "llms.txt"})
    if len(references) > MAX_REFERENCES:
        raise ValueError("Outbound references exceed the explicit review budget")
    known = {row["url"] for row in records}
    fetch_references = sorted((set(references) | {edge["fetch_url"] for edge in html_edges}) - known)
    if len(fetch_references) > MAX_REFERENCES:
        raise ValueError("Combined HTML/Markdown references exceed the review budget")
    with ThreadPoolExecutor(max_workers=4) as pool:
        captured = list(pool.map(lambda url: capture(url, snapshots, fetcher), fetch_references))
    for row, _, _ in captured:
        row["role"] = "direct_outbound_reference"
        records.append(row)
    recipe_path = ROOT / "research_mcp/reference_docs/agent-skills/ingestion_recipe.json"
    supplements = json.loads(recipe_path.read_text(encoding="utf-8"))["supplemental_references"] if recipe_path.exists() else []
    if len(supplements) > MAX_REFERENCES:
        raise ValueError("Supplemental references exceed the explicit review budget")
    for url in supplements:
        row, _, _ = capture(url, snapshots, fetcher)
        row["role"] = "linked_source_supplement"
        records.append(row)
    result = {"schema_version": 1, "captured_at": now(),
              "scope": "All pages in both the official documentation index and sitemap, plus every direct HTTPS reference in their Markdown. Outbound sites are not recursively mirrored.",
              "documentation_pages": len(documents),
              "documentation_complete": all(url in texts for url in documents),
              "direct_references": len(references),
              "retrieved": sum(row["status"] == "retrieved" for row in records),
              "unavailable": sum(row["status"] != "retrieved" for row in records),
              "records": records, "links": edges, "html_links": html_edges, "supplemental_references": supplements,
              "automatic_rule_activation": False,
              "review_status": "Captured content requires semantic review; retrieval is not verification or implementation.",
              "attribution": "Agent Skills contributors. Upstream documentation is CC-BY-4.0; linked sources retain their own licenses. Source URLs and raw-byte hashes are retained."}
    (output / "manifest.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def export_library(evidence, destination):
    """Package captured text and provenance, without changing scanner rules."""
    evidence, destination = Path(evidence), Path(destination)
    manifest = json.loads((evidence / "manifest.json").read_text(encoding="utf-8"))
    destination.mkdir(parents=True, exist_ok=False)
    manifest["evidence_scope"] = "Captured source text; byte-identical raw responses are retained in the ingestion evidence directory. Text has its own integrity hash."
    for row in manifest["records"]:
        row["id"] = hashlib.sha256(row["url"].encode()).hexdigest()[:24]
        row.setdefault("role", "site_document" if row["url"].endswith(".md") else "site_index")
        if row.get("text_file"):
            raw = (evidence / "snapshots" / row["text_file"]).read_bytes()
            # Full Agent Skills documentation and explicitly licensed pinned
            # examples are redistributable with their retained attribution and
            # notices. Other linked sites retain a short attributed excerpt;
            # their complete raw captures stay in local research evidence.
            full_text = row["url"].startswith(FULL_TEXT_PREFIXES)
            if not full_text:
                raw = (" ".join(raw.decode("utf-8").split()[:200]) + "\n").encode("utf-8")
            row["text_scope"] = "full_licensed_source_text" if full_text else "attributed_excerpt_max_200_words"
            row["text_sha256"] = hashlib.sha256(raw).hexdigest()
            (destination / row["text_file"]).write_bytes(raw)
        row.pop("raw_file", None)
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="New evidence directory; never overwrites")
    args = parser.parse_args(argv)
    result = ingest(args.output)
    print(json.dumps({key: result[key] for key in ("documentation_pages", "documentation_complete", "direct_references", "retrieved", "unavailable")}, indent=2))
    return 0 if result["documentation_complete"] and not result["unavailable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
