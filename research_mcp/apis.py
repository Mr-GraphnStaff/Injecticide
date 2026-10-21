"""Read-only public API adapters; no provider credentials or remote code loading.

GitHub contract: https://docs.github.com/en/rest/releases/releases#list-releases
Rate policy: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
"""
import json
import re
from urllib.parse import parse_qsl, urlsplit

API_CONNECTORS = {"github_releases", "github_advisories", "mcp_registry", "crossref"}


def api_connector(url: str) -> str | None:
    """Recognize provider contracts, never a generic permission to send queries.

    Sources: GitHub global-advisories REST docs; official MCP registry API;
    https://www.crossref.org/documentation/retrieve-metadata/rest-api/ .
    All list queries are deliberately first-page bounded in this increment.
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    params = dict(pairs)
    if len(params) != len(pairs):
        return None
    if is_github_releases_url(url):
        return "github_releases" if not params or params in ({"per_page": "1"}, {"per_page": "5"}) else None
    if parts.hostname == "api.github.com" and parts.path == "/advisories":
        if (set(params) == {"ecosystem", "affects", "per_page"}
                and params["ecosystem"] in ("pip", "npm") and params["per_page"] == "10"
                and params["affects"] in {"mcp", "@modelcontextprotocol/sdk", "langchain", "langchain-core"}):
            return "github_advisories"
    if parts.hostname == "registry.modelcontextprotocol.io" and parts.path == "/v0.1/servers":
        if params == {"limit": "10"}:
            return "mcp_registry"
    if parts.hostname == "api.crossref.org" and parts.path == "/works":
        if (set(params) == {"query", "rows"} and params["rows"] == "5"
                and params["query"] in {"prompt injection", "agent security"}):
            return "crossref"
    return None


def normalize_api(connector: str, body: bytes) -> dict:
    """Validate bounded provider records; returned content stays untrusted."""
    data = json.loads(body)
    coverage = "bounded first page only; not complete synchronization"
    if connector == "github_releases":
        return {"records": github_releases(body), "coverage": coverage}
    if connector == "github_advisories":
        if not isinstance(data, list) or len(data) > 10:
            raise ValueError("Expected at most ten advisory records")
        records = []
        for item in data:
            if not isinstance(item, dict) or not isinstance(item.get("ghsa_id"), str):
                raise ValueError("Invalid advisory record")
            records.append({k: item.get(k) for k in ("ghsa_id", "cve_id", "summary", "description", "html_url", "updated_at", "withdrawn_at", "vulnerabilities")})
    elif connector == "mcp_registry":
        if not isinstance(data, dict) or not isinstance(data.get("servers"), list) or len(data["servers"]) > 10:
            raise ValueError("Expected at most ten MCP registry records")
        records = []
        for item in data["servers"]:
            server = item.get("server") if isinstance(item, dict) else None
            if not isinstance(server, dict) or not all(isinstance(server.get(k), str) for k in ("name", "version")):
                raise ValueError("Invalid MCP registry server")
            records.append({k: server.get(k) for k in ("name", "version", "description", "repository")})
    elif connector == "crossref":
        message = data.get("message") if isinstance(data, dict) else None
        if not isinstance(message, dict) or not isinstance(message.get("items"), list) or len(message["items"]) > 5:
            raise ValueError("Expected at most five Crossref records")
        records = []
        for item in message["items"]:
            if not isinstance(item, dict) or not isinstance(item.get("DOI"), str):
                raise ValueError("Invalid Crossref work")
            records.append({k: item.get(k) for k in ("DOI", "title", "URL", "published", "updated", "relation", "update-to")})
    else:
        raise ValueError("Unsupported API connector")
    return {"records": records, "coverage": coverage}

GITHUB_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"}


def is_github_releases_url(url: str) -> bool:
    parts = urlsplit(url)
    return parts.hostname == "api.github.com" and bool(re.fullmatch(
        r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases", parts.path))


def github_releases(body: bytes) -> list[dict]:
    data = json.loads(body)
    if not isinstance(data, list) or len(data) > 30:
        raise ValueError("Expected a bounded GitHub releases list (at most 30)")
    records = []
    for item in data:
        if not isinstance(item, dict) or type(item.get("id")) is not int:
            raise ValueError("Invalid GitHub release record")
        for field in ("tag_name", "html_url"):
            if not isinstance(item.get(field), str):
                raise ValueError("Invalid GitHub release fields")
        records.append({"id": item["id"], "tag": item["tag_name"],
            "name": item.get("name"), "published_at": item.get("published_at"),
            "prerelease": item.get("prerelease"), "draft": item.get("draft"),
            "url": item["html_url"], "notes": str(item.get("body") or "")[:6000]})
    return records
