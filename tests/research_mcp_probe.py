"""Operator-run transport probe; never installs a plugin or activates a rule.

Run inside the research image against its loopback MCP endpoint.
"""
import asyncio
import json

from mcp.client import Client


async def main():
    async with Client("http://127.0.0.1:8200/mcp") as client:
        tools = await client.list_tools()
        assert len(tools.tools) == 7
        status = await client.call_tool("research_get_status", {})
        sources = await client.call_tool("research_list_sources", {})
        changes = await client.call_tool("research_get_changes", {"limit": 50})
        assert not status.is_error and not sources.is_error and not changes.is_error
        releases = await client.call_tool("research_get_releases", {"source_id": "codex-releases", "limit": 2})
        assert not releases.is_error
        release_data = dict(releases.structured_content)
        release_data["releases"] = [{k: r[k] for k in ("id", "tag", "published_at", "url")}
                                    for r in release_data["releases"]]
        items = changes.structured_content["items"]
        if items:
            snapshot = await client.call_tool("research_get_snapshot", {"snapshot_id": items[0]["id"]})
            assert snapshot.structured_content["sha256"] == items[0]["sha256"]
        print(json.dumps({"tool_names": [tool.name for tool in tools.tools],
            "status": status.structured_content,
            "api_releases": release_data,
            "sources": [{k: s[k] for k in ("id", "pages", "errors", "freshness")}
                        for s in sources.structured_content["sources"]],
            "retained_changes": len(items),
            "sample_provenance": [{k: item[k] for k in ("source", "url", "sha256", "verification")}
                                  for item in items[:3]]}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
