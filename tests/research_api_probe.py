"""Operator-run candidate probe: real collector -> catalog -> MCP.

Run inside the isolated research candidate, after its first scheduled cycle.
Does not install packages, modify scanner rules, or accept arbitrary source URLs.
It observes the next scheduled cycle and manually refreshes the five new sources.
"""
import asyncio
import json
from datetime import datetime, timezone

from mcp.client import Client

SOURCES = ("mcp-advisories", "mcp-js-advisories", "langchain-advisories",
           "mcp-registry", "crossref-prompt-injection")


async def main():
    async with Client("http://127.0.0.1:8200/mcp") as client:
        tools = await client.list_tools()
        assert len(tools.tools) == 7

        async def read(name, args=None):
            result = await client.call_tool(name, args or {})
            assert not result.is_error, name
            assert isinstance(result.structured_content, dict), name
            return result.structured_content

        status = await read("research_get_status")
        first = status["last_cycle"]
        assert first, "Wait for the first scheduled cycle before running this probe"
        deadline = asyncio.get_running_loop().time() + 660
        while True:
            status = await read("research_get_status")
            if status["last_cycle"] != first and not status["running"]:
                break
            assert asyncio.get_running_loop().time() < deadline, "Second scheduled cycle did not complete"
            await asyncio.sleep(10)
        second = status["last_cycle"]
        print(json.dumps({"second_scheduled_cycle": second, "result": status["last_result"]}), flush=True)

        requested = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        for source_id in SOURCES:
            queued = await read("research_refresh_source", {"source_id": source_id})
            assert queued["status"] == "queued", (source_id, queued)
        deadline = asyncio.get_running_loop().time() + 240
        while True:
            sources = (await read("research_list_sources"))["sources"]
            selected = [source for source in sources if source["id"] in SOURCES]
            if (len(selected) == len(SOURCES) and all(source["errors"] == 0 and
                    source["oldest_success"] and source["oldest_success"] >= requested for source in selected)):
                break
            assert asyncio.get_running_loop().time() < deadline, "Manual API refresh failed or remained incomplete"
            await asyncio.sleep(5)
        provenance = []
        for source in selected:
            query = await read("research_search", {"query": "", "source_id": source["id"], "limit": 1})
            item = query["items"][0]
            snapshot = await read("research_get_snapshot", {"snapshot_id": item["id"]})
            assert snapshot["sha256"] == item["sha256"]
            provenance.append({"source": source["id"], "snapshot": item["id"],
                               "hash_matches": True, "last_success": source["oldest_success"]})
        print(json.dumps({"tools": len(tools.tools), "scheduled_cycles": [first, second],
                          "manual_requested": requested, "provenance": provenance,
                          "coverage": "bounded first-page sampling, not full upstream synchronization"}, indent=2), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
