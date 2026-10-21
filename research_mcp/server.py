"""MCP transport and lifecycle for the independent research collector."""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse

from .catalog import Catalog
from .collector import Collector
from .news import build_news


def create_server(catalog: Catalog, collector: Collector, start_collector: bool = True) -> MCPServer:
    @asynccontextmanager
    async def lifespan(server):
        if start_collector:
            collector.thread.start()
        try:
            yield {"catalog": catalog}
        finally:
            await asyncio.to_thread(collector.close)

    server = MCPServer("injecticide_research_mcp", version="0.5.0", lifespan=lifespan)
    read = {"readOnlyHint": True, "destructiveHint": False,
            "idempotentHint": True, "openWorldHint": False}

    @server.tool(annotations=read, structured_output=True)
    def research_list_sources() -> dict[str, object]:
        """List approved source scopes, frontier limits, freshness and collection failures."""
        return catalog.list_sources()

    @server.tool(annotations=read, structured_output=True)
    def research_search(query: str, source_id: str = "", after_id: int = 0, limit: int = 20) -> dict[str, object]:
        """Search latest captured documents by literal text; paginated, source-attributed, unverified evidence."""
        return catalog.query(query, source_id, after_id, limit)

    @server.tool(annotations=read, structured_output=True)
    def research_get_changes(after_id: int = 0, source_id: str = "", limit: int = 20) -> dict[str, object]:
        """List retained new/changed snapshots after a cursor, including initial baselines; not semantic verification."""
        return catalog.query(source_id=source_id, after_id=after_id, limit=limit, latest_only=False)

    @server.tool(annotations=read, structured_output=True)
    def research_get_snapshot(snapshot_id: int, offset: int = 0) -> dict[str, object]:
        """Read up to 8000 characters of an untrusted snapshot plus URL, timestamp and content hash."""
        return catalog.snapshot(snapshot_id, offset)

    @server.tool(structured_output=True, annotations={"readOnlyHint": False, "destructiveHint": False,
                              "idempotentHint": False, "openWorldHint": True})
    def research_refresh_source(source_id: str) -> dict[str, object]:
        """Queue a bounded refresh of an existing approved source; no arbitrary URLs or rule activation."""
        return collector.request(source_id)

    @server.tool(annotations=read, structured_output=True)
    def research_get_status() -> dict[str, object]:
        """Get worker status and configured collection budgets. Freshness is reported separately per source."""
        return {**collector.status, "worker_alive": collector.thread.is_alive(),
                "interval_seconds": collector.interval, "page_budget": collector.page_budget,
                "authority": "research_evidence_not_active_rules"}

    @server.tool(annotations=read, structured_output=True)
    def research_get_releases(source_id: str, limit: int = 10) -> dict[str, object]:
        """Read structured cached GitHub API releases: IDs, tags, publication dates and notes; no downloads."""
        return catalog.releases(source_id, limit)

    @server.custom_route("/health", methods=["GET"])
    async def health(request):
        healthy = not start_collector or collector.thread.is_alive()
        return JSONResponse({"status": "ok" if healthy else "worker_stopped",
                             **collector.status}, status_code=200 if healthy else 503)

    @server.custom_route("/news", methods=["GET"])
    async def news(request):
        # Read-only projection shared with the web app; no MCP write tools are proxied.
        return JSONResponse(await asyncio.to_thread(build_news, catalog, collector),
                            headers={"Cache-Control": "no-store"})

    return server


def main():
    catalog = Catalog(Path(os.environ.get("RESEARCH_DB", "/data/research.sqlite3")),
                      Path(os.environ.get("RESEARCH_SOURCES", Path(__file__).with_name("sources.json"))))
    collector = Collector(catalog, int(os.environ.get("RESEARCH_INTERVAL_SECONDS", "3600")),
                          int(os.environ.get("RESEARCH_PAGE_BUDGET", "40")))
    server = create_server(catalog, collector)
    server.run(transport="streamable-http", host="0.0.0.0", port=8200,
               json_response=True, stateless_http=True, max_request_body_size=65536,
               transport_security=TransportSecuritySettings(
                   enable_dns_rebinding_protection=True,
                   allowed_hosts=["127.0.0.1:*", "localhost:*", "research_mcp:*", "injecticide-research-mcp:*"],
                   allowed_origins=["http://127.0.0.1:*", "http://localhost:*"]))


if __name__ == "__main__":
    main()
