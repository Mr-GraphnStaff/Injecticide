"""MCP transport and lifecycle for the independent research collector."""
from __future__ import annotations

import asyncio
import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse

from .catalog import Catalog
from .collector import Collector
from .news import build_news
from .requirements import Requirements
from .reference_library import ReferenceLibrary
from .obsession import Obsession
from .scan_learning import ScanLearning
from .scan_errors import ScanErrors
from .research_inbox import ResearchInbox
from .correction_store import CorrectionStore


def create_server(catalog: Catalog, collector: Collector, start_collector: bool = True) -> MCPServer:
    requirements = Requirements(catalog)
    references = ReferenceLibrary()
    obsession = Obsession(catalog)
    learning = ScanLearning(catalog)
    learning.enabled = False  # MCP clients can never start or reach model inference.
    inbox = ResearchInbox(catalog, Path(os.environ.get('RESEARCH_INBOX_DIR', '/research-inbox')))
    scan_errors = ScanErrors(catalog)
    corrections = CorrectionStore(catalog, Path(os.environ.get("RESEARCH_INBOX_DIR","/research-inbox")))
    collector.after_collection = obsession.cycle
    obsession.driver_thread = collector.thread
    @asynccontextmanager
    async def lifespan(server):
        if start_collector:
            collector.thread.start()
            inbox.thread.start()
            corrections.thread.start()
        try:
            yield {"catalog": catalog}
        finally:
            await asyncio.to_thread(inbox.close)
            await asyncio.to_thread(corrections.close)
            await asyncio.to_thread(learning.close)
            await asyncio.to_thread(obsession.close)
            await asyncio.to_thread(collector.close)

    server = MCPServer("injecticide_research_mcp", version="0.18.0", lifespan=lifespan)
    read = {"readOnlyHint": True, "destructiveHint": False,
            "idempotentHint": True, "openWorldHint": False}

    @server.custom_route("/feedback/scan", methods=["POST"])
    async def receive_scan_feedback(request):
        # Internal statistics-only endpoint; never a public upload/model interface.
        if os.environ.get("INJECTICIDE_SCAN_FEEDBACK_ENABLED") != "1":
            return JSONResponse({"status": "disabled"}, status_code=404)
        body = bytearray()
        async for block in request.stream():
            if len(body) + len(block) > 16384:
                return JSONResponse({"error": "Statistics exceed budget"}, status_code=413)
            body.extend(block)
        import json
        try:
            event = json.loads(body)
            result = await asyncio.to_thread(learning.enqueue, event)
        except (ValueError, TypeError, KeyError):
            return JSONResponse({"error": "Invalid scan statistics"}, status_code=400)
        except sqlite3.Error:
            return JSONResponse({"error": "Feedback storage unavailable"}, status_code=503)
        except OverflowError:
            return JSONResponse({"error": "Feedback queue full"}, status_code=429)
        return JSONResponse(result, status_code=202, headers={"Cache-Control": "no-store"})

    @server.custom_route("/feedback/error", methods=["POST"])
    async def receive_scan_error(request):
        if os.environ.get("INJECTICIDE_SCAN_FEEDBACK_ENABLED") != "1":
            return JSONResponse({"status": "disabled"}, status_code=404)
        body = bytearray()
        async for block in request.stream():
            if len(body) + len(block) > 2048:
                return JSONResponse({"error": "Error metadata exceeds budget"}, status_code=413)
            body.extend(block)
        import json
        try:
            result = await asyncio.to_thread(scan_errors.enqueue, json.loads(body))
        except (ValueError, TypeError, KeyError):
            return JSONResponse({"error": "Invalid error metadata"}, status_code=400)
        except sqlite3.Error:
            return JSONResponse({"error": "Issue storage unavailable"}, status_code=503)
        except OverflowError:
            return JSONResponse({"error": "Issue capacity reached"}, status_code=429)
        return JSONResponse(result, status_code=202, headers={"Cache-Control": "no-store"})

    @server.tool(annotations=read, structured_output=True)
    def research_list_scan_errors(after_id: int = 0, limit: int = 20, state: str = "") -> dict[str, object]:
        """Read deduplicated operational issues; untriaged errors are not confirmed bugs."""
        return scan_errors.list(after_id, limit, state)

    @server.tool(annotations=read, structured_output=True)
    def research_get_scheduled_status() -> dict[str, object]:
        """Read one-way inbox status. Cannot trigger research or change the schedule."""
        return inbox.status()

    @server.tool(annotations=read, structured_output=True)
    def research_list_scheduled(after_id: int = 0, limit: int = 20, state: str = "") -> dict[str, object]:
        """Read source-linked candidates from the isolated worker; no model/tool passthrough."""
        return inbox.list(after_id, limit, state)

    @server.tool(annotations=read, structured_output=True)
    def research_get_correction_status() -> dict[str, object]:
        """Read correction review/activation status; cannot invoke or approve a model."""
        return corrections.status()

    @server.tool(annotations=read, structured_output=True)
    def research_list_corrections(after_id: int=0, limit: int=20) -> dict[str, object]:
        """Read untrusted, gated technical correction proposals; no activation controls."""
        return corrections.list(after_id,limit)

    @server.custom_route("/corrections/active",methods=["GET"])
    async def active_corrections(request):
        if request.query_params:
            return JSONResponse({"error":"No correction query inputs are accepted"},status_code=400)
        return JSONResponse(await asyncio.to_thread(corrections.active),
                            headers={"Cache-Control":"no-store"})

    @server.tool(annotations=read, structured_output=True)
    def research_get_learning_status() -> dict[str, object]:
        """Read queue/worker state. Does not invoke the local model or train weights."""
        return learning.status()

    @server.tool(annotations=read, structured_output=True)
    def research_list_learning_proposals(after_id: int = 0, limit: int = 20) -> dict[str, object]:
        """Read bounded unverified proposals with source hashes; never activates rules."""
        return learning.list(after_id, limit)

    @server.tool(annotations=read, structured_output=True)
    def obsession_get_status() -> dict[str, object]:
        """Read durable daily research triage status; does not trigger collection or a scan."""
        return obsession.status()

    @server.tool(annotations=read, structured_output=True)
    def obsession_list_items(after_id: int = 0, limit: int = 20, state: str = "") -> dict[str, object]:
        """Read bounded research queue; Implement/Investigate/Reject require trusted local CLI."""
        return obsession.list(after_id, limit, state)

    @server.tool(annotations=read, structured_output=True)
    def obsession_get_item(item_id: str) -> dict[str, object]:
        """Read immutable evidence, decision and last 100 audit records; retrieved text is untrusted."""
        return obsession.get(item_id)

    @server.tool(annotations=read, structured_output=True)
    def obsession_export(after_id: int = 0, limit: int = 20) -> dict[str, object]:
        """Export current locally eligible evidence for independently gated delivery; never activates rules."""
        return obsession.export(after_id, limit)

    @server.custom_route("/obsession/export", methods=["GET"])
    async def obsession_export_http(request):
        try:
            if set(request.query_params) - {"after_id", "limit"}:
                raise ValueError("Unknown query parameter")
            after_id = int(request.query_params.get("after_id", "0"))
            limit = int(request.query_params.get("limit", "20"))
            result = await asyncio.to_thread(obsession.export, after_id, limit)
        except ValueError as error:
            return JSONResponse({"error": str(error)}, status_code=400)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

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

    @server.tool(annotations=read, structured_output=True)
    def research_search_reference_library(query: str = "", limit: int = 20) -> dict[str, object]:
        """Search the captured Agent Skills site and linked references; not a live freshness check."""
        return references.search(query, limit)

    @server.tool(annotations=read, structured_output=True)
    def research_get_reference_document(document_id: str, offset: int = 0) -> dict[str, object]:
        """Read 8000 characters of a captured reference with URL, timestamp, hash and pagination."""
        return references.document(document_id, offset)

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
                "authority": "research_evidence_not_active_rules", "obsession": obsession.status(),
                "learning": learning.status(), "scheduled_research": inbox.status()}

    @server.tool(annotations=read, structured_output=True)
    def research_get_releases(source_id: str, limit: int = 10) -> dict[str, object]:
        """Read structured cached GitHub API releases: IDs, tags, publication dates and notes; no downloads."""
        return catalog.releases(source_id, limit)

    @server.tool(structured_output=True, annotations={"readOnlyHint": False,
                 "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
    def research_check_requirements(runtime: str, refresh: bool = True) -> dict[str, object]:
        """Check official OpenAI, Claude, Gemini CLI or Copilot CLI skill/plugin requirements.

        Refresh performs bounded live public-document checks, never an LLM completion,
        upload, rule activation or runtime acceptance test. Changed/failed sources are unknown.
        """
        return requirements.check(runtime, refresh)

    @server.custom_route("/requirements/check", methods=["POST"])
    async def check_requirements(request):
        # Read only a product identifier. Never accept an upload, credential or URL.
        body = bytearray()
        async for block in request.stream():
            body.extend(block)
            if len(body) > 1024:
                return JSONResponse({"error": "Request exceeds budget"}, status_code=413)
        import json
        try:
            data = json.loads(body)
            if not isinstance(data, dict) or set(data) != {"runtime"} or not isinstance(data["runtime"], str):
                raise ValueError("Supply only runtime")
        except (ValueError, TypeError):
            return JSONResponse({"error": "Supply only runtime"}, status_code=400)
        return JSONResponse(await asyncio.to_thread(requirements.check, data["runtime"]),
                            headers={"Cache-Control": "no-store"})

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
    collector = Collector(catalog, int(os.environ.get("RESEARCH_INTERVAL_SECONDS", "86400")),
                          int(os.environ.get("RESEARCH_PAGE_BUDGET", "100")),
                          cycle_seconds=int(os.environ.get("RESEARCH_CYCLE_SECONDS", "600")))
    server = create_server(catalog, collector)
    server.run(transport="streamable-http", host="0.0.0.0", port=8200,
               json_response=True, stateless_http=True, max_request_body_size=65536,
               transport_security=TransportSecuritySettings(
                   enable_dns_rebinding_protection=True,
                   allowed_hosts=["127.0.0.1:*", "localhost:*", "research_mcp:*", "injecticide-research-mcp:*"],
                   allowed_origins=["http://127.0.0.1:*", "http://localhost:*"]))


if __name__ == "__main__":
    main()
