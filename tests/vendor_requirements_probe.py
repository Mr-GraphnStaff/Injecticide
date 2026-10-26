"""Explicit live, public-doc-only probe; never collected as a pytest test.

Run: python tests/vendor_requirements_probe.py --output-dir <scratch directory>
Requires the existing research MCP dependencies. No LLM completions or uploads.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time

import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from research_mcp.catalog import Catalog
from research_mcp.collector import Collector
from research_mcp.server import create_server
from webapp.api import _scan_skill_data


def probe(output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    catalog = Catalog(output_dir / "probe.sqlite3", ROOT / "research_mcp/sources.json")
    app = create_server(catalog, Collector(catalog), start_collector=False)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app.streamable_http_app(stateless_http=True),
                                         log_level="error"))
    worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    previous = os.environ.get("RESEARCH_MCP_URL")
    os.environ["RESEARCH_MCP_URL"] = f"http://127.0.0.1:{port}"
    worker.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        if not server.started:
            raise RuntimeError("Local research server did not start")
        registry = json.loads((ROOT / "research_mcp/requirements.json").read_text())
        summaries = []
        fixture = ("---\nname: demo\ndescription: " + "x" * 201 + "\n---\nSummarize the supplied text.\n").encode()
        for runtime in registry["profiles"]:
            result = _scan_skill_data(fixture, "demo/SKILL.md", "text/markdown", runtime, "{}", None)
            evidence = result["vendor_verification"]
            summary = {"runtime": runtime, "status": evidence["status"],
                       "live_check": evidence["live_check"], "compatibility": evidence["compatibility"],
                       "reason": evidence.get("reason"), "refresh_state": evidence.get("refresh_state"),
                       "documents": evidence["documents"], "checks": evidence["checks"]}
            summaries.append(summary)
            print(json.dumps(summary), flush=True)
        (output_dir / "results.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
        return summaries
    finally:
        server.should_exit = True
        worker.join(timeout=30)
        listener.close()
        if previous is None:
            os.environ.pop("RESEARCH_MCP_URL", None)
        else:
            os.environ["RESEARCH_MCP_URL"] = previous


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    probe(parser.parse_args().output_dir)
