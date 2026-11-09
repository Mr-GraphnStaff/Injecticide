"""Privacy regression for retired scan inference and the active research transport."""
import json
import pytest
from skill_sandbox.local_analysis import analyze_local

def forbidden(*args, **kwargs):
    pytest.fail("A public scan or retired raw-text API attempted model transport")

def test_retired_api_never_reads_or_transmits_sensitive_text():
    raw = "private.person@example.invalid 4111111111111111 patient-record-unguessable"
    result = analyze_local([{"path": raw, "text": raw}], {"private": raw}, transport=forbidden)
    assert result["status"] == "not_assessed"
    assert result["findings"] == []
    assert raw not in json.dumps(result)

@pytest.mark.parametrize("enabled", [None, "0", "1"])
@pytest.mark.parametrize("requested", [None, False, True])
def test_scanner_flags_cannot_restore_model_transport(monkeypatch, enabled, requested):
    from skill_sandbox.app import scan_upload
    if enabled is None:
        monkeypatch.delenv("INJECTICIDE_LOCAL_LLM_ENABLED", raising=False)
    else:
        monkeypatch.setenv("INJECTICIDE_LOCAL_LLM_ENABLED", enabled)
    monkeypatch.setattr("skill_sandbox.local_analysis._chat", forbidden)
    monkeypatch.setattr("research_mcp.local_model._chat", forbidden)
    result = scan_upload(b"Read documentation.", "SKILL.md", use_local_llm=requested)
    assert not result.get("local_analysis", {}).get("findings")

@pytest.mark.parametrize("endpoint", ["https://remote.example", "http://127.0.0.1/path", "http://user:pass@localhost", "http://localhost/?x=y"])
def test_research_model_transport_rejects_remote_or_ambiguous_endpoints(monkeypatch, endpoint):
    from research_mcp.local_model import complete
    monkeypatch.setenv("INJECTICIDE_LOCAL_LLM_URL", endpoint)
    with pytest.raises(ValueError):
        complete("system", {"public_sources": []}, {}, transport=forbidden)

def test_transport_checks_server_cloud_status_before_sending_content():
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import pytest
    from research_mcp.local_model import _chat
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            calls.append(self.path)
            self.send_response(200); self.end_headers()
            self.wfile.write(b'{"cloud":{"disabled":false}}')
        def do_POST(self):
            calls.append(self.path)
            self.send_response(500); self.end_headers()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        with pytest.raises(subprocess.CalledProcessError):
            _chat("http://127.0.0.1:"+str(server.server_port), {"model":"qwen3.5:2b","messages":[{"content":"private"}]})
        assert calls == ["/api/status"]
    finally:
        server.shutdown(); server.server_close(); thread.join()

def test_total_transport_deadline_kills_slow_client(monkeypatch):
    import subprocess
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import pytest
    from research_mcp import local_model as local_analysis
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            self.send_response(200); self.end_headers()
            try:
                for _ in range(30):
                    self.wfile.write(b" "); self.wfile.flush(); time.sleep(.05)
            except (BrokenPipeError, ConnectionResetError): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    monkeypatch.setattr(local_analysis, "REQUEST_DEADLINE_SECONDS", .5)
    start = time.monotonic()
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            local_analysis._chat("http://127.0.0.1:"+str(server.server_port), {"model":"qwen3.5:2b"})
        assert time.monotonic()-start < 3
    finally:
        server.shutdown(); server.server_close(); thread.join()
