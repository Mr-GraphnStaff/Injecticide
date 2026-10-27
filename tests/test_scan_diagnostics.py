import requests
from fastapi.testclient import TestClient

from webapp import api


def test_scan_success_has_matching_request_id_without_logging_payload(monkeypatch):
    monkeypatch.setattr(api, "_scan_skill_data", lambda *args: {"files": []})
    result = TestClient(api.app).post("/api/skills/scan", files={"file": ("demo.md", b"synthetic")})
    assert result.status_code == 200
    assert result.headers["X-Scan-Request-ID"] == result.json()["scan_request_id"]
    assert result.json()["scan_diagnostics"]["payload_logged"] is False


def test_invalid_input_and_busy_scan_explain_failure_stage():
    client = TestClient(api.app)
    invalid = client.post("/api/skills/scan", files={"file": ("demo.md", b"text")},
                          data={"target_runtime": "not-a-product"})
    assert invalid.status_code == 400
    assert invalid.json()["detail"]["stage"] == "validation"
    assert invalid.headers["X-Scan-Request-ID"] == invalid.json()["detail"]["request_id"]
    assert api.SKILL_SCAN_SLOT.acquire(blocking=False)
    try:
        busy = client.post("/api/skills/scan", files={"file": ("demo.md", b"text")})
    finally:
        api.SKILL_SCAN_SLOT.release()
    assert busy.status_code == 429 and busy.json()["detail"]["stage"] == "admission"


def test_framework_rejection_has_sanitized_correlated_diagnostics():
    response = TestClient(api.app).post("/api/skills/scan", data={})
    assert response.status_code == 422
    assert response.json()["detail"]["stage"] == "validation"
    assert response.headers["X-Scan-Request-ID"] == response.json()["detail"]["request_id"]
    malformed = TestClient(api.app).post("/api/skills/scan", data={"file": "SECRET_INVALID_FILE_FIELD"})
    assert malformed.status_code == 422 and "SECRET_INVALID_FILE_FIELD" not in malformed.text
    assert malformed.headers["X-Scan-Request-ID"] == malformed.json()["detail"]["request_id"]


def test_sandbox_validation_stage_is_preserved_by_correlation_middleware(monkeypatch):
    def reject(*args):
        raise api.HTTPException(status_code=422, detail="upstream-private-detail")
    monkeypatch.setattr(api, "_scan_skill_data", reject)
    response = TestClient(api.app).post("/api/skills/scan", files={"file": ("demo.md", b"text")})
    assert response.status_code == 422
    assert response.json()["detail"]["stage"] == "sandbox"
    assert "upstream-private-detail" not in response.text
    assert response.headers["X-Scan-Request-ID"] == response.json()["detail"]["request_id"]


def test_sandbox_failure_can_be_retried_and_does_not_expose_exception(monkeypatch):
    def fail(*args):
        raise requests.ConnectionError("private-upload-content-must-not-leak")
    monkeypatch.setattr(api, "_scan_skill_data", fail)
    client = TestClient(api.app)
    response = client.post("/api/skills/scan", files={"file": ("demo.md", b"text")})
    assert response.status_code == 502
    assert response.json()["detail"]["stage"] == "sandbox"
    assert "private-upload-content" not in response.text
    monkeypatch.setattr(api, "_scan_skill_data", lambda *args: {"files": []})
    assert client.post("/api/skills/scan", files={"file": ("demo.md", b"text")}).status_code == 200


def test_analysis_and_validation_diagnostics_never_reflect_private_values(monkeypatch, caplog):
    sentinel = "SECRET_SENTINEL_NOT_A_PUBLIC_DIAGNOSTIC"
    def fail(*args):
        raise ValueError(sentinel)
    monkeypatch.setattr(api, "_scan_skill_data", fail)
    client = TestClient(api.app)
    response = client.post("/api/skills/scan", files={"file": ("demo.md", b"text")})
    assert response.status_code == 400
    assert response.json()["detail"]["stage"] == "analysis"
    assert sentinel not in response.text and sentinel not in caplog.text
    response = client.post("/api/skills/scan", files={"file": ("demo.md", b"text")},
        data={"governance_evidence": '{"' + sentinel + '":1,"' + sentinel + '":2}'})
    assert response.status_code == 400 and sentinel not in response.text
