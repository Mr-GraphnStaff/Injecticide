"""Exercise the real static scanner through the editor API."""
import hashlib
import io
import threading
import time
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from skill_sandbox.app import scan_upload
from webapp.package_editor_api import create_editor_router


def test_actual_final_bytes_are_scanned_without_executing_packaged_code():
    original = io.BytesIO()
    with zipfile.ZipFile(original, "w") as archive:
        archive.writestr("example/SKILL.md", "---\nname: example\ndescription: Summarize a local example.\n---\n# Example\n")
        archive.writestr("example/scripts/probe.py", "raise AssertionError('Packaged code must never execute')\n")
    observed = []
    def real_scan(data, filename, runtime):
        observed.append(hashlib.sha256(data).hexdigest())
        return scan_upload(data, filename, runtime, use_local_llm=False)
    app = FastAPI()
    app.include_router(create_editor_router(real_scan, threading.BoundedSemaphore(1)))
    with TestClient(app) as client:
        headers = {"X-Editor-Token": "c" * 64}
        response = client.post("/api/skills/editor/export", headers=headers,
                               files={"file": ("example.skill", original.getvalue())},
                               data={"target_profile": "generic-agent-skills", "output_format": "skill"})
        assert response.status_code == 202
        receipt = response.json()
        for _ in range(1000):
            status = client.get(receipt["status_url"], headers=headers)
            if status.status_code != 202:
                break
            time.sleep(0.01)
        outcome = status.json()
        assert outcome["status"] == "ready", outcome
        result = outcome["result"]
        report = result["scan_result"]
        assert report["governance_evidence"]["artifact_sha256"] == result["sha256"] == observed[0]
        assert report["coverage"]["mandatory_components_complete"] is True
        download = client.get(result["download_url"] + "?acknowledge_limitations=true", headers=headers)
        assert download.status_code == 200
        assert hashlib.sha256(download.content).hexdigest() == result["sha256"]
        with zipfile.ZipFile(io.BytesIO(download.content)) as rebuilt:
            assert b"raise AssertionError" in rebuilt.read("example/scripts/probe.py")


def test_root_rescan_wrapper_forces_model_off(monkeypatch):
    from webapp import api
    calls = []
    def scan(*args, **kwargs):
        calls.append(kwargs)
        return {"files": []}
    monkeypatch.setattr(api, "_scan_skill_data", scan)
    result = api._rescan_edited_package(b"source-owned fixture", "example.skill", "auto")
    assert calls == [{"use_local_llm": False}]
    assert len(result["scan_request_id"]) == 32
