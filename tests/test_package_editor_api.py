"""Verify artifact release, privacy, owner capability and failure isolation."""
import hashlib
import io
import threading
import time
import zipfile

import pytest
import requests
from fastapi import FastAPI
from fastapi.testclient import TestClient

from webapp.package_editor_api import EditorJobs, create_editor_router

TOKEN = {"X-Editor-Token": "a" * 64}
OTHER = {"X-Editor-Token": "b" * 64}
SKILL = b"---\nname: example\ndescription: Use this example skill.\n---\n# Example\n"


def package():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(zipfile.ZipInfo("example/SKILL.md", (1980, 1, 1, 0, 0, 0)), SKILL)
    return buffer.getvalue()


def application(scan=None, jobs=None):
    calls = []
    def scanner(data, filename, runtime):
        calls.append((data, filename, runtime))
        return {"files": [{"path": "example/SKILL.md", "sha256": hashlib.sha256(SKILL).hexdigest(), "assessment_state": "text_analyzed", "analysis_coverage": {"extraction": {"status": "complete"}, "text_patterns": {"status": "complete_input"}}}], "governance_evidence": {"artifact_sha256": hashlib.sha256(data).hexdigest()}, "coverage": {"status": "complete_supported_content", "mandatory_components_complete": True},
                "summary": {"total_findings": 0}}
    app = FastAPI()
    slot = threading.BoundedSemaphore(1)
    app.include_router(create_editor_router(scan or scanner, slot, jobs))
    return TestClient(app), calls, slot


def submit(client, **options):
    return client.post("/api/skills/editor/export", headers=TOKEN,
                       files={"file": ("example.skill", package(), "application/zip")},
                       data=options)


def finished(client, url):
    for _ in range(500):
        response = client.get(url, headers=TOKEN)
        if response.status_code != 202:
            return response.json()
        time.sleep(0.01)
    pytest.fail("Editor job did not complete")


def test_inspection_requires_capability_and_local_advice_is_qualified():
    client, calls, slot = application()
    no_token = client.post("/api/skills/editor/inspect",
                          files={"file": ("example.skill", package())})
    assert no_token.status_code == 400
    response = client.post("/api/skills/editor/inspect", headers=TOKEN,
                           files={"file": ("example.skill", package())})
    assert response.status_code == 200
    manifest = response.json()
    assert manifest["archive_sha256"] == hashlib.sha256(package()).hexdigest()
    assert manifest["files"][0]["content"] == SKILL.decode()
    assert "never sent to an LLM" in manifest["advice_source"]
    assert not calls
    assert response.headers["cache-control"] == "no-store"


def test_final_bytes_are_rescanned_and_download_is_owner_scoped():
    client, calls, slot = application()
    response = submit(client, output_format="zip", target_profile="generic-agent-skills")
    assert response.status_code == 202
    receipt = response.json()
    assert client.get(receipt["status_url"], headers=OTHER).status_code == 404
    outcome = finished(client, receipt["status_url"])
    assert outcome["status"] == "ready"
    result = outcome["result"]
    assert result["installation_verified"] is False
    assert len(calls) == 1
    download = client.get(result["download_url"], headers=TOKEN)
    assert download.status_code == 200
    assert download.content == calls[0][0]
    assert hashlib.sha256(download.content).hexdigest() == result["sha256"]
    assert download.headers["x-package-sha256"] == result["sha256"]
    assert client.get(result["download_url"], headers=OTHER).status_code == 404
    assert client.get(result["download_url"]).status_code == 400
    assert "artifact" not in outcome and "owner" not in outcome
    assert "a" * 64 not in str(outcome)


def test_failed_rescan_never_releases_artifact_and_admission_recovers():
    def offline(*args):
        raise requests.ConnectionError("synthetic-private-content-must-not-appear")
    client, calls, slot = application(offline)
    receipt = submit(client).json()
    outcome = finished(client, receipt["status_url"])
    assert outcome["status"] == "failed"
    assert outcome["error"]["stage"] == "sandbox"
    assert "synthetic-private" not in str(outcome)
    assert client.get(receipt["status_url"] + "/download", headers=TOKEN).status_code == 404
    assert slot.acquire(blocking=False)
    slot.release()


def test_malformed_scan_result_fails_closed():
    client, calls, slot = application(lambda *args: {"detail": "Not a report"})
    receipt = submit(client).json()
    outcome = finished(client, receipt["status_url"])
    assert outcome["status"] == "failed"
    assert client.get(receipt["status_url"] + "/download", headers=TOKEN).status_code == 404


def test_busy_operations_are_rejected_without_consuming_other_slot():
    client, calls, slot = application()
    assert slot.acquire(blocking=False)
    response = submit(client)
    assert response.status_code == 429
    assert response.headers["retry-after"] == "3"
    assert not slot.acquire(blocking=False)
    slot.release()
    assert submit(client).status_code == 202


def test_invalid_json_and_validation_failure_do_not_publish():
    client, calls, slot = application()
    assert submit(client, changes='{"not":"an array"}').status_code == 422
    assert submit(client, changes='[{"path":"a","path":"b"}]').status_code == 422
    receipt = submit(client, target_profile="unknown").json()
    result = finished(client, receipt["status_url"])
    assert result["status"] == "failed"
    assert result["error"]["stage"] == "validation"
    assert not calls
    assert client.get(receipt["status_url"] + "/download", headers=TOKEN).status_code == 404


def test_expired_artifacts_disappear():
    now = [0.0]
    jobs = EditorJobs(ttl=1, clock=lambda: now[0])
    client, calls, slot = application(jobs=jobs)
    receipt = submit(client).json()
    result = finished(client, receipt["status_url"])["result"]
    now[0] = 2.0
    assert client.get(receipt["status_url"], headers=TOKEN).status_code == 404
    assert client.get(result["download_url"], headers=TOKEN).status_code == 404


@pytest.mark.parametrize("problem", ["empty", "archive_hash", "file_hash", "skipped", "truncated", "missing_stage", "database", "nested_partial"])
def test_incomplete_evidence_cannot_release_an_acknowledged_download(problem):
    def scanner(data, filename, runtime):
        entry = {"path": "example/SKILL.md", "sha256": hashlib.sha256(SKILL).hexdigest(),
                 "assessment_state": "text_analyzed",
                 "analysis_coverage": {"extraction": {"status": "complete"},
                                      "text_patterns": {"status": "complete_input"}}}
        report = {"files": [entry], "governance_evidence": {"artifact_sha256": hashlib.sha256(data).hexdigest()},
                  "coverage": {"status": "complete_supported_content", "mandatory_components_complete": True},
                  "summary": {"total_findings": 0}}
        if problem == "empty": report["files"] = []
        elif problem == "archive_hash": report["governance_evidence"]["artifact_sha256"] = "0" * 64
        elif problem == "file_hash": entry["sha256"] = "0" * 64
        elif problem == "skipped": entry["skipped"] = True
        elif problem == "truncated": entry["assessment_state"] = "limited_or_truncated"
        elif problem == "missing_stage": entry["analysis_coverage"] = {}
        elif problem == "nested_partial":
            report["files"].append({"path": "example/asset.pptx!/slide.xml", "sha256": "1" * 64, "assessment_state": "text_analyzed", "analysis_coverage": {"extraction": {"status": "partial"}, "text_patterns": {"status": "complete_input"}}})
        elif problem == "database":
            entry["assessment_state"] = "structured_content_analyzed"
            entry["database_profile"] = {"coverage": {"status": "partial", "rows_read": 1, "rows_total": 2, "unread": []}}
        return report
    client, calls, slot = application(scanner)
    receipt = submit(client).json()
    outcome = finished(client, receipt["status_url"])
    assert outcome["status"] == "failed"
    assert outcome["error"]["stage"] == "rescan"
    assert client.get(receipt["status_url"] + "/download?acknowledge_limitations=true", headers=TOKEN).status_code == 404


def test_remaining_findings_require_explicit_download_acknowledgement():
    def scanner(data, filename, runtime):
        return {"files": [{"path": "example/SKILL.md", "sha256": hashlib.sha256(SKILL).hexdigest(),
                          "assessment_state": "text_analyzed",
                          "analysis_coverage": {"extraction": {"status": "complete"}, "text_patterns": {"status": "complete_input"}}}],
                "governance_evidence": {"artifact_sha256": hashlib.sha256(data).hexdigest()},
                "coverage": {"status": "complete_supported_content", "mandatory_components_complete": True},
                "summary": {"total_findings": 1}}
    client, calls, slot = application(scanner)
    receipt = submit(client).json()
    outcome = finished(client, receipt["status_url"])
    assert outcome["status"] == "ready"
    assert outcome["result"]["requires_acknowledgement"] is True
    url = outcome["result"]["download_url"]
    assert client.get(url, headers=TOKEN).status_code == 403
    assert client.get(url + "?acknowledge_limitations=true", headers=TOKEN).status_code == 200


def test_authority_advice_is_scoped_to_instruction_files_not_handbook_policies():
    from webapp.package_editor_api import _recommendations
    manifest = {"files": [{"path": "example/SKILL.md", "content": "No exceptions. No overrides."},
                          {"path": "example/references/handbook.md", "content": "No exceptions. No overrides."}]}
    advice = _recommendations(manifest)
    assert len(advice) == 1
    assert advice[0]["path"] == "example/SKILL.md"
