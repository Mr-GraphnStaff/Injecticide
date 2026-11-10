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



def complete_coverage():
    return {'extraction': {'status': 'complete'}, 'text_patterns': {'status': 'complete_input'},
            'embedded_code': {'status': 'complete_input'}, 'decoded_text': {'status': 'complete_supported_candidates'},
            'code_security': {'status': 'not_performed'}, 'result_display': {'status': 'complete'}}

def application(scan=None, jobs=None):
    calls = []
    def scanner(data, filename, runtime):
        calls.append((data, filename, runtime))
        return {"files": [{"path": "example/SKILL.md", "sha256": hashlib.sha256(SKILL).hexdigest(), "assessment_state": "text_analyzed", "analysis_coverage": complete_coverage()}], "governance_evidence": {"artifact_sha256": hashlib.sha256(data).hexdigest()}, "coverage": {"status": "complete_supported_content", "mandatory_components_complete": True},
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
                 "analysis_coverage": complete_coverage()}
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
    assert outcome["error"]["stage"] == "checking_coverage"
    assert client.get(receipt["status_url"] + "/download?acknowledge_limitations=true", headers=TOKEN).status_code == 404


def test_remaining_findings_require_explicit_download_acknowledgement():
    def scanner(data, filename, runtime):
        return {"files": [{"path": "example/SKILL.md", "sha256": hashlib.sha256(SKILL).hexdigest(),
                          "assessment_state": "text_analyzed",
                          "analysis_coverage": complete_coverage()}],
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


def test_worker_reports_real_stage_elapsed_and_completion_without_exposing_owner():
    entered, proceed, released = threading.Event(), threading.Event(), threading.Event()
    now = [1.0]
    jobs = EditorJobs(clock=lambda: now[0])
    def work(progress):
        progress('rescanning', 'Synthetic scanner is running.')
        entered.set()
        assert proceed.wait(3)
        progress('checking_coverage', 'Synthetic coverage check.')
        return {'filename': 'example.skill', 'sha256': '1' * 64}, b'owned artifact'
    key = jobs.submit('owner', work, released.set, with_progress=True)
    try:
        assert entered.wait(2)
        now[0] = 4.0
        state = jobs.get(key, 'owner')
        assert state['status'] == 'running'
        assert state['progress'] == {'stage': 'rescanning', 'message': 'Synthetic scanner is running.', 'elapsed_seconds': 3.0}
        assert 'owner' not in state and 'artifact' not in state
        assert jobs.get(key, 'different-owner') is None
    finally:
        proceed.set()
    assert released.wait(3)
    for _ in range(100):
        state = jobs.get(key, 'owner')
        if state['status'] == 'ready': break
        time.sleep(.01)
    assert state['progress']['stage'] == 'ready'
    assert jobs.get(key, 'owner', artifact=True)[0] == b'owned artifact'


@pytest.mark.parametrize('stage', ['embedded_code', 'decoded_text', 'code_security', 'result_display'])
def test_optional_refinement_limits_are_preserved_and_require_download_ack(stage):
    def scanner(data, filename, runtime):
        coverage = complete_coverage()
        coverage[stage] = {'status': 'partial', 'reason': 'Synthetic bounded refinement limit.', 'scope': 'Raw text inspection completed; this refinement is limited.'}
        return {'files': [{'path': 'example/SKILL.md', 'sha256': hashlib.sha256(SKILL).hexdigest(),
                          'assessment_state': 'text_analyzed', 'analysis_coverage': coverage}],
                'governance_evidence': {'artifact_sha256': hashlib.sha256(data).hexdigest()},
                'coverage': {'status': 'complete_supported_content', 'mandatory_components_complete': True},
                'summary': {'total_findings': 0}}
    client, _, _ = application(scanner)
    receipt = submit(client).json()
    outcome = finished(client, receipt['status_url'])
    assert outcome['status'] == 'ready'
    result = outcome['result']
    assert result['requires_acknowledgement']
    assert result['verification']['analysis_limitations'][0]['stage'] == stage
    assert result['verification']['analysis_limitations'][0]['reason'] == 'Synthetic bounded refinement limit.'
    assert client.get(result['download_url'], headers=TOKEN).status_code == 403
    assert client.get(result['download_url'] + '?acknowledge_limitations=true', headers=TOKEN).status_code == 200


@pytest.mark.parametrize('status', ['error', 'failed', 'limited', 'future_schema', None])
def test_unsuccessful_or_unknown_refinement_is_not_an_acknowledgeable_limit(status):
    def scanner(data, filename, runtime):
        coverage = complete_coverage()
        coverage['decoded_text'] = {'status': status}
        return {'files': [{'path': 'example/SKILL.md', 'sha256': hashlib.sha256(SKILL).hexdigest(),
                          'assessment_state': 'text_analyzed', 'analysis_coverage': coverage}],
                'governance_evidence': {'artifact_sha256': hashlib.sha256(data).hexdigest()},
                'coverage': {'status': 'complete_supported_content', 'mandatory_components_complete': True},
                'summary': {'total_findings': 0}}
    client, _, _ = application(scanner)
    receipt = submit(client).json()
    outcome = finished(client, receipt['status_url'])
    assert outcome['status'] == 'failed'
    assert outcome['error']['stage'] == 'checking_coverage'
    assert client.get(receipt['status_url'] + '/download?acknowledge_limitations=true', headers=TOKEN).status_code == 404


def test_actual_office_receipt_is_required_and_tampered_counters_fail_closed():
    from webapp.package_editor_api import _verify_scan, RescanIncomplete
    from skill_sandbox import app as scanner
    import copy
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('[Content_Types].xml', '<Types/>')
        archive.writestr('ppt/presentation.xml', '<presentation/>')
    entry, _ = scanner._scan_file_bytes('example/asset.pptx', buffer.getvalue())
    report = {'files': [entry], 'governance_evidence': {'artifact_sha256': '1' * 64},
              'coverage': {'status': 'partial', 'mandatory_components_complete': True}, 'summary': {'total_findings': 0}}
    manifest = {'entries': [{'path': entry['path'], 'sha256': entry['sha256']}]}
    verification = _verify_scan(report, manifest, '1' * 64)
    assert verification['requires_acknowledgement']
    for change in ('schema', 'hash', 'container', 'missing_omissions', 'counter_bool', 'excluded'):
        mutated = copy.deepcopy(report)
        office = mutated['files'][0]['office_profile']
        if change == 'schema': office['schema'] = 'unrecognized'
        elif change == 'hash': office['sha256'] = '0' * 64
        elif change == 'container': office['container_inspection']['status'] = 'partial'
        elif change == 'missing_omissions': del office['coverage']['omitted']
        elif change == 'counter_bool': office['coverage']['xml_parts_read'] = True
        else: office['excluded_member_count'] = 1
        with pytest.raises(RescanIncomplete):
            _verify_scan(mutated, manifest, '1' * 64)


@pytest.mark.parametrize("stage,status,accepted", [
    ("code_security", "complete_supported_syntax", True),
    ("code_security", "complete_supported_embedded_syntax", True),
    ("result_display", "complete_supported_syntax", False),
    ("embedded_code", "complete_supported_embedded_syntax", False),
])
def test_python_completion_states_are_scoped_to_code_security(stage, status, accepted):
    from webapp.package_editor_api import _verify_scan, RescanIncomplete

    digest = hashlib.sha256(package()).hexdigest()
    member = {"path": "example/SKILL.md", "sha256": hashlib.sha256(SKILL).hexdigest()}
    entry = {**member, "assessment_state": "text_analyzed",
             "analysis_coverage": complete_coverage()}
    entry["analysis_coverage"][stage]["status"] = status
    report = {"files": [entry], "governance_evidence": {"artifact_sha256": digest},
              "coverage": {"status": "complete_supported_content",
                           "mandatory_components_complete": True},
              "summary": {"total_findings": 0}}
    if accepted:
        assert _verify_scan(report, {"entries": [member]}, digest)["requires_acknowledgement"] is False
    else:
        with pytest.raises(RescanIncomplete):
            _verify_scan(report, {"entries": [member]}, digest)


@pytest.mark.parametrize("rows_read,rows_total", [(1, 2), (2, 2)])
def test_incomplete_database_reports_row_scope_without_private_values(rows_read, rows_total):
    def scanner(data, filename, runtime):
        coverage = complete_coverage()
        coverage["extraction"]["status"] = "partial"
        return {"files": [{"path": "example/SKILL.md", "sha256": hashlib.sha256(SKILL).hexdigest(),
                          "assessment_state": "structured_content_analyzed", "analysis_coverage": coverage,
                          "database_profile": {"coverage": {"status": "partial", "rows_read": rows_read,
                              "rows_total": rows_total, "unread": [{"reason": "PRIVATE-CELL-MUST-NOT-APPEAR"}]}}}],
                "governance_evidence": {"artifact_sha256": hashlib.sha256(data).hexdigest()},
                "coverage": {"status": "partial", "mandatory_components_complete": True}}
    client, calls, slot = application(scanner)
    receipt = submit(client).json()
    outcome = finished(client, receipt["status_url"])
    assert outcome["status"] == "failed"
    assert outcome["error"]["code"] == "database_coverage_incomplete"
    assert outcome["error"]["path"] == "example/SKILL.md"
    assert f"Read {rows_read} of {rows_total} reported rows" in outcome["error"]["message"]
    assert "PRIVATE-CELL-MUST-NOT-APPEAR" not in str(outcome)
    assert client.get(receipt["status_url"] + "/download?acknowledge_limitations=true", headers=TOKEN).status_code == 404
