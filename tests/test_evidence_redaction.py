import copy
import hashlib
import io
import json
import zipfile

import pytest

from skill_sandbox.app import scan_upload
from skill_sandbox.evidence_redaction import redact_result, RedactionBudgetExceeded
from skill_sandbox.package_evidence import scanner_metadata


def package(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    raw = stream.getvalue()
    return raw, scan_upload(raw, "fixture.skill")


def test_credentials_are_redacted_everywhere_they_are_reflected_without_erasing_detection():
    sentinel = "SYNTHETIC_SECRET_SENTINEL_12345"
    config = {"mcpServers": {"demo": {
        "url": f"http://user:{sentinel}@example.test/endpoint?api_key={sentinel}&mode=read",
        "headers": {"Authorization": "Bearer " + sentinel}}}}
    raw, result = package({"mcp.json": json.dumps(config), "directory.md": "Contact reviewer@company.test."})
    output = json.dumps(result)
    assert sentinel not in output
    assert "reviewer@company.test" in output
    assert "example.test/endpoint" in output
    assert "api_key" in output and "mode=read" in output
    findings = {f["id"] for e in result["files"] for f in e["findings"]}
    assert {"literal_credential_declaration", "insecure_component_transport", "pii_email_address"} <= findings
    assert result["governance_evidence"]["artifact_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("password", ["a", "prompt_override", "system_exfiltration", "blocked", "pii_email_address", "require_approval", "high", "bad", "block_by_default"])
def test_an_attacker_chosen_password_cannot_change_computed_decisions_ids_or_hashes(password):
    trusted = {
        "governance_profile": {"execution_tier": "blocked", "brokered_tokens": {"decision": "block_by_default"},
                               "policy_capabilities": ["credential_handling", "code_execution"]},
        "risk_classification": {"overall_risk": "high", "recommendation": "block_by_default",
                                "instruction_risks": [{"classification": "bad", "instruction": f'password="{password}"'}]},
        "governance_evidence": {"artifact_sha256": "a" * 64},
        "scanner_metadata": {"scanner_version": "0.3.0", "engine_source_sha256": "a" * 64},
        "files": [{"findings": [{"id": "prompt_override", "status": "verified", "severity": "high",
                                  "observations": [{"text": f'password="{password}"', "confidence": "high", "context_tag": "imperative_disclosure"}],
                                  "samples": ["reviewer@company.test", f'password="{password}"']}]}],
    }
    expected = copy.deepcopy(trusted)
    redact_result(trusted, {"demo.md": f'password="{password}"'})
    assert trusted["governance_profile"] == expected["governance_profile"]
    assert trusted["governance_evidence"] == expected["governance_evidence"]
    assert trusted["scanner_metadata"] == expected["scanner_metadata"]
    assert trusted["risk_classification"]["overall_risk"] == "high"
    assert trusted["risk_classification"]["recommendation"] == "block_by_default"
    assert trusted["risk_classification"]["instruction_risks"][0]["classification"] == "bad"
    finding = trusted["files"][0]["findings"][0]
    assert finding["id"] == "prompt_override" and finding["severity"] == "high" and finding["status"] == "verified"
    assert finding["observations"][0]["confidence"] == "high"
    assert finding["observations"][0]["context_tag"] == "imperative_disclosure"
    assert "reviewer@company.test" in finding["samples"]
    assert "[REDACTED]" in finding["observations"][0]["text"]


def test_user_metadata_is_not_exempt_because_its_keys_match_report_schema():
    secret = "SYNTHETIC_SECRET_SENTINEL_12345"
    result = {"package_analysis": {"skills": [{"metadata": {"id": secret, "status": secret, "password": secret}}]}}
    redact_result(result, {"demo.md": f'password="{secret}"'})
    assert secret not in json.dumps(result)


def test_url_fragment_credentials_are_redacted_but_normal_fragments_are_preserved():
    secret = "SYNTHETIC_FRAGMENT_SENTINEL_12345"
    url = f"https://example.test/path#access_token={secret}&mode=read"
    result = {"behavioral_summary": {"external_dependencies": [url, "https://docs.python.org/interface#interface-options"]}}
    redact_result(result, {"example.md": url})
    assert secret not in json.dumps(result)
    assert "access_token=[REDACTED]&mode=read" in result["behavioral_summary"]["external_dependencies"][0]
    assert result["behavioral_summary"]["external_dependencies"][1] == "https://docs.python.org/interface#interface-options"


def test_credential_collection_work_budget_fails_closed_including_credentials_in_urls(monkeypatch):
    monkeypatch.setattr("skill_sandbox.evidence_redaction.MAX_SECRET_VALUES", 1)
    with pytest.raises(RedactionBudgetExceeded):
        redact_result({"samples": []}, {"demo.md": "https://example.test/?api_key=first-secret&access_token=second-secret"})


def test_scanner_engine_identity_is_stable_and_independent_of_uploaded_text():
    first = scanner_metadata()
    assert first["scanner_version"] == "0.11.0"
    assert first["adapter_version"] == "2026-10-28"
    assert len(first["engine_source_sha256"]) == 64
    assert first["engine_source_sha256"] == scanner_metadata()["engine_source_sha256"]
