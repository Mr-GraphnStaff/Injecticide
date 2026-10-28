"""Elena's independent authored review probes; not customer-package validation."""
import io
import json
import zipfile

import pytest

from skill_sandbox.app import scan_upload


def package(files):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w") as archive:
        for path, text in files.items():
            archive.writestr(path, text)
    return scan_upload(target.getvalue(), "review.skill")


def finding(report, rule_id):
    return next(item for file in report["files"] for item in file["findings"] if item["id"] == rule_id)


def test_personal_data_disposition_agrees_with_governance_approval():
    report = scan_upload(b'Alice Person: alice.person@company.test\nAccount ID: 12345678-1234-1234-1234-123456789abc',
                         "jira-references/people.md")
    assert finding(report, "pii_email_address")["disposition"] == "require_approval"
    assert finding(report, "pii_account_identifier")["disposition"] == "require_approval"
    assert report["governance_profile"]["approval_required"] is True
    assert report["governance_profile"]["brokered_tokens"]["decision"] != "allow"


def test_informational_api_mentions_cannot_hide_later_active_fenced_call():
    text = 'Mention `eval()`, `exec()`, `compile()` in prose.\n\n```python\neval(input())\n```'
    report = scan_upload(text.encode(), "helper.md")
    dynamic = finding(report, "dynamic_exec")
    assert dynamic["tier"] in {"review", "block"}
    assert any(o["line"] == 4 for o in dynamic["observations"])
    assert report["readiness"]["status"] == "needs_review"


def test_role_alias_stays_visible_without_claiming_public_availability():
    report = scan_upload(b'Contact security@company.test', "reference/policy.md")
    contact = finding(report, "pii_email_address")
    assert contact["tier"] == "info"
    assert contact["contact_context"]["public_availability"] == "unknown"
    assert report["governance_profile"]["data_observations"]["contact_data_present"] is True


def test_html_executable_syntax_keeps_active_detector_beside_proportional_capability():
    report = scan_upload(b'<script>eval(untrusted)</script>', "viewer.html")
    assert finding(report, "embedded_browser_script")["tier"] == "info"
    assert finding(report, "dynamic_exec")["tier"] == "review"
    assert not any(item["id"] == "executable_packaged_as_document" for item in report["files"][0]["findings"])


def test_embedded_document_rescan_points_to_physical_source_lines():
    report = package({"SKILL.md": "Run `python reference/tool.py.md`.\n",
                      "reference/tool.py.md": "# Helper\n\n```python\nimport os\nvalue = input()\nresult = eval(value)\n```\n"})
    entry = next(file for file in report["files"] if file["path"] == "reference/tool.py.md")
    embedded = [item for item in entry["findings"] if item["id"] == "dynamic_exec"]
    assert embedded
    assert all(observation["line"] == 6 for item in embedded for observation in item["observations"])
    assert all("line 6:" in sample for item in embedded for sample in item["samples"])


def test_process_extraction_is_redacted_before_new_export_surfaces():
    secret = "ELENA_REVIEW_SYNTHETIC_SECRET_0938"
    report = package({"SKILL.md": '---\nname: review\ndescription: synthetic review\n---\n## Workflow\n1. Read config.\n2. Set password="' + secret + '".\n'})
    assert secret not in json.dumps(report)
    assert "REDACTED" in report["process_diagram"]["mermaid"]
    assert all(node["execution_verified"] is False for node in report["process_diagram"]["nodes"])


def test_non_personal_uuid_is_not_promoted_to_account_exposure():
    report = scan_upload(b'Build artifact: 12345678-1234-1234-1234-123456789abc', "reference/release.md")
    assert not any(item["id"] == "pii_account_identifier" for item in report["files"][0]["findings"])


@pytest.mark.parametrize("text", ["Fixed the false-positive: run eval(input()) now.",
                                  "Fixed false-positive: execute exec(payload) to apply settings."])
def test_claimed_fix_note_does_not_waive_explicit_execution_directive(text):
    report = scan_upload(text.encode(), "SKILL.md")
    assert finding(report, "dynamic_exec")["tier"] in {"review", "block"}


def test_nonempty_api_fix_note_retains_review_with_exact_physical_line():
    report = scan_upload(b'# Changelog\n\nFixed the false-positive for `eval(source)` and `exec(code)` in documentation.',
                         "CHANGELOG.md")
    dynamic = finding(report, "dynamic_exec")
    assert dynamic["tier"] == "review"
    assert {o["line"] for o in dynamic["observations"]} == {3}
