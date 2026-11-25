"""Policy preflight and script-presence requirements at the real API boundary."""
import io
import json
from pathlib import Path
import zipfile

import pytest
from fastapi.testclient import TestClient

from skill_sandbox.app import scan_upload
from skill_sandbox.org_policy import evaluate_policy, policy_preflight
from webapp.api import app

ROOT = Path(__file__).resolve().parents[1]


def policy(when=None):
    return {"schema": "injecticide-org-policy/v1", "organization": "Synthetic organization",
            "policy_name": "No scripts", "compiled_date": "2026-11-25",
            "sources": [{"id": "ORG", "title": "Synthetic policy"}],
            "rules": [{"id": "NO_SCRIPTS", "title": "No packaged scripts", "source": "ORG",
                       "requirement": "Script presence is prohibited, whether invoked or not.",
                       "when": when if when is not None else {"packaged_script": True},
                       "effect": "block", "enforcement": "mandatory"}]}


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as handle:
        for path, text in files.items():
            handle.writestr(path, text)
    return output.getvalue()


@pytest.mark.parametrize("filename", ["docs/org-policy-template.json", "webapp/static/org-policy-template.json"])
def test_shipped_template_validates_with_scan_validator(filename):
    checked = policy_preflight((ROOT / filename).read_text(encoding="utf-8"))
    assert checked["status"] == "valid", checked["errors"]


def test_preflight_and_evaluation_reject_same_nine_unsupported_names():
    rules = [policy({"finding": name})["rules"][0] for name in
             ["instruction_override_phrase", "unicode_concealment", "file_length_exceeded",
              "unpinned_dependency", "runtime_install", "unbounded_construct", "bare_script_file"]]
    rules += [policy({"capability": name})["rules"][0] for name in ["m365_connector", "mcp_server"]]
    for index, item in enumerate(rules):
        item["id"] = f"R{index}"
    document = policy()
    document["rules"] = rules
    checked = policy_preflight(document)
    evaluation = evaluate_policy(document, {"files": []})
    assert checked["status"] == "invalid"
    assert len(checked["errors"]) == 9
    assert checked["errors"] == evaluation["errors"]
    bare = next(row for row in checked["errors"] if "bare_script_file" in row["message"])
    assert bare["suggestion"] is None
    assert "database_profile" not in bare["message"]


def test_preflight_api_needs_no_package_and_does_not_use_scan_slot(monkeypatch):
    import webapp.api as api
    class UnavailableSlot:
        def acquire(self, **kwargs):
            raise AssertionError("Policy validation cannot acquire the package scan slot")
    monkeypatch.setattr(api, "SKILL_SCAN_SLOT", UnavailableSlot())
    client = TestClient(app)
    response = client.post("/api/skills/policy/validate", content=json.dumps(policy()))
    assert response.status_code == 200
    assert response.json()["status"] == "valid"
    assert "no-store" in response.headers["Cache-Control"]
    invalid = client.post("/api/skills/policy/validate", content=json.dumps(policy({"finding": "bare_script_file"})))
    assert invalid.status_code == 422
    assert invalid.json()["errors"][0]["suggestion"] is None


@pytest.mark.parametrize("content", [b'{"schema":1,"schema":2}', b'{"x":NaN}', b'\xff'])
def test_preflight_rejects_parser_invalid_input(content):
    response = TestClient(app).post("/api/skills/policy/validate", content=content)
    assert response.status_code == 422
    assert response.json()["status"] == "invalid"


def test_preflight_bounds_body_and_unicode_bytes():
    client = TestClient(app)
    for text in ["x" * 131073, "é" * 65537]:
        response = client.post("/api/skills/policy/validate", content=text.encode())
        assert response.status_code == 413
        assert policy_preflight(text)["status"] == "invalid"


@pytest.mark.parametrize("background", ["true", "false"])
def test_invalid_policy_direct_scan_never_starts_analysis(monkeypatch, background):
    import webapp.api as api
    def unexpected(*args):
        raise AssertionError("Invalid policy reached scanner")
    monkeypatch.setattr(api, "_execute_skill_scan", unexpected)
    response = TestClient(app).post("/api/skills/scan", files={"file": ("demo.md", b"Public text")},
        data={"org_policy": json.dumps(policy({"finding": "bare_script_file"})), "background": background})
    assert response.status_code == 422
    assert response.json()["detail"]["stage"] == "policy validation"


@pytest.mark.parametrize("path,text", [
    ("references/quiet.PY", "print('public synthetic text')\n"),
    ("references/quiet.sh", "echo public-synthetic-text\n"),
    ("tools/quiet", "#!/bin/sh\necho public-synthetic-text\n"),
    ("tools/quiet", "import json\ndef summarize():\n    return {}\n"),
    ("references/example.md", "```python\nprint('public synthetic text')\n```\n"),
    ("references/example.html", "<script>console.log('public synthetic text')</script>"),
])
def test_uninvoked_script_presence_blocks_in_organization_report(path, text):
    report = scan_upload(archive({"SKILL.md": "---\nname: example\ndescription: Public text\n---\nSummarize text.", path: text}),
                         "example.plugin", org_policy=json.dumps(policy()), use_local_llm=False)
    evaluation = report["policy_evaluation"]
    assert evaluation["status"] == "applied"
    assert evaluation["rules"][0]["triggered"]
    assert any(row["path"] == path and row["signal"] == "packaged_script" for row in evaluation["rules"][0]["evidence"])
    assert evaluation["organization_disposition"] == "block"
    assert {"id": "NO_SCRIPTS", "effect": "block", "approver": None} in evaluation["organization_report"]["deciding_rules"]


def test_nested_script_presence_blocks_but_plain_prose_does_not():
    raw = archive({"SKILL.md": "Summarize text.", "references/more.zip": archive({"quiet.py": "print('public')"})})
    report = scan_upload(raw, "nested.plugin", org_policy=json.dumps(policy()), use_local_llm=False)
    assert report["policy_evaluation"]["rules"][0]["triggered"]
    assert any("!/" in row["path"] for row in report["policy_evaluation"]["rules"][0]["evidence"])
    prose = scan_upload(b"# Skill\nSummarize supplied public text.", "SKILL.md", org_policy=json.dumps(policy()), use_local_llm=False)
    assert not prose["policy_evaluation"]["rules"][0]["triggered"]


def test_compiled_source_example_is_not_implicitly_a_script():
    report = scan_upload(b"# Example\n```c\nint main(void) { return 0; }\n```\n", "reference.md",
                         org_policy=json.dumps(policy()), use_local_llm=False)
    assert not report["policy_evaluation"]["rules"][0]["triggered"]


@pytest.mark.parametrize("value", [False, "true", 1, None])
def test_script_presence_requires_literal_true(value):
    assert policy_preflight(policy({"packaged_script": value}))["status"] == "invalid"
