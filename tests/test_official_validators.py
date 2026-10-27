import copy
import json
from pathlib import Path

from skill_sandbox import official_validators as official


def check(text, runtime="generic"):
    result = {"package_analysis": {"target_runtime": runtime,
                                  "skills": [{"path": "demo/SKILL.md"}]},
              "readiness": {"status": "no_static_findings"},
              "governance_profile": {"decision": "unchanged"}}
    before = copy.deepcopy(result)
    official.attach_official_validator_results(result, {"demo/SKILL.md": text})
    assert result["readiness"] == before["readiness"]
    assert result["governance_profile"] == before["governance_profile"]
    return result["official_validator_results"]


def test_real_pinned_upstream_validators_disagree_without_deciding_policy():
    text = "---\nname: demo\ndescription: Read supplied text.\ncompatibility: Python\n---\n"
    rows = check(text)
    assert {r["id"]: r["status"] for r in rows} == {
        "openai_skill_creator": "fail", "anthropic_skill_creator": "pass"}
    assert all(len(r["revision"]) == 40 and len(r["sha256"]) == 64 for r in rows)
    assert all(r["runtime_acceptance_verified"] is False and r["policy_effect"] == "none" for r in rows)


def test_official_metadata_checks_do_not_execute_uploaded_body(tmp_path):
    marker = tmp_path / "must-not-exist"
    text = "---\nname: demo\ndescription: Read supplied text.\n---\n" + f"__import__('pathlib').Path({str(marker)!r}).touch()"
    assert all(r["status"] == "pass" for r in check(text))
    assert not marker.exists()


def test_unavailable_and_unsafe_frontmatter_never_get_a_pass():
    valid = "---\nname: demo\ndescription: Read supplied text.\n---\n"
    assert check(valid, "copilot")[0]["status"] == "unavailable"
    for header in ["name: demo\nname: other", "name: &name demo\ndescription: *name", "name: ["]:
        assert all(r["status"] == "unavailable" for r in check("---\n" + header + "\n---\n"))


def test_validator_integrity_failure_never_executes_modified_source(monkeypatch, tmp_path):
    manifest = json.loads((official.ROOT / "manifest.json").read_text())
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    marker = tmp_path / "must-not-exist"
    target = tmp_path / "openai"
    target.mkdir()
    (target / "quick_validate.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()")
    monkeypatch.setattr(official, "ROOT", tmp_path)
    row = check("---\nname: demo\ndescription: Read supplied text.\n---\n", "openai")[0]
    assert row["status"] == "error"
    assert not marker.exists()
