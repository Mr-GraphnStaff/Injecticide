import io
import tarfile
import zipfile
import time

import pytest
from fastapi.testclient import TestClient

from skill_sandbox import app as sandbox
from skill_sandbox.nested_archives import ArchiveFileLimitError, check_skill_file_counts
from webapp import api


def package(skill_count=7, files_per_skill=200):
    entries = [("bundle/.claude-plugin/plugin.json", b'{"name":"fixture"}')]
    for index in range(skill_count):
        root = f"bundle/skills/skill-{index}"
        entries.append((f"{root}/SKILL.md", b"---\nname: fixture\ndescription: Fixture\n---\nSummarize text."))
        entries.extend((f"{root}/references/{number}.txt", b"Reference text")
                       for number in range(files_per_skill - 1))
    return entries


def archive_bytes(entries, kind):
    output = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                archive.writestr(name, data)
    else:
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_seven_skills_allow_200_files_each_plus_plugin_metadata(tmp_path, kind):
    payload = archive_bytes(package(), kind)
    extract = sandbox._safe_extract_zip if kind == "zip" else sandbox._safe_extract_tar
    assert len(extract(payload, tmp_path, [])) == 1401


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_one_oversized_skill_cannot_borrow_from_six_small_skills(tmp_path, kind):
    entries = package(files_per_skill=2)
    entries.extend((f"bundle/skills/skill-3/references/extra-{n}.txt", b"text") for n in range(199))
    extract = sandbox._safe_extract_zip if kind == "zip" else sandbox._safe_extract_tar
    with pytest.raises(ArchiveFileLimitError) as caught:
        extract(archive_bytes(entries, kind), tmp_path, [])
    assert caught.value.detail == {"code": "archive_file_limit", "count": 201, "limit": 200, "skill_index": 4}


def test_shared_files_do_not_consume_skill_allowance_and_have_their_own_limit():
    names = [name for name, _ in package(files_per_skill=200)]
    check_skill_file_counts(names + [f"shared/{i}.txt" for i in range(199)])
    with pytest.raises(ArchiveFileLimitError) as caught:
        check_skill_file_counts(names + [f"shared/{i}.txt" for i in range(200)])
    assert caught.value.detail["skill_index"] is None


def test_nearest_skill_root_counts_descendants_once():
    check_skill_file_counts(["SKILL.md", "child/SKILL.md", "child/ref.txt"], limit=2)
    with pytest.raises(ArchiveFileLimitError):
        check_skill_file_counts(["root/SKILL.md", "root/a.txt", "root/b.txt"], limit=2)


def test_plugin_extension_and_nested_multiskill_package_are_actually_scanned():
    payload = archive_bytes(package(), "zip")
    direct = sandbox.scan_upload(payload, "seven.plugin")
    assert len(direct["files"]) == 1401
    nested = sandbox.scan_upload(archive_bytes([("seven.plugin", payload)], "zip"), "wrapper.zip")
    assert len(nested["files"]) == 1402
    assert any(file["path"].endswith("!/bundle/skills/skill-6/SKILL.md") for file in nested["files"])


def test_redaction_keeps_late_skill_credentials_private():
    from skill_sandbox.evidence_redaction import redact_result

    texts = {f"reference-{n}.txt": "Reference" for n in range(1400)}
    texts["last-skill/config.txt"] = 'api_key = "synthetic-late-skill-credential"'
    result = {"samples": ["synthetic-late-skill-credential"]}
    redact_result(result, texts)
    assert result["samples"] == ["[REDACTED]"]


def test_mcp_advertises_per_skill_and_overall_file_limits():
    from skill_sandbox.mcp_server import skill_scanner_capabilities

    budgets = skill_scanner_capabilities()["budgets"]
    assert budgets["archive_files"] == 200
    assert budgets["archive_files_scope"] == "per_skill_or_shared_package_area"
    assert budgets["package_files"] == sandbox.MAX_PACKAGE_FILES


@pytest.mark.parametrize("in_skill", [False, True])
def test_nested_references_inherit_the_parent_skill_or_shared_quota(in_skill):
    from skill_sandbox.nested_archives import NestedArchiveBudget, inspect_nested_zip

    prefix = "skill/" if in_skill else ""
    outer = [prefix + "a.zip", prefix + "b.zip"]
    if in_skill:
        outer.append("skill/SKILL.md")
    scopes = check_skill_file_counts(outer)
    budget = NestedArchiveBudget(max_files=10000, skill_files=scopes)
    count = 197 if in_skill else 198
    inner = archive_bytes([(f"{n}.txt", b"reference") for n in range(count)], "zip")
    first = inspect_nested_zip(inner, prefix + "a.zip", budget)
    second = inspect_nested_zip(inner, prefix + "b.zip", budget)
    assert len(first["entries"]) == count
    assert not second["entries"]
    assert second["container"]["status"] == "partial"
    assert second["excluded"][0]["code"] == "archive_file_limit"


def test_nested_archives_with_distinct_skills_get_distinct_allowances():
    from skill_sandbox.nested_archives import NestedArchiveBudget, inspect_nested_zip

    scopes = check_skill_file_counts(["first.skill", "second.skill"])
    budget = NestedArchiveBudget(max_files=10000, skill_files=scopes)
    inner = archive_bytes(package(skill_count=1), "zip")
    first = inspect_nested_zip(inner, "first.skill", budget)
    second = inspect_nested_zip(inner, "second.skill", budget)
    assert len(first["entries"]) == 201
    assert len(second["entries"]) == 201


def test_office_internals_keep_their_existing_member_budget():
    from skill_sandbox.artifact_text import extract_office_projection

    parts = [("[Content_Types].xml", b"<Types/>"), ("word/document.xml", b"<document>Core</document>")]
    parts.extend((f"word/part-{n}.xml", b"<root>text</root>") for n in range(199))
    text, profile = extract_office_projection(archive_bytes(parts, "zip"), "reference.docx")
    assert profile["coverage"]["status"] == "complete"
    assert profile["coverage"]["xml_parts_read"] == 201
    assert "Core" in text


def test_overall_package_count_remains_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "MAX_PACKAGE_FILES", 10)
    with pytest.raises(ValueError, match="overall package file budget"):
        sandbox._safe_extract_zip(archive_bytes(package(files_per_skill=2), "zip"), tmp_path, [])


@pytest.mark.parametrize("remote", [False, True])
@pytest.mark.parametrize("background", [False, True])
def test_web_explains_per_skill_rejection_without_reflecting_upload_content(monkeypatch, remote, background):
    if remote:
        class Response:
            status_code = 400

            def json(self):
                return {"detail": {"code": "archive_file_limit", "count": 201, "limit": 200,
                                   "skill_index": 4, "untrusted": "PRIVATE_UPLOAD_TEXT"}}

        monkeypatch.setenv("SKILL_SANDBOX_URL", "http://sandbox.invalid")
        monkeypatch.setattr(api.requests.Session, "post", lambda *args, **kwargs: Response())
    else:
        monkeypatch.delenv("SKILL_SANDBOX_URL", raising=False)
    payload = archive_bytes(package(skill_count=1, files_per_skill=201), "zip")
    client = TestClient(api.app)
    response = client.post("/api/skills/scan", files={"file": ("PRIVATE_UPLOAD_TEXT.plugin", payload)},
                           data={"background": "true" if background else "false"})
    if background:
        assert response.status_code == 202
        status_url = response.json()["status_url"]
        deadline = time.monotonic() + 5
        while True:
            response = client.get(status_url)
            if response.status_code != 202 or time.monotonic() >= deadline:
                break
            time.sleep(.01)
        job = response.json()
        assert job["http_status"] == 400
        assert job["status"] == "failed"
        body = job
    else:
        assert response.status_code == 400
        body = response.json()
    assert "201 files" in body["detail"]["message"]
    assert "200 files per skill" in body["detail"]["message"]
    assert "PRIVATE_UPLOAD_TEXT" not in response.text
