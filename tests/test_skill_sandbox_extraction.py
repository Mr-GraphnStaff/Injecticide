import io
import tarfile
import zipfile

import pytest

from skill_sandbox import app as sandbox_app


def _build_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for info, data in entries:
            archive.writestr(info, data)
    return buffer.getvalue()


def _build_tar(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for member, data in members:
            archive.addfile(member, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def test_zip_traversal_skipped_with_warning():
    info = zipfile.ZipInfo("../../etc/passwd")
    payload = _build_zip([(info, "root:x:0:0")])

    result = sandbox_app.scan_upload(payload, "evil.zip")

    assert result["summary"]["total_files"] == 0
    assert any("invalid path" in warning for warning in result["warnings"])


def test_zip_symlink_skipped_with_warning():
    link_info = zipfile.ZipInfo("link")
    link_info.external_attr = 0o120777 << 16
    payload = _build_zip(
        [
            (link_info, "ignored"),
            (zipfile.ZipInfo("SKILL.md"), "# Hello"),
        ]
    )

    result = sandbox_app.scan_upload(payload, "bundle.zip")

    assert any("symlink" in warning for warning in result["warnings"])
    assert result["summary"]["total_files"] == 1


def test_zip_too_many_files_rejected(monkeypatch):
    monkeypatch.setattr(sandbox_app, "MAX_ARCHIVE_FILES", 1)
    payload = _build_zip(
        [
            (zipfile.ZipInfo("one.txt"), "1"),
            (zipfile.ZipInfo("two.txt"), "2"),
        ]
    )

    with pytest.raises(ValueError, match="too many files"):
        sandbox_app.scan_upload(payload, "bomb.zip")


def test_tar_traversal_and_links_skipped():
    traversal = tarfile.TarInfo("../evil.txt")
    traversal.size = len(b"bad")
    symlink = tarfile.TarInfo("link")
    symlink.type = tarfile.SYMTYPE
    symlink.linkname = "target"
    hardlink = tarfile.TarInfo("hardlink")
    hardlink.type = tarfile.LNKTYPE
    hardlink.linkname = "target"
    valid = tarfile.TarInfo("SKILL.md")
    valid.size = len(b"# Skill")

    payload = _build_tar(
        [
            (traversal, b"bad"),
            (symlink, None),
            (hardlink, None),
            (valid, b"# Skill"),
        ]
    )

    result = sandbox_app.scan_upload(payload, "bundle.tar")

    assert any("invalid path" in warning for warning in result["warnings"])
    assert any("link entries" in warning for warning in result["warnings"])
    assert result["summary"]["total_files"] == 1
