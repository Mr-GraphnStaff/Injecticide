import io
import sqlite3
import tarfile
import tempfile
import zipfile
from pathlib import Path

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


def _build_large_sqlite_bytes():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as handle:
        db_path = handle.name

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE records (email TEXT, note TEXT)")
        large_note = "X" * 8192
        rows = [(f"user{idx}@hubinternational.com", large_note) for idx in range(900)]
        conn.executemany("INSERT INTO records (email, note) VALUES (?, ?)", rows)
        conn.commit()
        conn.close()

        data = Path(db_path).read_bytes()
        assert len(data) > sandbox_app.MAX_FILE_BYTES
        return data
    finally:
        import os

        os.unlink(db_path)


def _build_large_pptx_bytes():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            """<?xml version="1.0" encoding="UTF-8"?>
            <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
              <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
              <Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
            </Types>""",
        )
        archive.writestr(
            "ppt/presentation.xml",
            """<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>""",
        )
        archive.writestr(
            "ppt/slides/slide1.xml",
            """<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
                      xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
                 <p:cSld>
                   <p:spTree>
                     <p:sp>
                       <p:txBody>
                         <a:p><a:r><a:t>Template owner: Grady.Morrison@hubinternational.com</a:t></a:r></a:p>
                         <a:p><a:r><a:t>Phone: +1 (312) 555-0123</a:t></a:r></a:p>
                       </p:txBody>
                     </p:sp>
                   </p:spTree>
                 </p:cSld>
               </p:sld>""",
        )
        archive.writestr("ppt/media/padding.bin", b"X" * (6 * 1024 * 1024))

    data = buffer.getvalue()
    assert len(data) > sandbox_app.MAX_FILE_BYTES
    return data


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


def test_large_reference_sqlite_not_skipped():
    payload = _build_large_sqlite_bytes()
    result = sandbox_app.scan_upload(
        _build_zip(
            [
                (zipfile.ZipInfo("SKILL.md"), "# Skill"),
                (zipfile.ZipInfo("references/hub_users.db"), payload),
            ]
        ),
        "bundle.zip",
    )

    db_entry = next(item for item in result["files"] if item["path"].endswith("hub_users.db"))
    assert db_entry["skipped"] is False
    assert db_entry["reason"] == "Scanned SQLite database content."


def test_large_reference_pptx_not_skipped():
    payload = _build_large_pptx_bytes()
    result = sandbox_app.scan_upload(
        _build_zip(
            [
                (zipfile.ZipInfo("SKILL.md"), "# Skill"),
                (zipfile.ZipInfo("references/template.pptx"), payload),
            ]
        ),
        "bundle.zip",
    )

    pptx_entry = next(item for item in result["files"] if item["path"].endswith("template.pptx"))
    assert pptx_entry["skipped"] is False
    assert pptx_entry["reason"] == "Scanned Office document content."


def test_large_asset_pptx_not_skipped():
    payload = _build_large_pptx_bytes()
    result = sandbox_app.scan_upload(
        _build_zip(
            [
                (zipfile.ZipInfo("SKILL.md"), "# Skill"),
                (zipfile.ZipInfo("assets/template.pptx"), payload),
            ]
        ),
        "bundle.zip",
    )

    pptx_entry = next(item for item in result["files"] if item["path"].endswith("template.pptx"))
    assert pptx_entry["skipped"] is False
    assert pptx_entry["reason"] == "Scanned Office document content."
