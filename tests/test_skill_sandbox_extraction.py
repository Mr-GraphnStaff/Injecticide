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


def test_scan_upload_rejects_payload_above_transport_limit(monkeypatch):
    monkeypatch.setattr(sandbox_app, "MAX_UPLOAD_BYTES", 1024 * 1024)

    with pytest.raises(ValueError, match="exceeds 1 MiB size limit"):
        sandbox_app.scan_upload(b"X" * (1024 * 1024 + 1), "SKILL.md")


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


@pytest.fixture(scope="module")
def large_sqlite():
    return _build_large_sqlite_bytes()


@pytest.mark.parametrize("archive_type", ["zip", "tar.gz"])
@pytest.mark.parametrize("db_path", ["data/hub_users.db", "nested/data/records.sqlite"])
def test_large_sqlite_scanned_outside_references(large_sqlite, archive_type, db_path):
    buffer = io.BytesIO()
    if archive_type == "zip":
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("SKILL.md", "# Synthetic database fixture")
            archive.writestr(db_path, large_sqlite)
        filename = "bundle.skill"
    else:
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo(db_path)
            member.size = len(large_sqlite)
            archive.addfile(member, io.BytesIO(large_sqlite))
        filename = "bundle.tar.gz"
    result = sandbox_app.scan_upload(buffer.getvalue(), filename)
    entry = next(item for item in result["files"] if item["path"] == db_path)
    assert not entry["skipped"]
    assert entry["detected_content_type"] == "sqlite"
    assert entry["reason"] == "Scanned SQLite database content."
    assert "omitted records" in entry["analysis_scope"]
    assert entry["findings"]


def test_sqlite_at_32_mib_scanned(large_sqlite):
    data = large_sqlite.ljust(sandbox_app.MAX_SQLITE_FILE_BYTES, b"\0")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("data/records.db", data)
    result = sandbox_app.scan_upload(buffer.getvalue(), "boundary.skill")
    assert result["files"][0]["skipped"] is False
    assert result["files"][0]["detected_content_type"] == "sqlite"


@pytest.mark.parametrize("archive_type", ["zip", "tar"])
@pytest.mark.parametrize("header", [b"SQLite format 3\0", b"not a database!!"])
def test_database_allowance_requires_header_and_enforces_cap(monkeypatch, archive_type, header):
    monkeypatch.setattr(sandbox_app, "MAX_FILE_BYTES", 32)
    monkeypatch.setattr(sandbox_app, "MAX_SQLITE_FILE_BYTES", 64)
    data = header + b"x" * 65
    if archive_type == "zip":
        upload = _build_zip([(zipfile.ZipInfo("data/oversized.db"), data)])
    else:
        info = tarfile.TarInfo("data/oversized.db")
        info.size = len(data)
        upload = _build_tar([(info, data)])
    result = sandbox_app.scan_upload(upload, "bundle." + archive_type)
    assert result["summary"]["total_files"] == 0
    assert any("file too large" in warning for warning in result["warnings"])


@pytest.mark.parametrize("path", ["data/not-really-a-db.db", "data/large.txt"])
def test_non_sqlite_keeps_ordinary_file_limit(monkeypatch, path):
    monkeypatch.setattr(sandbox_app, "MAX_FILE_BYTES", 32)
    upload = _build_zip([(zipfile.ZipInfo(path), b"x" * 33)])
    result = sandbox_app.scan_upload(upload, "ordinary.skill")
    assert result["summary"]["total_files"] == 0
    assert any("file too large" in warning for warning in result["warnings"])


@pytest.mark.parametrize("archive_type", ["zip", "tar"])
def test_archive_total_budget_still_enforced(monkeypatch, archive_type):
    monkeypatch.setattr(sandbox_app, "MAX_ARCHIVE_TOTAL_BYTES", 64)
    data = b"SQLite format 3\0" + b"x" * 32
    if archive_type == "zip":
        upload = _build_zip([(zipfile.ZipInfo("data/a.db"), data),
                             (zipfile.ZipInfo("data/b.db"), data)])
    else:
        members = []
        for name in ["data/a.db", "data/b.db"]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            members.append((info, data))
        upload = _build_tar(members)
    with pytest.raises(ValueError, match="uncompressed size limit"):
        sandbox_app.scan_upload(upload, "bundle." + archive_type)


def test_sqlite_projection_bounds_large_values_and_quotes_identifiers(tmp_path):
    from skill_sandbox.artifact_text import _read_sqlite_rows

    database = tmp_path / "large-cell.db"
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE "odd""table" ("odd""column" TEXT, payload BLOB, count INTEGER)')
        connection.execute('INSERT INTO "odd""table" VALUES (?, ?, ?)',
                           (" " * 5000 + "beyond-cell-budget", b"ignored-binary-marker", 42))
    text = _read_sqlite_rows(str(database))
    assert 'odd"table' in text
    assert 'odd"column' in text
    assert 'count=42' in text
    assert "beyond-cell-budget" not in text
    assert "ignored-binary-marker" not in text
