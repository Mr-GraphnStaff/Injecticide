import io
import stat
import struct
import zipfile

from skill_sandbox.nested_archives import NestedArchiveBudget, inspect_nested_zip, is_nested_zip


def make_zip(entries, compression=zipfile.ZIP_DEFLATED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        for name, value in entries:
            archive.writestr(name, value)
    return stream.getvalue()


def test_nested_packages_preserve_boundaries_bytes_and_hashes():
    inner = make_zip([("SKILL.md", "Instructions"), ("scripts/run.py", "print('hello')")])
    result = inspect_nested_zip(make_zip([("bundle.skill", inner)]), "outer.zip")
    assert result["container"]["status"] == "inspected"
    paths = [entry["path"] for entry in result["entries"]]
    assert paths == ["outer.zip!/bundle.skill", "outer.zip!/bundle.skill!/SKILL.md", "outer.zip!/bundle.skill!/scripts/run.py"]
    assert result["entries"][0]["container_inspection"]["status"] == "inspected"
    assert result["entries"][1]["data"] == b"Instructions"
    assert len(result["entries"][1]["sha256"]) == 64


def test_shared_sibling_file_budget_cannot_reset():
    budget = NestedArchiveBudget(max_files=2)
    first = inspect_nested_zip(make_zip([("one.md", "one"), ("two.md", "two")]), "first.zip", budget)
    second = inspect_nested_zip(make_zip([("three.md", "three")]), "second.zip", budget)
    assert len(first["entries"]) == 2
    assert not second["entries"]
    assert second["container"]["status"] == "partial"
    assert "file budget" in second["excluded"][0]["reason"]


def test_shared_byte_budget_cannot_reset():
    budget = NestedArchiveBudget(max_bytes=10)
    first = inspect_nested_zip(make_zip([("one.md", "123456")]), "first.zip", budget)
    second = inspect_nested_zip(make_zip([("two.md", "123456")]), "second.zip", budget)
    assert len(first["entries"]) == 1
    assert not second["entries"]
    assert budget.bytes_used == 6
    assert "shared expanded byte budget" in second["excluded"][0]["reason"]


def test_depth_budget_blocks_descendants_but_keeps_container():
    payload = make_zip([("leaf.md", "leaf")])
    for index in range(4):
        payload = make_zip([(f"level{index}.zip", payload)])
    result = inspect_nested_zip(payload, "outer.zip", NestedArchiveBudget(max_depth=3))
    assert not any(entry["path"].endswith("leaf.md") for entry in result["entries"])
    assert any("depth budget" in item["reason"] for item in result["excluded"])
    assert result["container"]["status"] == "partial"


def test_per_member_expansion_limit_handles_compression_bomb():
    payload = make_zip([("big.txt", "A" * 1_000_000)])
    result = inspect_nested_zip(payload, "bomb.zip", NestedArchiveBudget(max_member_bytes=4096))
    assert not result["entries"]
    assert result["container"]["status"] == "partial"
    assert "per-member" in result["excluded"][0]["reason"]


def test_unsafe_names_case_collisions_and_symlink_are_excluded():
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    payload = make_zip([("../outside", "bad"), ("/absolute", "bad"), ("C:/drive", "bad"),
                        ("folder\\bad", "bad"), ("odd!/leaf", "bad"),
                        ("Good.md", "okay"), ("good.md", "collision"), (link, "target")])
    # Windows ZipInfo normalizes backslashes on creation; restore one in both
    # raw local/central names to exercise an actual ambiguous uploaded path.
    payload = payload.replace(b"folder/bad", b"folder\\bad")
    result = inspect_nested_zip(payload, "outer.zip")
    assert [entry["path"] for entry in result["entries"]] == ["outer.zip!/Good.md"]
    assert len(result["excluded"]) == 7
    assert all(item["skipped"] for item in result["excluded"])


def test_unsupported_compression_remains_explicit():
    result = inspect_nested_zip(make_zip([("readme.txt", "text")], zipfile.ZIP_BZIP2), "outer.zip")
    assert result["container"]["status"] == "partial"
    assert result["excluded"][0]["assessment_state"] == "unsupported"


def test_crc_failure_is_recorded_and_other_members_survive():
    data = bytearray(make_zip([("bad.txt", "bad data"), ("good.txt", "good data")], zipfile.ZIP_STORED))
    offset = data.find(b"bad data")
    data[offset] ^= 1
    result = inspect_nested_zip(bytes(data), "outer.zip")
    assert result["container"]["status"] == "malformed"
    assert [entry["path"] for entry in result["entries"]] == ["outer.zip!/good.txt"]
    assert result["excluded"][0]["assessment_state"] == "malformed_archive_entry"


def test_encrypted_entries_not_attempted():
    data = bytearray(make_zip([("private.txt", "secret")]))
    # Encryption flag in local and central headers, without using a password.
    struct.pack_into("<H", data, 6, 1)
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, central + 8, 1)
    result = inspect_nested_zip(bytes(data), "outer.zip")
    assert not result["entries"]
    assert "Encrypted" in result["excluded"][0]["reason"]


def test_forged_eocd_count_rejected_before_zipfile_materialization(monkeypatch):
    data = bytearray(make_zip([("one.md", "one"), ("two.md", "two")]))
    end = data.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", data, end + 8, 1, 1)
    def forbidden(*args, **kwargs):
        raise AssertionError("ZipFile should not be called before bounded preflight")
    monkeypatch.setattr(zipfile, "ZipFile", forbidden)
    result = inspect_nested_zip(bytes(data), "outer.zip")
    assert result["container"]["status"] == "malformed"


def test_malformed_zip_input_records_failure():
    result = inspect_nested_zip(b"not a zip", "outer.zip")
    assert result["container"]["status"] == "malformed"
    assert result["excluded"][0]["path"] == "outer.zip"


def test_office_and_plaintext_skill_are_not_recursed():
    data = make_zip([("[Content_Types].xml", "xml")])
    assert not is_nested_zip(data, "reference.docx")
    assert not is_nested_zip(b"skill instructions", "plain.skill")
    assert is_nested_zip(data, "bundle.skill")
    assert is_nested_zip(b"broken", "broken.zip")
    assert is_nested_zip(data, "archive.bin")


def test_zero_byte_member_and_empty_zip_are_supported():
    result = inspect_nested_zip(make_zip([("empty.txt", "")]), "outer.zip")
    assert result["entries"][0]["data"] == b""
    assert inspect_nested_zip(make_zip([]), "empty.zip")["container"]["status"] == "inspected"


def test_zip64_and_multipart_are_not_silently_supported():
    for field_offset, value in [(8, 0xffff), (4, 1)]:
        data = bytearray(make_zip([("one.md", "one")]))
        end = data.rindex(b"PK\x05\x06")
        struct.pack_into("<H", data, end + field_offset, value)
        result = inspect_nested_zip(bytes(data), "outer.zip")
        assert not result["entries"]
        assert result["container"]["status"] == "partial"


def test_truncated_and_mutated_archives_do_not_crash():
    data = make_zip([("readme.md", "hello")])
    for length in range(len(data)):
        result = inspect_nested_zip(data[:length], "outer.zip")
        assert result["container"]["status"] in {"malformed", "partial"}
    for offset in range(len(data)):
        changed = bytearray(data)
        changed[offset] ^= 0xff
        result = inspect_nested_zip(bytes(changed), "outer.zip")
        assert result["container"]["status"] in {"inspected", "partial", "malformed"}
