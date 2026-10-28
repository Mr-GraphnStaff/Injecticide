import hashlib
import json

import pytest

from research_mcp.reference_library import ReferenceLibrary


def test_complete_bundled_site_is_searchable_and_sources_survive_pagination():
    library = ReferenceLibrary()
    manifest = library.manifest()
    documents = [row for row in manifest["records"] if row["role"] == "site_document"]
    assert len(documents) == 9
    assert manifest["documentation_complete"] is True
    assert len(manifest["fallback_review"]) == 5
    result = library.search("with the skill", 50)
    assert any("evaluating-skills.md" in row["url"] for row in result["matches"])
    document = next(row for row in documents if "evaluating-skills" in row["url"])
    first = library.document(document["id"])
    assert first["live_check"] is False
    assert first["next_offset"] == 8000
    second = library.document(document["id"], first["next_offset"])
    assert len(first["sha256"]) == 64
    assert first["sha256"] == second["sha256"]
    assert first["text"] != second["text"]
    # Verify every captured reference, not just documents returned by a query.
    for row in manifest["records"]:
        if row.get("text_file"):
            assert hashlib.sha256(library._text(row).encode()).hexdigest() == row["text_sha256"]
            if row["text_scope"] == "attributed_excerpt_max_200_words":
                assert len(library._text(row).split()) <= 200
    assert all(row["text_scope"] == "full_licensed_source_text" for row in documents)


def test_captured_text_is_data_and_tampered_reference_never_gets_a_pass(tmp_path):
    text = "__import__('os').system('must never execute')"
    (tmp_path / "reference.txt").write_text(text, encoding="utf-8")
    row = {"id": "example", "url": "https://agentskills.io/example.md", "text_file": "reference.txt",
           "role": "site_document", "retrieved_at": "2026-10-28", "sha256": "a" * 64,
           "text_sha256": hashlib.sha256(text.encode()).hexdigest()}
    (tmp_path / "manifest.json").write_text(json.dumps({"records": [row]}), encoding="utf-8")
    library = ReferenceLibrary(tmp_path)
    assert library.document("example")["text"] == text
    (tmp_path / "reference.txt").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        library.document("example")
    row["text_file"] = "../outside.txt"
    (tmp_path / "manifest.json").write_text(json.dumps({"records": [row]}), encoding="utf-8")
    with pytest.raises(ValueError, match="fixed library"):
        library.document("example")


@pytest.mark.parametrize("query,limit", [("x" * 201, 1), ("", 0), ("", 51), ("", True)])
def test_reference_search_rejects_unbounded_inputs(query, limit):
    with pytest.raises(ValueError):
        ReferenceLibrary().search(query, limit)
