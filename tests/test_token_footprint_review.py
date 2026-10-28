"""Independent factual-count and package ownership challenges."""
from skill_sandbox.token_footprint import build_token_footprint


def test_nested_skill_owns_its_supporting_file_without_parent_double_count():
    sources = [{"path": "root/SKILL.md", "text": "parent"},
               {"path": "root/other/SKILL.md", "text": "child"},
               {"path": "root/other/notes.md", "text": "notes"}]
    skills = {row["path"]: row for row in build_token_footprint(sources)["skills"]}
    assert skills["root/SKILL.md"]["packaged_supporting_text"]["file_count"] == 0
    assert skills["root/other/SKILL.md"]["packaged_supporting_text"]["file_count"] == 1
    assert skills["root/other/SKILL.md"]["packaged_supporting_text"]["characters"] == 5


def test_physical_lines_and_unicode_bytes_are_measured_not_tokenized():
    text = "one\r\ntwo\n雪"
    result = build_token_footprint([{"path": "file.md", "text": text}])
    measured = result["extracted_text_total"]
    assert measured["characters"] == len(text)
    assert measured["utf8_bytes"] == len(text.encode("utf-8"))
    assert measured["lines"] == 3
    assert measured["exact_tokens"] is None and measured["estimated_tokens"] is None


def test_similar_prefix_siblings_and_archives_do_not_share_support():
    sources = [{"path": "a/SKILL.md", "text": "main"}, {"path": "ab/notes.md", "text": "sibling"},
               {"path": "a/inner.zip!/note.md", "text": "archive"}, {"path": "a/notes.md", "text": "owned"}]
    skill = build_token_footprint(sources)["skills"][0]
    assert skill["packaged_supporting_text"]["characters"] == 5
    assert skill["packaged_supporting_text"]["file_count"] == 1
