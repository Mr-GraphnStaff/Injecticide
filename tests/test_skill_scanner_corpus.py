from pathlib import Path

from webapp.skill_scanner import scan_upload


CORPUS_DIR = Path(__file__).resolve().parent / "fixtures" / "skill_corpus"


def _scan_skill_file(path: Path):
    return scan_upload(path.read_bytes(), str(path))


def _has_block(result) -> bool:
    return any(
        finding.get("tier") == "block"
        for item in result["files"]
        for finding in item.get("findings", [])
    )


def _review_info_volume(result) -> int:
    return sum(
        1
        for item in result["files"]
        for finding in item.get("findings", [])
        if finding.get("tier") in {"review", "info"}
    )


def test_labeled_skill_corpus_block_precision_and_recall():
    labeled_results = []

    for label in ("good", "malicious"):
        for skill_file in sorted((CORPUS_DIR / label).glob("*.skill/SKILL.md")):
            result = _scan_skill_file(skill_file)
            labeled_results.append(
                {
                    "label": label,
                    "path": skill_file,
                    "result": result,
                    "predicted_block": _has_block(result),
                    "review_info_volume": _review_info_volume(result),
                }
            )

    true_positive = sum(1 for item in labeled_results if item["label"] == "malicious" and item["predicted_block"])
    false_positive = sum(1 for item in labeled_results if item["label"] == "good" and item["predicted_block"])
    false_negative = sum(1 for item in labeled_results if item["label"] == "malicious" and not item["predicted_block"])

    precision = true_positive / (true_positive + false_positive)
    recall = true_positive / (true_positive + false_negative)
    known_good_volume = sum(item["review_info_volume"] for item in labeled_results if item["label"] == "good")

    assert precision == 1.0
    assert recall == 1.0
    assert false_positive == 0
    assert false_negative == 0
    assert known_good_volume <= 3
