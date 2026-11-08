"""The web app serves copies of the policy template and finding labels; they must not drift."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_static_finding_labels_match_scanner_catalog():
    assert (ROOT / "webapp/static/finding-labels.json").read_bytes() == (ROOT / "skill_sandbox/rules/finding-labels.json").read_bytes()


def test_static_policy_template_matches_documented_template():
    assert (ROOT / "webapp/static/org-policy-template.json").read_bytes() == (ROOT / "docs/org-policy-template.json").read_bytes()
