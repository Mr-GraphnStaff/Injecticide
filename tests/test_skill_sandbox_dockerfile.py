from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_skill_sandbox_dockerfile_copies_scanner_modules():
    dockerfile = (ROOT / "skill_sandbox" / "Dockerfile").read_text(encoding="utf-8")

    expected_modules = [
        "app.py",
        "artifact_text.py",
        "behavior_analysis.py",
        "contextual_rules.py",
        "disposition.py",
        "finding_enrichment.py",
        "governance.py",
        "scan_rules.py",
        "sensitive_data.py",
    ]

    for module_name in expected_modules:
        assert f"COPY {module_name} /app/{module_name}" in dockerfile
