from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_skill_sandbox_dockerfile_copies_scanner_modules():
    dockerfile = (ROOT / "skill_sandbox" / "Dockerfile").read_text(encoding="utf-8")

    expected_modules = [
        "app.py",
        "artifact_text.py",
        "asset_inspection.py",
        "code_security.py",
        "nested_archives.py",
        "package_graph.py",
        "process_diagram.py",
        "script_launchers.py",
        "standards_assessment.py",
        "text_projections.py",
        "behavior_analysis.py",
        "contextual_rules.py",
        "disposition.py",
        "finding_enrichment.py",
        "governance.py",
        "scan_rules.py",
        "sensitive_data.py",
        "package_formats.py",
        "package_threats.py",
        "package_evidence.py",
        "package_analysis.py",
        "package_checks.py",
        "review_evidence.py",
    ]

    for module_name in expected_modules:
        assert f"COPY {module_name} /app/{module_name}" in dockerfile
