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
        "token_footprint.py",
        "package_effects.py",
        "improvement_plan.py",
        "text_projections.py",
        "behavior_analysis.py",
        "contextual_rules.py",
        "disposition.py",
        "finding_enrichment.py",
        "governance.py",
        "scan_rules.py",
        "speech_acts.py",
        "sensitive_data.py",
        "secret_detection.py",
        "package_formats.py",
        "package_threats.py",
        "package_evidence.py",
        "package_analysis.py",
        "package_checks.py",
        "review_evidence.py",
    ]

    for module_name in expected_modules:
        assert f"COPY {module_name} /app/{module_name}" in dockerfile


def test_every_relatively_imported_scanner_module_is_copied():
    """A module imported by a copied module but missing from the image fails at scan time."""
    import re
    sandbox = ROOT / "skill_sandbox"
    dockerfile = (sandbox / "Dockerfile").read_text(encoding="utf-8")
    copied = set(re.findall(r"^COPY (\w+\.py) /app/", dockerfile, re.M))
    pending, missing = list(copied), set()
    while pending:
        module = pending.pop()
        source = (sandbox / module).read_text(encoding="utf-8")
        for name in re.findall(r"^\s*from \.(\w+) import", source, re.M):
            target = name + ".py"
            if (sandbox / target).exists() and target not in copied and target not in missing:
                missing.add(target)
    assert not missing, f"imported but not copied into the sandbox image: {sorted(missing)}"

