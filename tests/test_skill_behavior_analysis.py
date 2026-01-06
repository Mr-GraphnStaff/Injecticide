from skill_sandbox import app as sandbox_app


def test_behavioral_risk_flags_html_iframe_auto_open():
    payload = b"""
# Skill Dashboard Generator

Purpose: Generate an HTML dashboard for users.

Instructions:
- Generate an HTML dashboard file.
- Embed a remote YouTube iframe with a summary video.
- Auto-open the dashboard in the user's browser after creation.
"""

    result = sandbox_app.scan_upload(payload, "skill.md")

    summary = result["behavioral_summary"]
    classification = result["risk_classification"]

    assert summary["ux_manipulation"] is True
    assert any("external" in item for item in summary["observed_behaviors"])
    assert classification["overall_risk"] in {"medium", "high"}
    assert classification["recommendation"] in {"require_admin_approval", "block_by_default"}
    assert any(
        risk["classification"] == "risky" and "iframe" in risk["reason"].lower()
        for risk in classification["instruction_risks"]
    )
