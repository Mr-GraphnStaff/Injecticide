"""Independent integration regressions for root-owned readiness/decision wiring."""
import io
import zipfile

from skill_sandbox.app import scan_upload


def archive(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as output:
        for path, text in files.items():
            output.writestr(path, text)
    return data.getvalue()


def test_explicit_portable_missing_entrypoint_cannot_keep_allow_readiness():
    report = scan_upload(archive({"demo/README.md": "Ordinary notes."}), "review.zip", "generic")
    assert report["standards_assessment"]["overall_status"] == "fail"
    assert report["readiness"]["status"] == "needs_review"
    assert report["readiness"]["format_compatibility"] == "portable_format_failed"
    assert report["governance_profile"]["brokered_tokens"]["decision"] == "require_further_analysis"


def test_unknown_original_directory_is_incomplete_rather_than_passed():
    report = scan_upload(b"---\nname: demo\ndescription: Ordinary notes.\n---\nSummarize the input.", "SKILL.md", "generic")
    assert report["standards_assessment"]["overall_status"] == "not_assessed"
    assert report["readiness"]["status"] == "incomplete"
    assert report["readiness"]["format_compatibility"] == "unverified"
    assert report["governance_profile"]["brokered_tokens"]["decision"] == "require_further_analysis"


def test_runtime_and_vendor_unknowns_do_not_become_portable_format_failure():
    report = scan_upload(archive({"demo/SKILL.md": "---\nname: demo\ndescription: Ordinary notes.\n---\nSummarize the input."}), "review.zip", "generic")
    assert report["standards_assessment"]["overall_status"] == "pass"
    assert report["readiness"]["format_compatibility"] == "explicit_portable_profile_checked"
    assert report["readiness"]["status"] == "no_static_findings"
    assert report["governance_profile"]["brokered_tokens"]["decision"] == "allow"
    assert all(row["status"] == "not_assessed" for row in report["standards_assessment"]["requirements"] if row["category"] == "runtime_evaluation")
