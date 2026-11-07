"""Planted-secret regression: every supported format MUST produce a finding.

Synthetic values are assembled at run time so no complete token-shaped literal
exists in the repository (and repository secret scanning is never tripped).
None of these values is real. The scanner must report each one, and no full
value may appear anywhere in the serialized report.
"""
import io
import json
import zipfile

import pytest

from skill_sandbox.app import scan_upload
from skill_sandbox.secret_detection import mask


def _j(*parts):
    return "".join(parts)


R40 = "Zq7mW2xK9pL4vB8nR3tY6uH1jC5gF0dS2aE7wQ9z"  # synthetic, high-entropy filler

PLANTED = {
    "private_key": _j("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA", R40, "\n-----END RSA PRIVATE KEY-----"),
    "aws_access_key_id": _j("AKIA", "Q7ZK3LMN8PRT2WXY"),
    "aws_secret_access_key": _j("aws_secret_access_key = ", R40),
    "github_token": _j("gh", "p_", R40[:36]),
    "slack_token": _j("xo", "xb-", "1234567890-", R40[:24]),
    "stripe_live_key": _j("sk", "_live_", R40[:28]),
    "google_api_key": _j("AI", "za", R40[:35]),
    "anthropic_api_key": _j("sk-", "ant-", "api03-", R40, R40[:20]),
    "openai_api_key": _j("sk-", "proj-", R40, R40[:10]),
    "azure_storage_key": _j("DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=", R40, "Ab12Cd34==;"),
    "connection_string_password": _j("postgres", "ql://svc_user:", "Tr0ub4dor-Kx9q", "@db.internal:5432/app"),
    "jwt": _j("ey", "JhbGciOiJIUzI1NiJ9.", "ey", "JzdWIiOiJ1c2VyLTQyIn0.", R40[:30]),
    "credential_assignment": _j('client_secret: "', R40[:24], '"'),
}


def _report(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, text in files.items():
            archive.writestr(path, text)
    return scan_upload(buffer.getvalue(), "planted.zip")


def _secret_findings(report):
    return {entry["path"]: finding for entry in report["files"] for finding in entry.get("findings", [])
            if finding["id"] == "hardcoded_secret"}


def test_every_planted_secret_format_is_reported_and_none_is_echoed():
    body = "\n".join(f"{kind}: {value}" for kind, value in PLANTED.items())
    report = _report({"my-skill/SKILL.md": "---\nname: my-skill\ndescription: d\n---\nUse the config.\n",
                      "my-skill/config/settings.md": body})
    finding = _secret_findings(report)["my-skill/config/settings.md"]
    assert set(finding["secret_kinds"]) == set(PLANTED)
    assert finding["tier"] == "block" and finding["is_actionable"]
    serialized = json.dumps(report)
    # Distinctive inner fragments of each planted value; none may appear anywhere.
    probes = {"filler": R40[6:18], "aws_key_id": "Q7ZK3LMN8PRT", "password": "Tr0ub4dor-Kx9q",
              "pem_body": "MIIEowIBAAKCAQEA" + R40[:6], "jwt": "JzdWIiOiJ1c2VyLTQyIn0"}
    for name, probe in probes.items():
        assert probe not in serialized, f"{name} fragment leaked into the report"


@pytest.mark.parametrize("kind", sorted(PLANTED))
def test_each_format_alone_is_detected(kind):
    report = _report({"skill/SKILL.md": "---\nname: skill\ndescription: d\n---\n" + PLANTED[kind] + "\n"})
    findings = _secret_findings(report)
    assert findings, f"{kind} was not detected"
    assert kind in next(iter(findings.values()))["secret_kinds"]


def test_reference_documents_do_not_downgrade_a_real_secret():
    report = _report({"skill/SKILL.md": "---\nname: skill\ndescription: d\n---\nSee references.\n",
                      "skill/references/setup.md": "# Setup\n" + PLANTED["aws_access_key_id"] + "\n"})
    finding = _secret_findings(report)["skill/references/setup.md"]
    assert finding["tier"] == "block"


@pytest.mark.parametrize("text", [
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "api_key: 'YOUR_API_KEY_HERE'",
    'password: "changeme123"',
    'password = "${DB_PASSWORD}"',
    "postgresql://user:<password>@localhost/db",
    'client_secret: "xxxxxxxxxxxxxxxx"',
    'token = os.environ["API_TOKEN"]',
    "Never paste a password or API key into a skill.",
])
def test_placeholders_and_prose_are_not_reported(text):
    report = _report({"skill/SKILL.md": "---\nname: skill\ndescription: d\n---\n" + text + "\n"})
    assert not _secret_findings(report)


def test_generic_assignment_needs_review_rather_than_block():
    report = _report({"skill/SKILL.md": "---\nname: skill\ndescription: d\n---\n" + PLANTED["credential_assignment"] + "\n"})
    finding = next(iter(_secret_findings(report).values()))
    assert finding["tier"] == "review"


def test_mask_never_reveals_more_than_eight_characters():
    assert mask("A" * 4 + "B" * 30 + "C" * 4) == "AAAA…CCCC"
    assert mask("short123") == "sh…"
    assert mask("abc") == "…"
