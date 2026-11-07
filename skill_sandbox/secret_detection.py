"""Hardcoded credentials in package content: deterministic, masked, never echoed.

Each pattern is a published, vendor-documented token format or an explicit
assignment syntax; matches are classified by format, not guessed. Values are
masked before they enter any observation, so no complete secret reaches a
finding, sample or report. Documented example values and obvious placeholders
are skipped. A match establishes that credential-shaped material is packaged;
whether it is live or authorized is not established.

Format sources (checked 2026-11-07):
- AWS access key IDs: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
- GitHub tokens: https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
- Slack tokens: https://api.slack.com/authentication/token-types
- Stripe keys: https://docs.stripe.com/keys
- Google API keys: https://cloud.google.com/docs/authentication/api-keys
- Azure Storage connection strings: https://learn.microsoft.com/azure/storage/common/storage-configure-connection-string
- PEM private keys: https://www.rfc-editor.org/rfc/rfc7468
- JSON Web Tokens: https://www.rfc-editor.org/rfc/rfc7519
- Connection URIs with userinfo: https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List

MAX_OBSERVATIONS = 10
MAX_TEXT = 4 * 1024 * 1024

SOURCES = [
    {"name": "OWASP Secrets Management Cheat Sheet", "ref": "Detection of hardcoded secrets",
     "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"},
    {"name": "CWE-798", "ref": "Use of Hard-coded Credentials", "url": "https://cwe.mitre.org/data/definitions/798.html"},
]

# (kind, label, compiled pattern, value group, strong)
# strong=True: a vendor-specific format whose presence is itself evidence.
FORMATS = [
    ("private_key", "PEM private key block",
     re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), 0, True),
    ("aws_access_key_id", "AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0, True),
    ("aws_secret_access_key", "AWS secret access key",
     re.compile(r"(?i)aws_?secret_?access_?key\s*[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b"), 1, True),
    ("github_token", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"), 0, True),
    ("slack_token", "Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,250}\b"), 0, True),
    ("slack_webhook", "Slack incoming webhook URL",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}"), 0, True),
    ("stripe_live_key", "Stripe live secret or restricted key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,250}\b"), 0, True),
    ("google_api_key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0, True),
    ("anthropic_api_key", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9]{2,10}-[A-Za-z0-9_-]{40,250}\b"), 0, True),
    ("openai_api_key", "OpenAI API key",
     re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,250}\b|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"), 0, True),
    ("azure_storage_key", "Azure Storage account key in a connection string",
     re.compile(r"(?i)\bAccountKey=([A-Za-z0-9+/]{40,}={0,2})"), 1, True),
    ("connection_string_password", "Connection string with an embedded password",
     re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|ftp|sftp)://[^\s:/@\"']+:([^\s@/\"']{4,})@"), 1, True),
    ("jwt", "JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 0, False),
    ("credential_assignment", "Credential-named assignment with a literal value",
     re.compile(r"(?i)\b(?:password|passwd|pwd|secret|client_?secret|api_?key|apikey|access_?token|auth_?token|private_?key)\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,256})[\"']"), 1, False),
]

PLACEHOLDER_MARKS = ("example", "sample", "placeholder", "your", "changeme", "change_me", "dummy", "fake",
                     "redacted", "xxxx", "****", "...", "replace", "insert", "todo", "<", ">", "{{", "}}",
                     "${", "$(", "%(", "os.environ", "getenv")


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values()) if value else 0.0


def _placeholder(value: str) -> bool:
    lowered = value.casefold()
    return (any(mark in lowered for mark in PLACEHOLDER_MARKS) or len(set(value)) <= 3
            or lowered in {"password", "secret", "token", "apikey", "api_key", "none", "null"})


def mask(value: str) -> str:
    """Never more than a short prefix and suffix of a credential."""
    if len(value) >= 20:
        return value[:4] + "…" + value[-4:]
    if len(value) >= 8:
        return value[:2] + "…"
    return "…"


def detect_secret_findings(text: str, artifact_role: str, build_finding) -> List[Dict[str, object]]:
    if not isinstance(text, str) or not text:
        return []
    text = text[:MAX_TEXT]
    observations, kinds, total = [], Counter(), 0
    seen = set()
    for kind, label, pattern, group, strong in FORMATS:
        for match in pattern.finditer(text):
            value = match.group(group) if group else match.group(0)
            if kind != "private_key" and _placeholder(value):
                continue
            if not strong and _entropy(value) < 3.0:
                continue  # ordinary words and simple sequences
            key = (match.start(group) if group else match.start(), kind)
            if any(abs(key[0] - start) < 8 for start, _ in seen):
                continue  # one credential reported once, by its most specific format
            seen.add(key)
            total += 1
            kinds[kind] += 1
            if len(observations) < MAX_OBSERVATIONS:
                shown = label if kind == "private_key" else f"{label}: {mask(value)}"
                observations.append({"text": shown, "line": text.count("\n", 0, match.start()) + 1,
                                     "context_tag": "known_secret_format" if strong else "credential_like_value",
                                     "confidence": "high" if strong else "medium"})
    if not observations:
        return []
    finding = build_finding({
        "id": "hardcoded_secret", "category": "data", "finding_category": "data_presence",
        "subject": "credential", "action_state": "present", "status": "verified",
        "description": ("Credential-shaped material is packaged in this file (values masked). Remove it and rotate it; "
                        "whether it is live or authorized is not established."),
        "sources": SOURCES,
    }, observations, artifact_role)
    finding["count"] = total
    finding["secret_kinds"] = dict(sorted(kinds.items()))
    finding["observation_display"] = {"retained": len(observations), "total_matches": total,
                                      "selection": "First ten matches; every value masked."}
    return finding and [finding]
