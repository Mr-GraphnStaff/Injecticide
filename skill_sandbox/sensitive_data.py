from __future__ import annotations

import re
from typing import Dict, Iterable, List


SENSITIVE_DATA_RULES = (
    {
        "id": "pii_email_address",
        "category": "data",
        "severity": "low",
        "description": "Email addresses detected in artifact content.",
        "finding_category": "data_presence",
        "subject": "email_address",
        "action_state": "present",
        "disposition": "warn",
        "status": "verified",
        "sources": [
            {
                "name": "U.S. Department of Labor",
                "ref": "Personally identifiable information examples",
                "url": "https://www.dol.gov/general/ppii",
            }
        ],
        "compiled_pattern": re.compile(r"\b[A-Z0-9._%+-]+@(?!example\.com\b)[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    },
    {
        "id": "pii_phone_number",
        "category": "data",
        "severity": "low",
        "description": "Telephone numbers detected in artifact content.",
        "finding_category": "data_presence",
        "subject": "phone_number",
        "action_state": "present",
        "disposition": "warn",
        "status": "verified",
        "sources": [
            {
                "name": "U.S. Department of Labor",
                "ref": "Personally identifiable information examples",
                "url": "https://www.dol.gov/general/ppii",
            }
        ],
        "compiled_pattern": re.compile(
            r"\b(?:\+?1[-.\s]?)?(?:\(?[2-9]\d{2}\)?[-.\s]?)[2-9]\d{2}[-.\s]?\d{4}\b"
        ),
    },
    {
        "id": "pii_ssn",
        "category": "data",
        "severity": "medium",
        "description": "Social Security number patterns detected in artifact content.",
        "finding_category": "data_presence",
        "subject": "social_security_number",
        "action_state": "present",
        "disposition": "require_approval",
        "status": "verified",
        "sources": [
            {
                "name": "U.S. Department of Labor",
                "ref": "Personally identifiable information examples",
                "url": "https://www.dol.gov/general/ppii",
            }
        ],
        "compiled_pattern": re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
    },
    {
        "id": "pii_date_of_birth",
        "category": "data",
        "severity": "medium",
        "description": "Date of birth fields detected in artifact content.",
        "finding_category": "data_presence",
        "subject": "date_of_birth",
        "action_state": "present",
        "disposition": "require_approval",
        "status": "verified",
        "sources": [
            {
                "name": "U.S. Department of Labor",
                "ref": "Personally identifiable information examples",
                "url": "https://www.dol.gov/general/ppii",
            }
        ],
        "compiled_pattern": re.compile(
            r"\b(?:dob|date\s+of\s+birth|birth\s+date)\b[:\s-]{0,10}(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})",
            re.IGNORECASE,
        ),
    },
    {
        "id": "phi_medical_record_number",
        "category": "data",
        "severity": "medium",
        "description": "Medical record number fields detected in artifact content.",
        "finding_category": "data_presence",
        "subject": "medical_record_number",
        "action_state": "present",
        "disposition": "require_approval",
        "status": "verified",
        "sources": [
            {
                "name": "HHS",
                "ref": "PHI examples and identifiers",
                "url": "https://www.hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification/index.html",
            }
        ],
        "compiled_pattern": re.compile(
            r"\b(?:mrn|medical\s+record\s+number)\b[:\s#-]{0,10}[A-Z0-9-]{6,}",
            re.IGNORECASE,
        ),
    },
)

MEDICAL_CONTEXT_REGEX = re.compile(
    r"\b(patient|diagnosis|treatment|medication|prescription|provider|hospital|clinic|lab\s+result|medical(?:\s+record)?|therapy|clinical)\b",
    re.IGNORECASE,
)
PHI_STRONG_RULE_IDS = {
    "pii_ssn",
    "pii_date_of_birth",
    "phi_medical_record_number",
}

# These are lexical role aliases, not a claim of public availability or safety.
ROLE_EMAIL_ALIASES = {"security", "support", "info", "contact", "privacy", "help", "abuse", "noreply", "no-reply", "sales", "billing", "legal"}
ACCOUNT_IDENTIFIER = re.compile(
    r"\b(?:account[ _-]?(?:id|guid)|atlassian[ _-]?(?:account[ _-]?)?(?:id|guid)|user[ _-]?(?:id|guid))\b"
    r"[^\n]{0,60}?\b(?:[a-f0-9]{6,}:)?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b",
    re.I,
)


def detect_sensitive_data_findings(
    text: str,
    artifact_role: str,
    build_finding,
) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    matched_rule_ids = set()

    for rule in SENSITIVE_DATA_RULES:
        if rule["id"] == "pii_email_address":
            matches, contact_counts = _email_observations(rule["compiled_pattern"], text)
        else:
            matches = _observations_for_pattern(rule["compiled_pattern"], text)
        if not matches:
            continue
        finding = build_finding(rule, matches, artifact_role)
        if rule["id"] == "pii_email_address":
            finding["count"] = sum(contact_counts.values())
            finding["observation_display"] = {"retained": len(matches), "total_matches": finding["count"], "selection": "At most ten strongest contact observations; all supplied text counted."}
            finding["contact_context"] = {
                "classification": "role_alias_syntax_only" if not contact_counts["individual_or_unknown"] else "individual_or_unknown_contact",
                "role_alias_matches": contact_counts["role_alias"],
                "individual_or_unknown_matches": contact_counts["individual_or_unknown"],
                "public_availability": "unknown", "organizational_approval": "not_verified",
                "priority_basis": "Role-style local-part syntax receives informational priority; individual or unknown addresses require disclosure review regardless of documentation role.",
            }
        findings.append(finding)
        matched_rule_ids.add(rule["id"])

    identifiers = _observations_for_pattern(ACCOUNT_IDENTIFIER, text)
    if identifiers:
        findings.append(build_finding({
            "id": "pii_account_identifier", "category": "data", "finding_category": "data_presence",
            "subject": "account_identifier", "action_state": "present", "status": "verified",
            "description": "Account/user identifier label alongside a UUID-shaped value; disclosure review is required. Identity and public availability are unverified.",
            "sources": SENSITIVE_DATA_RULES[0]["sources"],
        }, identifiers, artifact_role))

    if MEDICAL_CONTEXT_REGEX.search(text) and matched_rule_ids.intersection(PHI_STRONG_RULE_IDS):
        findings.append(
            build_finding(
                {
                    "id": "phi_patient_record",
                    "category": "data",
                    "severity": "medium",
                    "description": "Patient or healthcare context appears alongside direct identifiers.",
                    "finding_category": "data_presence",
                    "subject": "patient_record",
                    "action_state": "present",
                    "disposition": "require_approval",
                    "status": "verified",
                    "sources": [
                        {
                            "name": "HHS",
                            "ref": "PHI identifiers and de-identification guidance",
                            "url": "https://www.hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification/index.html",
                        }
                    ],
                },
                [
                    {
                        "text": "patient-context-with-identifiers",
                        "line": _first_match_line(MEDICAL_CONTEXT_REGEX, text),
                        "context_tag": "pattern_match",
                        "confidence": "medium",
                    }
                ],
                artifact_role,
            )
        )

    return findings


def _email_observations(pattern, text):
    """Count all input matches with bounded evidence and incremental line scans."""
    aliases, individual = [], []
    counts = {"role_alias": 0, "individual_or_unknown": 0}
    previous, line = 0, 1
    for match in pattern.finditer(text):
        line += text.count("\n", previous, match.start())
        previous = match.start()
        value = match.group(0)
        is_alias = value.split("@", 1)[0].casefold() in ROLE_EMAIL_ALIASES
        counts["role_alias" if is_alias else "individual_or_unknown"] += 1
        retained = aliases if is_alias else individual
        if len(retained) < 10:
            retained.append({"text": value, "line": line,
                             "context_tag": "role_email_alias" if is_alias else "individual_or_unknown_email",
                             "confidence": "medium"})
    return (individual + aliases)[:10], counts


def _observations_for_pattern(pattern: re.Pattern[str], text: str) -> List[Dict[str, object]]:
    observations: List[Dict[str, object]] = []
    for match in pattern.finditer(text):
        observations.append(
            {
                "text": re.sub(r"\s+", " ", match.group(0)).strip(),
                "line": text.count("\n", 0, match.start()) + 1,
                "context_tag": "pattern_match",
                "confidence": "medium",
            }
        )
        if len(observations) >= 3:
            break
    return observations


def _first_match_line(pattern: re.Pattern[str], text: str) -> int:
    match = pattern.search(text)
    if not match:
        return 1
    return text.count("\n", 0, match.start()) + 1


def _normalize_matches(matches: Iterable[object]) -> List[str]:
    normalized: List[str] = []
    for match in matches:
        if isinstance(match, tuple):
            value = " ".join(str(item) for item in match if item)
        else:
            value = str(match)
        value = re.sub(r"\s+", " ", value).strip()
        if value and value not in normalized:
            normalized.append(value)
    return normalized[:3]
