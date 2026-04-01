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


def detect_sensitive_data_findings(
    text: str,
    artifact_role: str,
    build_finding,
) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    matched_rule_ids = set()

    for rule in SENSITIVE_DATA_RULES:
        matches = _normalize_matches(rule["compiled_pattern"].findall(text))
        if not matches:
            continue
        findings.append(build_finding(rule, matches, artifact_role))
        matched_rule_ids.add(rule["id"])

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
                ["patient-context-with-identifiers"],
                artifact_role,
            )
        )

    return findings


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
