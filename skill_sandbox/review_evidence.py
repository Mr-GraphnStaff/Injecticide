"""Verify administrator-issued evidence envelopes without contacting an issuer.

This is an Injecticide evidence transport, not a vendor signature format.
Source rationale: Anthropic enterprise skills review and NVIDIA trust pipeline;
see rules/package_sources.json. An authenticated assertion is not a safety proof.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

try:
    from .package_formats import bounded_data
except ImportError:
    from package_formats import bounded_data


def canonical_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def verify_envelope(envelope, artifact_hash):
    result = {"status": "not_verified", "controls": {}, "reason": "No trusted evidence envelope supplied"}
    if not isinstance(envelope, dict):
        return result
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    issuer = envelope.get("issuer")
    key_file = os.getenv("INJECTICIDE_EVIDENCE_KEYS")
    if not key_file or not Path(key_file).is_absolute() or not Path(key_file).is_file():
        return {**result, "reason": "Administrator evidence trust configuration is unavailable"}
    try:
        keys = bounded_data(Path(key_file).read_text(encoding="utf-8"))
        key = keys.get(issuer) if isinstance(keys, dict) and isinstance(issuer, str) else None
        if not isinstance(key, str) or len(bytes.fromhex(key)) < 32 or not isinstance(payload, dict) or not isinstance(signature, str):
            raise ValueError("Untrusted issuer or invalid envelope")
        expected = hmac.new(bytes.fromhex(key), canonical_payload(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Evidence authentication failed")
        if payload.get("artifact_sha256") != artifact_hash:
            raise ValueError("Evidence artifact fingerprint differs")
        now = datetime.now(timezone.utc)
        issued = datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
        if issued.tzinfo is None or expires.tzinfo is None or not issued <= now < expires:
            raise ValueError("Evidence expired or not yet valid")
        controls = payload.get("controls", {})
        if not isinstance(controls, dict):
            raise ValueError("Controls must be a mapping")
        accepted = {k: v for k, v in controls.items() if isinstance(v, dict) and v.get("status") in {"pass", "fail"}}
        return {"status": "authenticated_issuer_assertion", "issuer": issuer[:100], "controls": accepted,
                "reason": "Hash-bound, current assertion authenticated against administrator trust configuration"}
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return {**result, "reason": "Evidence is invalid, expired, hash-mismatched or untrusted"}


def evaluation_status(control):
    cases = control.get("cases", []) if isinstance(control, dict) else []
    required = {"positive_trigger", "negative_trigger", "coexistence", "bounded_workflow"}
    if not isinstance(cases, list) or not 4 <= len(cases) <= 100:
        return "insufficient_evidence"
    if not required.issubset({c.get("kind") for c in cases if isinstance(c, dict)}):
        return "insufficient_evidence"
    if any(not isinstance(c, dict) or type(c.get("passed")) is not bool for c in cases):
        return "insufficient_evidence"
    return "passed_by_authenticated_issuer" if all(c["passed"] for c in cases) and control.get("status") == "pass" else "failed_by_authenticated_issuer"
