"""Coverage, governance evidence, and optional OMS verification.

Sources: NVIDIA signing-agent-skills and Anthropic enterprise guidance.
The trust anchor and verifier path are server-admin configuration, never upload data.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from datetime import date

try:
    from .package_formats import bounded_data
    from .review_evidence import verify_envelope, evaluation_status
except ImportError:
    from package_formats import bounded_data
    from review_evidence import verify_envelope, evaluation_status


def signature_evidence(records, extraction_root=None):
    signatures = [e for e in records if e["path"].endswith("/skill.oms.sig") or e["path"] == "skill.oms.sig"]
    if not signatures:
        return {"status": "not_present", "format": "OMS", "trusted_publisher": "not_verified"}
    trust = os.getenv("INJECTICIDE_OMS_TRUST_ANCHOR")
    verifier = os.getenv("INJECTICIDE_OMS_VERIFIER")
    results = []
    for entry in signatures:
        result = {"path": entry["path"], "format": "OMS", "status": "present_unverified", "trusted_publisher": "not_verified"}
        if not trust or not verifier:
            result["reason"] = "Administrator-configured trust anchor and verifier are required"
        elif not extraction_root or any(e.get("assessment_state") in {"rejected_unsafe_entry", "limited_or_truncated"} for e in records):
            result["reason"] = "Original complete skill directory is required for verification"
        elif not Path(trust).is_absolute() or not Path(verifier).is_absolute() or not Path(trust).is_file() or not Path(verifier).is_file():
            result.update(status="verifier_unavailable", reason="Configured verifier/trust anchor is unavailable")
        else:
            root = Path(extraction_root).resolve()
            signature = (root / entry["path"]).resolve()
            if not signature.is_relative_to(root) or not signature.is_file():
                result.update(status="verification_failed", reason="Signature path is unavailable or outside package")
            else:
                # Source: https://docs.nvidia.com/skills/signing-agent-skills
                # Fixed argument vector: no shell and no upload-selected program/options.
                try:
                    run = subprocess.run([verifier, "verify", "certificate", str(signature.parent),
                                          "--signature", str(signature), "--certificate-chain", trust],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         timeout=10, check=False)
                    result.update(status="verified" if run.returncode == 0 else "verification_failed",
                                  trusted_publisher="verified_against_configured_anchor" if run.returncode == 0 else "not_verified")
                except (OSError, subprocess.TimeoutExpired):
                    result.update(status="verification_failed", reason="Verifier unavailable or timed out")
        results.append(result)
    return {"status": "verified" if results and all(r["status"] == "verified" for r in results) else "not_verified",
            "results": results, "scope": "signature_integrity_only_not_behavioral_safety"}


def evidence_profile(records, texts, analysis, artifact_sha256, supplied=None, extraction_root=None):
    metadata = []
    for skill in analysis["skills"]:
        values = skill.get("metadata", {})
        metadata.append({"path": skill["path"], "claims": values, "status": "declared_unverified",
                         "missing_recommended_fields": [k for k in ("owner", "version", "last-eval-date", "data-classification") if k not in values]})
    evidence = supplied or {}
    if not isinstance(evidence, dict):
        raise ValueError("Governance evidence must be a JSON object")
    bound = evidence.get("artifact_sha256") == artifact_sha256
    authenticated = verify_envelope(evidence.get("envelope"), artifact_sha256)
    checks = []
    for key in ("independent_review", "source_control", "version_pinning", "evaluation", "coexistence_evaluation",
                "tenant_access", "publishing_approval", "runtime_sandbox", "audit_logging", "deprecation"):
        provided = key in evidence
        checks.append({"control": key, "status": "declared_unverified" if provided and bound else "not_assessed",
                       "reason": "Supplied evidence is hash-bound but has no independently verified issuer" if provided and bound else
                                 "Evidence is for a different artifact" if provided else "Requires authorized external evidence or isolated runtime evaluation"})
        if key in authenticated["controls"]:
            checks[-1].update(status="authenticated_issuer_" + authenticated["controls"][key]["status"],
                              reason="Current artifact-bound assertion from a configured reviewer/tenant evidence issuer")
    signatures = signature_evidence(records, extraction_root)
    return {"artifact_sha256": artifact_sha256, "metadata": metadata, "controls": checks,
            "signature_verification": signatures, "policy_effect": "advisory_not_tenant_enforcement",
            "evidence_authentication": {k: v for k, v in authenticated.items() if k != "controls"},
            "evaluation": {"status": evaluation_status(authenticated["controls"]["evaluation"]) if "evaluation" in authenticated["controls"] else "declared_unverified" if bound and "evaluation" in evidence else "not_assessed",
                           "reason": "No uploaded code, model endpoint or evaluation command is executed by a static scan"}}


def coverage_report(records):
    counts = {}
    for e in records:
        state = e.get("assessment_state", "unsupported")
        counts[state] = counts.get(state, 0) + 1
    covered = {"text_analyzed", "structured_content_analyzed"}
    analyzed = [e for e in records if e.get("assessment_state") in covered]
    partial = (len(analyzed) != len(records) or not records
               or any(e.get("assessment_state") == "structured_content_analyzed" for e in records)
               or any(stage.get("status") == "partial" for e in records
                      for name, stage in e.get("analysis_coverage", {}).items()
                      if name != "creator_markers"))
    total_bytes = sum(e.get("size", 0) for e in records)
    assets = [e for e in records if e.get("asset_inspection")]
    structurally_inspected = [e for e in assets if e["asset_inspection"]["status"] == "inspected"]
    archives = [e for e in records if e.get("archive_inspection")]
    unsupported = [e for e in records if e.get("assessment_state") not in covered and not e.get("asset_inspection") and not e.get("archive_inspection")]
    return {"status": "partial" if partial else "complete_supported_content",
            "total_files": len(records), "analyzed_files": len(analyzed), "unassessed_files": len(records) - len(analyzed),
            "total_bytes": total_bytes, "analyzed_file_bytes": sum(e.get("size", 0) for e in analyzed),
            "byte_metric_scope": "Original file sizes represented by analysis; not bytes exhaustively inspected",
            "states": counts, "binary_security_analysis": "not_performed",
            "inspection_summary": {
                "text_or_structured_files_analyzed": len(analyzed),
                "assets_with_structural_inspection": sum(bool(e["asset_inspection"]["checks"]) for e in assets),
                "assets_passing_supported_structural_checks": len(structurally_inspected),
                "nested_archives_with_structural_inspection": sum(bool(e["archive_inspection"]["checks"]) for e in archives),
                "files_without_supported_inspection": len(unsupported) + sum(not bool(e["asset_inspection"]["checks"]) for e in assets) + sum(not bool(e["archive_inspection"]["checks"]) for e in archives),
                "asset_metadata_files_analyzed": sum(bool(e.get("analysis_coverage", {}).get("text_patterns", {}).get("supplied_characters")) for e in assets),
                "image_visual_analysis": "not_performed", "font_program_analysis": "not_performed",
                "scope": "Text analysis and asset structure are separate inspection stages; neither certifies runtime safety.",
            },
            "detector_coverage": [{"path": e["path"], "detectors": e.get("analysis_coverage", {})} for e in records],
            "creator_mitigation_scope": "Creator reading-convention verification is separate from scanner detector completeness and target runtime acceptance.",
            "statement": "No findings applies only to analyzed content. Binary assets and excluded content are not certified safe.",
            "mandatory_components_complete": not any(e.get("required_component") and e.get("assessment_state") not in covered for e in records)}


def scanner_metadata():
    base = Path(__file__).resolve().parent
    engine_digest = hashlib.sha256()
    for source in sorted(base.glob("*.py"), key=lambda item: item.name):
        raw = source.read_bytes()
        engine_digest.update(source.name.encode("utf-8") + b"\0")
        engine_digest.update(len(raw).to_bytes(8, "big"))
        engine_digest.update(raw)
    manifest = base / "vendor_validators" / "manifest.json"
    if manifest.is_file():
        engine_digest.update(b"vendor_validators/manifest.json\0" + manifest.read_bytes())
    catalogs = []
    for name in ("violations", "dispositions", "package_sources", "skill_standards", "standards_sources", "obsession_signatures"):
        path = base / "rules" / (name + ".json")
        data = json.loads(path.read_text())
        reviewed = data.get("last_reviewed")
        age = (date.today() - date.fromisoformat(reviewed)).days if reviewed else None
        catalogs.append({"name": name, "version": data.get("catalog_version"), "last_reviewed": reviewed,
                         "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                         "freshness": "unknown" if age is None or age < 0 else "stale" if age > 90 else "current",
                         "age_days": age})
    return {"scanner_version": "0.14.0", "adapter_version": "2026-10-29", "catalogs": catalogs,
            "engine_source_sha256": engine_digest.hexdigest(),
            "engine_fingerprint_scope": "Sorted local scanner Python modules and shipped validator manifest; excludes uploaded content.",
            "update_policy": "reviewed_application_release", "automatic_research_activation": False,
            "network_access_during_static_analysis": False,
            "network_scope": "Built-in static analyzers never connect; optional administrator verifier isolation is operator-managed",
            "optional_signature_verifier": "administrator_configured_local_process"}
