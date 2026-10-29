from __future__ import annotations

from typing import Dict, Iterable, List


SOURCE_CHANNELS = {"user_turn", "retrieved_document", "tool_output", "uploaded_artifact", "unknown"}
INSTRUCTION_POLICY_RULES = {"secret_exfiltration", "system_exfiltration", "prompt_override",
                            "autonomous_authoritative_write", "bulk_enterprise_modification",
                            "workflow_manipulation", "cross_system_automation"}
UNTRUSTED_CHANNELS = {"retrieved_document", "tool_output", "uploaded_artifact", "unknown"}


def apply_instruction_policy(scan_results, source_channel="uploaded_artifact"):
    """Evaluate evidence in adapter-supplied context, never an upload's claim.

    The detector's retained speech-act observations and this policy decision are
    separate evidence. Legacy severity fields mirror policy for existing clients.
    Source channels are analysis inputs, not runtime provenance authentication.
    """
    if not isinstance(source_channel, str) or source_channel not in SOURCE_CHANNELS:
        raise ValueError("Unsupported source channel")
    rank = {"block": 0, "review": 1, "flag": 2, "allow_log": 3}
    for item in scan_results:
        context_limits = sorted({observation["context_limit"] for finding in item.get("findings", [])
                                 for observation in finding.get("observations", [])
                                 if observation.get("context_limit")})
        if context_limits:
            item.setdefault("analysis_coverage", {})["instruction_context"] = {
                "status": "partial", "limits": context_limits,
                "reason": "Bounded discourse context was exhausted. Candidate detection remains separate; complete intent or reference resolution is not established."}
        for finding in item.get("findings", []):
            if finding.get("id") not in INSTRUCTION_POLICY_RULES:
                continue
            decisions = []
            for observation in finding.get("observations", []):
                act = observation.get("speech_act", "ambiguous")
                target = observation.get("target", "unspecified")
                confidence = observation.get("confidence", "medium")
                if act == "described_risk":
                    action, reason = "allow_log", "Describes a risk; no operative request established."
                elif act == "example":
                    action, reason = "flag", "Illustrative content retains its instruction evidence; flag model exposure."
                elif (act == "request" and observation.get("imperative_evidence") is True
                      and target == "model_or_system" and confidence == "high"
                      and source_channel in UNTRUSTED_CHANNELS):
                    action, reason = "block", "High-confidence model-directed request from an untrusted source."
                elif act == "request" and source_channel == "user_turn":
                    action, reason = "review", "User-turn request requires policy review; user origin does not establish authorization for sensitive actions."
                else:
                    action, reason = "review", "Intent, target, confidence or source provenance is unresolved; review required."
                decisions.append({"speech_act": act, "target": target, "confidence": confidence,
                                  "imperative_evidence": bool(observation.get("imperative_evidence")),
                                  "action": action, "reason": reason, "line": observation.get("line"),
                                  "line_end": observation.get("line_end")})
            if not decisions:
                decisions = [{"speech_act": "ambiguous", "target": "unspecified", "confidence": "low",
                              "imperative_evidence": False, "action": "review", "line": None,
                              "reason": "No classified instruction evidence supplied."}]
            action = min((decision["action"] for decision in decisions), key=rank.__getitem__)
            finding["policy_evaluation"] = {"action": action, "source_channel": source_channel,
                                             "observations": decisions,
                                             "scope": "static_recommendation_not_runtime_enforcement"}
            if any(decision["speech_act"] == "request" for decision in decisions):
                finding["action_state"] = "requested"
                finding["description"] = "Instruction-request evidence detected; the separate policy evaluation records source channel, target, confidence and recommended response. Execution was not observed."
            elif action == "review":
                finding["action_state"] = "intent_unverified"
            elif action == "flag":
                finding["action_state"] = ("declared_test_input" if finding.get("observations") and all(
                    observation.get("context_tag") == "test_fixture" for observation in finding["observations"])
                    else "example_flagged")
                finding["description"] = "Illustrative instruction content remains detected and flagged for model exposure; example framing does not remove its evidence or establish runtime safety."
            else:
                finding["action_state"] = ("protective_guidance" if finding.get("observations") and all(
                    observation.get("context_tag") in {"protective_language", "negated_or_defined"}
                    for observation in finding["observations"]) else "documented_risk")
            # Structured evaluation inputs keep their existing review flag for
            # compatibility. That presentation does not turn policy flag into
            # block: governance consumes policy_evaluation independently below.
            needs_review = action == "review" or (action == "flag" and finding["action_state"] == "declared_test_input")
            finding.update(tier="block" if action == "block" else "review" if needs_review else "info",
                           severity="high" if action == "block" else "medium" if needs_review else "info",
                           disposition="block" if action == "block" else "require_approval" if needs_review else "info",
                           counts_for_governance=action == "block", is_actionable=action == "block" or needs_review,
                           display_kind="actionable_finding" if action == "block" or needs_review else "informational_signal")


BLOCK_BY_DEFAULT_RULES = {
    "prompt_override",
    "system_exfiltration",
    "secret_exfiltration",
    "dynamic_exec",
    "autonomous_authoritative_write",
    "bulk_enterprise_modification",
    "workflow_manipulation",
    "cross_system_automation",
}

CODE_EXECUTION_RULES = {
    "code_in_text_artifact",
    "executable_packaged_as_document",
    "declared_execution_target",
    "declared_process_launch",
    "broad_tool_preapproval",
    "insecure_component_transport",
    "dynamic_exec",
    "subprocess_spawn",
    "tool_escape",
    "declared_tool_execution",
}

NETWORK_RULES = {
    "network_calls",
    "url_fetch",
}

FILESYSTEM_RULES = {
    "filesystem_access",
    "dangerous_file_ops",
    "home_write",
}

ENTERPRISE_WRITE_RULES = {
    "autonomous_authoritative_write",
    "bulk_enterprise_modification",
    "workflow_manipulation",
    "cross_system_automation",
}

SENSITIVE_HANDLING_RULES = {
    "literal_credential_declaration",
    "secret_exfiltration",
    "sensitive_keywords",
}

REGULATED_DATA_RULES = {
    "pii_ssn",
    "pii_date_of_birth",
    "phi_medical_record_number",
    "phi_patient_record",
}
CONTACT_PRESENCE_RULES = {"pii_email_address", "pii_phone_number"}


def build_governance_profile(
    scan_results: Iterable[Dict[str, object]],
    behavior_report: Dict[str, object],
) -> Dict[str, object]:
    scan_results = list(scan_results)
    observed_ids = {finding["id"] for item in scan_results for finding in item.get("findings", [])}
    findings = _collect_actionable_findings(scan_results)
    governance_findings = _collect_governance_findings(findings)
    finding_ids = {finding["id"] for finding in findings}
    governance_finding_ids = {finding["id"] for finding in governance_findings}
    personal_contact_review = bool(finding_ids.intersection({"pii_email_address", "pii_account_identifier"}))
    required_capabilities = set(
        behavior_report.get("behavioral_summary", {}).get("required_capabilities", [])
    )
    policy_capabilities = _infer_policy_capabilities(finding_ids, required_capabilities)

    sandbox_required = bool(
        policy_capabilities.intersection({"file_write", "network", "code_execution", "state_persistence"})
    )
    approval_required = bool(
        sandbox_required
        or "enterprise_access" in policy_capabilities
        or "credential_handling" in policy_capabilities
        or "regulated_data" in policy_capabilities
        or personal_contact_review
        or governance_finding_ids.intersection(ENTERPRISE_WRITE_RULES)
    )

    blocked = bool(governance_findings)
    execution_tier = _execution_tier(blocked, sandbox_required, policy_capabilities)
    if personal_contact_review and execution_tier == "read_only":
        execution_tier = "governed"

    decision_reasons = _build_decision_reasons(
        blocked=blocked,
        sandbox_required=sandbox_required,
        approval_required=approval_required,
        policy_capabilities=policy_capabilities,
        finding_ids=governance_finding_ids,
    )

    recommended_controls = _recommended_controls(
        blocked=blocked,
        sandbox_required=sandbox_required,
        approval_required=approval_required,
        policy_capabilities=policy_capabilities,
        finding_ids=governance_finding_ids,
    )
    if personal_contact_review:
        if policy_capabilities == {"read_only"}:
            decision_reasons = [r for r in decision_reasons if r != "Human approval should gate execution because the artifact is not purely read-only."]
            recommended_controls = [r for r in recommended_controls if r != "Require explicit human approval before side-effecting actions."]
        decision_reasons.append("Personal or unknown contact/account data requires disclosure review before execution or sharing.")
        recommended_controls.append("Review personal contact and account identifier disclosure; documentation role does not establish approval.")

    return {
        "data_observations": {"contact_data_present": bool(observed_ids.intersection(CONTACT_PRESENCE_RULES)),
                              "account_identifier_present": "pii_account_identifier" in observed_ids,
                              "sensitive_identifier_or_clinical_signal": bool(finding_ids.intersection(REGULATED_DATA_RULES)),
                              "disclosure_attempt_detected": any(
                                  finding.get("id") == "secret_exfiltration"
                                  and finding.get("action_state") == "requested"
                                  and any(observation.get("speech_act") == "request" and observation.get("imperative_evidence") is True
                                          for observation in finding.get("observations", []))
                                  for finding in findings),
                              "classification_scope": "Pattern observations, not a legal classification, ownership attestation or proof of a data transfer."},
        "policy_capabilities": sorted(policy_capabilities),
        "execution_tier": execution_tier,
        "sandbox_required": sandbox_required,
        "approval_required": approval_required,
        "brokered_tokens": _route_decision(
            mode="brokered",
            blocked=blocked,
            approval_required=approval_required,
            policy_capabilities=policy_capabilities,
            finding_ids=governance_finding_ids | finding_ids.intersection({"pii_email_address", "pii_account_identifier"}),
        ),
        "customer_managed_keys": _route_decision(
            mode="byo",
            blocked=blocked,
            approval_required=approval_required,
            policy_capabilities=policy_capabilities,
            finding_ids=governance_finding_ids | finding_ids.intersection({"pii_email_address", "pii_account_identifier"}),
        ),
        "decision_reasons": decision_reasons,
        "blocking_findings": [
            {"path": item.get("path"), "id": finding.get("id"),
             "tier": finding.get("tier"), "action_state": finding.get("action_state"),
             "policy_action": finding.get("policy_evaluation", {}).get("action"),
             "source_channel": finding.get("policy_evaluation", {}).get("source_channel"),
             "observations": [{key: observation.get(key) for key in ("line", "line_end", "context_tag", "confidence", "speech_act", "target", "activation_evidence")}
                              for observation in finding.get("observations", [])]}
            for item in scan_results for finding in _collect_governance_findings(
                _collect_actionable_findings([item]))
        ],
        "decision_scope": "Static evidence-based policy recommendation; tenant enforcement and runtime behavior are not verified.",
        "recommended_controls": recommended_controls,
    }


def _collect_actionable_findings(scan_results: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for item in scan_results:
        findings.extend(
            finding
            for finding in item.get("findings", [])
            if finding.get("is_actionable", finding.get("severity") != "info")
        )
    return findings


def _collect_governance_findings(findings: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    return [
        finding
        for finding in findings
        if (finding.get("policy_evaluation", {}).get("action") == "block"
            if finding.get("id") in INSTRUCTION_POLICY_RULES and finding.get("policy_evaluation")
            else finding.get("counts_for_governance") is True or finding.get("tier") == "block")
    ]


def _infer_policy_capabilities(finding_ids: set[str], required_capabilities: set[str]) -> set[str]:
    policy_capabilities: set[str] = set()

    if "file_write" in required_capabilities or finding_ids.intersection(FILESYSTEM_RULES | ENTERPRISE_WRITE_RULES):
        policy_capabilities.add("file_write")
    if (
        "external_content_embedding" in required_capabilities
        or finding_ids.intersection(NETWORK_RULES)
    ):
        policy_capabilities.add("network")
    if "credential_handling" in required_capabilities or finding_ids.intersection(SENSITIVE_HANDLING_RULES):
        policy_capabilities.add("credential_handling")
    if finding_ids.intersection(REGULATED_DATA_RULES):
        policy_capabilities.add("regulated_data")
    if "enterprise_access" in required_capabilities or finding_ids.intersection(ENTERPRISE_WRITE_RULES):
        policy_capabilities.add("enterprise_access")
    if finding_ids.intersection(CODE_EXECUTION_RULES):
        policy_capabilities.add("code_execution")
    if "state_persistence" in required_capabilities:
        policy_capabilities.add("state_persistence")

    if not policy_capabilities:
        policy_capabilities.add("read_only")

    return policy_capabilities


def _execution_tier(
    blocked: bool,
    sandbox_required: bool,
    policy_capabilities: set[str],
) -> str:
    if blocked:
        return "blocked"
    if sandbox_required:
        return "sandboxed"
    if policy_capabilities.intersection({"enterprise_access", "credential_handling", "regulated_data"}):
        return "governed"
    return "read_only"


def _route_decision(
    mode: str,
    blocked: bool,
    approval_required: bool,
    policy_capabilities: set[str],
    finding_ids: set[str],
) -> Dict[str, str]:
    if blocked:
        return {
            "decision": "block_by_default",
            "reason": "Detected high-risk prompt, credential, or enterprise action behavior.",
        }

    if finding_ids.intersection({"pii_email_address", "pii_account_identifier"}):
        return {"decision": "require_admin_approval", "reason": "Personal or unknown contact/account data requires disclosure review; public availability and approval are unverified."}

    if mode == "brokered" and policy_capabilities.intersection({"credential_handling", "enterprise_access", "regulated_data"}):
        return {
            "decision": "require_admin_approval",
            "reason": "Brokered execution against enterprise or credential-sensitive flows should stay under admin review.",
        }

    if approval_required or finding_ids.intersection(CODE_EXECUTION_RULES | NETWORK_RULES | FILESYSTEM_RULES):
        return {
            "decision": "require_admin_approval",
            "reason": "Skill needs side-effect controls before execution.",
        }

    if policy_capabilities == {"read_only"}:
        return {
            "decision": "allow",
            "reason": "Read-only skill with no side-effecting execution indicators.",
        }

    return {
        "decision": "allow_with_warnings",
        "reason": "Low-impact skill, but preserve governance visibility.",
    }


def _build_decision_reasons(
    *,
    blocked: bool,
    sandbox_required: bool,
    approval_required: bool,
    policy_capabilities: set[str],
    finding_ids: set[str],
) -> List[str]:
    reasons: List[str] = []

    if blocked:
        reasons.append("Blocking static findings require security review; see blocking_findings for source and classification evidence.")
    if "enterprise_access" in policy_capabilities:
        reasons.append("Skill claims access to enterprise systems or authoritative records.")
    if finding_ids.intersection(ENTERPRISE_WRITE_RULES):
        reasons.append("Artifact describes autonomous or workflow-changing writes to enterprise systems.")
    if "credential_handling" in policy_capabilities:
        reasons.append("Skill handles secrets, credentials, or key material.")
    if "regulated_data" in policy_capabilities:
        reasons.append("Artifact contains PII, PHI, or other regulated personal data patterns.")
    if sandbox_required:
        reasons.append("Execution requires sandboxing because the artifact implies code, file, network, or persistence side effects.")
    if approval_required and not blocked:
        reasons.append("Human approval should gate execution because the artifact is not purely read-only.")
    if not reasons:
        reasons.append("Artifact is consistent with a read-only skill profile.")

    return reasons


def _recommended_controls(
    *,
    blocked: bool,
    sandbox_required: bool,
    approval_required: bool,
    policy_capabilities: set[str],
    finding_ids: set[str],
) -> List[str]:
    controls: List[str] = []

    if blocked:
        controls.append("Block installation or execution by default pending security review.")
    if approval_required:
        controls.append("Require explicit human approval before side-effecting actions.")
    if sandbox_required:
        controls.append("Run only inside a sandbox with write-scope and network-egress restrictions.")
    if "enterprise_access" in policy_capabilities:
        controls.append("Restrict to least-privilege enterprise scopes and preserve audit provenance.")
    if "credential_handling" in policy_capabilities:
        controls.append("Disallow raw secret disclosure and prefer brokered or ephemeral credentials.")
    if "regulated_data" in policy_capabilities:
        controls.append("Treat embedded personal data as regulated content and require human review before distribution or execution.")
    if finding_ids.intersection(ENTERPRISE_WRITE_RULES):
        controls.append("Limit to draft-only or read-only modes unless an enterprise admin explicitly authorizes writes.")
    if not controls:
        controls.append("Eligible for read-only execution without extra brokered-token controls.")

    return controls
