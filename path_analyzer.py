"""Deterministic trust-boundary analysis for architecture scenarios."""

from __future__ import annotations

from typing import Any, Dict, List, Set

from architecture_profiles import get_profile
from architecture_scenarios import get_scenario
from trace import (
    BoundaryCrossing,
    PathFinding,
    PathScore,
    ScenarioTrace,
    TraceEdge,
)


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def analyze_architecture_scenario(profile_id: str, scenario_id: str) -> Dict[str, Any]:
    """Analyze a scenario against an architecture profile."""

    profile = get_profile(profile_id)
    scenario = get_scenario(scenario_id)

    components = {
        str(component["id"]): component for component in profile.get("components", [])
    }

    missing_components = [
        step_component
        for step in scenario.get("path", [])
        for step_component in (step["source"], step["target"])
        if step_component not in components
    ]
    if missing_components:
        missing = ", ".join(sorted(set(missing_components)))
        raise ValueError(
            f"Profile {profile_id} is missing components required by {scenario_id}: {missing}"
        )

    edges: List[TraceEdge] = []
    crossings: List[BoundaryCrossing] = []
    touched: List[str] = []
    privileges_exposed: Set[str] = set()

    for step in scenario.get("path", []):
        edge = TraceEdge(
            source=step["source"],
            target=step["target"],
            transport=step["transport"],
            content_type=step["content_type"],
            rationale=step["rationale"],
            carries_untrusted_content=bool(step.get("carries_untrusted_content")),
            carries_model_output=bool(step.get("carries_model_output")),
            privileged_action=bool(step.get("privileged_action")),
            writes_memory=bool(step.get("writes_memory")),
        )
        edges.append(edge)
        touched.extend([edge.source, edge.target])

        source_component = components[edge.source]
        target_component = components[edge.target]
        source_trust = str(source_component.get("trust_level", "unknown"))
        target_trust = str(target_component.get("trust_level", "unknown"))

        if source_trust != target_trust or edge.privileged_action or edge.writes_memory:
            crossings.append(
                BoundaryCrossing(
                    source=edge.source,
                    target=edge.target,
                    boundary_type=_boundary_type(edge, source_component, target_component),
                    severity=_boundary_severity(edge, source_component, target_component),
                    reason=edge.rationale,
                )
            )

        if edge.target in {"enterprise_write", "code_exec", "memory"}:
            privileges_exposed.add(edge.target)

    findings = _build_findings(profile, scenario, edges)
    score = PathScore(
        overall=_overall_severity(findings),
        attack_entry_point=str(scenario["entry_point"]),
        components_touched=_unique_preserve_order(touched),
        privileges_exposed=sorted(privileges_exposed),
        data_sensitivity=str(scenario.get("data_sensitivity", "unknown")),
        propagation_likelihood=str(scenario.get("propagation_likelihood", "unknown")),
    )

    trace = ScenarioTrace(
        profile_id=profile_id,
        scenario_id=scenario_id,
        scenario_name=str(scenario["name"]),
        entry_point=str(scenario["entry_point"]),
        components_touched=_unique_preserve_order(touched),
        edges=edges,
        boundary_crossings=crossings,
        findings=findings,
        score=score,
    )

    return {
        "profile": {
            "id": profile["id"],
            "name": profile["name"],
            "description": profile["description"],
        },
        "scenario": {
            "id": scenario["id"],
            "name": scenario["name"],
            "description": scenario["description"],
            "category": scenario["category"],
        },
        "trace": trace.to_dict(),
        "summary": {
            "finding_count": len(findings),
            "boundary_crossing_count": len(crossings),
            "highest_severity": score.overall,
        },
    }


def _build_findings(
    profile: Dict[str, Any],
    scenario: Dict[str, Any],
    edges: List[TraceEdge],
) -> List[PathFinding]:
    findings: List[PathFinding] = []
    function_runner = next(
        (
            component
            for component in profile.get("components", [])
            if component.get("id") == "function_runner"
        ),
        {},
    )
    boundary_mode = str(function_runner.get("boundary_mode", "direct_grouped"))
    isolated_execution = "sandbox" in boundary_mode or "brokered" in boundary_mode

    if scenario["category"] == "context_poisoning":
        findings.append(
            PathFinding(
                finding_id="context_poisoning",
                title="Context poisoning reaches privileged execution",
                severity="high",
                summary="Retrieved content can influence model behavior before a privileged action occurs.",
                evidence=[
                    "Untrusted retrieval content is inserted into model context.",
                    "The modeled path continues from model output into a write-capable tool group.",
                ],
                recommended_controls=[
                    "Separate retrieval instructions from executable orchestration state.",
                    "Require policy validation before write-capable tool calls sourced from retrieval context.",
                ],
            )
        )

    if any(edge.carries_model_output and edge.target == "function_runner" for edge in edges):
        findings.append(
            PathFinding(
                finding_id="tool_invocation_abuse",
                title="Model output drives tool invocation",
                severity="medium" if isolated_execution else "high",
                summary="Model-generated instructions reach the function runner without an independent approval boundary.",
                evidence=[
                    f"Function runner boundary mode is {boundary_mode}.",
                    "Model output is used as the control signal for a downstream tool call.",
                ],
                recommended_controls=[
                    "Require a policy gate between model output and tool selection.",
                    "Constrain tool arguments with an allow-listed schema per group.",
                ],
            )
        )

    if any(edge.privileged_action for edge in edges):
        findings.append(
            PathFinding(
                finding_id="privilege_escalation_chained_actions",
                title="Chained action path reaches privileged capability",
                severity="high",
                summary="The scenario reaches a privileged tool group after crossing at least one untrusted boundary.",
                evidence=[
                    "A privileged action occurs downstream of untrusted or model-generated content.",
                    "The exposed path reaches grouped execution capabilities rather than a read-only boundary.",
                ],
                recommended_controls=[
                    "Split high-risk tool groups from read-only groups.",
                    "Run privileged groups with ephemeral credentials and explicit approvals.",
                ],
            )
        )

    if any(edge.writes_memory for edge in edges):
        findings.append(
            PathFinding(
                finding_id="memory_contamination",
                title="Execution path writes into memory",
                severity="medium",
                summary="The modeled path persists execution-derived content into memory that can influence later responses.",
                evidence=[
                    "The scenario includes a memory write after tool or code execution.",
                    "Stored state can re-enter future context unless validated.",
                ],
                recommended_controls=[
                    "Require validation and provenance tags before memory writes.",
                    "Keep execution artifacts out of durable conversational memory by default.",
                ],
            )
        )

    return findings


def _boundary_type(
    edge: TraceEdge,
    source_component: Dict[str, Any],
    target_component: Dict[str, Any],
) -> str:
    if edge.writes_memory:
        return "memory_write"
    if edge.privileged_action:
        return "privileged_action"
    if source_component.get("trust_level") != target_component.get("trust_level"):
        return "trust_crossing"
    return "data_flow"


def _boundary_severity(
    edge: TraceEdge,
    source_component: Dict[str, Any],
    target_component: Dict[str, Any],
) -> str:
    if edge.privileged_action:
        return "high"
    if edge.writes_memory:
        return "medium"
    if source_component.get("trust_level") == "untrusted" and target_component.get("trust_level") in {"trusted", "privileged"}:
        return "high"
    if edge.carries_model_output:
        return "medium"
    return "low"


def _overall_severity(findings: List[PathFinding]) -> str:
    highest = "low"
    for finding in findings:
        if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest]:
            highest = finding.severity
    return highest


def _unique_preserve_order(values: List[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered
