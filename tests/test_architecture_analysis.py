import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from architecture_profiles import get_profile, list_profiles
from path_analyzer import analyze_architecture_scenario


def test_list_profiles_returns_grouped_agent_profile():
    profiles = list_profiles()

    assert profiles
    assert any(profile["id"] == "mcp_grouped_agent" for profile in profiles)


def test_get_profile_contains_required_architecture_components():
    profile = get_profile("mcp_grouped_agent")
    component_ids = {component["id"] for component in profile["components"]}

    assert {"client", "model", "function_runner", "memory", "retrieval_source"}.issubset(component_ids)


def test_architecture_analysis_returns_trace_and_findings():
    result = analyze_architecture_scenario(
        profile_id="mcp_grouped_agent",
        scenario_id="poisoned_retrieval_to_enterprise_write",
    )

    trace = result["trace"]
    finding_ids = {finding["finding_id"] for finding in trace["findings"]}

    assert result["summary"]["finding_count"] >= 2
    assert trace["score"]["attack_entry_point"] == "retrieval_source"
    assert "context_poisoning" in finding_ids
    assert "privilege_escalation_chained_actions" in finding_ids
