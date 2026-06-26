"""Deterministic architecture scenarios for MCP threat analysis."""

from __future__ import annotations

from typing import Dict, List


SCENARIOS: List[Dict[str, object]] = [
    {
        "id": "poisoned_retrieval_to_enterprise_write",
        "name": "Poisoned Retrieval To Enterprise Write",
        "description": "External retrieval content influences the model and reaches a write-capable tool group.",
        "entry_point": "retrieval_source",
        "category": "context_poisoning",
        "path": [
            {
                "source": "retrieval_source",
                "target": "model",
                "transport": "retrieval_context",
                "content_type": "retrieved_content",
                "rationale": "Retrieved content is injected into active context before generation.",
                "carries_untrusted_content": True,
            },
            {
                "source": "model",
                "target": "function_runner",
                "transport": "tool_call",
                "content_type": "model_generated_instruction",
                "rationale": "Model output selects a downstream tool action.",
                "carries_model_output": True,
            },
            {
                "source": "function_runner",
                "target": "enterprise_write",
                "transport": "connector_call",
                "content_type": "side_effecting_action",
                "rationale": "Write-capable enterprise connector executes the action.",
                "privileged_action": True,
            },
            {
                "source": "enterprise_write",
                "target": "output_handler",
                "transport": "result_delivery",
                "content_type": "execution_result",
                "rationale": "Observed result is returned to the operator.",
            },
        ],
        "data_sensitivity": "regulated",
        "propagation_likelihood": "high",
    },
    {
        "id": "model_output_to_code_exec",
        "name": "Model Output To Code Execution",
        "description": "Prompt-derived model output is sent into a code execution boundary.",
        "entry_point": "client",
        "category": "tool_invocation_abuse",
        "path": [
            {
                "source": "client",
                "target": "model",
                "transport": "prompt_submission",
                "content_type": "user_input",
                "rationale": "User-controlled prompt enters the model context.",
                "carries_untrusted_content": True,
            },
            {
                "source": "model",
                "target": "function_runner",
                "transport": "tool_call",
                "content_type": "model_generated_instruction",
                "rationale": "Model output is used to request tool execution.",
                "carries_model_output": True,
            },
            {
                "source": "function_runner",
                "target": "code_exec",
                "transport": "sandbox_job",
                "content_type": "execution_request",
                "rationale": "Execution worker runs a code-capable task.",
                "privileged_action": True,
            },
            {
                "source": "code_exec",
                "target": "memory",
                "transport": "state_write",
                "content_type": "execution_artifact",
                "rationale": "Generated artifacts or observations are persisted for later context.",
                "writes_memory": True,
            },
            {
                "source": "memory",
                "target": "output_handler",
                "transport": "result_delivery",
                "content_type": "response_context",
                "rationale": "Stored state later influences what is shown back to operators.",
            },
        ],
        "data_sensitivity": "internal",
        "propagation_likelihood": "medium",
    },
]


def list_scenarios() -> List[Dict[str, object]]:
    """Return scenario metadata for the UI."""

    return [
        {
            "id": item["id"],
            "name": item["name"],
            "description": item["description"],
            "entry_point": item["entry_point"],
            "category": item["category"],
        }
        for item in SCENARIOS
    ]


def get_scenario(scenario_id: str) -> Dict[str, object]:
    """Return a scenario by identifier."""

    for scenario in SCENARIOS:
        if scenario["id"] == scenario_id:
            return scenario

    raise KeyError(f"Unknown architecture scenario: {scenario_id}")
