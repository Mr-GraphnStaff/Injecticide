"""Trace models for architecture-aware MCP analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class TraceEdge:
    """A directed interaction between two architecture components."""

    source: str
    target: str
    transport: str
    content_type: str
    rationale: str
    carries_untrusted_content: bool = False
    carries_model_output: bool = False
    privileged_action: bool = False
    writes_memory: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BoundaryCrossing:
    """A trust or privilege boundary crossed by a trace edge."""

    source: str
    target: str
    boundary_type: str
    severity: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PathFinding:
    """A deterministic architecture finding backed by evidence."""

    finding_id: str
    title: str
    severity: str
    summary: str
    evidence: List[str] = field(default_factory=list)
    recommended_controls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PathScore:
    """Summary of risk across a modeled attack path."""

    overall: str
    attack_entry_point: str
    components_touched: List[str]
    privileges_exposed: List[str]
    data_sensitivity: str
    propagation_likelihood: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScenarioTrace:
    """Full trace for a modeled architecture scenario."""

    profile_id: str
    scenario_id: str
    scenario_name: str
    entry_point: str
    components_touched: List[str]
    edges: List[TraceEdge]
    boundary_crossings: List[BoundaryCrossing]
    findings: List[PathFinding]
    score: PathScore

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "entry_point": self.entry_point,
            "components_touched": list(self.components_touched),
            "edges": [edge.to_dict() for edge in self.edges],
            "boundary_crossings": [
                boundary.to_dict() for boundary in self.boundary_crossings
            ],
            "findings": [finding.to_dict() for finding in self.findings],
            "score": self.score.to_dict(),
        }
