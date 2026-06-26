"""Profile loading for architecture-aware MCP analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml


PROFILES_DIR = Path(__file__).resolve().parent / "profiles"
REQUIRED_PROFILE_KEYS = {
    "id",
    "name",
    "description",
    "components",
    "tool_groups",
    "memory_rules",
    "data_classifications",
}
REQUIRED_COMPONENT_KEYS = {"id", "kind", "trust_level"}


def list_profiles() -> List[Dict[str, Any]]:
    """Return all valid architecture profiles."""

    profiles: List[Dict[str, Any]] = []
    for path in sorted(PROFILES_DIR.glob("*.yaml")):
        profile = _load_profile_file(path)
        profiles.append(_profile_summary(profile))
    return profiles


def get_profile(profile_id: str) -> Dict[str, Any]:
    """Return a validated architecture profile by identifier."""

    for path in sorted(PROFILES_DIR.glob("*.yaml")):
        profile = _load_profile_file(path)
        if profile["id"] == profile_id:
            return profile

    raise KeyError(f"Unknown architecture profile: {profile_id}")


def _load_profile_file(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        profile = yaml.safe_load(handle) or {}

    validate_profile(profile, source=str(path))
    return profile


def validate_profile(profile: Dict[str, Any], *, source: str = "inline") -> None:
    """Validate the minimum contract required by the architecture analyzer."""

    missing = sorted(REQUIRED_PROFILE_KEYS - set(profile))
    if missing:
        missing_text = ", ".join(missing)
        raise ValueError(f"Profile {source} is missing required keys: {missing_text}")

    components = profile.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError(f"Profile {source} must define at least one component")

    component_ids = set()
    for component in components:
        if not isinstance(component, dict):
            raise ValueError(f"Profile {source} contains a non-dictionary component")
        component_missing = sorted(REQUIRED_COMPONENT_KEYS - set(component))
        if component_missing:
            missing_text = ", ".join(component_missing)
            raise ValueError(
                f"Profile {source} component is missing required keys: {missing_text}"
            )
        component_id = str(component["id"])
        if component_id in component_ids:
            raise ValueError(f"Profile {source} has duplicate component id: {component_id}")
        component_ids.add(component_id)

    tool_groups = profile.get("tool_groups")
    if not isinstance(tool_groups, list) or not tool_groups:
        raise ValueError(f"Profile {source} must define at least one tool group")


def _profile_summary(profile: Dict[str, Any]) -> Dict[str, Any]:
    execution_component = next(
        (
            component
            for component in profile.get("components", [])
            if component.get("id") == "function_runner"
        ),
        {},
    )
    return {
        "id": profile["id"],
        "name": profile["name"],
        "description": profile["description"],
        "component_count": len(profile.get("components", [])),
        "tool_group_count": len(profile.get("tool_groups", [])),
        "function_boundary_mode": execution_component.get("boundary_mode", "unknown"),
    }
