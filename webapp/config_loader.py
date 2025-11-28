"""Helpers for loading secure UI configuration.

This module keeps API credentials and preset definitions on the server so the
frontend can discover available options without exposing secrets.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


SECURE_CONFIG_PATH = Path(__file__).parent / "secure_config.yaml"


def _load_secure_file(config_path: Path = SECURE_CONFIG_PATH) -> Dict[str, Any]:
    """Load the secure configuration YAML if it exists.

    The file is intentionally optional to avoid breaking the UI when a custom
    deployment has not provided credentials yet.
    """

    if not config_path.exists():
        return {"endpoints": [], "payload_presets": []}

    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    return {
        "endpoints": data.get("endpoints", []) or [],
        "payload_presets": data.get("payload_presets", []) or [],
    }


def get_endpoint_options() -> List[Dict[str, Any]]:
    """Return sanitized endpoint options for the UI.

    API keys are never exposed; the frontend only receives metadata needed for
    dropdown labels and target selection.
    """

    config = _load_secure_file()
    endpoints: List[Dict[str, Any]] = []

    for endpoint in config["endpoints"]:
        if not endpoint.get("enabled", True):
            continue

        endpoints.append(
            {
                "name": endpoint.get("name"),
                "target_service": endpoint.get("target_service"),
                "model": endpoint.get("model"),
                "endpoint_url": endpoint.get("endpoint_url"),
                "description": endpoint.get("description", ""),
                "has_api_key": bool(endpoint.get("api_key")),
            }
        )

    return endpoints


def get_payload_presets() -> List[Dict[str, Any]]:
    """Return payload preset definitions for dropdown selection."""

    config = _load_secure_file()
    presets: List[Dict[str, Any]] = []

    for preset in config["payload_presets"]:
        presets.append(
            {
                "name": preset.get("name"),
                "test_categories": preset.get("test_categories", []) or [],
                "custom_payloads": preset.get("custom_payloads", []) or [],
                "description": preset.get("description", ""),
            }
        )

    return presets


def resolve_endpoint(name: Optional[str]) -> Optional[Dict[str, Any]]:
    """Find a stored endpoint configuration by name."""

    if not name:
        return None

    for endpoint in _load_secure_file().get("endpoints", []):
        if endpoint.get("name") == name and endpoint.get("enabled", True):
            return endpoint

    return None


def resolve_payload_preset(name: Optional[str]) -> Optional[Dict[str, Any]]:
    """Find a payload preset by name."""

    if not name:
        return None

    for preset in _load_secure_file().get("payload_presets", []):
        if preset.get("name") == name:
            return preset

    return None
