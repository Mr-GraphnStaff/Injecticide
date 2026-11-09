"""Privacy boundary: finite technical vocabulary, never report-derived prose."""
from __future__ import annotations
import json
import os
import re
import uuid
from pathlib import Path

SIGNALS = {
    "instruction_boundary": "Instruction priority and indirect prompt injection.",
    "secret_handling": "Credential handling and secret exfiltration controls.",
    "execution_boundary": "Tool execution, sandboxing and unsafe command execution.",
    "network_boundary": "Outbound network capabilities and external data transfer.",
    "data_protection": "PII, PHI and PCI handling controls; never actual records.",
    "unclassified_finding": "A scanner finding needs classification; no private evidence is available.",
    "incomplete_coverage": "Unsupported content or incomplete static analysis.",
}
RULE_MAP = {
    "prompt_override":"instruction_boundary", "system_exfiltration":"instruction_boundary",
    "secret_exfiltration":"secret_handling", "hardcoded_secret":"secret_handling",
    "dynamic_exec":"execution_boundary", "subprocess_spawn":"execution_boundary",
    "tool_escape":"execution_boundary", "network_calls":"network_boundary",
    "url_fetch":"network_boundary", "pii_email_address":"data_protection",
    "pii_phone_number":"data_protection", "pii_ssn":"data_protection",
    "phi_patient_record":"data_protection", "phi_medical_record_number":"data_protection",
    "contact_directory":"data_protection", "opaque_database":"incomplete_coverage",
    "database_not_cleared":"incomplete_coverage",
}
SCHEMA = "injecticide.research-signals.v1"


def signal_ids(report):
    # Only membership tests on controlled detector IDs; never copy string values.
    values = set()
    for file in report.get("files", [])[:200]:
        for finding in file.get("findings", [])[:1000]:
            key = finding.get("id")
            if isinstance(key, str):
                values.add(RULE_MAP.get(key, "unclassified_finding"))
    if report.get("coverage", {}).get("status") != "complete_supported_content":
        values.add("incomplete_coverage")
    return sorted(values)


def validate_signal(value):
    if (not isinstance(value, dict) or set(value) != {"schema", "event_id", "signals"}
            or value["schema"] != SCHEMA or not isinstance(value["event_id"], str)
            or not re.fullmatch(r"[a-f0-9]{32}", value["event_id"])
            or not isinstance(value["signals"], list) or len(value["signals"]) > len(SIGNALS)
            or any(not isinstance(x, str) or x not in SIGNALS for x in value["signals"])):
        raise ValueError("Only finite technical signals are accepted")
    return sorted(set(value["signals"]))


def model_signals(values):
    # Reconstruct all model text from trusted constants; no IDs/paths/counts cross.
    if not isinstance(values, (set, list, tuple)) or any(x not in SIGNALS for x in values):
        raise ValueError("Unknown technical signal")
    return [{"category": key, "description": SIGNALS[key]} for key in sorted(set(values))]


def publish_signal(report, event_id=None):
    folder = os.environ.get("INJECTICIDE_RESEARCH_SIGNALS_DIR")
    if not folder:
        return {"status":"disabled", "sensitive_data_retained":False}
    try:
        root = Path(folder)
        if not root.is_dir() or root.is_symlink():
            raise ValueError("Trusted signal volume required")
        value = {"schema":SCHEMA, "event_id":event_id or uuid.uuid4().hex, "signals":signal_ids(report)}
        validate_signal(value)
        if sum(1 for _ in root.glob("*.json")) >= 10000:
            raise ValueError("Signal capacity reached; evidence retained")
        target = root/(value["event_id"]+".json")
        temporary = root/("."+uuid.uuid4().hex+".tmp")
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value,stream,sort_keys=True)
        os.replace(temporary,target)
        return {"status":"queued", "sensitive_data_retained":False}
    except Exception:
        return {"status":"unavailable", "sensitive_data_retained":False}


def read_signals(folder):
    result = set()
    if not Path(folder).is_dir():
        return result
    for path in sorted(Path(folder).glob("*.json"))[-1000:]:
        try:
            if path.is_symlink() or path.stat().st_size > 2048:
                continue
            result.update(validate_signal(json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, ValueError, TypeError):
            continue
    return result
