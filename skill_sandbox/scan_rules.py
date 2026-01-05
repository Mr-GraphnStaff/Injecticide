from __future__ import annotations

import re
from typing import Dict, Tuple

PROMPT_PATTERNS: Tuple[Dict[str, str], ...] = (
    {
        "id": "prompt_override",
        "category": "prompt",
        "severity": "high",
        "description": "Attempts to override or ignore higher-priority instructions.",
        "regex": r"\b(ignore|override|bypass)\s+(previous|prior|above|system|developer)\b",
    },
    {
        "id": "system_exfiltration",
        "category": "prompt",
        "severity": "high",
        "description": "Requests or leaks system/developer messages or hidden prompts.",
        "regex": r"\b(system|developer)\s+(prompt|message|instructions)\b|\breveal\s+the\s+system\s+prompt\b",
    },
    {
        "id": "secret_exfiltration",
        "category": "prompt",
        "severity": "medium",
        "description": "Requests secrets, tokens, or keys in prompt text.",
        "regex": r"\b(api\s*key|secret|token|password|credential|access\s+key|private\s+key|ssh|pem)\b",
    },
    {
        "id": "tool_escape",
        "category": "prompt",
        "severity": "medium",
        "description": "Attempts to execute or escape to external tools or files.",
        "regex": r"\b(run|execute|shell|terminal|powershell|bash|cmd\.exe)\b",
    },
)

CODE_PATTERNS: Tuple[Dict[str, str], ...] = (
    {
        "id": "dynamic_exec",
        "category": "code",
        "severity": "high",
        "description": "Dynamic code execution helpers detected.",
        "regex": r"\b(exec|eval|compile)\s*\(",
    },
    {
        "id": "subprocess_spawn",
        "category": "code",
        "severity": "medium",
        "description": "Process execution via subprocess or os.system.",
        "regex": r"\b(subprocess\.run|subprocess\.Popen|os\.system)\b",
    },
    {
        "id": "network_calls",
        "category": "code",
        "severity": "medium",
        "description": "Network or HTTP request usage detected.",
        "regex": r"\b(requests\.|urllib\.|httpx\.|socket\.)\b",
    },
    {
        "id": "filesystem_access",
        "category": "code",
        "severity": "low",
        "description": "File system access or environment reads detected.",
        "regex": r"\b(open\(|pathlib\.|os\.environ|os\.listdir)\b",
    },
)

URL_FETCH_PATTERNS: Tuple[Dict[str, str], ...] = (
    {
        "id": "url_fetch",
        "category": "code",
        "severity": "medium",
        "description": "Remote fetch or download helpers detected.",
        "regex": r"\b(curl|wget|Invoke-WebRequest|fetch\s*\(|requests\.get\s*\()\b",
    },
)

OBFUSCATION_PATTERNS: Tuple[Dict[str, str], ...] = (
    {
        "id": "base64_usage",
        "category": "obfuscation",
        "severity": "medium",
        "description": "Base64 helpers or long encoded blobs detected.",
        "regex": r"\bbase64\b|[A-Za-z0-9+/]{80,}={0,2}",
    },
)

FILE_OP_PATTERNS: Tuple[Dict[str, str], ...] = (
    {
        "id": "dangerous_file_ops",
        "category": "code",
        "severity": "medium",
        "description": "Potentially destructive file system operations detected.",
        "regex": r"\b(rm\s+-rf|del\s+/f\s+/s|Remove-Item\s+-Recurse|shutil\.rmtree|chmod\s+[0-7]{3,4})\b",
    },
    {
        "id": "home_write",
        "category": "code",
        "severity": "low",
        "description": "Writes to home directories or user profiles detected.",
        "regex": r"\b(/home/|~\/|C:\\\\Users\\\\|\\.ssh/)\b",
    },
)

SENSITIVE_PATTERNS: Tuple[Dict[str, str], ...] = (
    {
        "id": "sensitive_keywords",
        "category": "prompt",
        "severity": "medium",
        "description": "Sensitive keywords or credential references detected.",
        "regex": r"\b(private\s+key|ssh|pem)\b",
    },
)


def compile_patterns() -> Tuple[Dict[str, object], ...]:
    compiled = []
    for pattern in (
        *PROMPT_PATTERNS,
        *CODE_PATTERNS,
        *URL_FETCH_PATTERNS,
        *OBFUSCATION_PATTERNS,
        *FILE_OP_PATTERNS,
        *SENSITIVE_PATTERNS,
    ):
        compiled.append(
            {
                **pattern,
                "compiled": re.compile(pattern["regex"], re.IGNORECASE),
            }
        )
    return tuple(compiled)
