"""Advanced payload collection for comprehensive LLM testing."""

from .baseline import BASELINE_PAYLOADS
from .extraction import EXTRACTION_PAYLOADS
from .jailbreak import JAILBREAK_PAYLOADS
from .encoding import ENCODING_PAYLOADS
from .context import CONTEXT_MANIPULATION_PAYLOADS
from .role import ROLE_PLAY_PAYLOADS
from .insurance import INSURANCE_SECTOR_PAYLOADS
from .policy import POLICY_VIOLATION_PAYLOADS

def get_all_payloads():
    """Return all available payload categories."""
    return {
        "baseline": BASELINE_PAYLOADS,
        "extraction": EXTRACTION_PAYLOADS,
        "jailbreak": JAILBREAK_PAYLOADS,
        "encoding": ENCODING_PAYLOADS,
        "context": CONTEXT_MANIPULATION_PAYLOADS,
        "roleplay": ROLE_PLAY_PAYLOADS,
        "insurance_us_ca": INSURANCE_SECTOR_PAYLOADS,
        "policy": POLICY_VIOLATION_PAYLOADS,
    }

__all__ = [
    "BASELINE_PAYLOADS",
    "EXTRACTION_PAYLOADS", 
    "JAILBREAK_PAYLOADS",
    "ENCODING_PAYLOADS",
    "CONTEXT_MANIPULATION_PAYLOADS",
    "ROLE_PLAY_PAYLOADS",
    "INSURANCE_SECTOR_PAYLOADS",
    "POLICY_VIOLATION_PAYLOADS",
    "get_all_payloads",
]
