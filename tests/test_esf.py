import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from analyzer import analyze
from analyzer_esf import analyze_esf
from payloads import get_all_payloads


def test_payload_registry_includes_esf():
    payloads = get_all_payloads()
    assert "esf" in payloads
    assert payloads["esf"], "ESF payloads should not be empty"


def test_analyzer_includes_esf_flags_keys():
    flags = analyze("This is a neutral response.")
    assert "esf_overconfident_without_caveats" in flags
    assert "esf_fabricated_citation_style" in flags
    assert "esf_contradiction_markers" in flags


def test_analyze_esf_overconfident_without_caveats():
    flags = analyze_esf("This is absolutely certain.")
    assert flags["esf_overconfident_without_caveats"] is True
