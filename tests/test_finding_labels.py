"""Every finding id the scanner can emit must have a plain-English label.

Discovery is deliberately fail-closed:

* Rule ids come from the JSON catalogs (violations.json and the Obsession
  signature manifest).
* Literal ids come from an AST walk of every ``skill_sandbox/*.py`` module:
  any dict literal with a constant ``"id"`` and a finding-shaped key
  (severity, tier, category, ...) is a finding or a package format finding.
* Ids built from a variable (``{"id": code, ...}``) are only allowed at the
  known helper sites listed in ``DYNAMIC_SITES``; for each of those the test
  recovers ids from the helper's call sites. A new dynamic site makes the test
  fail until it is added here, so a new detector cannot go unlabelled quietly.
* As a cross-check, the labelled skill corpus is scanned end to end and every
  emitted id must be labelled and must also have been found statically.
"""
import ast
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "skill_sandbox"
RULES = PACKAGE / "rules"
LABELS_PATH = RULES / "finding-labels.json"

FINDING_KEYS = {"severity", "tier", "category", "finding_category", "disposition", "subject"}

# (module, enclosing function) -> how to recover ids from its call sites:
# (callee name, positional index of the id argument), or a catalog marker.
DYNAMIC_SITES = {
    ("asset_inspection.py", "_finding"): ("call", "_finding", 1),
    ("package_threats.py", "finding"): ("call", "finding", 0),
    ("finding_enrichment.py", "build_finding"): ("catalog", "rule dicts: violations.json + literal dicts", None),
    ("obsession_signatures.py", "load_rules"): ("catalog", "obsession_signatures.json", None),
}

# Dict literals that carry an "id" but are not findings. Each needs a reason.
NON_FINDING_SITES = {
    ("correction_rules.py", "evaluate_pack"): "source-owned synthetic interpreter gate, never emitted by scanner",
    ("correction_gate.py", "_native_findings"): "offline gate-only profile fingerprint, never emitted by scanner",
    ("governance.py", "build_governance_profile"): "copies an existing finding id into blocking_findings",
    ("improvement_plan.py", "add"): "improvement-plan row id (plan_<hash>); rule_id refers to an existing finding",
    ("process_diagram.py", "node"): "diagram node id (n<index>)",
}

# Ids defined by the 0.16.0 database-asset contract; labelled ahead of the
# detector landing so the UI never shows a raw id.
CONTRACT_IDS = {"contact_directory", "database_not_cleared", "opaque_database", "embedded_executable_blob"}


def _constant_strings(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _constant_strings(node.body) | _constant_strings(node.orelse)
    return set()


class _Collector(ast.NodeVisitor):
    def __init__(self, module):
        self.module = module
        self.stack = []
        self.literal_ids = set()
        self.dynamic_sites = set()
        self.calls = []

    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Dict(self, node):
        if (self.module,self.stack[-1] if self.stack else "<module>") in NON_FINDING_SITES:
            self.generic_visit(node)
            return
        keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
        spread = any(k is None for k in node.keys)
        if "id" in keys and (keys & FINDING_KEYS or spread):
            value = node.values[[getattr(k, "value", None) for k in node.keys].index("id")]
            constants = _constant_strings(value)
            if constants:
                self.literal_ids |= constants
            else:
                self.dynamic_sites.add((self.module, self.stack[-1] if self.stack else "<module>"))
        self.generic_visit(node)

    def visit_Call(self, node):
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        self.calls.append((name, node.args))
        self.generic_visit(node)


def discover_finding_ids():
    literal, dynamic, calls = set(), set(), []
    for path in sorted(PACKAGE.glob("*.py")):
        collector = _Collector(path.name)
        collector.visit(ast.parse(path.read_text(encoding="utf-8")))
        literal |= collector.literal_ids
        dynamic |= collector.dynamic_sites
        calls.extend((path.name, name, args) for name, args in collector.calls)

    unknown_sites = dynamic - set(DYNAMIC_SITES) - set(NON_FINDING_SITES)
    assert not unknown_sites, (
        "New finding helper builds ids from a variable; teach DYNAMIC_SITES in "
        "tests/test_finding_labels.py how to recover its ids: " + repr(sorted(unknown_sites)))

    ids = set(literal)
    for (module, _function), (kind, callee, index) in DYNAMIC_SITES.items():
        if kind != "call":
            continue
        for call_module, name, args in calls:
            if call_module == module and name == callee and len(args) > index:
                recovered = _constant_strings(args[index])
                assert recovered, f"{module}:{callee} called with a non-literal id; cannot verify its label"
                ids |= recovered

    violations = json.loads((RULES / "violations.json").read_text(encoding="utf-8"))
    ids |= {rule["id"] for rule in violations["rules"]}
    signatures = json.loads((RULES / "obsession_signatures.json").read_text(encoding="utf-8"))
    ids |= {item["id"] for item in signatures.get("signatures", [])}
    return ids


def load_labels():
    return json.loads(LABELS_PATH.read_text(encoding="utf-8"))


def test_discovery_finds_known_detectors():
    ids = discover_finding_ids()
    # Sentinels from each discovery path, so a broken walker cannot pass vacuously.
    for expected in ("prompt_override", "hardcoded_secret", "pii_email_address", "phi_patient_record",
                     "credential_source_to_network_payload", "declared_tool_execution", "png_crc_mismatch",
                     "embedded_browser_script", "component_path", "skill_frontmatter", "frontmatter_extension",
                     "unverifiable_chunk_marker"):
        assert expected in ids, expected


def test_every_emittable_finding_id_has_a_label():
    labels = load_labels()
    missing = sorted((discover_finding_ids() | CONTRACT_IDS) - set(labels))
    assert not missing, "Finding ids without a plain-English label in finding-labels.json: " + ", ".join(missing)


def test_label_entries_are_well_formed():
    labels = load_labels()
    assert labels, "finding-labels.json is empty"
    for finding_id, entry in labels.items():
        assert set(entry) == {"label", "plain"}, finding_id
        assert entry["label"].strip() and len(entry["label"]) <= 60, finding_id
        assert entry["label"] != finding_id and "_" not in entry["label"], finding_id
        plain = entry["plain"].strip()
        assert plain.endswith(".") and 20 <= len(plain) <= 320, finding_id


@pytest.mark.parametrize("finding_id, forbidden", [
    ("secret_exfiltration", ("exfiltration",)),
    ("hardcoded_secret", ()),
])
def test_misleading_names_are_replaced(finding_id, forbidden):
    entry = load_labels()[finding_id]
    for word in forbidden:
        assert word not in entry["label"].lower()


def test_disclosure_request_label_says_secrets_are_not_present():
    entry = load_labels()["secret_exfiltration"]
    assert "request" in entry["label"].lower()
    assert "not mean" in entry["plain"] or "does not" in entry["plain"]


def test_corpus_scan_emits_only_labelled_and_discovered_ids():
    from webapp.skill_scanner import scan_upload

    labels = load_labels()
    discovered = discover_finding_ids()
    corpus = ROOT / "tests" / "fixtures" / "skill_corpus"
    files = sorted(corpus.glob("*/*.skill/SKILL.md"))
    assert files, "skill corpus fixtures missing"
    emitted = set()
    for path in files:
        result = scan_upload(path.read_bytes(), str(path))
        for item in result["files"]:
            emitted |= {finding["id"] for finding in item.get("findings", [])}
        emitted |= {issue["id"] for issue in (result.get("package") or {}).get("format_findings", []) if isinstance(issue, dict)}
    assert emitted, "corpus scan produced no findings; cross-check would be vacuous"
    assert not sorted(emitted - set(labels))
    assert not sorted(emitted - discovered), "static discovery missed ids the scanner emitted"
