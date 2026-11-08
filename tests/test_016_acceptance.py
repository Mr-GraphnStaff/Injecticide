"""Injecticide 0.16.0 independent acceptance tests (issues #78-#83).

Written from the 0.16.0 shared contracts and the issue text, not from any
implementation. They state what *correct* means for a large enterprise skill
built by ``tests/fixtures/synthetic_complex_skill.py``. Tests marked "already
true on 0.15.6" guard behaviour that must not regress; the rest describe new
0.16.0 contracts and are expected to fail until those features integrate.

All data is synthetic (organisation domain ``example-corp.test``).
"""
import io
import json
import re
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path

import pytest

import architecture_map
from skill_sandbox.app import scan_upload
from tests.fixtures import synthetic_complex_skill as fx

LABELS_PATH = Path(__file__).resolve().parents[1] / "skill_sandbox" / "rules" / "finding-labels.json"
VIOLATIONS_PATH = Path(__file__).resolve().parents[1] / "skill_sandbox" / "rules" / "violations.json"
DIRECTORY = f"{fx.ROOT}/data/directory.db"
HANDBOOK = f"{fx.ROOT}/data/handbook.db"
REGISTRY = f"{fx.ROOT}/data/registry.db"
EXCEPTIONS = f"{fx.ROOT}/data/exceptions.db"
VAULT = f"{fx.ROOT}/data/vault.db"
DISGUISED_SCRIPT_IDS = {"executable_packaged_as_document", "declared_execution_target", "code_in_text_artifact"}
PRIORITY_RANK = {"block": 0, "review": 1, "info": 2}
# A generous ceiling. 0.15.6 (50-row database sampling) scanned this fixture in
# 19-32 s on the reference Windows workstation. A complete 20,000-row read adds
# work, but the scan must stay usable from the web app; 180 s (about 6x the
# slowest measured run) separates "slower" from "hung or quadratic".
# Keep the final limit below the API read timeout (120 s).
SCAN_SECONDS_LIMIT = 110

# The contract names the policy conditions and effects but not the key that
# holds a rule's condition. "when" is assumed here; align with
# docs/org-policy.md / docs/org-policy-template.json at integration.
CONDITION_KEY = "when"


def _policy(rules):
    return json.dumps({"schema": "injecticide-org-policy/v1", "policy_name": "Example Corp AI package policy",
                       "organization": "Example Corp (fictional)", "compiled_date": "2026-11-07",
                       "sources": [{"id": "TEST", "title": "Synthetic acceptance policy"}], "rules": rules})


def _rule(rule_id, condition, effect, title=None):
    return {"id": rule_id, "title": title or rule_id.replace("-", " "), CONDITION_KEY: condition,
            "effect": effect, "enforcement": "mandatory", "approver": "AI review board",
            "source": "TEST", "requirement": title or rule_id.replace("-", " ")}


VALID_POLICY = _policy([
    _rule("untrusted-live-docs", {"external_origin": fx.LIVE_DOCS_HOST}, "require_approval"),
    _rule("no-disguised-scripts", {"finding": "executable_packaged_as_document"}, "block"),
    _rule("contact-directory-ok", {"finding": "contact_directory"}, "allow"),
    _rule("salesforce-warning", {"connector_mentioned": "Salesforce"}, "warn"),  # must not trigger
])


# --------------------------------------------------------------------------- scans (module scoped)

@pytest.fixture(scope="module")
def complex_zip():
    return fx.build_zip()


@pytest.fixture(scope="module")
def timed_scan(complex_zip):
    started = time.perf_counter()
    result = scan_upload(complex_zip, "acme-ops-core.zip")
    return result, time.perf_counter() - started


@pytest.fixture(scope="module")
def result(timed_scan):
    return timed_scan[0]


@pytest.fixture(scope="module")
def policy_result(complex_zip):
    return scan_upload(complex_zip, "acme-ops-core.zip", org_policy=VALID_POLICY)


@pytest.fixture(scope="module")
def plain_result():
    return scan_upload(fx.build_plain_zip(), "plain-notes.zip")


def _entry(result, path):
    return next(e for e in result["files"] if e["path"] == path)


def _findings(result, path=None):
    for entry in result["files"]:
        if path is None or entry["path"] == path:
            for finding in entry.get("findings", []):
                yield entry["path"], finding


def _profile(result, path):
    profile = _entry(result, path).get("database_profile")
    assert profile, f"{path} has no database_profile"
    assert profile["schema"] == "injecticide-db-profile/v1"
    return profile


def _table(profile, name):
    return next(t for t in profile["tables"] if t["name"] == name)


def _citations(finding):
    return [o["citation"] for o in finding.get("observations", []) if isinstance(o.get("citation"), dict)]


def _overview(result):
    overview = result["process_diagram"]["overview"]
    assert overview["schema"] == "injecticide-overview/v1"
    return overview


# --------------------------------------------------------------------------- fixture self-checks (pass on 0.15.6)

def test_fixture_shape_is_a_large_enterprise_skill():
    files = fx.build_files()
    assert 180 <= len(files) <= 220
    assert all(path.startswith(fx.ROOT + "/") for path in files)
    router = files[f"{fx.ROOT}/capabilities/capability-router.md"].decode()
    assert "| Caller need | Load |" in router
    assert len(fx.DOMAINS) == 12 and all(3 <= len(stems) <= 15 for *_, stems in fx.DOMAINS)
    assert len(fx.SCRIPT_PATHS) == 10 and all(p in files for p in fx.SCRIPT_PATHS)
    skill = files[f"{fx.ROOT}/SKILL.md"].decode()
    for script in fx.SCRIPTS:
        assert f"scripts/{script[0]}" in skill and f"`{script[0]}`" in skill
    assert f"{fx.ROOT}/capabilities/weekly/weekly-environment.md" in files
    assert not any(p.endswith("/environment.md") for p in files)  # false-reference trap
    assert not files[VAULT].startswith(b"SQLite format 3\x00")
    assert fx.build_zip() == fx.build_zip()  # deterministic


def test_fixture_databases_contain_the_planted_hazards():
    files = fx.build_files()
    with tempfile.TemporaryDirectory() as folder:
        def connect(path):
            target = Path(folder) / Path(path).name
            target.write_bytes(files[path])
            return sqlite3.connect(target)
        directory = connect(DIRECTORY)
        assert directory.execute("SELECT count(*) FROM employees").fetchone()[0] == fx.DIRECTORY_ROWS
        assert directory.execute("SELECT notes FROM employees WHERE rowid=?", (fx.HOSTILE_ROW,)).fetchone()[0] == fx.HOSTILE_TEXT
        assert fx.SECRET_VALUE in directory.execute("SELECT notes FROM employees WHERE rowid=?", (fx.SECRET_ROW,)).fetchone()[0]
        domains = {row[0].split("@")[1] for row in directory.execute("SELECT email FROM employees")}
        assert domains == {fx.ORG_DOMAIN}
        directory.close()
        handbook = connect(HANDBOOK)
        names = {row[0] for row in handbook.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "sections" in names and any(n.startswith("handbook_fts_") for n in names)
        handbook.close()
        registry = connect(REGISTRY)
        trigger = registry.execute("SELECT sql FROM sqlite_master WHERE type='trigger'").fetchone()[0]
        assert fx.TRIGGER_URL_HOST in trigger
        blob = registry.execute("SELECT bundle FROM connectors WHERE name='atlassian'").fetchone()[0]
        assert zipfile.is_zipfile(io.BytesIO(blob))
        registry.close()
        exceptions = connect(EXCEPTIONS)
        assert exceptions.execute("SELECT count(*) FROM exceptions").fetchone()[0] == 2
        exceptions.close()


# --------------------------------------------------------------------------- #78 databases

def test_directory_database_is_read_completely(result):
    profile = _profile(result, DIRECTORY)
    coverage = profile["coverage"]
    assert coverage["status"] == "complete"
    assert coverage["rows_read"] == coverage["rows_total"] == fx.DIRECTORY_ROWS
    employees = _table(profile, "employees")
    assert employees["row_count"] == employees["rows_read"] == fx.DIRECTORY_ROWS
    assert not any(f["id"] == "database_not_cleared" for _, f in _findings(result, DIRECTORY))


def test_hostile_row_beyond_sampling_is_detected_with_citation(result):
    prompt_ids = {r["id"] for r in json.loads(VIOLATIONS_PATH.read_text(encoding="utf-8"))["rules"]
                  if r["category"] == "prompt"}
    cited = [c for _, f in _findings(result, DIRECTORY) if f["id"] in prompt_ids for c in _citations(f)]
    assert {"table": "employees", "column": "notes", "row": fx.HOSTILE_ROW} in [
        {k: c.get(k) for k in ("table", "column", "row")} for c in cited]


def test_secret_in_database_is_detected_masked_and_never_echoed(result):
    secret = [f for _, f in _findings(result, DIRECTORY) if f["id"] == "hardcoded_secret"]
    assert secret, "secret in employees.notes was not reported"
    assert any(c.get("row") == fx.SECRET_ROW and c.get("column") == "notes" for c in _citations(secret[0]))
    serialized = json.dumps(result)
    for probe in fx.SECRET_PROBES:
        assert probe not in serialized


def test_fts_shadow_tables_are_skipped_and_recorded(result):
    tables = _profile(result, HANDBOOK)["tables"]
    skipped = [t["name"] for t in tables if t.get("skipped_reason") == "fts_shadow"]
    assert skipped and all(name.startswith("handbook_fts_") for name in skipped)
    sections = _table({"tables": tables}, "sections")
    assert sections["rows_read"] == sections["row_count"] == 40


def test_trigger_with_instruction_is_flagged(result):
    objects = _profile(result, REGISTRY)["schema_objects"]
    trigger = next(o for o in objects if o["type"] == "trigger" and o["name"] == "audit_sync")
    assert trigger["flagged"] is True


def test_blob_archive_is_counted(result):
    blobs = _profile(result, REGISTRY)["blobs"]
    assert blobs["total"] >= 1 and blobs["archives"] >= 1
    assert blobs["executables"] == 0


def test_unreadable_db_is_opaque_not_silently_skipped(result):
    assert any(f["id"] == "opaque_database" for _, f in _findings(result, VAULT))
    assert _profile(result, VAULT)["coverage"]["status"] == "opaque"


def test_small_database_is_profiled_completely(result):
    coverage = _profile(result, EXCEPTIONS)["coverage"]
    assert coverage["status"] == "complete" and coverage["rows_total"] == 2


def test_contact_directory_reports_volume_and_never_echoes_work_emails(result):
    contact = [f for _, f in _findings(result, DIRECTORY) if f["id"] == "contact_directory"]
    assert len(contact) == 1
    assert contact[0]["tier"] == "review"  # 20,000 records is above the 200-record info tier
    assert re.search(r"20,?000", contact[0]["description"])
    # A local part made only of word characters directly before the domain is unmasked.
    leaked = re.findall(r"[\w.+-]*\w@" + re.escape(fx.ORG_DOMAIN), json.dumps(result))
    assert leaked == [], f"unmasked work emails in result: {leaked[:3]}"


def test_personal_data_is_distinct_from_business_contact_data(result):
    employees = _table(_profile(result, DIRECTORY), "employees")
    classes = {c["name"]: set(c["data_classes"]) for c in employees["columns"]}
    assert "business_contact_email" in classes["email"] and "personal_email" not in classes["email"]
    assert {"personal_email", "ssn"} <= classes["notes"]
    ssn = [f for _, f in _findings(result, DIRECTORY) if f["id"] == "pii_ssn"]
    assert ssn and {c.get("row") for c in _citations(ssn[0])} <= set(fx.SSN_ROWS)
    personal = [c for _, f in _findings(result, DIRECTORY) if f["id"] == "pii_email_address" for c in _citations(f)]
    assert personal, "free-mail addresses in notes were not reported as personal data"
    # Business contact emails belong to contact_directory, not to the personal-data finding.
    assert all(c.get("column") == "notes" and c.get("row") in fx.PERSONAL_EMAIL_ROWS for c in personal)


# --------------------------------------------------------------------------- #79/#80 architecture

def test_overview_declares_areas_from_the_router(result):
    overview = _overview(result)
    declared = [a for a in overview["areas"] if a["source"] == "declared"]
    assert len(declared) >= 10
    weekly = [a for a in declared if any(p.endswith("weekly-environment.md") for p in a["files"])]
    assert len(weekly) == 1
    comms = next(s for s in overview["shared_services"] if s["path"].endswith("shared/comms-log.md"))
    assert len(comms["used_by"]) >= 3


def test_overview_data_stores_carry_row_counts_and_coverage(result):
    stores = {s["path"]: s for s in _overview(result)["data_stores"]}
    assert stores[DIRECTORY]["row_count"] == fx.DIRECTORY_ROWS
    assert stores[VAULT]["coverage_status"] == "opaque"


def test_overview_external_systems(result):
    systems = _overview(result)["external_systems"]

    def text(system):
        return (system["id"] + " " + system["label"]).lower()
    web = [s for s in systems if s["kind"] == "web" and s["untrusted"]]
    assert any(fx.LIVE_DOCS_HOST in text(s) or any(e.get("path") for e in s["evidence"]) for s in web)
    assert any(s["kind"] == "other_skill" and fx.OTHER_SKILL in text(s) for s in systems)
    writes = [text(s) for s in systems if s["direction"] == "write"]
    assert any("jira" in t or "ticket" in t for t in writes)
    assert any("confluence" in t or "wiki" in t for t in writes)
    assert all(s["evidence"] for s in systems)


def test_architecture_map_uses_real_kinds_and_flags(result):
    document = result["process_diagram"]["architecture_map"]
    architecture_map.validate_map(document)
    kinds = {n["kind"] for n in document["nodes"]}
    assert {"data", "code", "skill"} <= kinds
    assert {"retrieval", "approval"} & kinds  # declared live-doc fetch and preview gate
    assert any(e["untrusted"] for e in document["edges"])
    assert any(e["write"] for e in document["edges"])


def test_plan_map_proposes_real_tests(result):
    plan = architecture_map.plan_map(result["process_diagram"]["architecture_map"])
    # Threshold 5: given the contract's kinds the planner deterministically yields
    # one package test for the skill node, one control test for the approval node,
    # one edge test per untrusted edge and per write edge (>= 2), and at least one
    # untrusted-to-action path test. 0.15.6 yields exactly 1 (the package test).
    assert len(plan["tests"]) >= 5
    assert any(t["id"].startswith("path-") for t in plan["tests"])


def test_product_names_are_not_file_references(result):
    edges = result["package_analysis"]["relationship_graph"]["edges"]
    bad = [e for e in edges if e["target"].rsplit("/", 1)[-1] in {"Node.js", "ASP.NET"}]
    assert bad == []
    labels = {n["label"].rsplit("/", 1)[-1] for n in result["process_diagram"]["architecture_map"]["nodes"]
              if n["kind"] == "unresolved_reference"}
    assert not labels & {"Node.js", "ASP.NET"}


def test_filename_inside_longer_name_is_not_extracted(result):
    """Already true on 0.15.6; guards against regression."""
    edges = result["package_analysis"]["relationship_graph"]["edges"]
    assert not [e for e in edges if e["target"].rsplit("/", 1)[-1] == "environment.md"]


def test_plain_skill_gets_inferred_areas(plain_result):
    areas = _overview(plain_result)["areas"]
    assert areas and all(a["source"] == "inferred" for a in areas)
    assert all(a["basis"] for a in areas)


# --------------------------------------------------------------------------- #82 policy

def test_valid_policy_applies_with_evidence(policy_result, result):
    evaluation = policy_result["policy_evaluation"]
    assert evaluation["schema"] == "injecticide-policy-results/v1"
    assert evaluation["status"] == "applied" and not evaluation["errors"]
    assert len(evaluation["policy"]["sha256"]) == 64
    rules = {r["id"]: r for r in evaluation["rules"]}
    for rule_id in ("untrusted-live-docs", "no-disguised-scripts", "contact-directory-ok"):
        assert rules[rule_id]["triggered"] is True and rules[rule_id]["evidence"], rule_id
    assert rules["salesforce-warning"]["triggered"] is False
    scripts = {e["path"] for e in rules["no-disguised-scripts"]["evidence"]}
    assert set(fx.SCRIPT_PATHS) <= scripts
    assert evaluation["effect_summary"]["block"] >= 1


def test_allow_rule_marks_but_never_removes_findings(policy_result, result):
    def ids(scan):
        return sorted((path, f["id"]) for path, f in _findings(scan))
    assert ids(policy_result) == ids(result)
    allowed = [f for _, f in _findings(policy_result) if f["id"] == "contact_directory"]
    assert allowed and all(f.get("policy_disposition") == "allowed_by_policy" for f in allowed)
    assert all("contact-directory-ok" in json.dumps(f) for f in allowed)
    # The scanner's own verdict is unchanged beside the policy result.
    assert policy_result["governance_profile"] == result["governance_profile"]
    assert result.get("policy_evaluation", {"status": "none"})["status"] == "none"


def test_invalid_policy_is_reported_and_scan_still_succeeds():
    bad = _policy([_rule("typo", {"finding_idd": "contact_directory"}, "block")])
    scan = scan_upload(fx.build_plain_zip(), "plain-notes.zip", org_policy=bad)
    assert scan["files"] and scan["summary"]["total_files"] == 6
    evaluation = scan["policy_evaluation"]
    assert evaluation["status"] == "invalid"
    error = evaluation["errors"][0]
    assert error["path"] and "finding_idd" in error["message"]
    assert "finding" in error["suggestion"]


def test_secret_exfiltration_used_for_presence_gets_a_warning():
    """``secret_exfiltration`` means a request to disclose secrets; presence is ``hardcoded_secret``.

    The contract does not say where the warning sits, so this only requires that
    the policy still applies and the evaluation points the author at hardcoded_secret.
    """
    policy = _policy([_rule("no-secrets", {"finding": "secret_exfiltration"}, "block",
                            "Block packages that contain secrets")])
    evaluation = scan_upload(fx.build_plain_zip(), "plain-notes.zip", org_policy=policy)["policy_evaluation"]
    assert evaluation["status"] == "applied"
    assert "hardcoded_secret" in json.dumps(evaluation)


def test_garbage_governance_evidence_is_reported_not_dropped():
    scan = scan_upload(fx.build_plain_zip(), "plain-notes.zip",
                       governance_evidence={"attestations": "yes please", "trust_me": True})
    evidence = scan["evidence_input"]
    assert evidence["status"] == "ignored"
    assert evidence["reasons"] and all(isinstance(r, str) and r for r in evidence["reasons"])


def test_no_policy_and_no_evidence_report_none(plain_result):
    assert plain_result["policy_evaluation"]["status"] == "none"
    assert plain_result["evidence_input"]["status"] == "none"


def test_web_api_accepts_org_policy_form_field():
    from fastapi.testclient import TestClient
    from webapp.api import app
    policy = _policy([_rule("meeting-notes", {"finding": "contact_directory"}, "warn")])
    response = TestClient(app).post("/api/skills/scan", data={"org_policy": policy},
                                    files={"file": ("plain-notes.zip", fx.build_plain_zip(), "application/zip")})
    assert response.status_code == 200
    assert response.json()["policy_evaluation"]["status"] == "applied"


# --------------------------------------------------------------------------- #81 fix summary

def test_disguised_scripts_merge_into_one_fix_item(result):
    items = result["fix_summary"]["items"]
    holders = [i for i in items if set(i["finding_ids"]) & DISGUISED_SCRIPT_IDS]
    assert len(holders) == 1, [i["title"] for i in holders]
    assert set(fx.SCRIPT_PATHS) <= set(holders[0]["files"])
    assert len(holders[0]["files"]) == len(set(holders[0]["files"]))  # each file listed once


def test_fix_items_are_ordered_by_priority(result):
    summary = result["fix_summary"]
    assert summary["schema"] == "injecticide-fix-summary/v1"
    ranks = [PRIORITY_RANK[i["priority"]] for i in summary["items"]]
    assert ranks == sorted(ranks)


def test_every_actionable_finding_is_covered_by_a_fix_item(result):
    covered = {(path, fid) for item in result["fix_summary"]["items"]
               for path in item["files"] for fid in item["finding_ids"]}
    missing = sorted({(path, f["id"]) for path, f in _findings(result)
                      if f.get("tier") in {"review", "block"}} - covered)
    assert missing == []


# --------------------------------------------------------------------------- #83 labels

def test_every_emitted_finding_has_a_label(result, policy_result):
    labels = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    emitted = {f["id"] for scan in (result, policy_result) for _, f in _findings(scan)}
    emitted |= {"database_not_cleared", "opaque_database", "embedded_executable_blob",
                "contact_directory", "hardcoded_secret"}
    missing = sorted(i for i in emitted if not (labels.get(i, {}).get("label") and labels[i].get("plain")))
    assert missing == []


# --------------------------------------------------------------------------- frontmatter and performance

def test_standards_check_names_the_extra_frontmatter_fields(result):
    """Already true on 0.15.6; guards against regression."""
    failed = [r for r in result["standards_assessment"]["requirements"]
              if r["id"] == "frontmatter_fields" and r["status"] == "fail"]
    assert failed
    message = json.dumps(failed) + json.dumps(result["improvement_plan"])
    assert "owner_team" in message and "deployment_ring" in message


def test_full_fixture_scan_time_is_bounded(timed_scan):
    _, seconds = timed_scan
    print(f"\nfull synthetic enterprise scan: {seconds:.1f} s")
    assert seconds < SCAN_SECONDS_LIMIT
