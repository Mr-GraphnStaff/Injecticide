"""Architecture overview and evidence-based map kinds for a synthetic skill.

All names are invented: the ``vendor-review`` skill of the fictitious
organisation ``example-corp.test``. No uploaded code executes and no origin is
contacted. Each inferred rule has a paired negative case.
"""
import json

from architecture_map import plan_map, validate_map
from skill_sandbox.architecture_overview import build_overview, extract_declared_structure
from skill_sandbox.package_graph import build_package_graph
from skill_sandbox.process_diagram import build_process_diagram, extract_documented_steps

SKILL = """---
name: vendor-review
description: Review vendor records for example-corp.test.
allowed-tools: WebFetch, Bash, Read, mcp__ticketing__create_issue
compatibility: Requires the ticketing MCP server.
---
# Vendor review

| Caller need | Load | Connector |
|---|---|---|
| Weekly vendor summary | [weekly](capabilities/weekly-report.md) | ticketing MCP |
| Vendor risk check | `capabilities/vendor-risk.md` | |
| Raise a ticket | [tickets](capabilities/ticketing.md) | ticketing MCP |

## Workflow
1. Fetch the vendor feed from https://feeds.example-corp.test/vendors.
2. Show the user a preview and wait for approval before filing.
3. Run `python scripts/sync_vendors.py` and `python scripts/export.py`.

Built with Node.js and Vue.js; see wsr‑environment.md for setup.
"""


def vendor_review_sources():
    return {
        "vendor-review/SKILL.md": SKILL,
        "vendor-review/capabilities/weekly-report.md": "Use `shared/format-rules.md` and `data/vendors.sqlite`.\n",
        "vendor-review/capabilities/vendor-risk.md": "Use [rules](../shared/format-rules.md) and [terms](../shared/terms.md).\n",
        "vendor-review/capabilities/ticketing.md": "Apply [rules](../shared/format-rules.md). Hand off to the `weekly-digest` skill.\n",
        "vendor-review/shared/format-rules.md": "Format rules.\n",
        "vendor-review/shared/terms.md": "Terms.\n",
        "vendor-review/scripts/sync_vendors.py": (
            "import requests\nimport sqlite3\n"
            "feed = requests.get('https://feeds.example-corp.test/vendors')\n"
            "db = sqlite3.connect('data/vendors.sqlite')\n"
            "requests.post('https://ticketing.example-corp.test/api/issues', json={})\n"),
        "vendor-review/scripts/export.py.md": "print('export')\n",
        "vendor-review/references/wsr-environment.md": "Environment notes.\n",
        "vendor-review/references/wsr-layout.md": "Layout notes.\n",
    }


PROFILE = {"schema": "injecticide-db-profile/v1",
           "tables": [{"name": "vendors", "row_count": 40, "rows_read": 40, "skipped_reason": None,
                       "columns": [{"name": "contact", "declared_type": "TEXT",
                                    "data_classes": ["business_contact_email", "person_name"],
                                    "values_scanned": 40, "opaque_values": 0}]}],
           "coverage": {"status": "partial", "rows_read": 40, "rows_total": 40, "unread": []}}


def report(sources, extra_files=(), findings=None, profile=None):
    files = [{"path": path, "assessment_state": "text_analyzed", "findings": list((findings or {}).get(path, []))}
             for path in list(sources) + list(extra_files)]
    for record in files:
        if profile and record["path"].endswith(".sqlite"):
            record["database_profile"] = profile
    text_sources = [{"path": path, "text": text} for path, text in sources.items()]
    graph = build_package_graph(text_sources, files)
    return {"files": files, "package_analysis": {"relationship_graph": graph},
            "documented_process": extract_documented_steps(text_sources, graph),
            "governance_evidence": {"artifact_sha256": "a" * 64}}


def vendor_report(**kwargs):
    findings = {"vendor-review/scripts/export.py.md": [{"id": "executable_packaged_as_document"}],
                "vendor-review/capabilities/ticketing.md": [{"id": "hardcoded_secret"}]}
    return report(vendor_review_sources(), ["vendor-review/data/vendors.sqlite"], findings=findings, **kwargs)


def by_label(items, label):
    return next(item for item in items if item["label"] == label)


def test_router_table_declares_areas_with_need_labels_and_entry_files():
    overview = build_process_diagram(vendor_report(profile=PROFILE))["overview"]
    assert overview["schema"] == "injecticide-overview/v1"
    declared = [a for a in overview["areas"] if a["source"] == "declared" and a["id"] != "area-entry"]
    assert [a["label"] for a in declared] == ["Weekly vendor summary", "Vendor risk check", "Raise a ticket"]
    weekly = declared[0]
    assert weekly["entry_files"] == ["vendor-review/capabilities/weekly-report.md"]
    assert "Router table in SKILL.md line 11" == weekly["basis"]
    entry = by_label(overview["areas"], "Skill entry")
    assert entry["files"] == ["vendor-review/SKILL.md"] and entry["steps"] == 4


def test_without_router_areas_are_inferred_and_say_so():
    sources = {"weekly-report/SKILL.md": "Read [a](wsr-a.md) and [b](wsr-b.md).\n",
               "weekly-report/wsr-a.md": "A", "weekly-report/wsr-b.md": "B"}
    overview = build_process_diagram(report(sources))["overview"]
    inferred = [a for a in overview["areas"] if a["source"] == "inferred"]
    assert inferred and all(a["basis"].startswith("Inferred:") for a in inferred)
    assert inferred[0]["files"] == ["weekly-report/wsr-a.md", "weekly-report/wsr-b.md"]
    assert "filename family wsr-*" in inferred[0]["basis"]
    assert not any(a["source"] == "declared" and a["id"] != "area-entry" for a in overview["areas"])


def test_two_linked_rows_are_a_router_but_one_link_is_not():
    two = "| Need | Load |\n|---|---|\n| Weekly | [w](w.md) |\n| Tickets | [t](t.md) |\n"
    one = "| Need | Load |\n|---|---|\n| Weekly | [w](w.md) |\n| No file | none |\n"
    for text, expected in ((two, 2), (one, 0)):
        sources = {"SKILL.md": text, "w.md": "W", "t.md": "T"}
        graph = build_package_graph([{"path": p, "text": t} for p, t in sources.items()],
                                    [{"path": p} for p in sources])
        routes = extract_declared_structure([{"path": p, "text": t} for p, t in sources.items()], graph)["routes"]
        assert len(routes) == expected


def test_file_used_by_three_areas_is_shared_but_by_two_is_not():
    overview = build_process_diagram(vendor_report())["overview"]
    shared = {item["path"]: item for item in overview["shared_services"]}
    assert set(shared) == {"vendor-review/shared/format-rules.md"}
    assert len(shared["vendor-review/shared/format-rules.md"]["used_by"]) == 3
    # terms.md is used by one area only: it belongs to that area, not to shared services.
    risk = by_label(overview["areas"], "Vendor risk check")
    assert "vendor-review/shared/terms.md" in risk["files"]


def test_data_store_uses_database_profile_and_tolerates_its_absence():
    with_profile = build_process_diagram(vendor_report(profile=PROFILE))["overview"]["data_stores"]
    assert with_profile == [{"id": "data-1", "label": "vendors.sqlite", "path": "vendor-review/data/vendors.sqlite",
                             "row_count": 40, "data_classes": ["business_contact_email", "person_name"],
                             "coverage_status": "partial"}]
    without = build_process_diagram(vendor_report())["overview"]["data_stores"]
    assert without[0]["row_count"] is None and without[0]["data_classes"] == []
    assert without[0]["coverage_status"] == "not_profiled"


def test_external_systems_have_evidenced_directions_and_unknown_otherwise():
    overview = build_process_diagram(vendor_report())["overview"]
    systems = {(s["kind"], s["label"]): s for s in overview["external_systems"]}
    feed = systems[("web", "feeds.example-corp.test")]
    assert feed["direction"] == "read" and feed["untrusted"] is True
    assert {"path": "vendor-review/scripts/sync_vendors.py", "line": 3} in feed["evidence"]
    ticket_api = systems[("web", "ticketing.example-corp.test")]
    assert ticket_api["direction"] == "write" and ticket_api["untrusted"] is False
    assert systems[("mcp", "ticketing (MCP)")]["direction"] == "unknown"
    assert systems[("tool", "WebFetch")]["untrusted"] is True
    assert systems[("other_skill", "weekly-digest")]["direction"] == "unknown"
    assert not any(label == "vendor-review" for _, label in systems)  # its own name is not another skill
    links = overview["links"]
    assert any(l["untrusted"] and l["source"] == feed["id"] for l in links)
    assert any(l["write"] and l["target"] == ticket_api["id"] for l in links)
    # The call's own URL text is not counted again as a separate mention.
    assert [l["count"] for l in links if l["target"] == ticket_api["id"]] == [1]
    assert not any(l["target"] == feed["id"] for l in links)


def test_mentioned_origin_without_fetch_or_write_stays_unknown():
    sources = {"SKILL.md": "Documentation lives at https://docs.example-corp.test/guide.\n"}
    overview = build_process_diagram(report(sources))["overview"]
    (system,) = overview["external_systems"]
    assert system["direction"] == "unknown" and system["untrusted"] is False


def test_risk_badges_count_files_by_cause_in_each_area():
    overview = build_process_diagram(vendor_report(profile=PROFILE))["overview"]
    ticket = by_label(overview["areas"], "Raise a ticket")
    assert {"code": "secret", "label": "Secrets", "count": 1} in ticket["risk_badges"]
    assert not by_label(overview["areas"], "Weekly vendor summary")["risk_badges"]
    entry = by_label(overview["areas"], "Skill entry")
    assert entry["risk_badges"] == []


def test_overview_stays_bounded_and_readable_at_twelve_areas_and_200_files():
    domains = ["vendor-review", "weekly-report", "ticketing", "billing", "audit", "intake",
               "onboarding", "renewals", "contracts", "invoices", "metrics", "alerts"]
    rows = "".join(f"| {d} need | [{d}](capabilities/{d}.md) |\n" for d in domains)
    sources = {"big/SKILL.md": "| Need | Load |\n|---|---|\n" + rows,
               "big/shared/common.md": "Common."}
    for d in domains:
        links = "".join(f"[p{i}](../refs/{d}-part{i}.md) " for i in range(15))
        sources[f"big/capabilities/{d}.md"] = links + "[c](../shared/common.md)\n"
        for i in range(15):
            sources[f"big/refs/{d}-part{i}.md"] = "Part."
    assert len(sources) >= 190
    overview = build_process_diagram(report(sources))["overview"]
    declared = [a for a in overview["areas"] if a["source"] == "declared" and a["id"] != "area-entry"]
    assert len(declared) == 12
    assert all(len(a["files"]) == 16 for a in declared)
    assert [s["path"] for s in overview["shared_services"]] == ["big/shared/common.md"]
    assert overview["unassigned_files"] == 0
    assert len(overview["links"]) <= 300
    assert len(json.dumps(overview)) < 60000


def test_missing_relationship_data_yields_an_empty_overview_not_an_error():
    overview = build_process_diagram({"files": [{"path": "SKILL.md"}]})["overview"]
    assert overview["schema"] == "injecticide-overview/v1"
    assert overview["shared_services"] == [] and overview["external_systems"] == []
