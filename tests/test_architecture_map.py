import copy

import pytest
from fastapi.testclient import TestClient

from architecture_map import plan_map
from webapp.api import app


def node(key, kind, trust="internal"):
    return dict(id=key, kind=kind, label=key, x=0, y=0, trust=trust,
                sensitivity="unknown", controls="")


def edge(key, source, target):
    return dict(id=key, source=source, target=target, untrusted=False, write=False)


def sample():
    return dict(schema_version=1, name="System", nodes=[node("u", "user", "external"),
                node("a", "agent"), node("g", "gateway"), node("m", "model"),
                node("t", "mcp")], edges=[edge("ua", "u", "a"), edge("ag", "a", "g"),
                edge("gm", "g", "m"), edge("at", "a", "t")])


def test_branch_plan_does_not_invent_gateway_coverage():
    data = sample()
    result = plan_map(data)
    path = next(t for t in result["tests"] if t["id"] == "path-u-t")
    assert path["node_ids"] == ["u", "a", "t"]
    assert path["edge_ids"] == ["ua", "at"]
    assert "g" not in path["node_ids"]
    assert all(t["status"] == "not_run" for t in result["tests"])
    assert result == plan_map(copy.deepcopy(data))
    data["nodes"][2]["controls"] = "Everything is protected"
    assert [t["id"] for t in plan_map(data)["tests"]] == [t["id"] for t in result["tests"]]
    assert plan_map(data)["map_hash"] != result["map_hash"]


def test_cycle_disconnected_and_empty_maps():
    data = sample()
    data["edges"].append(edge("loop", "t", "u"))
    assert len(plan_map(data)["tests"]) == 4
    data["edges"] = []
    assert not any(t["id"].startswith("path-") for t in plan_map(data)["tests"])
    assert plan_map(dict(schema_version=1, name="Empty", nodes=[], edges=[]))["tests"] == []


def test_llm_client_is_distinct_from_person_model_and_agent():
    data = sample()
    data["nodes"].append(node("sdk", "llm_client"))
    data["edges"] = [edge("us", "u", "sdk"), edge("sa", "sdk", "a"), edge("at", "a", "t")]
    result = plan_map(data)
    path = next(t for t in result["tests"] if t["id"] == "path-u-t")
    assert path["node_ids"] == ["u", "sdk", "a", "t"]
    assert not any(t["id"] == "prompt-sdk" for t in result["tests"])


@pytest.mark.parametrize("change", [
    lambda d: d["nodes"].append(d["nodes"][0]),
    lambda d: d["edges"].append(edge("bad", "missing", "a")),
    lambda d: d.update(schema_version=2),
    lambda d: d["nodes"][0].update(x=3001),
    lambda d: d["nodes"][0].update(kind="imaginary"),
    lambda d: d["edges"][0].update(write="false"),
    lambda d: d["nodes"][0].update(url="https://never-fetch.example"),
    lambda d: d.update(nodes=[node(str(i), "model") for i in range(101)]),
])
def test_invalid_maps_rejected(change):
    data = sample()
    change(data)
    with pytest.raises(ValueError):
        plan_map(data)


def test_budget_reports_omissions():
    nodes = [node(str(i), "mcp", "external") for i in range(100)]
    edges = [edge(str(i), str(i), str((i+1)%100)) for i in range(100)]
    result = plan_map(dict(schema_version=1, name="Cycle", nodes=nodes, edges=edges))
    assert len(result["tests"]) == 500
    assert result["omitted_tests"] == 9400


def test_api_request_limits_and_no_live_execution(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("Planning must never contact a service")
    monkeypatch.setattr("requests.sessions.Session.request", unexpected)
    client = TestClient(app)
    result = client.post("/api/architecture/plan", json=sample())
    assert result.status_code == 200
    assert result.json()["status"] == "modeled_only"
    assert result.headers["cache-control"] == "no-store"
    assert client.post("/api/architecture/plan", content=b" "*262145).status_code == 413
    assert client.post("/api/architecture/plan", content=b'{"x":NaN}').status_code == 422
    assert client.post("/api/architecture/plan", json=[]).status_code == 422
