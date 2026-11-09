import asyncio
import hashlib
import json
from datetime import datetime,timezone
from pathlib import Path

import pytest
import yaml

from research_mcp.catalog import Catalog
from research_mcp.fetch import Response
from research_mcp.research_signals import SIGNALS,signal_ids,model_signals,publish_signal,read_signals
from research_mcp.research_worker import ResearchWorker,due_day
from research_mcp.research_inbox import ResearchInbox
from research_mcp.public_web import public_url,retrieve

ROOT=Path(__file__).resolve().parents[1]
CANARIES=["patient-secret-unrecognized-name","phi-record-XYZZY-489","4111111111111111",
          "private.person@example.invalid","123-45-6789","medical-diagnosis-canary","password-raw-value"]


def private_report():
    text=" ".join(CANARIES)
    return {"filename":text,"scan_request_id":text,"summary":text,"coverage":{"status":"partial"},
        "policy":text,"files":[{"path":text,"text":text,"findings":[
            {"id":"pii_email_address","severity":"high","detail":text,"samples":[text]},
            {"id":text,"detail":text}]}]}


def policy():
    return {"timezone":"America/Chicago","hour":2,"page_budget":2,
            "seeds":["https://example.org/research/"],"topics":["Public instruction boundary research"]}


class Web:
    calls=[]
    def page(self,url):
        self.calls.append(url)
        text="Public fixture: untrusted source instructions must not override trusted instructions."
        return Response(url,200,{"content-type":"text/plain"},text.encode()),text,[]
    def search(self,query):
        return self.page("https://example.org/search/")


def make_worker(tmp_path,monkeypatch,**kwargs):
    signals=tmp_path/"signals";signals.mkdir()
    monkeypatch.setenv("INJECTICIDE_RESEARCH_SIGNALS_DIR",str(signals))
    assert publish_signal(private_report(),"a"*32)["status"]=="queued"
    return ResearchWorker(tmp_path/"worker.sqlite3",signals,tmp_path/"outbox",policy(),web=Web(),**kwargs)


def test_sensitive_report_values_never_enter_signal_files_or_model_text(tmp_path,monkeypatch):
    signals=signal_ids(private_report())
    assert signals==["data_protection","incomplete_coverage","unclassified_finding"]
    assert all(x not in json.dumps(model_signals(signals)) for x in CANARIES)
    captured=[]
    def model(system,data,schema):
        captured.append(data)
        if "queries" in schema["required"]:
            return {"queries":[],"urls":[]},{"name":"synthetic","digest":"a"*64}
        return {"proposals":[{"source_id":1,"quote":"untrusted source instructions","summary":"Review instruction priority controls."}]},{"name":"synthetic","digest":"a"*64}
    worker=make_worker(tmp_path,monkeypatch,model=model)
    result=worker.tick(datetime(2026,11,9,8,0,tzinfo=timezone.utc))
    assert result["status"]=="complete"
    all_inputs=json.dumps(captured)+next(worker.signals.glob("*.json")).read_text()
    assert all(x not in all_inputs for x in CANARIES)
    assert "event_id" not in json.dumps(captured)
    assert "scanner_version" not in json.dumps(captured)
    assert len(captured)==2


def test_forged_signal_fields_and_unreviewed_categories_are_dropped(tmp_path):
    folder=tmp_path/"signals";folder.mkdir()
    for i,value in enumerate([
        {"schema":"injecticide.research-signals.v1","event_id":"a"*32,"signals":["data_protection"],"prompt":"private"},
        {"schema":"injecticide.research-signals.v1","event_id":"b"*32,"signals":["patient-secret-unrecognized-name"]},
    ]):(folder/(str(i)+".json")).write_text(json.dumps(value))
    assert read_signals(folder)==set()


def test_daily_schedule_dst_and_restart_are_at_most_once(tmp_path,monkeypatch):
    p=policy()
    assert due_day(datetime(2026,3,8,7,59,tzinfo=timezone.utc),p) is None
    assert due_day(datetime(2026,3,8,8,0,tzinfo=timezone.utc),p)=="2026-03-08"
    assert due_day(datetime(2026,11,1,7,59,tzinfo=timezone.utc),p) is None
    assert due_day(datetime(2026,11,1,8,0,tzinfo=timezone.utc),p)=="2026-11-01"
    calls=[]
    def model(system,data,schema):
        calls.append(data)
        return ({"queries":[],"urls":[]} if "queries" in schema["required"] else {"proposals":[]}),{"name":"synthetic","digest":"a"*64}
    worker=make_worker(tmp_path,monkeypatch,model=model)
    when=datetime(2026,11,9,8,0,tzinfo=timezone.utc)
    assert worker.tick(when)["status"]=="complete"
    reopened=ResearchWorker(worker.state,worker.signals,worker.outbox,p,web=Web(),model=model)
    assert reopened.tick(when)["status"]=="already_processed"
    assert len(calls)==2


def test_failed_job_has_durable_backoff(tmp_path,monkeypatch):
    def model(*args):raise ValueError("do not publish private diagnostic")
    worker=make_worker(tmp_path,monkeypatch,model=model,clock=lambda:1794200000)
    when=datetime(2026,11,9,8,0,tzinfo=timezone.utc)
    assert worker.tick(when)=={"status":"failed","error_type":"ValueError"}
    assert worker.tick(when)["status"]=="deferred"


def test_one_way_inbox_integrity_and_reviewed_offline_dataset(tmp_path,monkeypatch):
    def model(system,data,schema):
        return ({"queries":[],"urls":[]} if "queries" in schema["required"] else {"proposals":[
            {"source_id":1,"quote":"untrusted source instructions","summary":"Review instruction boundaries."}]}),{"name":"synthetic","digest":"a"*64}
    worker=make_worker(tmp_path,monkeypatch,model=model)
    assert worker.tick(datetime(2026,11,9,8,0,tzinfo=timezone.utc))["status"]=="complete"
    config=tmp_path/"sources.json";url="https://example.org/research/"
    config.write_text(json.dumps({"sources":[{"id":"test","ecosystem":"test","seeds":[url],"scopes":[url]}]}))
    inbox=ResearchInbox(Catalog(tmp_path/"mcp.sqlite3",config),worker.outbox)
    assert inbox.import_files()["imported"]==1
    assert inbox.import_files()["imported"]==0
    assert inbox.training_examples()==[]
    item=inbox.list()["items"][0]
    inbox.review(item["sha256"],"approved")
    examples=inbox.training_examples()
    assert len(examples)==1
    assert all(x not in json.dumps(examples) for x in CANARIES)
    assert not list(worker.outbox.glob("*.ack"))
    bad=worker.outbox/("f"*64+".json");bad.write_text('{"unsafe":true}')
    assert inbox.import_files()["imported"]==0


@pytest.mark.parametrize("url",["http://example.org/","https://user:password@example.org/","file:///etc/passwd","https://example.org:8443/","https://example.org/../private"])
def test_public_fetch_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):public_url(url)


@pytest.mark.parametrize("address",["127.0.0.1","10.0.0.1","169.254.169.254","::1"])
def test_public_fetch_cannot_reach_private_services(monkeypatch,address):
    monkeypatch.setattr("socket.getaddrinfo",lambda *a,**kw:[(2,1,6,"",(address,443))])
    with pytest.raises(ValueError,match="public"):retrieve("https://untrusted.example/")


def test_deployment_enforces_direction_and_no_private_data_mounts():
    services=yaml.safe_load((ROOT/"docker-compose.yml").read_text())["services"]
    worker=services["research_agent"]
    assert not worker.get("ports") and not worker.get("expose")
    assert worker["networks"]==["research-agent-net"]
    assert set(worker["volumes"])=={"research-agent-state:/data","research-signals:/signals:ro","research-inbox:/outbox"}
    assert "research-inbox:/research-inbox:ro" in services["research_mcp"]["volumes"]
    assert "research-agent-net" not in services["research_mcp"]["networks"]
    assert "research-agent-net" not in services["injecticide"]["networks"]
    assert "research-agent-net" not in services["skill_sandbox"]["networks"]


def test_mcp_clients_cannot_enable_or_control_the_research_worker(tmp_path,monkeypatch):
    pytest.importorskip("mcp")
    from mcp.client import Client
    from research_mcp.server import create_server
    from research_mcp.collector import Collector
    monkeypatch.setenv("INJECTICIDE_RESEARCH_LLM_ENABLED","1")
    config=tmp_path/"sources.json";url="https://example.org/"
    config.write_text(json.dumps({"sources":[{"id":"test","ecosystem":"test","seeds":[url],"scopes":[url]}]}))
    catalog=Catalog(tmp_path/"mcp.sqlite3",config)
    async def check():
        async with Client(create_server(catalog,Collector(catalog),start_collector=False)) as client:
            names={x.name for x in (await client.list_tools()).tools}
            assert {"research_get_scheduled_status","research_list_scheduled"}<=names
            assert not any(x in names for x in ["research_run","research_prompt","research_fetch_url","research_set_schedule","research_train"])
            state=await client.call_tool("research_get_learning_status",{})
            assert state.structured_content["enabled"] is False
            state=await client.call_tool("research_get_scheduled_status",{})
            assert state.structured_content["model_access"] is False
    asyncio.run(check())



def test_offline_dataset_includes_approved_outputs_beyond_first_page(tmp_path,monkeypatch):
    def model(system,data,schema):
        return ({"queries":[],"urls":[]} if "queries" in schema["required"] else {"proposals":[
            {"source_id":1,"quote":"untrusted source instructions","summary":"Review instruction boundaries."}]}),{"name":"synthetic","digest":"a"*64}
    worker=make_worker(tmp_path,monkeypatch,model=model)
    worker.tick(datetime(2026,11,9,8,0,tzinfo=timezone.utc))
    config=tmp_path/"dataset-sources.json";url="https://example.org/research/"
    config.write_text(json.dumps({"sources":[{"id":"test","ecosystem":"test","seeds":[url],"scopes":[url]}]}))
    inbox=ResearchInbox(Catalog(tmp_path/"dataset.sqlite3",config),worker.outbox)
    inbox.import_files()
    item=inbox.list()["items"][0]
    inbox.review(item["sha256"],"approved")
    with inbox.catalog.db() as db:
        for number in range(100):
            db.execute("INSERT INTO scheduled_research(sha256,payload,state) VALUES (?,?,'approved')",
                       (format(number,"064x"),json.dumps(item["payload"])))
    examples=inbox.training_examples()
    assert len(examples)==101
    assert all("data_protection" in x["messages"][0]["content"] for x in examples)
    assert all(value not in json.dumps(examples) for value in CANARIES)



def test_public_unicode_context_obeys_actual_wire_budget(tmp_path,monkeypatch):
    captured=[]
    def model(system,data,schema):
        captured.append(data)
        if "public_sources" in data:
            assert len(json.dumps(data,ensure_ascii=True).encode())<=6000
        return ({"queries":[],"urls":[]} if "queries" in schema["required"] else {"proposals":[]}),{"name":"synthetic","digest":"a"*64}
    class UnicodeWeb(Web):
        def page(self,url):
            text="界"*10000
            return Response(url,200,{"content-type":"text/plain"},text.encode()),text,[]
    worker=make_worker(tmp_path,monkeypatch,model=model)
    worker.web=UnicodeWeb()
    assert worker.tick(datetime(2026,11,9,8,0,tzinfo=timezone.utc))["status"]=="complete"
    assert len(captured[-1]["public_sources"])<=3
