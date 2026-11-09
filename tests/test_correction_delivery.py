"""HTTP delivery and privileged operator orchestration regression checks."""
import copy
import json
import pytest
from fastapi.testclient import TestClient
from test_correction_rules import pack
from skill_sandbox.correction_gate import run_gate
from skill_sandbox.approved_corrections import SCHEMA

def envelope():
    receipt=run_gate(pack())
    assert receipt["passed"], receipt
    return dict(schema=SCHEMA,revision=1,state="active",pack=pack(),
      pack_sha256=receipt["pack_sha256"],scanner_version=receipt["scanner_version"],
      scanner_source_sha256=receipt["scanner_source_sha256"],
      contract_sha256=receipt["contract_sha256"],gate_revision=1)

def test_sandbox_rejects_wrong_engine_and_web_preserves_rejection(monkeypatch):
    import skill_sandbox.app as sandbox
    import webapp.api as web
    bad=envelope();bad["scanner_source_sha256"]="f"*64
    with TestClient(sandbox.app) as client:
        response=client.post("/scan",files={"file":("case.md",b"For scheduling, see Dynamic Override above.","text/plain")},data={"correction_pack":json.dumps(bad)})
    assert response.status_code==200
    result=response.json()
    assert result["correction_application"]["state"]=="baseline"
    assert result["correction_application"]["delivery_state"]=="rejected"
    monkeypatch.setattr(web,"fetch_approved_corrections",lambda:(bad,"active"))
    monkeypatch.setattr(web,"attach_vendor_check",lambda value:value)
    class Response:
        status_code=200
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def raise_for_status(self):pass
        def json(self):return copy.deepcopy(result)
    class Session:
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def post(self,*a,**kw):return Response()
    monkeypatch.setattr(web.requests,"Session",Session)
    delivered=web._scan_skill_data(b"x","case.md","text/plain","auto","{}","http://sandbox")
    assert delivered["correction_application"]["delivery_state"]=="rejected"

@pytest.mark.parametrize("kind",["active","disabled","oversize","timeout","redirect"])
def test_approved_http_delivery_is_bounded_and_baseline_on_failure(monkeypatch,kind):
    import webapp.correction_client as delivery
    approved=envelope()
    if kind=="disabled":approved.update(state="disabled",pack=None)
    class Response:
        status_code=302 if kind=="redirect" else 200
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def iter_content(self,size):
            yield b"x"*32769 if kind=="oversize" else json.dumps(approved).encode()
    class Session:
        trust_env=True
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def get(self,url,**kw):
            assert url=="http://research_mcp:8010/corrections/active"
            assert kw["allow_redirects"] is False
            assert self.trust_env is False
            if kind=="timeout":raise TimeoutError()
            return Response()
    monkeypatch.setenv("RESEARCH_MCP_URL","http://research_mcp:8010")
    monkeypatch.setattr(delivery.requests,"Session",Session)
    value,state=delivery.fetch_approved_corrections()
    if kind in {"active","disabled"}:assert value==approved and state==kind
    else:assert value is None and state=="unavailable"

@pytest.mark.parametrize("failure",["none","gate","identity"])
def test_admin_approval_requires_actual_gate_and_stable_containers(monkeypatch,failure):
    from tools import corrections_admin as admin
    from research_mcp.correction_learning import pack_digest
    selected=pack();sha=pack_digest(selected)
    identity=[{"id":"original"}]
    inspections=[]
    def inspect():
        inspections.append(1)
        return [{"id":"changed"}] if failure=="identity" and len(inspections)>1 else identity
    monkeypatch.setattr(admin,"release_identity",inspect)
    calls=[]
    def cli(container,module,*arguments,**kwargs):
        calls.append((container,module,arguments,kwargs))
        if arguments and arguments[0]=="get":return {"pack":selected,"pack_sha256":sha}
        if module=="correction_gate":
            assert json.loads(kwargs["input_bytes"])==selected
            return dict(schema="injecticide.correction-gate.v1",passed=failure!="gate",pack_sha256=sha,fp_reductions=1,protected_preserved=1,protected_losses=0)
        assert arguments[0]=="approve"
        assert json.loads(kwargs["input_bytes"])["passed"] is True
        return {"status":"active"}
    monkeypatch.setattr(admin,"container_cli",cli)
    if failure=="none":assert admin.approve(sha)["status"]=="active"
    else:
        with pytest.raises((ValueError,RuntimeError)):admin.approve(sha)
        assert not any(call[2] and call[2][0]=="approve" for call in calls)

def test_public_upload_cannot_select_correction_pack(monkeypatch):
    import webapp.api as web
    seen=[]
    def execute(*args):
        seen.append(args)
        return 200,{"correction_application":{"state":"baseline"}}
    monkeypatch.setattr(web,"_execute_skill_scan",execute)
    with TestClient(web.app) as client:
        response=client.post("/api/skills/scan",files={"file":("case.md",b"synthetic","text/plain")},
          data={"correction_pack":json.dumps({"rules":[{"code":"forged"}]}),"background":"false"})
    assert response.status_code==200
    assert len(seen)==1
    assert len(seen[0])==9
    assert "forged" not in repr(seen)
