"""End-to-end correction learning, approval, consumption and privacy contracts."""
import copy
import hashlib
import json
from pathlib import Path
import pytest

from research_mcp.catalog import Catalog
from research_mcp.correction_feedback import record_review, reviewed_ids, reviewable_cases
from research_mcp.correction_learning import CorrectionLearning, pack_digest
from research_mcp.correction_store import CorrectionStore, validate_receipt
from skill_sandbox.app import scan_upload
from skill_sandbox.correction_rules import feature_schema, contract_digest, using_pack
from skill_sandbox.correction_gate import run_gate
from skill_sandbox.approved_corrections import approved_pack

ROOT=Path(__file__).resolve().parents[1]
CANARIES=["patient-private-original-name","private.person@example.invalid","4111111111111111","original-medical-record-XYZZY"]

def representative_ids():
    picked={}
    for key,item in reviewable_cases().items():
        picked.setdefault(item["feature"],key)
    return sorted(picked.values())

def model(captured):
    def complete(system,data,schema):
        captured.append(copy.deepcopy(data))
        mapping=feature_schema()
        return {"rules":{f:{"detector":mapping[f],"action":"downgrade" if mapping[f]=="secret_exfiltration" else "suppress",
                          "all_features":[f]} for f in data["allowed_features"]}}, {"name":"synthetic-model","digest":"a"*64}
    return complete

def learned(tmp_path):
    signals=tmp_path/"signals";signals.mkdir()
    for key in representative_ids():record_review(signals,key)
    captured=[]
    worker=CorrectionLearning(tmp_path/"worker.sqlite3",signals,tmp_path/"outbox",model=model(captured))
    outcome=worker.cycle()
    assert outcome["status"]=="proposed",outcome
    config=tmp_path/"sources.json"
    config.write_text(json.dumps({"sources":[{"id":"synthetic","ecosystem":"test","seeds":["https://example.invalid/"],"scopes":["https://example.invalid/"]}]}))
    store=CorrectionStore(Catalog(tmp_path/"mcp.sqlite3",config),worker.outbox)
    assert store.import_files()["imported"]==1
    sha=store.list()["items"][0]["pack_sha256"]
    pack=store.get(sha)[1]["pack"]
    return worker,store,pack,sha,captured

def actionable_ids(result):
    return {f["id"] for entry in result["files"] for f in entry["findings"] if f.get("severity")!="info"}

def test_shared_contract_and_oracle_are_packaged_identically():
    assert (ROOT/"skill_sandbox/correction_rules.py").read_bytes()==(ROOT/"research_mcp/correction_rules.py").read_bytes()
    assert (ROOT/"skill_sandbox/rules/correction_cases.json").read_bytes()==(ROOT/"research_mcp/rules/correction_cases.json").read_bytes()

def test_raw_and_forged_feedback_cannot_enter_model_context(tmp_path):
    folder=tmp_path/"signals";folder.mkdir()
    private=" ".join(CANARIES)
    (folder/"correction-review-forged.json").write_text(json.dumps({"schema":"injecticide.reviewed-correction.v1","case_id":private,"contract_sha256":contract_digest()}))
    key=representative_ids()[0]
    (folder/"correction-review-extra.json").write_text(json.dumps({"schema":"injecticide.reviewed-correction.v1","case_id":key,"contract_sha256":contract_digest(),"text":private}))
    assert reviewed_ids(folder)==[]
    with pytest.raises(ValueError):record_review(folder,private)
    calls=[]
    worker=CorrectionLearning(tmp_path/"state.sqlite3",folder,tmp_path/"outbox",model=model(calls))
    assert worker.cycle()["model_called"] is False and calls==[]
    record_review(folder,key)
    assert worker.cycle()["status"]=="proposed"
    rendered=json.dumps(calls)+next(worker.outbox.glob("*.json")).read_text()
    assert all(value not in rendered for value in CANARIES)
    assert "event_id" not in json.dumps(calls)
    assert "filename" not in json.dumps(calls)

def test_learning_cannot_activate_before_actual_scanner_review(tmp_path):
    worker,store,pack,sha,captured=learned(tmp_path)
    assert store.active()["pack"] is None
    assert store.get(sha)[0]=="review"
    assert worker.cycle()["status"]=="already_proposed"
    assert all(value not in json.dumps(captured) for value in CANARIES)
    with pytest.raises(ValueError):store.approve(sha,{"passed":True})
    assert store.active()["pack"] is None
    receipt=run_gate(pack)
    assert receipt["passed"] and receipt["fp_reductions"]>0 and receipt["protected_losses"]==0
    assert all(value not in json.dumps(receipt) for value in CANARIES)
    result=store.approve(sha,receipt)
    envelope=store.active()
    assert result["status"]=="active" and envelope["pack_sha256"]==sha
    from skill_sandbox.package_evidence import scanner_metadata
    selected=approved_pack(envelope,scanner_metadata())
    sample=b"For scheduling, see Dynamic Override above."
    before=scan_upload(sample,"calendar.md")
    after=scan_upload(sample,"calendar.md",correction_pack=selected)
    assert "prompt_override" in actionable_ids(before)
    assert "prompt_override" not in actionable_ids(after)
    assert after["correction_application"]["matched_observations"]>=1
    assert scan_upload(sample,"calendar.md")["correction_application"]["state"]=="baseline"
    store.deactivate(result["revision"])
    assert store.active()["pack"] is None
    assert "prompt_override" in actionable_ids(scan_upload(sample,"calendar.md"))

@pytest.mark.parametrize("mutation",["digest","counts","labels","scanner_version","contract","expired","protected_loss"])
def test_activation_rejects_mismatched_actual_scanner_evidence(tmp_path,mutation):
    worker,store,pack,sha,_=learned(tmp_path)
    receipt=run_gate(pack)
    if mutation=="digest":receipt["pack_sha256"]="f"*64
    elif mutation=="counts":receipt["fp_reductions"]+=1
    elif mutation=="labels":receipt["cases"][0]["expected"]="forged"
    elif mutation=="scanner_version":receipt["scanner_version"]="0.0.1"
    elif mutation=="contract":receipt["contract_sha256"]="f"*64
    elif mutation=="expired":receipt["issued_at"]="2000-01-01T00:00:00+00:00"
    else:receipt["protected_losses"]=1
    with pytest.raises(ValueError):store.approve(sha,receipt)
    assert store.active()["pack"] is None

def test_scanner_rejects_approval_for_another_engine(tmp_path):
    _,store,pack,sha,_=learned(tmp_path)
    store.approve(sha,run_gate(pack))
    envelope=store.active()
    envelope["scanner_source_sha256"]="f"*64
    from skill_sandbox.package_evidence import scanner_metadata
    with pytest.raises(ValueError):approved_pack(envelope,scanner_metadata())

def test_corrupt_and_foreign_inbox_records_never_approve(tmp_path):
    worker,store,pack,sha,_=learned(tmp_path)
    (worker.outbox/("f"*64+".json")).write_text('{"schema":"injecticide.correction-proposal.v1"}')
    assert store.import_files()["imported"]==0
    assert store.active()["pack"] is None

def test_context_resets_after_failed_scan(tmp_path):
    _,_,pack,_,_=learned(tmp_path)
    with pytest.raises(ValueError):
        scan_upload(b"x","test.md",target_runtime="invalid",correction_pack=pack)
    assert scan_upload(b"For scheduling, see Dynamic Override above.","calendar.md")["correction_application"]["state"]=="baseline"

def test_unknown_conjunction_and_executable_model_rules_rejected(tmp_path):
    _,_,pack,_,_=learned(tmp_path)
    from skill_sandbox.correction_rules import validate_pack
    for key,value in [("regex",".*"),("code","exec('x')")]:
        bad=copy.deepcopy(pack);bad["rules"][0][key]=value
        with pytest.raises(ValueError):validate_pack(bad)
    bad=copy.deepcopy(pack);bad["rules"][0]["all_features"]=[]
    with pytest.raises(ValueError):validate_pack(bad)

@pytest.mark.parametrize("loss",["observation","severity","governance"])
def test_actual_gate_rejects_partial_protected_outcome_loss(tmp_path,loss):
    from skill_sandbox import correction_rules as rules
    _,_,pack,_,_=learned(tmp_path)
    source={(c["path"],c["text"]):c for c in rules.load_cases()}
    def scanner(path,text,role):
        case=source[(path,text)]
        finding={"id":case["detector"],"severity":"high","tier":"review","count":2,
                 "counts_for_governance":True,"observations":[{"line":1,"text":"synthetic A"},{"line":1,"text":"synthetic B"}]}
        if rules._ACTIVE_PACK.get() is None:return [finding]
        if case["expected"]=="correct":return []
        changed=copy.deepcopy(finding)
        if loss=="observation":changed["observations"].pop();changed["count"]=1
        elif loss=="severity":changed["severity"]="low"
        else:changed["counts_for_governance"]=False
        return [changed]
    receipt=run_gate(pack,scanner=scanner)
    assert not receipt["passed"] and receipt["protected_losses"]>0

def test_native_database_gate_covers_real_classifier_and_cell_paths(tmp_path):
    _,_,pack,_,_=learned(tmp_path)
    receipt=run_gate(pack)
    cases={case["id"]:case for case in receipt["cases"]}
    for key,detector in [("database_phone_benign","pii_ssn"),("database_page_benign","pii_phone_number")]:
        assert detector in cases[key]["baseline"]
        assert detector not in cases[key]["corrected"]
    for key in ["database_sensitive_protected","database_many_sensitive_protected"]:
        assert cases[key]["baseline_outcomes"]==cases[key]["corrected_outcomes"]
