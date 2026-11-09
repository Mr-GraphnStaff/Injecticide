"""Local-only bounded transport migrated from the optional scan reviewer."""
from __future__ import annotations
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlsplit

REQUEST_DEADLINE_SECONDS = 90
MAX_RESPONSE_BYTES = 65536
WORKER = r"""
import json,sys,urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
endpoint,payload=json.load(sys.stdin)
def request(path,body=None):
    data=None if body is None else json.dumps(body).encode()
    req=urllib.request.Request(endpoint+path,data=data,headers={"Content-Type":"application/json"})
    with opener.open(req,timeout=85) as response:raw=response.read(65537)
    if len(raw)>65536:raise ValueError("response_budget")
    return json.loads(raw)
status=request("/api/status")
if status.get("cloud",{}).get("disabled") is not True:raise ValueError("cloud_must_be_disabled")
metadata=request("/api/show",{"model":payload["model"]})
if metadata.get("remote_host") or metadata.get("remote_model") or metadata.get("details",{}).get("format")!="gguf":
    raise ValueError("local_weights_required")
tags=request("/api/tags")
entry=next((x for x in tags.get("models",[]) if x.get("name")==payload["model"]),None)
if not entry or not entry.get("digest") or entry.get("remote_host") or entry.get("remote_model"):
    raise ValueError("local_model_identity_required")
result=request("/api/chat",payload)
result["_local_model_digest"]=entry["digest"]
print(json.dumps(result))
"""

def _chat(endpoint, payload):
    run = subprocess.run([sys.executable, "-B", "-c", WORKER],
                         input=json.dumps([endpoint, payload]).encode(),
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         timeout=REQUEST_DEADLINE_SECONDS, check=True)
    if len(run.stdout) > MAX_RESPONSE_BYTES + 1024:
        raise ValueError("response_budget")
    return json.loads(run.stdout)
def complete(system, data, schema, *, transport=None):
    endpoint = os.environ.get("INJECTICIDE_LOCAL_LLM_URL", "http://127.0.0.1:11434").rstrip("/")
    model = os.environ.get("INJECTICIDE_LOCAL_MODEL", "qwen3.5:2b")
    url = urlsplit(endpoint)
    if (url.scheme != "http" or url.hostname not in {"127.0.0.1", "localhost", "::1", "injecticide-local-llm"}
            or url.username or url.password or url.path or url.query or url.fragment):
        raise ValueError("Local endpoint required")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", model) or "cloud" in model.lower():
        raise ValueError("Local model required")
    content = json.dumps(data, ensure_ascii=True, sort_keys=True)
    if len(content.encode()) > 24000:
        raise ValueError("Input budget")
    result = (transport or _chat)(endpoint, {
        "model": model, "stream": False, "think": False,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": content}],
        "format": schema, "keep_alive": "10m",
        "options": {"temperature": 0, "num_ctx": 8192, "num_predict": 512, "num_thread": 2}})
    if (result.get("done") is not True or result.get("done_reason") != "stop"
            or not re.fullmatch(r"[a-f0-9]{64}", str(result.get("_local_model_digest", "")))):
        raise ValueError("Incomplete or unidentified generation")
    answer = result["message"]["content"]
    if not isinstance(answer, str) or len(answer.encode()) > MAX_RESPONSE_BYTES:
        raise ValueError("Output budget")
    return json.loads(answer), {"name": model, "digest": result["_local_model_digest"]}
