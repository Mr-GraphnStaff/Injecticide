"""Per-scan read of the approved correction control plane; no model calls or cache."""
from __future__ import annotations
import json
import os
import time
from urllib.parse import urlsplit
import requests
from skill_sandbox.approved_corrections import approved_pack

def fetch_approved_corrections():
    origin=os.environ.get("RESEARCH_MCP_URL","").rstrip("/")
    if not origin:
        return None,"not_configured"
    url=urlsplit(origin)
    if (url.scheme!="http" or url.hostname not in {
            "127.0.0.1","localhost","::1","research_mcp","injecticide-research-mcp"}
            or url.username or url.password or url.path or url.query or url.fragment):
        return None,"rejected_origin"
    try:
        started=time.monotonic()
        with requests.Session() as session:
            session.trust_env=False
            with session.get(origin+"/corrections/active",timeout=(1,1),stream=True,
                             allow_redirects=False,headers={"Cache-Control":"no-store"}) as response:
                if response.status_code!=200:
                    return None,"unavailable"
                raw=bytearray()
                for block in response.iter_content(1024):
                    if time.monotonic()-started>3 or len(raw)+len(block)>32768:
                        raise ValueError("Correction response budget")
                    raw.extend(block)
        envelope=json.loads(raw)
        approved_pack(envelope)
        return envelope,envelope["state"]
    except Exception:
        return None,"unavailable"
