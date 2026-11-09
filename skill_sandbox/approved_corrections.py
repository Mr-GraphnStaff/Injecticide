"""Validate a trusted-control-plane correction envelope; never select rules from uploads."""
from __future__ import annotations
import hashlib
import json
import re
try:
    from .correction_rules import validate_pack, evaluate_pack, contract_digest
    from .package_evidence import SCANNER_VERSION
except ImportError:
    from correction_rules import validate_pack, evaluate_pack, contract_digest
    from package_evidence import SCANNER_VERSION

SCHEMA="injecticide.approved-corrections.v1"

def pack_digest(pack):
    return hashlib.sha256(json.dumps(pack,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()

def approved_pack(envelope, scanner_identity=None):
    fields={"schema","revision","state","pack","pack_sha256","scanner_version",
            "scanner_source_sha256","contract_sha256","gate_revision"}
    if (not isinstance(envelope,dict) or set(envelope)!=fields or envelope["schema"]!=SCHEMA
            or type(envelope["revision"]) is not int or envelope["revision"]<0
            or envelope["state"] not in {"active","disabled","stale"}
            or envelope["scanner_version"]!=SCANNER_VERSION
            or envelope["contract_sha256"]!=contract_digest() or type(envelope["gate_revision"]) is not int or envelope["gate_revision"]!=2):
        raise ValueError("Correction approval envelope mismatch")
    if envelope["state"]!="active":
        if envelope["pack"] is not None:
            raise ValueError("Inactive correction pack")
        return None
    pack=validate_pack(envelope["pack"])
    if (not pack["rules"] or envelope["revision"]<1
            or envelope["pack_sha256"]!=pack_digest(pack)
            or not re.fullmatch(r"[a-f0-9]{64}",str(envelope["scanner_source_sha256"]))
            or evaluate_pack(pack).get("passed") is not True):
        raise ValueError("Unvalidated correction pack")
    if scanner_identity is not None and (
            envelope["scanner_source_sha256"]!=scanner_identity["engine_source_sha256"]
            or envelope["scanner_version"]!=scanner_identity["scanner_version"]):
        raise ValueError("Approved correction belongs to another scanner build")
    return pack
