"""Finite, deterministic interpretation of reviewed scanner correction packs.

Packs contain feature names, never code or regular expressions. Source content
stays inside this scanner; this module has no network/model client.
"""
from __future__ import annotations

import copy
import json
import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
import re
from pathlib import Path

CASES_PATH = Path(__file__).parent / "rules" / "correction_cases.json"
_ACTIVE_PACK = ContextVar("scanner_correction_pack", default=None)
_APPLIED = ContextVar("scanner_correction_evidence", default=None)
FEATURE_DETECTORS = {
    "cross_reference": "prompt_override",
    "defensive_catalog": "secret_exfiltration",
    "zip_plus4": "pii_ssn",
    "typed_phone_value": "pii_ssn",
    "generic_health_policy": "phi_patient_record",
    "trailing_phone_spacer": "unicode_deception",
    "confluence_page_id": "pii_phone_number",
}
# These are scanner-owned predicates. No pack can add a predicate or relax them.
OPERATIVE = re.compile(r"\b(?:ignore|disregard|override)\s+(?:all\s+|the\s+|previous\s+)*(?:instructions?|rules?|system|developer)|\b(?:you must|you should|assistant[:,]|execute|eval\s*\(|exec\s*\(|subprocess|os\.system|send.{0,50}(?:secret|token|credential)|reveal.{0,40}(?:secret|prompt|token))", re.I)
SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)|\b(?:ssn|social security)\b", re.I)
PERSONAL = re.compile(r"\b(?:patient|diagnosis|diagnosed|date of birth|dob|medical record|mrn)\s*(?:[:=#]|number|id)|\b[A-Z][a-z]+ [A-Z][a-z]+\b.{0,60}\b(?:diagnosed|diagnosis|patient)\b", re.I)
PHONE = re.compile(r"(?:phone|telephone|mobile|fax|tel|mobilePhone|businessPhones|telephoneNumber|phone_number|work_phone)\s*[:=]\s*([+()\d .-]+)\u200b?\s*$", re.I)


def _features(text):
    features = set()
    if re.search(r"\bsee\s+(?:the\s+)?dynamic override\s+(?:above|below)\b", text, re.I):
        features.add("cross_reference")
    if re.search(r"\b(?:MITRE|ATT&CK|ATLAS)\b", text, re.I) and re.search(r"\b(?:adversaries|attackers)\s+(?:(?:may|can|could)\s+)?(?:extract|exfiltrate|steal|collect|obtain)\b", text, re.I) and not re.search(r"\b(?:you|now|must|should)\b", text, re.I):
        features.add("defensive_catalog")
    if re.search(r"(?<![\d-])\d{5}-\d{4}(?![\d-])", text):
        features.add("zip_plus4")
    phone = PHONE.fullmatch(text.strip())
    if phone and re.fullmatch(r"\d{9}", phone[1].strip()):
        features.add("typed_phone_value")
    if re.search(r"\b(?:employees?|workplace)\b", text, re.I) and re.search(r"\b(?:accommodation|medical|health)\b", text, re.I) and re.search(r"\b(?:policy|policies|guidelines)\b", text, re.I):
        allowed = {"employee", "employees", "workplace", "accommodation", "accommodations", "and", "or", "medical", "health", "policy", "policies", "guidelines", "the", "a", "an", "for", "of", "to", "in", "with", "under", "are", "is", "provided", "reasonable", "work", "staff", "general", "benefits", "support", "requests", "process", "access", "information"}
        normative = re.search(r"\b(?:provides?|available|eligible|eligibility|entitled|required?|requires?|shall|must|may|can|offered?|requests?|process)\b", text, re.I)
        if normative or set(re.findall(r"[a-z]+", text.lower())).issubset(allowed):
            features.add("generic_health_policy")
    if phone and text.rstrip().endswith("\u200b") and not re.search(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069]", text.rstrip()[:-1]):
        features.add("trailing_phone_spacer")
    page = re.compile(r"(?:https://[^\s/]+)?/wiki/(?:spaces/[^/\s]+/)?pages/\d+(?:/[^\s)\]]*)?|\b(?:confluence\s+)?page[ _-]?id\s*[:=#]?\s*\d+", re.I)
    if page.search(text):
        remaining = page.sub("", text)
        for match in page.finditer(text):
            identifier = re.search(r"(?:/pages/|id\s*[:=#]?\s*)(\d+)", match[0], re.I)
            if identifier:
                remaining = remaining.replace("[" + identifier[1] + "]", "")
        if not re.search(r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}", remaining):
            features.add("confluence_page_id")
    return features


def feature_schema():
    return dict(FEATURE_DETECTORS)


def load_cases():
    return json.loads(CASES_PATH.read_text(encoding="utf-8"))


def contract_digest():
    digest = hashlib.sha256()
    for value in (Path(__file__).read_bytes().replace(b"\r\n", b"\n"),
                  CASES_PATH.read_bytes().replace(b"\r\n", b"\n"),
                  json.dumps(feature_schema(), sort_keys=True).encode()):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def validate_pack(pack):
    if not isinstance(pack, dict) or set(pack) != {"schema_version", "version", "contract_sha256", "rules"}:
        raise ValueError("Invalid correction pack fields")
    if type(pack["schema_version"]) is not int or pack["schema_version"] != 1 or not isinstance(pack["version"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", pack["version"]):
        raise ValueError("Unsupported correction pack version")
    if not isinstance(pack["contract_sha256"], str) or pack["contract_sha256"] != contract_digest():
        raise ValueError("Correction contract digest mismatch")
    if not isinstance(pack["rules"], list) or len(pack["rules"]) > 32:
        raise ValueError("Expected at most 32 correction rules")
    ids = set()
    for rule in pack["rules"]:
        if not isinstance(rule, dict) or set(rule) != {"id", "detector", "action", "all_features"}:
            raise ValueError("Invalid correction rule fields")
        if not isinstance(rule["id"], str) or not re.fullmatch(r"[a-f0-9]{8,64}", rule["id"]) or rule["id"] in ids:
            raise ValueError("Invalid/duplicate correction id")
        ids.add(rule["id"])
        features = rule["all_features"]
        if not isinstance(rule["detector"], str) or not isinstance(features, list) or not features or len(features) > len(FEATURE_DETECTORS) or any(not isinstance(f, str) or FEATURE_DETECTORS.get(f) != rule["detector"] for f in features) or len(set(features)) != len(features):
            raise ValueError("Unknown or incompatible correction feature")
        if rule["detector"]=="secret_exfiltration" and rule["action"]!="downgrade":
            raise ValueError("Defensive catalog evidence remains informational")
        if rule["detector"] in {"pii_ssn", "phi_patient_record"} and rule["action"] != "suppress":
            raise ValueError("Sensitive false labels require suppression")
        if not isinstance(rule["action"], str) or rule["action"] not in {"suppress", "downgrade"}:
            raise ValueError("Unsupported correction action")
    return pack


def _catalog_lines(source):
    lines = source.splitlines()
    if not re.search(r"\b(?:MITRE|ATT&CK|ATLAS)\b", source, re.I):
        return set()
    eligible = set()
    for i, line in enumerate(lines):
        if not re.match(r"^\s*[-*]\s+", line):
            continue
        start = next((j for j in range(i, max(-1, i-120), -1) if re.match(r"^##\s+", lines[j])), None)
        if start is None or not re.match(r"^##\s+(?:Tactic\b|TA\d{4}\b)", lines[start], re.I):
            continue
        subsection = next((j for j in range(i,start,-1) if re.match(r"^###\s+",lines[j])),None)
        if subsection is None:continue
        end = next((j for j in range(i+1,min(len(lines),start+120)) if re.match(r"^#{2,3}\s+",lines[j])),min(len(lines),start+120))
        before,after="\n".join(lines[subsection:i]),"\n".join(lines[i+1:end])
        if (re.search(r"^###\s+",before,re.M) and re.search(r"\*\*Technique:\*\*\s*\S",before,re.I)
            and re.search(r"\*\*Azure attack patterns:\*\*",before,re.I)
            and not re.search(r"\*\*Key controls:\*\*",before,re.I)
            and re.search(r"\*\*Key controls:\*\*",after,re.I)):
            eligible.add(i+1)
    return eligible


def _decision(rule, local, source, *, catalog=False):
    if catalog:
        if re.search(r"\b(?:you|assistant|agent)\s+(?:must|should|shall)|\b(?:follow|obey|execute|run|apply)\s+(?:these|those|above|the\s+(?:catalog|attack|patterns|examples))\b",source,re.I) or re.search(r"\x60|<script|\b(?:eval|exec|subprocess|powershell|curl|wget)\b|bash\s+-c",local,re.I):
            return False
        eligible=_catalog_lines(source)
        source="\n".join(line for n,line in enumerate(source.splitlines(),1) if n not in eligible)
    # Full-source guards prevent sampled benign observations hiding a later attack.
    if OPERATIVE.search(source) or "```" in local or re.search(r"<script|\b(?:eval|exec)\s*\(|(?:^|[;.!?:]\s*)(?:copy|extract|exfiltrate|output|print|dump|steal|bypass|disable)\b", source, re.I | re.M):
        return False
    detector = rule["detector"]
    if detector == "pii_ssn" and SSN.search(source):
        return False
    if detector == "pii_ssn":
        remaining = "\n".join(line for line in source.splitlines() if "typed_phone_value" not in _features(line))
        remaining = re.sub(r"\b\d{5}-\d{4}\b", "", remaining)
        if re.search(r"(?<!\d)\d{9}(?!\d)", remaining):
            return False
    if detector == "phi_patient_record":
        remaining = "\n".join(line for line in source.splitlines() if "typed_phone_value" not in _features(line) and "confluence_page_id" not in _features(line))
        remaining = re.sub(r"\b\d{5}-\d{4}\b", "", remaining)
        if PERSONAL.search(source) or SSN.search(source) or re.search(r"[@\d]|\b(?:diagnos(?:is|ed)|prescription|mrn|date of birth|dob)\b|\b(?:patient|employee|member)\s+name\s*[:=]|\b[A-Z][a-z]+\s+[A-Z][a-z]+\s+(?:has|takes|suffers|was diagnosed|is receiving)\b", remaining, re.I):
            return False
    return set(rule["all_features"]).issubset(_features(local)|({"defensive_catalog"} if catalog else set()))


def apply_corrections(path, text, findings, pack=None):
    pack = _ACTIVE_PACK.get() if pack is None else validate_pack(pack)
    if pack is None:
        return findings
    result = []
    lines = text.splitlines()
    catalog_lines=_catalog_lines(text)
    fenced,fence_lines=False,set()
    for i,line in enumerate(lines,1):
        if re.match(r"^\s*(?:\x60{3,}|~{3,})",line):
            fence_lines.add(i);fenced=not fenced
        elif fenced:fence_lines.add(i)
    for original in findings:
        finding = copy.deepcopy(original)
        observations = finding.get("observations", [])
        # Never remove findings whose full match population was truncated.
        if finding.get("count", len(observations)) > len(observations):
            result.append(finding)
            continue
        kept, applied, downgraded = [], [], []
        for observation in observations:
            catalog=finding.get("id")=="secret_exfiltration" and observation.get("line") in catalog_lines
            if not catalog and (observation.get("imperative_evidence") or observation.get("speech_act") == "request"):
                kept.append(observation)
                continue
            number = observation.get("line")
            local = lines[number - 1] if type(number) is int and 1 <= number <= len(lines) else ""
            if number in fence_lines:
                kept.append(observation)
                continue
            rule = next((r for r in pack["rules"] if r["detector"] == finding.get("id") and _decision(r, local, text, catalog=catalog)), None)
            if rule is None:
                kept.append(observation)
            else:
                applied.append(rule["id"])
                stats=_APPLIED.get()
                if stats is not None:
                    stats["matched_observations"]+=1
                    stats["rules"].add(rule["id"])
                if rule["action"] == "downgrade":
                    downgraded.append(observation)
        if not applied:
            result.append(finding)
            continue
        if kept:
            finding["observations"] = kept + downgraded
        elif downgraded:
            finding["observations"] = downgraded
            finding.update(severity="info", tier="info", disposition="informational", is_actionable=False, counts_for_governance=False)
            finding["label"] = "Reviewed contextual reference"
            finding["display_kind"] = "informational_signal"
            finding["finding_category"] = "topic_mention"
            finding["subject"] = "technical_reference"
            finding["description"] = "Deterministic reviewed correction matched a bounded technical reference; retained as context."
            finding["action_state"] = "reviewed_contextual_reference"
        else:
            continue
        finding["count"] = len(finding["observations"])
        finding["samples"] = [o.get("text", "") for o in finding["observations"]][:3]
        finding["correction"] = {"version": pack["version"], "rules": sorted(set(applied))}
        result.append(finding)
    return result


def evaluate_pack(pack, scanner=None):
    """Gate every proposed rule using the source-owned contrastive corpus.

    With scanner=None this tests the interpreter with synthetic finding objects.
    With scanner provided, it additionally compares actual scanner outcomes.
    """
    validate_pack(pack)
    results = []
    reductions = protected = not_triggered = 0
    for rule in pack["rules"]:
        single = dict(pack, rules=[rule])
        corrected = False
        for case in load_cases():
            if case["feature"] not in rule["all_features"]:
                continue
            finding = {"id": case["detector"], "severity": "high", "count": 1,
                       "observations": [{"line": case.get("observation_line",1), "text": "synthetic"}]}
            output = apply_corrections(case["path"], case["text"], [finding], single)
            actual = "suppress" if not output else "downgrade" if output[0]["severity"] == "info" else "keep"
            expected = rule["action"] if case["expected"] == "correct" else "keep"
            passed = actual == expected
            if case["expected"] == "correct" and passed:
                corrected = True
            if scanner is not None:
                with using_pack(None):
                    baseline = scanner(case["path"], case["text"], "active")
                with using_pack(single, gate=False):
                    scanned = scanner(case["path"], case["text"], "active")
                before = [f for f in baseline if f.get("id") == case["detector"]]
                after = [f for f in scanned if f.get("id") == case["detector"]]
                if not before:
                    not_triggered += 1
                if expected == "keep":
                    passed = passed and before == after
                    if before and before == after:
                        protected += 1
                elif before:
                    reduction = not after if expected == "suppress" else all(f.get("severity") == "info" for f in after)
                    passed = passed and reduction
                    reductions += int(reduction and (expected=="suppress" or any(f.get("severity")!="info" for f in before)))
            results.append({"rule": rule["id"], "id": case["id"], "passed": passed, "actual": actual})
        results.append({"rule": rule["id"], "id": "positive_coverage", "passed": corrected})
    return {"passed": all(c["passed"] for c in results), "mode": "scanner" if scanner else "interpreter", "fp_reductions": reductions, "protected_preserved": protected, "not_triggered": not_triggered, "cases": results}


@contextmanager
def using_pack(pack, *, gate=True):
    """Install a validated request-local pack; always restore the caller context."""
    if pack is not None:
        validate_pack(pack)
        if gate and not evaluate_pack(pack)["passed"]:
            raise ValueError("Correction regression gate failed")
        pack = copy.deepcopy(pack)
    token = _ACTIVE_PACK.set(pack)
    stats={"matched_observations":0,"rules":set()}
    evidence_token=_APPLIED.set(stats)
    try:
        yield stats
    finally:
        _ACTIVE_PACK.reset(token)
        _APPLIED.reset(evidence_token)


def corrects_typed_phone(value, column):
    """Share the same reviewed predicate with database content classification."""
    pack = _ACTIVE_PACK.get()
    if pack is None:
        return False
    text = str(column) + "=" + str(value)
    return any(r["detector"] == "pii_ssn" and r["action"] == "suppress" and
               "typed_phone_value" in r["all_features"] and _decision(r, text, text)
               for r in pack["rules"])

def _typed_data_text(value, column):
    column=str(column or "")
    if re.fullmatch(r"phone|telephone|mobile|fax|tel|mobilePhone|businessPhones|telephoneNumber|phone_number|work_phone",column,re.I):
        return column+"="+str(value)
    words=re.sub(r"([a-z])([A-Z])",r"\1 \2",column).lower().replace("_"," ").split()
    if "id" in words and any(word in words for word in ("page","pages","space")):
        return "confluence page id="+str(value)
    return str(value)

def corrects_data_value(detector,value,column):
    pack=_ACTIVE_PACK.get()
    if pack is None:return False
    text=_typed_data_text(value,column)
    return any(rule["detector"]==detector and rule["action"]=="suppress"
               and _decision(rule,text,text) for rule in pack["rules"])

def apply_database_corrections(path, texts, columns, findings):
    if _ACTIVE_PACK.get() is None:return findings
    result=[]
    eligible={"pii_ssn","phi_patient_record","pii_phone_number","unicode_deception"}
    for finding in findings:
        observations=finding.get("observations",[])
        if finding.get("id") not in eligible or finding.get("count",len(observations))>len(observations) or not observations:
            result.append(finding);continue
        for observation in observations:
            number=observation.get("line")
            if type(number) is not int or not 1<=number<=len(texts):
                result.append(dict(finding,observations=[observation],count=1));continue
            local=_typed_data_text(texts[number-1],columns[number-1])
            piece=copy.deepcopy(finding)
            piece["observations"]=[dict(observation,line=1)]
            piece["count"]=1
            for corrected in apply_corrections(path,local,[piece]):
                for item in corrected.get("observations",[]):item["line"]=number
                result.append(corrected)
    return result

def trusted_informational_correction(finding):
    """Only a downgrade applied in this request can survive later policy."""
    pack,stats=_ACTIVE_PACK.get(),_APPLIED.get()
    marker=finding.get("correction")
    if (not pack or not stats or not isinstance(marker,dict)
            or set(marker)!={"version","rules"} or marker["version"]!=pack["version"]
            or not isinstance(marker["rules"],list) or not marker["rules"]
            or any(not isinstance(value,str) for value in marker["rules"])
            or len(marker["rules"])!=len(set(marker["rules"]))
            or finding.get("severity")!="info" or finding.get("tier")!="info"
            or finding.get("is_actionable") is not False
            or finding.get("counts_for_governance") is not False
            or finding.get("action_state")!="reviewed_contextual_reference"):
        return False
    allowed={rule["id"] for rule in pack["rules"]
             if rule["detector"]==finding.get("id") and rule["action"]=="downgrade"}
    return set(marker["rules"]).issubset(allowed & stats["rules"])
