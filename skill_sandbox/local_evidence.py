"""Bounded multi-file evidence selection, independent of security verdicts."""
import json
import re
from pathlib import PurePosixPath

RISK_RULES = {"prompt_override", "system_exfiltration", "secret_exfiltration", "dynamic_exec",
    "tool_escape", "autonomous_authoritative_write", "bulk_enterprise_modification",
    "workflow_manipulation", "cross_system_automation", "self_modifying_skill"}


def select_evidence(sources, report, byte_budget=6000, max_fragments=24):
    files = {f["path"]: f for f in report.get("files", [])}
    queues = []
    unlocated = 0
    for source in sources:
        path, text = source["path"], source["text"]
        if not text:
            continue
        candidates, seen = [], set()
        def add(anchor, rank, basis):
            start = max(0, anchor - 80)
            end = min(len(text), start + 240)
            excerpt = text[start:end]
            if not excerpt or excerpt in seen:
                return
            seen.add(excerpt)
            candidates.append(dict(path=path, text=excerpt, line=text.count("\n", 0, start)+1,
                full_file=start == 0 and end == len(text), rank=rank, basis=basis,
                role=source.get("artifact_role", "unknown")))
        lines, offsets = None, []
        for finding in files.get(path, {}).get("findings", []):
            if finding.get("id") not in RISK_RULES:
                continue
            for observation in finding.get("observations", []):
                line = observation.get("line")
                if type(line) is not int or line < 1:
                    unlocated += 1
                    continue
                if lines is None:
                    lines = text.splitlines(keepends=True)
                    offset = 0
                    for value in lines:
                        offsets.append(offset)
                        offset += len(value)
                if line <= len(lines):
                    literal = observation.get("text", "")
                    within = lines[line-1].find(literal) if literal else -1
                    if within < 0 and literal:
                        normalized = re.search(r"\s+".join(re.escape(token) for token in literal.split()), lines[line-1])
                        if normalized:
                            within = normalized.start()
                    if within < 0:
                        unlocated += 1
                        # Do not label an unrelated line prefix as the exact detected action.
                        for relative in (0, len(lines[line-1])//2, max(0, len(lines[line-1])-160)):
                            add(offsets[line-1]+relative, 1, "Static signal line; exact location unavailable")
                    else:
                        add(offsets[line-1]+within,
                            0 if finding.get("tier") == "block" else 1,
                            "Static signal: " + finding["id"])
        rank = 2 if PurePosixPath(path).name.lower() == "skill.md" else 3
        for anchor in (0, len(text)//2, max(0, len(text)-160)):
            add(anchor, rank, "Distributed source sample")
        candidates.sort(key=lambda c: (c["rank"], c["line"]))
        queues.append(candidates)
    queues.sort(key=lambda q: (q[0]["rank"], q[0]["path"].casefold()))
    selected, mapping = [], {}
    def encode(items):
        return json.dumps({"untrusted_evidence": items}, ensure_ascii=False, separators=(",", ":"))
    for turn in range(max((len(q) for q in queues), default=0)):
        for queue in queues:
            if len(selected) >= max_fragments or turn >= len(queue):
                continue
            candidate = queue[turn]
            key = "E" + str(len(selected)+1)
            item = dict(id=key, role=candidate["role"], partial=not candidate["full_file"], text=candidate["text"])
            if len(encode(selected+[item]).encode()) <= byte_budget:
                selected.append(item)
                mapping[key] = candidate
    paths = {c["path"] for c in mapping.values()}
    all_paths = {s["path"] for s in sources if s["text"]}
    complete = {c["path"] for c in mapping.values() if c["full_file"]}
    coverage = dict(status="partial" if all_paths-complete else "bounded_text_only",
        selected_files=len(paths), files_considered=len(all_paths),
        files_not_selected=len(all_paths-paths), files_with_partial_context=len(paths-complete),
        omitted_or_clipped_files=len(all_paths-complete), fragments_selected=len(selected),
        unlocated_static_signals=unlocated, input_byte_budget=byte_budget, selection_method="Static contexts and distributed samples")
    return encode(selected), mapping, coverage
