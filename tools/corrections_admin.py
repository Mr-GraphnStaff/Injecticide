"""Trusted host-only correction workflow using fixed local container commands.

No public approval listener, target selector, arbitrary file input, shell,
operator-supplied receipt, or scan-text input is accepted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys

MCP = "injecticide-research-mcp"
SANDBOX = "injecticide-skill-sandbox"
WEB = "injecticide-web"
RESEARCH = "injecticide-research-agent"
MAX_OUTPUT = 262144
INSPECT_FORMAT = '{"running":{{json .State.Running}},"image":{{json .Config.Image}},"id":{{json .Id}}}'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Invalid JSON constant")


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)


def execute(argv, *, input_bytes=None, timeout=120):
    # Every caller supplies a fixed argv; validated technical IDs are the only
    # operator-controlled arguments. Raw subprocess output never enters errors.
    result = subprocess.run(argv, input=input_bytes, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False,
                            stdin=subprocess.DEVNULL if input_bytes is None else None)
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise RuntimeError("Trusted command output exceeded budget")
    if result.returncode:
        raise RuntimeError("Trusted correction command failed")
    return result.stdout


def container_cli(container, module, *arguments, input_bytes=None, timeout=120):
    argv = ["docker", "exec"]
    if input_bytes is not None:
        argv.append("-i")
    argv.extend([container, "python", "-m", module, *arguments])
    return parse_json(execute(argv, input_bytes=input_bytes, timeout=timeout))


def release_identity():
    raw = execute(["docker", "inspect", "--format", INSPECT_FORMAT, MCP, SANDBOX])
    rows = [parse_json(line) for line in raw.splitlines() if line.strip()]
    if len(rows) != 2 or any(not isinstance(row, dict) or row.get("running") is not True
                             or not isinstance(row.get("id"), str)
                             or not re.fullmatch(r"[a-f0-9]{64}", row["id"])
                             or not isinstance(row.get("image"), str) for row in rows):
        raise RuntimeError("Both release containers must be running")
    tags = []
    for row, expected in zip(rows, ("injecticide-research-mcp", "injecticide-skill-sandbox")):
        name, separator, tag = row["image"].rpartition(":")
        if (separator != ":" or name != expected
                or not re.fullmatch(r"[a-f0-9]{12,40}", tag)
                or tag.lower() in {"local", "latest", "dev", "test"}):
            raise RuntimeError("Expected explicit release image tags")
        tags.append(tag)
    if tags[0] != tags[1]:
        raise RuntimeError("Scanner and research release tags differ")
    return rows


def approve(sha):
    identity = release_identity()
    proposal = container_cli(MCP, "research_mcp.correction_store", "get", "--sha", sha)
    if not isinstance(proposal, dict) or not isinstance(proposal.get("pack"), dict):
        raise ValueError("Correction proposal missing")
    pack = proposal["pack"]
    if hashlib.sha256(canonical(pack)).hexdigest() != sha or proposal.get("pack_sha256") != sha:
        raise ValueError("Correction proposal digest mismatch")
    receipt = container_cli(SANDBOX, "correction_gate", input_bytes=canonical(pack), timeout=600)
    if (not isinstance(receipt, dict) or receipt.get("schema") != "injecticide.correction-gate.v1"
            or receipt.get("passed") is not True or receipt.get("pack_sha256") != sha
            or type(receipt.get("fp_reductions")) is not int or receipt["fp_reductions"] < 1
            or type(receipt.get("protected_preserved")) is not int or receipt["protected_preserved"] < 1
            or receipt.get("protected_losses") != 0):
        raise ValueError("Actual scanner gate did not pass")
    if release_identity() != identity:
        raise RuntimeError("Release containers changed during review")
    # Only this in-memory receipt from the fixed actual scanner process reaches
    # activation. There is no receipt-file argument or skip-gate switch.
    return container_cli(MCP, "research_mcp.correction_store", "approve", "--sha", sha,
                         input_bytes=canonical(receipt))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    record = sub.add_parser("record")
    record.add_argument("--case", required=True)
    sub.add_parser("research")
    for command in ("approve", "reject"):
        action = sub.add_parser(command)
        action.add_argument("--sha", required=True)
    deactivate = sub.add_parser("deactivate")
    deactivate.add_argument("--expected-revision", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if args.command in {"approve", "reject"} and not re.fullmatch(r"[a-f0-9]{64}", args.sha):
            raise ValueError("Expected a SHA256 digest")
        if args.command == "record" and not re.fullmatch(r"[a-z0-9_-]{1,96}", args.case):
            raise ValueError("Expected a source-owned case ID")
        if args.command == "deactivate" and args.expected_revision < 0:
            raise ValueError("Expected a nonnegative revision")
        if args.command == "approve":
            result = approve(args.sha)
        elif args.command == "record":
            result = container_cli(WEB, "research_mcp.correction_feedback", "record", "--case", args.case)
        elif args.command == "research":
            result = container_cli(RESEARCH, "research_mcp.correction_learning", timeout=1800)
        elif args.command == "reject":
            result = container_cli(MCP, "research_mcp.correction_store", "reject", "--sha", args.sha)
        elif args.command == "deactivate":
            result = container_cli(MCP, "research_mcp.correction_store", "deactivate",
                                   "--expected-revision", str(args.expected_revision))
        else:
            result = container_cli(MCP, "research_mcp.correction_store", "list")
        print(canonical(result).decode("utf-8"))
        return 0
    except (ValueError, TypeError, KeyError, OSError, RuntimeError, subprocess.TimeoutExpired,
            RecursionError) as error:
        print(json.dumps({"error": type(error).__name__, "status": "not_completed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
