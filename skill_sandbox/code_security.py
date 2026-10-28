"""Bounded static credential-source to network-request flow observations.

Primary API contracts (checked 2026-10-27):
https://docs.python.org/3/library/ast.html
https://requests.readthedocs.io/en/latest/user/quickstart/#more-complicated-post-requests

ASTs are data only. No uploaded function is called and no network is contacted.
Findings establish recognized source/sink syntax and conservative local value
flow, not actual execution, malicious intent, or complete program analysis.
"""
from __future__ import annotations

import ast
import posixpath
import re
from dataclasses import dataclass


MAX_CHARACTERS = 131072
MAX_AST_NODES = 20000
MAX_WORK = 100000
MAX_DEPTH = 64
MAX_FINDINGS = 80
MAX_ORIGINS = 16
CREDENTIAL_ENV = re.compile(r"(?:^|_)(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?)(?:_|$)", re.I)
CREDENTIAL_FILES = {"id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", ".netrc", ".npmrc", ".pypirc", ".env"}
NETWORK_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
PAYLOAD_KEYS = {"data", "json", "files", "params", "content", "body"}
SOURCES = [
    {"name": "Python abstract syntax trees", "url": "https://docs.python.org/3/library/ast.html"},
    {"name": "Requests request bodies and query parameters", "url": "https://requests.readthedocs.io/en/latest/user/quickstart/"},
]


@dataclass(frozen=True)
class _Origin:
    kind: str
    line: int
    source: str


@dataclass(frozen=True)
class _Value:
    origins: tuple = ()
    literal: str | None = None
    symbol: str | None = None
    path: str | None = None
    path_kind: str | None = None


class _Budget(Exception):
    pass


def analyze_code_security(path, text, declared_language=None, line_offset=0):
    """Analyze Python source without executing it; return findings and coverage.

    Only explicit credential-named environment reads and selected credential
    file reads are sources. Ordinary file/network capability combinations alone
    are not findings. Authentication/header fields are excluded from payload
    sinks: passing a credential to its authentication mechanism is not classified
    as credential-body disclosure by this detector. ``declared_language`` lets
    the caller select Python for independently recognized whole-file syntax or
    a Python code fence without changing the evidence path. It does not grant
    trust to source content. ``line_offset`` maps an extracted block's first
    line back to the original source (original first line minus one).
    """
    if type(line_offset) is not int or not 0 <= line_offset <= 1_000_000_000:
        raise ValueError("line_offset must be a bounded nonnegative integer")
    coverage = {"status": "complete_supported_syntax", "supplied_characters": len(text),
                "source_start_line": line_offset + 1,
                "limits": [], "scope": "Conservative intraprocedural Python value flow; no runtime/control-flow proof or interprocedural return analysis."}
    if not str(path).lower().endswith((".py", ".pyw")) and declared_language not in ("python", "py"):
        coverage.update(status="not_performed", reason="Python AST analysis only")
        return {"findings": [], "coverage": coverage}
    if len(text) > MAX_CHARACTERS:
        coverage.update(status="partial", limits=["source_character_budget"])
        return {"findings": [], "coverage": coverage}
    try:
        tree = ast.parse(text)
        for index, _ in enumerate(ast.walk(tree)):
            if index >= MAX_AST_NODES:
                raise _Budget("ast_node_budget")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        coverage.update(status="partial", limits=["python_parse_unavailable"])
        return {"findings": [], "coverage": coverage}
    except _Budget as exc:
        coverage.update(status="partial", limits=[str(exc)])
        return {"findings": [], "coverage": coverage}
    if line_offset:
        ast.increment_lineno(tree, line_offset)
    flow = _Flow(path)
    try:
        flow.statements(tree.body, {}, 0)
    except (_Budget, RecursionError) as exc:
        flow.limits.add(str(exc) if isinstance(exc, _Budget) else "recursion_budget")
    if flow.limits:
        coverage.update(status="partial", limits=sorted(flow.limits))
    coverage["work_units"] = flow.work
    return {"findings": flow.findings, "coverage": coverage}


class _Flow:
    def __init__(self, path):
        self.path = path
        self.work = 0
        self.findings = []
        self.finding_keys = set()
        self.limits = set()

    def tick(self, depth):
        self.work += 1
        if self.work > MAX_WORK:
            raise _Budget("work_budget")
        if depth > MAX_DEPTH:
            raise _Budget("depth_budget")

    def combine(self, values):
        origins = []
        for value in values:
            for origin in value.origins:
                if origin not in origins:
                    origins.append(origin)
                    if len(origins) > MAX_ORIGINS:
                        self.limits.add("source_origin_budget")
                        return _Value(origins=tuple(origins[:MAX_ORIGINS]))
        return _Value(origins=tuple(origins))

    def expr(self, node, env, depth):
        self.tick(depth)
        if node is None:
            return _Value()
        if isinstance(node, ast.Name):
            return env.get(node.id, _Value(symbol="open" if node.id == "open" else None))
        if isinstance(node, ast.Constant):
            return _Value(literal=node.value if isinstance(node.value, str) else None)
        if isinstance(node, ast.Attribute):
            owner = self.expr(node.value, env, depth + 1)
            if owner.path and node.attr == "parent" and owner.path_kind in {"concrete_path", "pure_path"}:
                return _Value(path=posixpath.dirname(owner.path) or ".", path_kind=owner.path_kind)
            if owner.path and node.attr == "name" and owner.path_kind in {"concrete_path", "pure_path"}:
                return _Value(literal=posixpath.basename(owner.path))
            readable = node.attr in ({"read_text", "read_bytes"} if owner.path_kind == "concrete_path" else {"read", "readline", "readlines"} if owner.path_kind == "file" else set())
            return _Value(origins=owner.origins, path=owner.path if readable else None, path_kind=owner.path_kind if readable else None,
                          symbol=(owner.symbol + "." + node.attr) if owner.symbol else None)
        if isinstance(node, ast.Subscript):
            owner = self.expr(node.value, env, depth + 1)
            key = self.expr(node.slice, env, depth + 1)
            if owner.symbol == "os.environ" and key.literal and CREDENTIAL_ENV.search(key.literal):
                return _Value(origins=(_Origin("credential_named_environment", node.lineno, key.literal),))
            return self.combine([owner, key])
        if isinstance(node, ast.BinOp):
            left, right = self.expr(node.left, env, depth + 1), self.expr(node.right, env, depth + 1)
            combined = self.combine([left, right])
            if isinstance(node.op, ast.Div) and (left.path_kind in {"concrete_path", "pure_path"} or right.path_kind in {"concrete_path", "pure_path"}) and (left.path or left.literal) and (right.path or right.literal):
                return _Value(origins=combined.origins, path=posixpath.join(left.path or left.literal, right.path or right.literal), path_kind=left.path_kind if left.path_kind in {"concrete_path", "pure_path"} else right.path_kind)
            if isinstance(node.op, ast.Add) and left.literal is not None and right.literal is not None:
                return _Value(origins=combined.origins, literal=left.literal + right.literal)
            return combined
        if isinstance(node, ast.Call):
            function = self.expr(node.func, env, depth + 1)
            args = [self.expr(arg, env, depth + 1) for arg in node.args]
            kwargs = {keyword.arg: self.expr(keyword.value, env, depth + 1) for keyword in node.keywords}
            name = function.symbol or ""
            if name in {"pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath", "pathlib.PurePosixPath", "pathlib.PureWindowsPath"}:
                parts = [value.path or value.literal for value in args]
                return _Value(path=posixpath.join(*parts) if parts and all(part is not None for part in parts) else None, path_kind="pure_path" if name.startswith("pathlib.Pure") else "concrete_path")
            if name in {"pathlib.Path.home", "pathlib.PosixPath.home", "pathlib.WindowsPath.home"}:
                return _Value(path="~", path_kind="concrete_path")
            if name in {"os.getenv", "os.environ.get"} and args and args[0].literal and CREDENTIAL_ENV.search(args[0].literal):
                return _Value(origins=(_Origin("credential_named_environment", node.lineno, args[0].literal),))
            if name in {"os.path.expanduser", "os.path.abspath"} and args:
                return _Value(path=args[0].path or args[0].literal, path_kind="path_string")
            if name == "os.path.join" and args:
                parts = [value.path or value.literal for value in args]
                return _Value(path=posixpath.join(*parts) if all(part is not None for part in parts) else None, path_kind="path_string")
            if name in {"open", "io.open"} and args:
                mode = args[1].literal if len(args) > 1 else kwargs.get("mode", _Value(literal="r")).literal
                # Preserve a readable file handle path, not its contents.
                return _Value(path=(args[0].path or args[0].literal) if mode is not None and not any(c in mode for c in "wax") else None, path_kind="file")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"read", "read_text", "read_bytes", "readline", "readlines"} and function.path:
                if _credential_file(function.path):
                    return _Value(origins=(_Origin("credential_file", node.lineno, function.path),))
                return _Value()
            if name in {"requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient"}:
                return _Value(symbol=name.split(".")[0] + ".session")
            if _network_sink(name):
                payloads = list(args) + [value for key, value in kwargs.items() if key in PAYLOAD_KEYS or key is None]
                taint = self.combine(payloads)
                if taint.origins:
                    self.finding(node, name, taint.origins)
                return _Value()
            # Request constructors carry content to urlopen, not a send by
            # themselves. Unknown transforms conservatively retain provenance.
            return self.combine([function] + args + list(kwargs.values()))
        if isinstance(node, ast.NamedExpr):
            value = self.expr(node.value, env, depth + 1)
            self.assign(node.target, value, env)
            return value
        return self.combine([self.expr(child, env, depth + 1) for child in ast.iter_child_nodes(node)])

    def assign(self, target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            # Tuple destructuring is conservatively correlated, not element-wise.
            self.limits.add("destructuring_approximation")
            for child in target.elts:
                self.assign(child, value, env)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            self.limits.add("attribute_or_container_write_not_tracked")

    def statements(self, statements, env, depth):
        self.tick(depth)
        for node in statements:
            self.tick(depth)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    env[alias.asname or alias.name.split(".")[0]] = _Value(symbol=alias.name if alias.asname else alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        self.limits.add("wildcard_import_unresolved")
                    else:
                        env[alias.asname or alias.name] = _Value(symbol=(node.module + "." + alias.name) if node.module and node.level == 0 else None)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = self.expr(node.value, env, depth + 1)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if isinstance(node, ast.AugAssign):
                    value = self.combine([self.expr(node.target, env, depth + 1), value])
                for target in targets:
                    self.assign(target, value, env)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                env[node.name] = _Value()
                local = dict(env)
                for parameter in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                    local[parameter.arg] = _Value()
                for parameter in (node.args.vararg, node.args.kwarg):
                    if parameter:
                        local[parameter.arg] = _Value()
                # Python binds assigned/imported names throughout a local scope.
                for child in _scope_nodes(node.body):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                        local[child.id] = _Value()
                self.statements(node.body, local, depth + 1)
            elif isinstance(node, ast.ClassDef):
                env[node.name] = _Value()
                self.statements(node.body, dict(env), depth + 1)
            elif isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try)):
                for name in ("test", "iter"):
                    if hasattr(node, name):
                        self.expr(getattr(node, name), env, depth + 1)
                if hasattr(node, "target"):
                    self.assign(node.target, _Value(), env)
                variants = []
                for block in (getattr(node, "body", []), getattr(node, "orelse", [])):
                    branch = dict(env)
                    self.statements(block, branch, depth + 1)
                    variants.append(branch)
                for handler in getattr(node, "handlers", []):
                    branch = dict(env)
                    self.statements(handler.body, branch, depth + 1)
                    variants.append(branch)
                for key in set().union(*(variant.keys() for variant in variants)):
                    values = [variant.get(key, _Value()) for variant in variants]
                    env[key] = values[0] if all(value == values[0] for value in values) else self.combine(values)
                self.statements(getattr(node, "finalbody", []), env, depth + 1)
                self.limits.add("branch_and_loop_overapproximation")
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    value = self.expr(item.context_expr, env, depth + 1)
                    if item.optional_vars:
                        self.assign(item.optional_vars, value, env)
                self.statements(node.body, env, depth + 1)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    self.assign(target, _Value(), env)
            else:
                for child in ast.iter_child_nodes(node):
                    self.expr(child, env, depth + 1)

    def finding(self, node, sink, origins):
        key = (node.lineno, sink, origins)
        if key in self.finding_keys:
            return
        if len(self.findings) >= MAX_FINDINGS:
            raise _Budget("finding_budget")
        self.finding_keys.add(key)
        sources = [{"kind": origin.kind, "line": origin.line, "path": origin.source} for origin in origins]
        self.findings.append({
            "id": "credential_source_to_network_payload", "category": "sensitive_data", "severity": "high", "tier": "review",
            "description": "A credential-file or credential-named environment read flows into a recognized network request URL or payload in supported Python syntax. Review authorization and destination; execution and malicious intent are not established.",
            "finding_category": "static_data_flow", "subject": "credential_network_flow", "action_state": "declared",
            "disposition": "require_approval", "count": len(origins), "samples": [f"{self.path}:{origin.line} {origin.kind} -> {sink} at line {node.lineno}" for origin in origins],
            "observations": [{"source": self.path, "line": node.lineno, "operation": sink, "sources": sources,
                              "evidence_scope": "conservative_intraprocedural_value_flow", "execution_verified": False}],
            "counts_for_governance": True, "status": "static_flow_observed", "sources": SOURCES,
            "is_actionable": True, "display_kind": "actionable_finding",
        })


def _network_sink(name):
    parts = name.split(".")
    if parts[0] in {"requests", "httpx"} and parts[-1] in NETWORK_METHODS and len(parts) in {2, 3}:
        return True
    return name in {"urllib.request.urlopen", "urllib.request.urlretrieve"}


def _credential_file(path):
    normalized = path.replace("\\", "/").lower().rstrip("/")
    basename = normalized.rsplit("/", 1)[-1]
    return basename in CREDENTIAL_FILES or normalized.endswith(("/.aws/credentials", "/.config/gcloud/application_default_credentials.json"))


def _scope_nodes(statements):
    pending = list(statements)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        pending.extend(ast.iter_child_nodes(node))
