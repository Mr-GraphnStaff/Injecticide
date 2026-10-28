"""Bounded package-local Python effect provenance, without executing package code.

Primary design references: CodeQL Python global data flow and path queries,
https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/
https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/
These motivate explicit argument/return edges, not a claim to implement CodeQL.
Opaque calls retain uncertainty; a function name claiming sanitization is not proof.
"""
from __future__ import annotations

import ast
import hashlib
import posixpath
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

try:
    from .code_security import CREDENTIAL_ENV, PAYLOAD_KEYS, SOURCES, _credential_file, _network_sink
except ImportError:
    from code_security import CREDENTIAL_ENV, PAYLOAD_KEYS, SOURCES, _credential_file, _network_sink

MAX_FILES = 200
MAX_FILE_CHARACTERS = 131072
MAX_TOTAL_CHARACTERS = 2 * 1024 * 1024
MAX_AST_NODES = 20000
MAX_WORK = 200000
MAX_CALL_DEPTH = 8
MAX_CONTEXTS = 256
MAX_ORIGINS = 16
MAX_TRACE = 32
MAX_FINDINGS = 80
MAX_OBSERVATIONS = 300
MAX_LITERAL = 4096
MAX_CONTAINER_ITEMS = 256
UNSET = object()
API_MODULES = {"os", "io", "pathlib", "requests", "httpx", "urllib", "json", "base64", "hashlib"}
PROPAGATORS = {"str", "bytes", "bytearray", "json.dumps", "json.loads", "base64.b64encode", "base64.b64decode"}
PURE_BUILTINS = {"print", "len", "bool", "int", "float", "isinstance", "range"}


@dataclass(frozen=True)
class _Step:
    path: str
    line: int
    kind: str
    operation: str = ""


@dataclass(frozen=True)
class _Taint:
    path: str
    line: int
    kind: str
    trace: tuple
    confirmed: bool = True


@dataclass(frozen=True)
class _Value:
    taints: tuple = ()
    literal: object = UNSET
    api: str | None = None
    module: str | None = None
    function: object = None
    kind: str = "unknown"
    file_path: str | None = None
    reason: str | None = None
    items: tuple = ()


@dataclass
class _Function:
    path: str
    node: object
    defaults: dict
    invoked: bool = False


class _Budget(Exception):
    pass


def _safe_path(path):
    return isinstance(path, str) and bool(path) and not path.startswith(("/", "\\")) and ".." not in path.replace("\\", "/").split("/")


def analyze_package_effects(text_sources, inventory=None):
    """Return static source/call/return/sink witnesses and explicit boundaries.

    ``text_sources`` contains path/text dictionaries. Only original .py/.pyw
    sources are analyzed; unsupported languages are outside this engine's scope.
    File inventory supplies skill and nested-container identities, never imports
    from the host. No files outside these supplied values are read by analysis.
    """
    engine = _Engine(text_sources, inventory or [])
    try:
        engine.run()
    except (_Budget, RecursionError, MemoryError) as exc:
        engine.limit(str(exc) if isinstance(exc, _Budget) else "analysis_resource_budget")
    return engine.result()


class _Engine:
    def __init__(self, sources, inventory):
        self.sources = {}
        self.trees = {}
        self.modules = {}
        self.module_states = {}
        self.functions = []
        self.stack = []
        self.observations = []
        self.findings = {}
        self.observation_keys = set()
        self.limits = []
        self.limit_keys = set()
        self.sink_sites = {}
        self.pruned = []
        self.work = 0
        self.contexts = 0
        self.finding_count = 0
        self.invalidated_apis = set()
        self.python_files = 0
        self.characters = 0
        self.inventory = {item.get("path") for item in inventory if isinstance(item, dict) and isinstance(item.get("path"), str)}
        self.skill_roots = set()
        for item in sources:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                continue
            path, text = item["path"], item.get("text")
            self.inventory.add(path)
            if posixpath.basename(path).lower() == "skill.md":
                self.skill_roots.add(posixpath.dirname(path))
            if not path.lower().endswith((".py", ".pyw")) or not isinstance(text, str):
                continue
            self.python_files += 1
            if not _safe_path(path):
                self.limit("invalid_source_identity", path)
                continue
            if path in self.sources:
                self.limit("duplicate_source_identity", path)
                self.sources[path] = None
                continue
            if len(self.sources) >= MAX_FILES or self.characters + len(text) > MAX_TOTAL_CHARACTERS:
                self.limit("package_source_budget", path)
                continue
            if len(text) > MAX_FILE_CHARACTERS:
                self.limit("file_source_budget", path)
                continue
            self.sources[path] = text
            self.characters += len(text)
        for path in self.inventory:
            if posixpath.basename(path).lower() == "skill.md":
                self.skill_roots.add(posixpath.dirname(path))

    def tick(self):
        self.work += 1
        if self.work > MAX_WORK:
            raise _Budget("package_work_budget")

    def limit(self, kind, path=None, line=None):
        key = kind, path, line
        if key not in self.limit_keys:
            self.limit_keys.add(key)
            self.limits.append({"kind": kind, **({"path": path} if path else {}), **({"line": line} if line else {})})

    def boundary(self, path, line, reason, values=()):
        self.limit(reason, path, line)
        value = self.combine(values)
        self.observe({"kind": "unknown_boundary", "status": "unknown", "path": path, "line": line,
                      "reason": reason, "execution_verified": False,
                      "trace": [self.step_dict(t.trace[-1]) for t in value.taints if t.trace]})
        return replace(value, taints=tuple(replace(t, confirmed=False) for t in value.taints), reason=reason)

    def observe(self, observation):
        key = repr(observation)
        if key in self.observation_keys:
            return
        if len(self.observations) >= MAX_OBSERVATIONS:
            raise _Budget("package_observation_budget")
        self.observation_keys.add(key)
        observation["id"] = hashlib.sha256(key.encode()).hexdigest()[:20]
        self.observations.append(observation)

    @staticmethod
    def step_dict(step):
        return {"path": step.path, "line": step.line, "kind": step.kind, "operation": step.operation}

    def combine(self, values):
        values = list(values)
        taints = []
        for value in values:
            for taint in value.taints:
                if taint not in taints:
                    taints.append(taint)
                    if len(taints) > MAX_ORIGINS:
                        raise _Budget("package_origin_budget")
        return _Value(taints=tuple(taints), reason="unresolved_value" if any(v.reason for v in values) else None)

    def traced(self, value, step):
        taints = []
        for taint in value.taints:
            if len(taint.trace) >= MAX_TRACE:
                raise _Budget("package_trace_budget")
            taints.append(replace(taint, trace=taint.trace + (step,)))
        return replace(value, taints=tuple(taints))

    def origin(self, path, line, kind):
        return _Value(taints=(_Taint(path, line, kind, (_Step(path, line, "source", kind),)),), kind="string")

    def run(self):
        for path, text in self.sources.items():
            self.tick()
            if text is None:
                continue
            try:
                tree = ast.parse(text)
                for index, _ in enumerate(ast.walk(tree)):
                    self.tick()
                    if index >= MAX_AST_NODES:
                        raise _Budget("file_ast_budget")
                self.trees[path] = tree
            except _Budget as exc:
                if str(exc) != "file_ast_budget":
                    raise
                self.limit("file_ast_budget", path)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                self.limit("python_parse_unavailable", path)
        for path in self.trees:
            self.module(path)
        # Also inspect exported bodies without inventing a caller or parameter
        # source. Internal source/sink syntax may exist in an uninvoked function.
        for function in self.functions[:MAX_CONTEXTS]:
            if not function.invoked:
                self.call_function(function, [], {}, function.path, function.node.lineno, definition_scan=True)

    def module(self, path):
        if self.module_states.get(path) == "analyzing":
            self.limit("circular_import_boundary", path)
            return self.modules[path]
        if path in self.modules:
            return self.modules[path]
        env = {}
        self.modules[path] = env
        self.module_states[path] = "analyzing"
        self.block(self.trees[path].body, env, path, 0)
        self.module_states[path] = "analyzed"
        return env

    def root(self, path):
        boundary = path.rsplit("!/", 1)[0] + "!/" if "!/" in path else ""
        roots = [r for r in self.skill_roots if (not r or path.startswith(r.rstrip("/") + "/")) and (not boundary or r.startswith(boundary) or r + "/" == boundary)]
        return max(roots, key=len) if roots else boundary.rstrip("/")

    def resolve(self, source, name, level=0):
        root = self.root(source)
        parent = posixpath.dirname(source)
        if level:
            base = parent
            for _ in range(level - 1):
                base = posixpath.dirname(base)
            bases = [base]
        else:
            bases = list(dict.fromkeys([parent, root]))
        relative = name.replace(".", "/")
        candidates = set()
        for base in bases:
            stem = posixpath.normpath(posixpath.join(base, relative))
            for path in (stem + ".py", posixpath.join(stem, "__init__.py")):
                if root and not path.startswith(root.rstrip("/") + "/"):
                    continue
                if path in self.inventory:
                    candidates.add(path)
        return sorted(candidates)

    def imported(self, path, module, level, line):
        candidates = self.resolve(path, module, level)
        if len(candidates) > 1:
            return self.boundary(path, line, "ambiguous_local_import")
        if candidates:
            candidate = candidates[0]
            if candidate not in self.trees:
                return self.boundary(path, line, "local_module_source_unavailable")
            self.module(candidate)
            return _Value(module=candidate, kind="module")
        if not level and module.split(".")[0] in API_MODULES:
            return _Value(api=module, kind="api")
        return self.boundary(path, line, "unresolved_import")

    def expr(self, node, env, path, depth):
        self.tick()
        if node is None:
            return _Value(literal=None, kind="constant")
        line = getattr(node, "lineno", 1)
        if isinstance(node, ast.Constant):
            literal = node.value
            if isinstance(literal, str) and len(literal) > MAX_LITERAL:
                return self.boundary(path, line, "literal_character_budget")
            return _Value(literal=literal, kind="string" if isinstance(literal, str) else "constant")
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            if node.id in PURE_BUILTINS | PROPAGATORS | {"open"}:
                return _Value(api=node.id, kind="api")
            return _Value(reason="unbound_symbol")
        if isinstance(node, ast.Attribute):
            owner = self.expr(node.value, env, path, depth)
            if owner.module:
                return self.modules[owner.module].get(node.attr, _Value(reason="module_member_unresolved"))
            if owner.file_path and owner.kind in {"path", "pure_path"} and node.attr == "parent":
                return replace(owner, file_path=posixpath.dirname(owner.file_path) or ".", api=None)
            if owner.file_path and owner.kind in {"path", "pure_path"} and node.attr == "name":
                return _Value(literal=posixpath.basename(owner.file_path), kind="string")
            if owner.kind in {"path", "pure_path", "file"} and node.attr not in ({"read_text", "read_bytes"} if owner.kind == "path" else {"read", "readline", "readlines"} if owner.kind == "file" else set()):
                return replace(owner, file_path=None, kind="unknown", reason="unsupported_path_or_file_attribute", api=None)
            return replace(owner, api=owner.api + "." + node.attr if owner.api else None,
                           function=None, module=None)
        if isinstance(node, ast.Subscript):
            owner, key = self.expr(node.value, env, path, depth), self.expr(node.slice, env, path, depth)
            if owner.api == "os.environ" and isinstance(key.literal, str) and CREDENTIAL_ENV.search(key.literal):
                return self.origin(path, line, "credential_named_environment")
            if owner.kind == "dict" and key.literal is not UNSET and not owner.reason:
                selected = dict(owner.items).get(key.literal)
                return selected if selected is not None else self.boundary(path, line, "dictionary_key_not_present", [owner])
            if owner.kind in {"list", "tuple"} and type(key.literal) is int and not owner.reason:
                if -len(owner.items) <= key.literal < len(owner.items):
                    return owner.items[key.literal]
                return self.boundary(path, line, "sequence_index_not_present", [owner])
            if owner.kind in {"string", "bytes"}:
                return self.combine([owner])
            return self.boundary(path, line, "container_selection_not_resolved", [owner, key])
        if isinstance(node, ast.BinOp):
            left, right = self.expr(node.left, env, path, depth), self.expr(node.right, env, path, depth)
            joined = self.combine([left, right])
            if isinstance(node.op, ast.Div) and (left.kind in {"path", "pure_path"} or right.kind in {"path", "pure_path"}) and isinstance(left.file_path or left.literal, str) and isinstance(right.file_path or right.literal, str):
                return replace(joined, file_path=posixpath.join(left.file_path or left.literal, right.file_path or right.literal), kind=left.kind if left.kind in {"path", "pure_path"} else right.kind)
            if isinstance(node.op, ast.Add) and isinstance(left.literal, str) and isinstance(right.literal, str):
                if len(left.literal) + len(right.literal) > MAX_LITERAL:
                    return self.boundary(path, line, "literal_character_budget", [joined])
                return replace(joined, literal=left.literal + right.literal, kind="string")
            return joined
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.expr(node.operand, env, path, depth)
            return _Value(literal=not value.literal, kind="constant") if value.literal is not UNSET else value
        if isinstance(node, ast.IfExp):
            condition = self.expr(node.test, env, path, depth)
            if condition.literal is not UNSET and isinstance(condition.literal, (bool, int, str, type(None))):
                return self.expr(node.body if condition.literal else node.orelse, env, path, depth)
            left, right = self.expr(node.body, env, path, depth), self.expr(node.orelse, env, path, depth)
            if left == right:
                return left
            self.limit("conditional_expression_not_proven", path, line)
            return self.combine([left, right])
        if isinstance(node, ast.NamedExpr):
            value = self.expr(node.value, env, path, depth)
            self.assign(node.target, value, env, path)
            return value
        if isinstance(node, ast.Call):
            function = self.expr(node.func, env, path, depth)
            args = [self.expr(arg, env, path, depth) for arg in node.args]
            kwargs = {arg.arg: self.expr(arg.value, env, path, depth) for arg in node.keywords}
            if any(isinstance(arg, ast.Starred) for arg in node.args) or None in kwargs:
                return self.boundary(path, line, "dynamic_call_arguments", args + list(kwargs.values()))
            if function.function:
                return self.call_function(function.function, args, kwargs, path, line)
            name = function.api or ""
            if any(name == invalidated or name.startswith(invalidated + ".") for invalidated in self.invalidated_apis):
                return self.boundary(path, line, "mutated_api_binding", [function] + args + list(kwargs.values()))
            if name in {"os.getenv", "os.environ.get"} and args and isinstance(args[0].literal, str) and CREDENTIAL_ENV.search(args[0].literal):
                return self.origin(path, line, "credential_named_environment")
            if name in {"os.getenv", "os.environ.get"}:
                return _Value(kind="string") if args and isinstance(args[0].literal, str) else self.boundary(path, line, "dynamic_environment_key")
            if name in {"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath", "pathlib.PurePath", "pathlib.PurePosixPath", "pathlib.PureWindowsPath", "os.path.expanduser", "os.path.abspath"}:
                value = args[0] if args else _Value()
                kind = "pure_path" if name.startswith("pathlib.Pure") else "string" if name.startswith("os.path.") else "path"
                return replace(value, file_path=value.file_path or (value.literal if isinstance(value.literal, str) else None), kind=kind)
            if name in {"pathlib.Path.home", "pathlib.PosixPath.home"}:
                return _Value(file_path="~", kind="path")
            if name == "os.path.join" and all(isinstance(a.literal, str) for a in args):
                return _Value(file_path=posixpath.join(*(a.literal for a in args)), kind="string")
            if name in {"open", "io.open"}:
                value = args[0] if args else _Value()
                mode = args[1].literal if len(args) > 1 else kwargs.get("mode", _Value(literal="r")).literal
                if isinstance(mode, str) and not any(c in mode for c in "wax"):
                    return replace(value, file_path=value.file_path or (value.literal if isinstance(value.literal, str) else None), kind="file")
                return _Value(kind="file")
            if isinstance(node.func, ast.Attribute) and function.file_path and node.func.attr in ({"read_text", "read_bytes"} if function.kind == "path" else {"read", "readline", "readlines"} if function.kind == "file" else set()):
                return self.origin(path, line, "credential_file") if _credential_file(function.file_path) else _Value(kind="string")
            if name in {"requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient"}:
                return _Value(api=name.split(".")[0] + ".session", kind="api")
            if _known_network_sink(name):
                self.sink(path, line, name, args, kwargs)
                return _Value(kind="network_response")
            if name == "urllib.request.Request":
                return replace(self.combine(args[:2] + [v for k, v in kwargs.items() if k in {"url", "data"}]), kind="request")
            if name in PROPAGATORS:
                value = self.combine(args + list(kwargs.values()))
                return replace(self.traced(value, _Step(path, line, "call", name)), kind="string")
            if name in PURE_BUILTINS:
                # Numeric/Boolean/length transformations are not declassification.
                # Only print's return value is known independent of its arguments.
                return _Value(literal=None, kind="constant") if name == "print" else self.traced(self.combine(args + list(kwargs.values())), _Step(path, line, "call", name))
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"encode", "decode", "strip", "lstrip", "rstrip", "replace", "format", "join"} and function.kind == "string":
                return replace(self.combine([function] + args + list(kwargs.values())), kind="string")
            return self.boundary(path, line, function.reason or "opaque_call", [function] + args + list(kwargs.values()))
        if isinstance(node, ast.Dict):
            pairs, values, resolved = [], [], True
            for key_node, value_node in zip(node.keys, node.values):
                key = self.expr(key_node, env, path, depth) if key_node is not None else _Value()
                value = self.expr(value_node, env, path, depth)
                values.extend([key, value])
                if key.literal is UNSET or not isinstance(key.literal, (str, int, float, bool, type(None))) or key_node is None:
                    resolved = False
                else:
                    pairs.append((key.literal, value))
            if len(pairs) > MAX_CONTAINER_ITEMS:
                self.limit("container_shape_budget", path, line)
                resolved = False
            return replace(self.combine(values), kind="dict", items=tuple(pairs[:MAX_CONTAINER_ITEMS]), reason=None if resolved else "dictionary_shape_unresolved")
        if isinstance(node, (ast.List, ast.Tuple)):
            values = [self.expr(value, env, path, depth) for value in node.elts]
            oversized = len(values) > MAX_CONTAINER_ITEMS
            if oversized:
                self.limit("container_shape_budget", path, line)
            return replace(self.combine(values), kind="list" if isinstance(node, ast.List) else "tuple", items=tuple(values[:MAX_CONTAINER_ITEMS]), reason="sequence_shape_unresolved" if oversized else None)
        if isinstance(node, (ast.Set, ast.JoinedStr)):
            return self.combine([self.expr(child, env, path, depth) for child in ast.iter_child_nodes(node)])
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp, ast.Await, ast.Yield, ast.YieldFrom)):
            return self.boundary(path, line, "unsupported_expression_dispatch")
        return self.combine([self.expr(child, env, path, depth) for child in ast.iter_child_nodes(node)])

    def assign(self, target, value, env, path):
        if isinstance(target, ast.Name):
            env[target.id] = value
        else:
            line = getattr(target, "lineno", 1)
            if isinstance(target, (ast.Attribute, ast.Subscript)):
                owner = self.expr(target.value, env, path, len(self.stack))
                if owner.api:
                    self.invalidated_apis.add(owner.api + "." + target.attr if isinstance(target, ast.Attribute) else owner.api)
                if isinstance(target.value, ast.Name):
                    combined = self.boundary(path, line, "container_or_attribute_write", [owner, value])
                    env[target.value.id] = combined
                    return
            self.boundary(path, line, "container_or_destructuring_write", [value])

    def call_function(self, function, args, kwargs, call_path, call_line, definition_scan=False):
        key = function.path, function.node.lineno
        if key in self.stack:
            return self.boundary(call_path, call_line, "recursive_call_boundary", args + list(kwargs.values()))
        if len(self.stack) >= MAX_CALL_DEPTH or self.contexts >= MAX_CONTEXTS:
            return self.boundary(call_path, call_line, "call_context_budget", args + list(kwargs.values()))
        node = function.node
        if node.args.vararg or node.args.kwarg or isinstance(node, ast.AsyncFunctionDef):
            return self.boundary(call_path, call_line, "variadic_or_async_function_boundary", args + list(kwargs.values()))
        parameters = node.args.posonlyargs + node.args.args
        all_parameters = parameters + node.args.kwonlyargs
        if len(args) > len(parameters) or any(k not in {p.arg for p in all_parameters} for k in kwargs):
            return self.boundary(call_path, call_line, "argument_binding_unresolved", args + list(kwargs.values()))
        if any(p.arg in kwargs for p in node.args.posonlyargs):
            return self.boundary(call_path, call_line, "positional_only_argument_binding", args + list(kwargs.values()))
        local = dict(self.modules[function.path])
        for child in _scope_nodes(node.body):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                local[child.id] = _Value(reason="local_binding_uninitialized")
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                local[child.name] = _Value(reason="local_binding_uninitialized")
            if isinstance(child, ast.Import):
                for alias in child.names:
                    local[alias.asname or alias.name.split(".")[0]] = _Value(reason="local_binding_uninitialized")
            if isinstance(child, ast.ImportFrom):
                for alias in child.names:
                    if alias.name != "*":
                        local[alias.asname or alias.name] = _Value(reason="local_binding_uninitialized")
            if isinstance(child, (ast.Global, ast.Nonlocal)):
                return self.boundary(call_path, call_line, "nonlocal_mutation_boundary", args + list(kwargs.values()))
        assigned = {}
        for index, parameter in enumerate(all_parameters):
            if index < len(args):
                if parameter.arg in kwargs:
                    return self.boundary(call_path, call_line, "argument_binding_unresolved", args + list(kwargs.values()))
                value = args[index]
            else:
                value = kwargs.get(parameter.arg, function.defaults.get(parameter.arg, _Value(reason="unbound_parameter")))
            if value.reason == "unbound_parameter" and not definition_scan:
                return self.boundary(call_path, call_line, "missing_function_argument", args + list(kwargs.values()))
            value = self.traced(value, _Step(call_path, call_line, "argument", "local_parameter_binding"))
            assigned[parameter.arg] = value
        local.update(assigned)
        self.contexts += 1
        function.invoked = True
        self.stack.append(key)
        try:
            returned, falls_through = self.block(node.body, local, function.path, len(self.stack))
        finally:
            self.stack.pop()
        result = self.combine(returned + ([_Value(literal=None, kind="constant")] if falls_through else []))
        if len(returned) == 1 and not falls_through:
            result = returned[0]
        return self.traced(result, _Step(call_path, call_line, "call", "resolved_local_function"))

    def block(self, statements, env, path, depth):
        returns = []
        for node in statements:
            self.tick()
            line = getattr(node, "lineno", 1)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported = self.imported(path, alias.name, 0, line)
                    if "." in alias.name and not alias.asname and imported.module:
                        imported = self.boundary(path, line, "dotted_import_binding_unresolved")
                    elif "." in alias.name and not alias.asname and imported.api:
                        imported = replace(imported, api=alias.name.split(".")[0])
                    env[alias.asname or alias.name.split(".")[0]] = imported
            elif isinstance(node, ast.ImportFrom):
                imported = self.imported(path, node.module or "", node.level, line)
                for alias in node.names:
                    if alias.name == "*":
                        self.boundary(path, line, "wildcard_import_boundary")
                    elif imported.module:
                        env[alias.asname or alias.name] = self.modules[imported.module].get(alias.name, _Value(reason="imported_member_unresolved"))
                    else:
                        env[alias.asname or alias.name] = _Value(api=imported.api + "." + alias.name, kind="api") if imported.api else imported
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if depth or node.decorator_list:
                    env[node.name] = self.boundary(path, line, "closure_or_decorated_function_boundary")
                    continue
                positional = node.args.posonlyargs + node.args.args
                defaults = {parameter.arg: self.expr(value, env, path, depth) for parameter, value in zip(positional[len(positional) - len(node.args.defaults):], node.args.defaults)}
                defaults.update({p.arg: self.expr(v, env, path, depth) for p, v in zip(node.args.kwonlyargs, node.args.kw_defaults) if v is not None})
                function = _Function(path, node, defaults)
                self.functions.append(function)
                env[node.name] = _Value(function=function, kind="function")
            elif isinstance(node, ast.ClassDef):
                env[node.name] = self.boundary(path, line, "class_dispatch_boundary")
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = self.expr(node.value, env, path, depth)
                if isinstance(node, ast.AugAssign):
                    value = self.combine([self.expr(node.target, env, path, depth), value])
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    self.assign(target, value, env, path)
            elif isinstance(node, ast.Expr):
                self.expr(node.value, env, path, depth)
            elif isinstance(node, ast.Return):
                value = self.expr(node.value, env, path, depth)
                returns.append(self.traced(value, _Step(path, line, "return")))
                return returns, False
            elif isinstance(node, ast.If):
                condition = self.expr(node.test, env, path, depth)
                if condition.literal is not UNSET and isinstance(condition.literal, (bool, int, str, type(None))):
                    chosen, skipped = (node.body, node.orelse) if condition.literal else (node.orelse, node.body)
                    if isinstance(node.test, ast.Constant) and skipped:
                        self.pruned.append({"path": path, "start_line": skipped[0].lineno, "end_line": getattr(skipped[-1], "end_lineno", skipped[-1].lineno), "reason": "literal_constant_guard"})
                    found, alive = self.block(chosen, env, path, depth)
                    returns.extend(found)
                    if not alive:
                        return returns, False
                else:
                    self.limit("conditional_path_not_proven", path, line)
                    variants, live = [], False
                    for branch in (node.body, node.orelse):
                        alternative = dict(env)
                        found, alive = self.block(branch, alternative, path, depth)
                        returns.extend(found)
                        if alive:
                            variants.append(alternative)
                            live = True
                    self.merge(env, variants)
                    if not live:
                        return returns, False
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    value = self.expr(item.context_expr, env, path, depth)
                    if item.optional_vars:
                        self.assign(item.optional_vars, value, env, path)
                found, alive = self.block(node.body, env, path, depth)
                returns.extend(found)
                if not alive:
                    return returns, False
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.Try)):
                self.limit("loop_or_exception_control_boundary", path, line)
                branches = [node.body, getattr(node, "orelse", [])] + [h.body for h in getattr(node, "handlers", [])]
                variants = [dict(env)]
                for branch in branches:
                    alternative = dict(env)
                    found, _ = self.block(branch, alternative, path, depth)
                    returns.extend(found)
                    variants.append(alternative)
                self.merge(env, variants)
                found, _ = self.block(getattr(node, "finalbody", []), env, path, depth)
                returns.extend(found)
            elif isinstance(node, (ast.Pass, ast.ImportFrom)):
                continue
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    self.assign(target, _Value(reason="deleted_binding"), env, path)
            else:
                self.boundary(path, line, "unsupported_statement")
        return returns, True

    def merge(self, env, variants):
        if not variants:
            return
        for key in set().union(*(v.keys() for v in variants)):
            values = [v.get(key, _Value()) for v in variants]
            env[key] = values[0] if all(v == values[0] for v in values) else self.combine(values)

    def sink(self, path, line, operation, args, kwargs):
        payloads = [("positional", v) for v in args] + [(k, v) for k, v in kwargs.items() if k in PAYLOAD_KEYS]
        site = self.sink_sites.setdefault((path, line, operation), {"path": path, "line": line, "operation": operation, "outcomes": set()})
        taints = [(channel, taint) for channel, value in payloads for taint in value.taints]
        unresolved = any(v.reason for _, v in payloads)
        site["outcomes"].add("source_flow" if any(t.confirmed for _, t in taints) else "unknown" if taints or unresolved else "no_source_flow")
        if unresolved:
            self.boundary(path, line, "unresolved_payload_value", [v for _, v in payloads])
        for channel, taint in taints:
            if not taint.confirmed:
                self.boundary(path, line, "opaque_provenance_at_sink", [_Value(taints=(taint,))])
                continue
            trace = self.traced(_Value(taints=(taint,)), _Step(path, line, "sink", operation)).taints[0].trace
            witness = [self.step_dict(step) for step in trace]
            observation = {"kind": "credential_network_flow", "status": "static_witness",
                           "source": {"path": taint.path, "line": taint.line, "kind": taint.kind},
                           "sink": {"path": path, "line": line, "operation": operation, "channel": channel},
                           "trace": witness, "execution_verified": False}
            self.observe(observation)
            key = taint.path, taint.line, path, line, operation, channel
            flow_id = hashlib.sha256(repr(key).encode()).hexdigest()[:20]
            if any(f.get("flow_id") == flow_id for f in self.findings.get(path, [])):
                continue
            if self.finding_count >= MAX_FINDINGS:
                raise _Budget("package_finding_budget")
            self.finding_count += 1
            self.findings.setdefault(path, []).append({
                "id": "credential_source_to_network_payload", "category": "sensitive_data", "severity": "high", "tier": "review",
                "description": "A credential source reaches a recognized network URL or payload through resolved package-local Python calls. This is a static witness, not runtime execution, authorization or malicious-intent proof.",
                "finding_category": "static_data_flow", "subject": "credential_network_flow", "action_state": "declared", "disposition": "require_approval",
                "count": 1, "flow_id": flow_id, "samples": [f"{taint.path}:{taint.line} -> {path}:{line} ({operation})"],
                "observations": [{"source": path, "line": line, "operation": operation,
                                  "sources": [{"kind": taint.kind, "line": taint.line, "path": taint.path}],
                                  "witness_trace": witness, "flow_id": flow_id, "evidence_scope": "package_interprocedural", "execution_verified": False}],
                "counts_for_governance": True, "status": "static_flow_observed", "sources": SOURCES,
                "is_actionable": True, "display_kind": "actionable_finding"})

    def result(self):
        sites = [{**{k: v for k, v in site.items() if k != "outcomes"}, "outcome": "source_flow" if "source_flow" in site["outcomes"] else "unknown" if "unknown" in site["outcomes"] else "no_source_flow"} for site in self.sink_sites.values()]
        return {"schema_version": 1, "status": "partial" if self.limits else "complete_supported_syntax" if self.trees else "not_performed",
                "runtime_verified": False, "observations": self.observations, "findings_by_path": self.findings,
                "coverage": {"supported_languages": ["python"], "files_supplied": self.python_files, "files_analyzed": len(self.trees),
                             "contexts_analyzed": self.contexts, "work_units": self.work, "source_characters": self.characters,
                             "modeled_sink_sites": sites, "pruned_ranges": self.pruned,
                             "scope": "Bounded package-local Python argument/return/effect provenance. Static witnesses do not establish reachability, runtime feasibility, arbitrary-language behavior or authorization."},
                "limits": self.limits}


def _scope_nodes(statements):
    pending = list(statements)
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(ast.iter_child_nodes(node))


def _known_network_sink(name):
    parts = name.split(".")
    return _network_sink(name) and (len(parts) == 2 or parts[:2] in (["requests", "session"], ["httpx", "session"]) or name in {"urllib.request.urlopen", "urllib.request.urlretrieve"})
