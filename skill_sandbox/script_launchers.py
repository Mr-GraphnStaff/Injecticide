"""Bounded declaration parsers; never execute commands or resolve dependencies.

Recognized launcher grammar comes from these primary references (reviewed
2026-10-28), not from shell execution or inferred command semantics:
https://docs.astral.sh/uv/guides/scripts/
https://docs.astral.sh/uv/reference/cli/#uv-run
https://pipx.pypa.io/stable/reference/examples.html#run
https://pipx.pypa.io/stable/how-to/run-scripts.html
https://docs.npmjs.com/cli/v11/commands/npx/
https://docs.deno.com/runtime/reference/cli/run/
https://bun.sh/docs/runtime
https://docs.python.org/3/using/cmdline.html
https://peps.python.org/pep-0723/

This is a documented subset. Unknown options, dynamic operands and unsupported
forms stay unknown. An argv operand after the target is never another script.
"""
from __future__ import annotations

import io
import re
import shlex
import tokenize

try:
    import tomllib
except ImportError:  # Python 3.10 remains supported without a new dependency.
    tomllib = None
try:
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
except ImportError:
    Requirement = SpecifierSet = None

MAX_COMMAND_CHARACTERS = 8192
MAX_COMMAND_TOKENS = 128
MAX_METADATA_CHARACTERS = 65536
MAX_METADATA_SOURCE = 131072
MAX_METADATA_TOKENS = 30000
MAX_DEPENDENCIES = 100
MAX_DECLARATION_CHARACTERS = 2048
LAUNCHER = re.compile(r"^(?:python(?:3(?:\.\d+)?)?(?:\.exe)?|bash|sh|zsh|fish|node|nodejs|pwsh|powershell|ruby|perl|php|lua|Rscript|groovy|cscript|wscript|cmd(?:\.exe)?|uv|uvx|pipx|npx|npm|deno|bun)$", re.I)
COMMAND_START = re.compile(r"(?:^[ \t]*(?:\$[ \t]+)?|[;&|][ \t]*|`)"
                           r"(?P<command>(?:python(?:3(?:\.\d+)?)?(?:\.exe)?|bash|sh|zsh|fish|node|nodejs|pwsh|powershell|ruby|perl|php|lua|Rscript|groovy|cscript|wscript|cmd(?:\.exe)?|uv|uvx|pipx|npx|npm|deno|bun)[ \t]+[^`\n]+)", re.I | re.M)
SCRIPT_SUFFIX = re.compile(r"\.(?:py|pyw|js|mjs|cjs|jsx|ts|tsx|sh|bash|ps1|cmd|bat|rb|pl|php|lua|r)$", re.I)
DYNAMIC = re.compile(r"\$|\{\{|[\*?]")
DYNAMIC_VALUE = re.compile(r"\$|\{\{")


def _result(launcher, **values):
    return {"launcher": launcher, "status": "recognized_static_syntax", "script": None,
            "package_declarations": [], "execution_verified": False, **values}


def _unknown(result, reason):
    return {**result, "status": "unknown", "reason": reason, "verification": "STATUS: UNKNOWN — UNVERIFIED"}


def parse_script_command(command):
    """Return recognized target/dependency declarations, or explicit unknown.

    Only scanner input data is parsed. No shell expansion, environment lookup,
    file existence lookup, downloads, imports or package-manager calls occur.
    """
    if len(command) > MAX_COMMAND_CHARACTERS:
        return _unknown(_result("unknown"), "command_character_budget")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return _unknown(_result("unknown"), "command_tokenization_unavailable")
    if not tokens or not LAUNCHER.fullmatch(tokens[0]):
        return None
    result = _result(tokens[0].lower())
    if len(tokens) > MAX_COMMAND_TOKENS:
        return _unknown(result, "command_token_budget")
    if any(token in {";", "&&", "||", "|", "&", ">", "<"} for token in tokens):
        # Independent shell segments are handled by the line scanner; do not
        # pretend a shell expression is one argv list.
        return _unknown(result, "shell_expression_not_interpreted")
    launcher, args = result["launcher"], tokens[1:]
    option_values, option_flags = {}, set()

    def options(arguments, flags=(), values=(), dependencies=()):
        index = 0
        while index < len(arguments) and arguments[index].startswith("-"):
            token = arguments[index]
            if token == "--":
                return arguments[index + 1:], None
            name, equals, value = token.partition("=")
            if name in flags and not equals:
                option_flags.add(name)
                index += 1
                continue
            if name in values or name in dependencies:
                if not equals:
                    index += 1
                    if index >= len(arguments):
                        return [], "missing_option_value"
                    value = arguments[index]
                if not value or value.startswith("-") or DYNAMIC_VALUE.search(value):
                    return [], "dynamic_or_empty_option_value"
                option_values[name] = value
                if name in dependencies:
                    result["package_declarations"].append({"kind": "launcher_dependency", "value": value})
                index += 1
                continue
            return [], "unsupported_launcher_option"
        return arguments[index:], None

    def target(arguments, *, allow_any_file=False):
        if not arguments:
            return _unknown(result, "missing_target")
        operand = arguments[0]
        if operand == "-":
            return _unknown(result, "stdin_script_not_available")
        if operand.startswith(("http://", "https://")):
            if launcher not in {"uv", "pipx", "deno"}:
                return _unknown(result, "remote_script_operand_not_supported_by_launcher")
            if DYNAMIC_VALUE.search(operand):
                return _unknown(result, "dynamic_target")
            return {**result, "external_script": operand}
        if DYNAMIC.search(operand):
            return _unknown(result, "dynamic_target")
        if SCRIPT_SUFFIX.search(operand) or allow_any_file:
            return {**result, "script": operand}
        return _unknown(result, "target_not_recognized_as_local_script")

    def interpreter(name, arguments):
        if name.startswith("python"):
            flags, values = {"-u", "-B", "-E", "-I", "-s", "-S", "-O", "-OO"}, {"-W", "-X"}
            if arguments[:1] in (["-m"], ["-c"]):
                return _unknown(result, "module_or_inline_code_not_resolved")
        elif name in {"pwsh", "powershell"}:
            flags, values = {"-NoProfile", "-NonInteractive", "-File"}, set()
            if arguments and arguments[0].casefold() == "-file":
                return target(arguments[1:], allow_any_file=True)
        elif name in {"bash", "sh", "zsh"}:
            flags, values = {"-e", "-u", "-x", "-eu", "-eux"}, set()
        elif name in {"node", "nodejs"}:
            flags, values = {"--no-warnings", "--enable-source-maps"}, set()
        elif name in {"cmd", "cmd.exe"}:
            if arguments and arguments[0].casefold() == "/c" and len(arguments) > 1 and re.search(r"\.(?:cmd|bat)$", arguments[1], re.I):
                return target(arguments[1:])
            return _unknown(result, "cmd_shell_expression_not_interpreted")
        elif name in {"cscript", "wscript"}:
            if arguments and arguments[0].casefold() == "//nologo":
                arguments = arguments[1:]
            if arguments and arguments[0].startswith("//"):
                return _unknown(result, "unsupported_launcher_option")
            flags, values = set(), set()
        else:
            flags, values = set(), set()
        rest, reason = options(arguments, flags, values)
        if reason:
            return _unknown(result, reason)
        if name in {"pwsh", "powershell"} and rest and rest[0].casefold() == "-file":
            rest = rest[1:]
        return target(rest, allow_any_file=True)

    if launcher == "uv":
        if not args or args[0] != "run":
            return _unknown(result, "unsupported_uv_subcommand")
        args, reason = options(args[1:], {"--no-project", "--no-sync", "--frozen", "--locked", "--offline", "--isolated", "--no-config", "--script"},
                               {"--python", "-p"}, {"--with", "-w", "--with-editable"})
        if reason:
            return _unknown(result, reason)
        if args and LAUNCHER.fullmatch(args[0]) and args[0] not in {"uv", "uvx", "pipx", "npx", "npm", "bun", "deno"}:
            return interpreter(args[0], args[1:])
        return target(args)
    if launcher == "pipx":
        if not args or args[0] != "run":
            return _unknown(result, "unsupported_pipx_subcommand")
        args = args[1:]
        args, reason = options(args, {"--path", "--no-cache"}, {"--spec", "--python"})
        if reason:
            return _unknown(result, reason)
        if not args:
            return _unknown(result, "missing_target")
        force_path = "--path" in option_flags
        spec = option_values.get("--spec")
        if force_path and spec:
            return _unknown(result, "conflicting_pipx_target_options")
        if spec:
            result["package_declarations"].append({"kind": "pipx_package", "value": spec})
            return result
        if force_path or args[0].startswith(("./", "../", "http://", "https://")) or "/" in args[0]:
            return target(args)
        if SCRIPT_SUFFIX.search(args[0]):
            return _unknown({**result, "script_candidate": args[0]}, "pipx_file_or_package_ambiguous")
        if DYNAMIC.search(args[0]):
            return _unknown(result, "dynamic_package_declaration")
        result["package_declarations"].append({"kind": "pipx_package", "value": args[0]})
        return result
    if launcher in {"npx", "npm", "uvx"}:
        if launcher == "npm":
            if not args or args[0] not in {"exec", "x"}:
                return _unknown(result, "unsupported_npm_subcommand")
            args = args[1:]
        dependency_options = {"--package", "-p"} if launcher != "uvx" else {"--from"}
        if launcher == "npm":
            dependency_options = {"--package"}
        args, reason = options(args, {"--yes", "-y", "--no", "--offline", "--no-install"}, dependencies=dependency_options)
        if reason:
            return _unknown(result, reason)
        if not args:
            return _unknown(result, "missing_target")
        if result["package_declarations"]:
            if LAUNCHER.fullmatch(args[0]) and args[0] not in {"uv", "uvx", "pipx", "npx", "npm", "bun", "deno"}:
                return interpreter(args[0], args[1:])
            return result
        if DYNAMIC.search(args[0]):
            return _unknown(result, "dynamic_package_declaration")
        result["package_declarations"].append({"kind": "npm_package" if launcher != "uvx" else "uv_tool_package", "value": args[0]})
        return result
    if launcher == "deno":
        if not args or args[0] != "run":
            return _unknown(result, "unsupported_deno_subcommand")
        # Permission flags with explicit '=' values are declarations only.
        original = tokens[2:]
        args, reason = options(original, {"-A", "--allow-all", "--allow-read", "--allow-write", "--allow-net", "--allow-env", "--no-check", "--cached-only"},
                               {"--allow-read", "--allow-write", "--allow-net", "--allow-env"})
        if reason:
            return _unknown(result, reason)
        if args and args[0].startswith(("npm:", "jsr:")):
            result["package_declarations"].append({"kind": "deno_module", "value": args[0]})
            return result
        return target(args)
    if launcher == "bun":
        args, reason = options(args, {"--watch", "--check"})
        if reason:
            return _unknown(result, reason)
        if args[:1] == ["run"]:
            args = args[1:]
        return target(args)
    return interpreter(launcher, args)


def inspect_inline_script_metadata(text):
    """Read real top-level PEP 723 comments with bounded TOML parsing.

    Invalid or unavailable analysis is unknown, not a standards pass. PEP 508
    validation uses an existing packaging installation when present; never
    installs it. Declarations do not prove dependency availability or execution.
    """
    result = {"status": "not_present", "line": None, "dependencies": [], "requires_python": None,
              "line_accuracy": "metadata_block_start", "requirement_validation": "not_performed", "runtime_verified": False, "limits": []}
    if not re.search(r"(?m)^# /// script\b", text):
        return result

    def unknown(reason):
        return {**result, "status": "unknown", "verification": "STATUS: UNKNOWN — UNVERIFIED", "limits": [reason]}

    if len(text) > MAX_METADATA_SOURCE:
        return unknown("inline_metadata_source_budget")
    comment_lines = set()
    try:
        for index, token in enumerate(tokenize.generate_tokens(io.StringIO(text).readline)):
            if index >= MAX_METADATA_TOKENS:
                return unknown("inline_metadata_token_budget")
            if token.type == tokenize.COMMENT and token.start[1] == 0:
                comment_lines.add(token.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError, RecursionError):
        return unknown("inline_metadata_lexing_unavailable")
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "# /// script" and i + 1 in comment_lines]
    if not starts:
        if any(re.match(r"^# /// script\b", line) and i + 1 in comment_lines for i, line in enumerate(lines)):
            return unknown("malformed_inline_script_marker")
        return result
    result["line"] = starts[0] + 1
    if len(starts) != 1:
        return unknown("duplicate_inline_script_blocks")
    start, end = starts[0], None
    for i in range(start + 1, len(lines)):
        if i + 1 not in comment_lines or not (lines[i] == "#" or lines[i].startswith("# ")):
            break
        if lines[i] == "# ///":
            end = i
    if end is None:
        return unknown("unclosed_inline_script_block_ignored")
    content = "\n".join(line[2:] if line.startswith("# ") else line[1:] for line in lines[start + 1:end])
    if len(content) > MAX_METADATA_CHARACTERS:
        return unknown("inline_metadata_character_budget")
    if tomllib is None:
        return unknown("toml_parser_unavailable")
    try:
        data = tomllib.loads(content)
    except (ValueError, RecursionError, MemoryError):
        return unknown("malformed_inline_toml")
    if any(key not in {"dependencies", "requires-python", "tool"} for key in data):
        return unknown("unsupported_inline_metadata_fields")
    if "tool" in data and not isinstance(data["tool"], dict):
        return unknown("invalid_inline_tool_table_type")
    dependencies, requires = data.get("dependencies", []), data.get("requires-python")
    if not isinstance(dependencies, list) or any(not isinstance(d, str) or not d for d in dependencies):
        return unknown("invalid_inline_dependency_type")
    if requires is not None and not isinstance(requires, str):
        return unknown("invalid_requires_python_type")
    if len(dependencies) > MAX_DEPENDENCIES or any(len(d) > MAX_DECLARATION_CHARACTERS for d in dependencies) or (requires is not None and len(requires) > MAX_DECLARATION_CHARACTERS):
        return unknown("inline_dependency_budget")
    result.update(dependencies=dependencies, requires_python=requires)
    if any(DYNAMIC_VALUE.search(d) for d in dependencies) or (requires is not None and DYNAMIC_VALUE.search(requires)):
        return unknown("dynamic_inline_declaration")
    if Requirement is None or SpecifierSet is None:
        return unknown("requirement_validator_unavailable")
    try:
        for dependency in dependencies:
            Requirement(dependency)
        if requires is not None:
            SpecifierSet(requires)
    except (ValueError, TypeError):
        return unknown("invalid_dependency_or_python_specifier")
    result.update(status="parsed_declarations", requirement_validation="pep508_and_python_specifier_syntax_only")
    return result
