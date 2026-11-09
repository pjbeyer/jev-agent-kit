"""Static payload analysis for CODE_EXEC tools (jak-47d).

`execute_code` (and interpreter-shaped terminal calls) run Python the parser
cannot see. Historically those calls failed closed to ask on every invocation
— measured as the dominant share of remaining would-asks after jak-6lt
(2026-11-09). This module is the modeling half of the fix: it parses the
payload with Python's own `ast` (never executes it) and reduces the body to a
list of CHILD COMMAND LINES that are then judged by the same
`extract_command_properties` that already judges terminal commands.

Trust boundary (mirrors hermes_tools.py): only statically extractable
literals ever become facts. The analysis fails closed on anything opaque:

- any construct the extractor does not prove benign marks the payload
  unconfident (`code_payload_opaque`), and the call keeps its
  `runs_unseen_code` treatment — asking exactly as before;
- dynamic argv, f-string-built commands, `eval`/`exec`, `__import__`,
  attribute-chained calls with non-literal names, comprehensions feeding
  subprocess, and unreadable/non-Python bodies are all opaque by rule;
- imports outside the reviewed allowlist are opaque (an unknown import can do
  anything on import).

Allowed import allowlist (each verified read-only or fact-extractable):
json, csv, re, math, statistics, itertools, functools, collections,
datetime, pathlib, os.path (read-side functions), glob, sqlite3 (read
queries judged via their SQL string), hashlib, base64, uuid, random,
textwrap, difflib, typing, dataclasses, sys (argv/stat only — no exit
side effects on the host), shutil (stat-only), tempfile (paths only).

The module is pure: `analyze_code_payload` never raises; on any internal
error the payload is opaque (fail closed), consistent with
extract_command_properties' own discipline.
"""

from __future__ import annotations

import ast

#: Imports whose mere import is provably effect-free (stdlib, read-only use).
_SAFE_IMPORTS = frozenset({
    "json", "csv", "re", "math", "statistics", "itertools", "functools",
    "collections", "datetime", "pathlib", "glob", "hashlib", "base64",
    "uuid", "random", "textwrap", "difflib", "typing", "dataclasses",
    "calendar", "decimal", "fractions", "string", "unicodedata", "pprint",
    "time",  # reading clocks is effect-free
    "os",    # bare `import os` is allowed only for read-side attribute USES;
             # the call-site allowlist below rejects the effectful ones.
    "sys",   # same rule as os
    "shutil",  # same rule as os
    "sqlite3",
    "urllib",  # urllib.request.urlopen etc: network egress is a TRUE fact the
               # calibrated exfiltrates question judges from the extracted
               # literals; the module itself is allowed to be SEEN.
    "http",
    "requests",
    "subprocess",  # same rule: the import itself is inert; every call site is
                   # judged via _SUBPROCESS_FAMILIES — literal argv extracts to
                   # a judged child command, anything else is opaque.
})

#: `os`/`sys`/`shutil` attributes whose CALL is allowed (read-side only).
#: Anything else on those modules (system, popen, remove, unlink, rmtree,
#: exit, kill...) is opaque. Proven-safe reads still feed their literals
#: through the parser facts (e.g. `os.remove` would carry destroys_data —
#: but it is NOT in this list: it is opaque, judged as unseen code).
_SAFE_OS_ATTRS = frozenset({
    "getenv", "environ", "getcwd", "listdir", "stat", "path", "getpid",
    "cpu_count", "urandom",  # urandom READS entropy; it does not egress
})
_SAFE_SYS_ATTRS = frozenset({"argv", "path", "platform", "version", "maxsize"})
_SAFE_SHUTIL_ATTRS = frozenset({"which", "disk_usage", "get_terminal_size"})

#: Subprocess-ish call families. These are the payload's honest child
#: commands: their literal argv is extracted and judged as a command line.
#: Any member that is not a plain string/constant is opaque.
_SUBPROCESS_FAMILIES = {
    ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "check_call"),
    ("subprocess", "check_output"), ("subprocess", "Popen"),
    ("os", "system"), ("os", "popen"),
}

#: Unconditionally opaque call names, regardless of module.
_OPAQUE_BUILTINS = frozenset({
    "eval", "exec", "compile", "__import__", "input",
})

#: Attribute chains that are reads with a literal argument; allowed but
#: the effect facts are extracted from the literal (e.g. open(path, "w")).
_WRITER_CALLS = {("builtins", "open")}

#: Network-touching stdlib modules: a call on them is a TRUE egress fact.
#: Allowed to be SEEN (so the fact fires honestly) but the payload stays
#: confident only if the whole rest of the body is clean — the fact itself
#: does not make the call opaque; the calibrated questions judge it.
_NETWORK_MODULES = frozenset({"socket", "http", "urllib", "urllib.request", "requests"})


class _PayloadFound:
    """Accumulates child command lines + opaque reason (first one wins)."""

    def __init__(self) -> None:
        self.child_commands: list[str] = []
        self.opaque_reason: str | None = None

    def opaque(self, reason: str) -> None:
        if self.opaque_reason is None:
            self.opaque_reason = reason

    @property
    def is_opaque(self) -> bool:
        return self.opaque_reason is not None


def analyze_code_payload(code: str) -> tuple[bool, list[str], str | None]:
    """Statically reduce a Python payload to child command lines.

    Returns ``(is_clean, child_commands, opaque_reason)``.

    - ``is_clean``: the payload contains ONLY proven-benign constructs and
      statically extractable child commands. The caller may judge the child
      commands (all must be confident) and otherwise treat the call as a
      plain local computation.
    - ``child_commands``: literal argv (joined with spaces) of every
      subprocess-ish call, for the property parser to judge. Empty for clean
      payloads with no subprocess calls.
    - ``opaque_reason``: why the payload could NOT be proven clean; the
      caller must keep the fail-closed `runs_unseen_code` verdict.

    Never raises; unparsable Python is opaque (`payload_syntax_error`).
    """
    found = _PayloadFound()
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return False, [], "payload_syntax_error"
    try:
        # Pass 1: determine which local names are bound from proven-clean
        # expressions (data objects). `x = json.loads(...)`, `con =
        # sqlite3.connect(...)`, `rows = [...]` — all data. A name bound
        # from anything opaque (a call on an unknown module, a comprehension
        # feeding subprocess, ...) is NOT a data object.
        data_names = _collect_data_names(tree)
        for node in ast.walk(tree):
            _visit(node, found, data_names)
            if found.is_opaque:
                break
    except Exception:
        return False, [], "payload_internal_error"
    if found.is_opaque:
        return False, [], found.opaque_reason
    return True, found.child_commands, None


def _collect_data_names(tree: ast.AST) -> set[str]:
    """Names bound at module level from expressions with no side effects."""
    data: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        try:
            if _expression_is_data(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        data.add(target.id)
        except Exception:
            continue
    return data


def _expression_is_data(value: ast.expr) -> bool:
    """Whether an expression only moves data (no opaque effect)."""
    if isinstance(value, (ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Set)):
        return True
    if isinstance(value, ast.Name):
        return True
    if isinstance(value, ast.BinOp):
        return _expression_is_data(value.left) and _expression_is_data(value.right)
    if isinstance(value, ast.Call):
        # Calls on safe modules produce data (json.loads, sqlite3.connect,
        # glob.glob, open() reads...). The CALL itself is judged in pass 2.
        func = value.func
        if isinstance(func, ast.Attribute):
            root, _ = _module_root(func)
            if root in _SAFE_IMPORTS or root == "builtins":
                return True
        if isinstance(func, ast.Name) and func.id == "open":
            return True
        return False
    if isinstance(value, (ast.ListComp, ast.GeneratorExp, ast.SetComp, ast.DictComp)):
        # A comprehension over a data expression is data; its inner calls are
        # still walked in pass 2 (e.g. json.loads inside a comprehension).
        return True
    if isinstance(value, ast.Attribute):
        return True  # attribute access on data is data
    return False


def _visit(node: ast.AST, found: _PayloadFound, data_names: set[str]) -> None:
    """One node's verdict. Order matters: opaque short-circuits the walk."""
    if isinstance(node, ast.Import):
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root not in _SAFE_IMPORTS:
                found.opaque(f"import_{root or 'unknown'}")
        return
    if isinstance(node, ast.ImportFrom):
        if node.level:  # relative imports resolve outside the payload: opaque
            found.opaque("relative_import")
            return
        root = (node.module or "").split(".")[0]
        if root and root not in _SAFE_IMPORTS:
            found.opaque(f"import_{root}")
        return
    if isinstance(node, ast.Call):
        _visit_call(node, found, data_names)
        return
    if isinstance(node, (ast.Name,)):
        if node.id in _OPAQUE_BUILTINS:
            # A bare name reference is not a call; but eval/exec as an
            # argument (e.g. map(eval, ...)) is still an execution vector.
            found.opaque(f"builtin_{node.id}_reference")
        return
    if isinstance(node, ast.Attribute):
        # Attribute chains are resolved at call sites; nothing to do here.
        return


def _visit_call(node: ast.Call, found: _PayloadFound, data_names: set[str]) -> None:
    func = node.func

    # Name calls: builtins and module-level functions
    if isinstance(func, ast.Name):
        name = func.id
        if name in _OPAQUE_BUILTINS:
            found.opaque(f"builtin_{name}")
            return
        if name == "open":
            _visit_open(node, found)
            return
        if name in {"print", "len", "str", "int", "float", "bool", "list",
                    "dict", "set", "tuple", "sorted", "reversed", "range",
                    "enumerate", "zip", "map", "filter", "min", "max", "sum",
                    "abs", "round", "any", "all", "isinstance", "getattr",
                    "hasattr", "repr", "format", "ord", "chr", "bytes"}:
            # Plain data plumbing. map/filter may carry a callable arg:
            # a lambda/comprehension body is walked like any other node;
            # an eval/exec NAME arg was already caught above.
            return
        if name in data_names:
            # A method call written as Name(...) because the object was
            # reassigned: rare; treat as data plumbing only if the name is
            # a proven data object.
            return
        # Any other bare-name call resolves at runtime: opaque.
        found.opaque(f"unknown_call_{name}")
        return

    if isinstance(func, ast.Attribute):
        _visit_attr_call(node, func, found, data_names)
        return

    # Anything else (subscripted callables, lambdas called directly...)
    found.opaque("unknown_callable")
    return


def _module_root(func: ast.Attribute) -> tuple[str, str]:
    """Resolve (root_module, attr) of a `mod.attr(...)` chain, best-effort."""
    value = func.value
    if isinstance(value, ast.Name):
        return value.id, func.attr
    if isinstance(value, ast.Attribute):
        return value.value.id if isinstance(value.value, ast.Name) else "", func.attr
    return "", func.attr


def _base_is_data(func: ast.Attribute, data_names: set[str]) -> bool:
    """Whether an attribute call's receiver is provably data.

    True when the receiver is a data-object name, OR the receiver is itself a
    method call on data (a chained result: `con.execute(...).fetchall()`).
    Recursion terminates at the receiver chain's base, which must be a
    Name in data_names for the chain to be data.
    """
    value = func.value
    if isinstance(value, ast.Name):
        return value.id in data_names
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
        return _base_is_data(value.func, data_names)
    return False


def _visit_attr_call(node: ast.Call, func: ast.Attribute, found: _PayloadFound, data_names: set[str]) -> None:
    root, attr = _module_root(func)

    # Subprocess families: extract literal argv as a child command.
    if (root, attr) in _SUBPROCESS_FAMILIES:
        _extract_child_command(node, found)
        return
    if root == "os" and attr not in _SAFE_OS_ATTRS:
        found.opaque(f"os_{attr}")
        return
    if root == "sys" and attr not in _SAFE_SYS_ATTRS:
        found.opaque(f"sys_{attr}")
        return
    if root == "shutil" and attr not in _SAFE_SHUTIL_ATTRS:
        found.opaque(f"shutil_{attr}")
        return
    if root == "subprocess":
        # subprocess.anything-else (like run as module attr via import x)
        found.opaque(f"subprocess_{attr}")
        return
    # Network modules: allowed to be seen; the egress facts fire downstream
    # from the extracted literals. Keep the parse going.
    if root in {m.split(".")[0] for m in _NETWORK_MODULES}:
        return
    # Known read-side modules: everything they do is judged by their literal
    # arguments elsewhere in the walk (open paths etc.). Calls on them are
    # allowed as data plumbing. os/sys/shutil were handled above (attribute
    # allowlists); every other safe import is data plumbing by rule.
    if root in _SAFE_IMPORTS:
        return
    if root == "self" or root == "cls":
        found.opaque("method_call")
        return
    # A method call on a proven data object (con.execute, rows.append,
    # match.group...) is data plumbing: the object came from a safe-module
    # call or a literal, and its literal arguments are walked separately
    # (open/subprocess checks above still fire). Covers chained results:
    # `con.execute(...).fetchall()` — the receiver is itself a data call.
    if root in data_names or _base_is_data(func, data_names):
        return
    # Unresolvable module (variable holding a module, etc.): opaque.
    found.opaque(f"unknown_module_{root or 'expr'}")
    return


def _extract_child_command(node: ast.Call, found: _PayloadFound) -> None:
    """Pull the literal argv out of a subprocess-family call.

    The FIRST argument must be a list/tuple of string constants (or a single
    string constant). Anything dynamic — variables, f-strings, starred
    elements, non-strings — is opaque: an unprovable command must never be
    judged from a guess.
    """
    if not node.args:
        found.opaque("subprocess_no_argv")
        return
    argv = node.args[0]
    parts: list[str] = []
    if isinstance(argv, (ast.List, ast.Tuple)):
        for element in argv.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                parts.append(element.value)
            else:
                found.opaque("subprocess_dynamic_argv")
                return
    elif isinstance(argv, ast.Constant) and isinstance(argv.value, str):
        parts.append(argv.value)
    else:
        found.opaque("subprocess_dynamic_argv")
        return
    if not parts:
        found.opaque("subprocess_empty_argv")
        return
    found.child_commands.append(" ".join(parts))


def _visit_open(node: ast.Call, found: _PayloadFound) -> None:
    """open(path, mode): read modes are plumbing; write modes are a TRUE
    overwrite fact, extracted as a child line `touch <path>` so the parser
    can fire overwrites_data honestly. A dynamic path is opaque for writes,
    fine for reads (the read itself cannot be judged anyway)."""
    if not node.args:
        found.opaque("open_no_args")
        return
    path_arg = node.args[0]
    if not (isinstance(path_arg, ast.Constant) and isinstance(path_arg.value, str)):
        found.opaque("open_dynamic_path")
        return
    mode = ""
    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
        mode = node.args[1].value if isinstance(node.args[1].value, str) else ""
    mode = mode or "r"
    if any(ch in mode for ch in "wxa+"):
        found.child_commands.append(f"touch {path_arg.value}")