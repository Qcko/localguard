from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from .report import Confidence, Finding, SurfaceKind
from .walker import SourceFile


OUTBOUND_FQNS = {
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch",
    "httpx.delete", "httpx.head", "httpx.request", "httpx.stream",
    "httpx.AsyncClient", "httpx.Client",
    "urllib.request.urlopen", "urllib.request.Request",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "aiohttp.ClientSession", "aiohttp.request",
    "websockets.connect",
}

SUBPROCESS_FQNS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output", "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "os.system", "os.popen", "os.execv", "os.execve", "os.execvp",
    "os.execvpe", "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
    "pty.spawn",
}

LISTENING_FQNS = {
    "asyncio.start_server", "asyncio.start_unix_server",
    "uvicorn.run", "uvicorn.Server",
    "socketserver.TCPServer", "socketserver.UDPServer",
    "socketserver.ThreadingTCPServer", "socketserver.ForkingTCPServer",
    "http.server.HTTPServer", "http.server.ThreadingHTTPServer",
}

FS_WRITE_METHODS = {"write_text", "write_bytes"}
FS_COPY_FQNS = {"shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.move"}

OBFUSCATION_FQNS = {"builtins.exec", "builtins.eval", "builtins.compile"}
# Functions whose return value, when fed straight into exec/eval/compile, is
# the hallmark of supply-chain attack code: `exec(base64.b64decode("..."))`,
# `eval(zlib.decompress(payload))`, `exec(__import__('marshal').loads(...))`,
# etc. We classify findings with one of these as the immediate arg as
# `shape: encoded` and weight them at full severity. Plain `exec(<var>)`
# without a decode/decompress wrapper gets `shape: dynamic` and weighs less:
# legitimate code-gen in numpy/setuptools/sqlalchemy/jinja2 looks like that.
ENCODED_OBFUSCATION_FQNS = {
    "base64.b64decode", "base64.b85decode", "base64.b32decode",
    "base64.b16decode", "base64.urlsafe_b64decode", "base64.decodebytes",
    "binascii.unhexlify", "binascii.a2b_base64", "binascii.a2b_qp",
    "zlib.decompress", "gzip.decompress",
    "lzma.decompress", "bz2.decompress",
    "codecs.decode",
    "marshal.loads", "pickle.loads", "dill.loads",
}

SECRET_NAME_PATTERN = re.compile(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|CREDENTIAL)", re.IGNORECASE)
SENSITIVE_VAR_HINT = re.compile(r"(token|secret|password|api[_-]?key|credential|cookie|session)", re.IGNORECASE)


@dataclass
class _Context:
    findings: list[Finding]
    source: SourceFile


def audit_python(source: SourceFile) -> list[Finding]:
    # RecursionError: machine-generated files (e.g. sympy's nested
    # expressions) can exceed the interpreter limit during parse or visit.
    # Such a file is valid Python that RUNS but cannot be analyzed, so the
    # skip is reported as an unauditable_file finding -- padding a payload
    # past the recursion limit must leave a trace, not a blind spot.
    # SyntaxError stays a silent skip: a file that cannot parse cannot
    # execute either, so it is not an audit-evasion channel.
    # MemoryError joins RecursionError: deep unary chains ("not not ... 1")
    # blow parser memory rather than the recursion limit, and whether such a
    # file imports cleanly depends on the host -- report it rather than
    # crash or silently skip. Accepted trade: genuine host memory pressure
    # during an audit gets recorded as a property of the file (cap bounds
    # the damage; a re-audit on a healthy host clears it).
    try:
        tree = ast.parse(source.text, filename=source.rel)
    except SyntaxError:
        return []
    except (RecursionError, MemoryError):
        return [_unauditable_finding(source, stage="parse")]
    context = _Context(findings=[], source=source)
    aliases = _collect_aliases(tree)
    try:
        _PythonVisitor(context, aliases).visit(tree)
    except (RecursionError, MemoryError):
        context.findings.append(_unauditable_finding(source, stage="visit"))
    return context.findings


def _unauditable_finding(source: SourceFile, *, stage: str) -> Finding:
    return Finding(
        kind=SurfaceKind.UNAUDITABLE_FILE,
        file=source.rel,
        line=0,
        detail=f"nesting exceeds the auditor recursion limit ({stage}); file runs but was not analyzed",
        extra={"stage": stage},
    )


def _collect_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, context: _Context, aliases: dict[str, str]) -> None:
        self.context = context
        self.aliases = aliases

    def visit_Call(self, node: ast.Call) -> None:
        fqn = _resolve_call_fqn(node.func, self.aliases)
        self._check_outbound(node, fqn)
        self._check_subprocess(node, fqn)
        self._check_listening(node, fqn)
        self._check_fs_write(node, fqn)
        self._check_obfuscation(node, fqn)
        self._check_env_secret(node, fqn)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        fqn = _resolve_attr_fqn(node.value, self.aliases)
        if fqn == "os.environ" and _looks_secret(_const_str(node.slice)):
            self._add(SurfaceKind.ENV_SECRET_READ, node, f"os.environ[{ast.unparse(node.slice)}]")
        self.generic_visit(node)

    def _check_outbound(self, node: ast.Call, fqn: str) -> None:
        if fqn in OUTBOUND_FQNS:
            detail = _format_call(node, fqn)
            kind, extra = _classify_egress(node, fqn)
            self._add(kind, node, detail, extra=extra)
            self._check_exfil_hint(node)
        elif fqn.endswith(".connect") and _root_alias(fqn, self.aliases) == "socket":
            self._add(SurfaceKind.OUTBOUND_DYNAMIC, node, _format_call(node, fqn), extra={"fqn": fqn})

    def _check_subprocess(self, node: ast.Call, fqn: str) -> None:
        if fqn in SUBPROCESS_FQNS:
            self._add(SurfaceKind.SUBPROCESS, node, _format_call(node, fqn), extra={"fqn": fqn})

    def _check_listening(self, node: ast.Call, fqn: str) -> None:
        if fqn in LISTENING_FQNS:
            self._add(SurfaceKind.LISTENING_PORT, node, _format_call(node, fqn), extra={"fqn": fqn})
            return
        if fqn.endswith(".listen") and _root_alias(fqn, self.aliases) == "socket":
            self._add(SurfaceKind.LISTENING_PORT, node, _format_call(node, fqn), extra={"fqn": fqn})

    def _check_fs_write(self, node: ast.Call, fqn: str) -> None:
        if fqn == "builtins.open" or fqn.endswith(".open") and len(fqn.split(".")) <= 2:
            mode = _open_mode(node)
            if mode and any(flag in mode for flag in "wax"):
                self._add(SurfaceKind.FS_WRITE, node, _format_call(node, "open"), extra={"mode": mode})
            return
        if fqn in FS_COPY_FQNS:
            self._add(SurfaceKind.FS_WRITE, node, _format_call(node, fqn), extra={"fqn": fqn})
            return
        attr = _trailing_attr(node.func)
        if attr in FS_WRITE_METHODS:
            self._add(SurfaceKind.FS_WRITE, node, _format_call(node, f".{attr}"), extra={"method": attr})

    def _check_obfuscation(self, node: ast.Call, fqn: str) -> None:
        if fqn in OBFUSCATION_FQNS and node.args and not _is_string_literal(node.args[0]):
            bare = fqn.rsplit(".", 1)[-1]
            shape = "encoded" if _is_encoded_chain(node.args[0], self.aliases) else "dynamic"
            self._add(SurfaceKind.OBFUSCATION, node, f"{bare}(<{shape}>)", extra={"builtin": bare, "shape": shape})

    def _check_env_secret(self, node: ast.Call, fqn: str) -> None:
        is_env_getter = fqn in {"os.getenv", "os.environ.get"}
        if not is_env_getter or not node.args:
            return
        name = _const_str(node.args[0])
        if name and _looks_secret(name):
            self._add(SurfaceKind.ENV_SECRET_READ, node, f"{fqn}({name!r})", extra={"env_name": name})

    def _check_exfil_hint(self, node: ast.Call) -> None:
        for kw in node.keywords:
            if kw.arg not in {"json", "data", "files", "params"}:
                continue
            if _references_sensitive(kw.value):
                self._add(SurfaceKind.DATA_EXFIL_HINT, node, f"{kw.arg}=<sensitive>", confidence=Confidence.TRACED)

    def _add(self, kind: SurfaceKind, node: ast.AST, detail: str, *, confidence: Confidence = Confidence.LITERAL, extra: dict | None = None) -> None:
        self.context.findings.append(Finding(
            kind=kind,
            file=self.context.source.rel,
            line=getattr(node, "lineno", 0),
            detail=detail,
            confidence=confidence,
            extra=extra or {},
        ))


def _resolve_call_fqn(func: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(func, ast.Name):
        return aliases.get(func.id, f"builtins.{func.id}")
    if isinstance(func, ast.Attribute):
        return _resolve_attr_fqn(func, aliases)
    return ""


def _resolve_attr_fqn(node: ast.AST, aliases: dict[str, str]) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        parts.reverse()
        root_resolved = aliases.get(parts[0], parts[0])
        return ".".join([root_resolved, *parts[1:]])
    return ""


def _root_alias(fqn: str, aliases: dict[str, str]) -> str:
    head = fqn.split(".")[0]
    for original in aliases.values():
        if original.split(".")[0] == head:
            return head
    return head


def _trailing_attr(func: ast.AST) -> str:
    return func.attr if isinstance(func, ast.Attribute) else ""


def _open_mode(node: ast.Call) -> str | None:
    if len(node.args) >= 2:
        mode = _const_str(node.args[1])
        if mode:
            return mode
    for kw in node.keywords:
        if kw.arg == "mode":
            return _const_str(kw.value)
    return "r"


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_encoded_chain(arg: ast.AST, aliases: dict[str, str]) -> bool:
    """The argument to exec/eval/compile is a decode/decompress chain.

    Recognizes `base64.b64decode(...)`, `zlib.decompress(...)`,
    `marshal.loads(...)`, any `.decode()` method call, and bytewise
    concatenation of any of the above (the `b'...' + b'...'` obfuscation).
    Recurses into wrapped calls so `exec(zlib.decompress(b64decode(x)))`
    is still classified encoded.
    """
    if isinstance(arg, ast.Call):
        callee = _resolve_call_fqn(arg.func, aliases)
        if callee in ENCODED_OBFUSCATION_FQNS:
            return True
        if _trailing_attr(arg.func) == "decode":
            return True
        for sub in arg.args:
            if _is_encoded_chain(sub, aliases):
                return True
    if isinstance(arg, ast.BinOp):
        return _is_encoded_chain(arg.left, aliases) or _is_encoded_chain(arg.right, aliases)
    return False


def _is_string_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _looks_secret(name: str | None) -> bool:
    return bool(name and SECRET_NAME_PATTERN.search(name))


def _references_sensitive(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and SENSITIVE_VAR_HINT.search(child.id):
            return True
        if isinstance(child, ast.Attribute) and SENSITIVE_VAR_HINT.search(child.attr):
            return True
    return False


def _classify_egress(node: ast.Call, fqn: str) -> tuple[SurfaceKind, dict]:
    host = _extract_static_host(node)
    if host:
        return SurfaceKind.OUTBOUND_NETWORK, {"fqn": fqn, "host": host}
    return SurfaceKind.OUTBOUND_DYNAMIC, {"fqn": fqn, "host": None}


def _extract_static_host(node: ast.Call) -> str | None:
    if not node.args:
        return None
    url = _const_str(node.args[0])
    if not url:
        return None
    return _host_from_url(url)


def _host_from_url(url: str) -> str | None:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.hostname:
        return parsed.hostname
    return None


def _format_call(node: ast.Call, label: str) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return f"{label}(...)"
