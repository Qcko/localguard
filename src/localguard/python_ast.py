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

OBFUSCATION_BUILTINS = {"exec", "eval", "compile"}

SECRET_NAME_PATTERN = re.compile(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|CREDENTIAL)", re.IGNORECASE)
SENSITIVE_VAR_HINT = re.compile(r"(token|secret|password|api[_-]?key|credential|cookie|session)", re.IGNORECASE)


@dataclass
class _Context:
    findings: list[Finding]
    source: SourceFile


def audit_python(source: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(source.text, filename=source.rel)
    except SyntaxError:
        return []
    context = _Context(findings=[], source=source)
    aliases = _collect_aliases(tree)
    _PythonVisitor(context, aliases).visit(tree)
    return context.findings


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
            self._add(SurfaceKind.OUTBOUND_NETWORK, node, detail, extra={"fqn": fqn})
            self._check_exfil_hint(node)
        elif fqn.endswith(".connect") and _root_alias(fqn, self.aliases) == "socket":
            self._add(SurfaceKind.OUTBOUND_NETWORK, node, _format_call(node, fqn), extra={"fqn": fqn})

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
        bare = fqn.split(".")[-1]
        if bare in OBFUSCATION_BUILTINS and node.args and not _is_string_literal(node.args[0]):
            self._add(SurfaceKind.OBFUSCATION, node, f"{bare}(<dynamic>)", extra={"builtin": bare})

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


def _format_call(node: ast.Call, label: str) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return f"{label}(...)"
