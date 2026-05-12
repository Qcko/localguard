from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from .report import Confidence, Finding, SurfaceKind
from .walker import SourceFile


NETWORK_BARE_CALLS = {"fetch"}
NETWORK_CONSTRUCTORS = {"XMLHttpRequest", "WebSocket", "EventSource"}
OBFUSCATION_BARE_CALLS = {"eval", "Function"}

NETWORK_MODULES = {"http", "https", "node:http", "node:https", "node-fetch", "undici", "got", "axios", "request", "needle", "superagent"}
SUBPROCESS_MODULES = {"child_process", "node:child_process"}
FS_MODULES = {"fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra", "graceful-fs"}
NETWORK_METHODS = {"request", "get", "post", "put", "patch", "delete", "head", "options", "fetch"}
SUBPROCESS_METHODS = {"exec", "execSync", "spawn", "spawnSync", "fork", "execFile", "execFileSync"}
FS_WRITE_METHODS = {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream", "outputFile", "outputFileSync", "writeJson", "writeJsonSync"}

SECRET_NAME_PATTERN = re.compile(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|CREDENTIAL)", re.IGNORECASE)
SENSITIVE_VAR_HINT = re.compile(r"(token|secret|password|api[_-]?key|credential|cookie|session|auth)", re.IGNORECASE)


def audit_js(source: SourceFile) -> list[Finding]:
    parser = _parser_for(source.path)
    if parser is None:
        return []
    source_bytes = source.text.encode("utf-8", errors="replace")
    tree = parser.parse(source_bytes)
    aliases = _collect_module_aliases(tree.root_node, source_bytes)
    findings: list[Finding] = []
    _walk(tree.root_node, source_bytes, source.rel, aliases, findings)
    return findings


def _parser_for(path: Path):
    suffix = path.suffix.lower()
    if suffix in {".ts"}:
        return _ts_parser("typescript")
    if suffix == ".tsx":
        return _ts_parser("tsx")
    if suffix in {".js", ".mjs", ".cjs", ".jsx"}:
        return _js_parser()
    return None


@lru_cache(maxsize=1)
def _js_parser():
    import tree_sitter_javascript
    from tree_sitter import Language, Parser
    return Parser(Language(tree_sitter_javascript.language()))


@lru_cache(maxsize=2)
def _ts_parser(flavor: str):
    import tree_sitter_typescript
    from tree_sitter import Language, Parser
    lang_fn = tree_sitter_typescript.language_typescript if flavor == "typescript" else tree_sitter_typescript.language_tsx
    return Parser(Language(lang_fn()))


def _collect_module_aliases(root, source_bytes: bytes) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in _walk_all(root):
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            module = _module_from_require(value_node, source_bytes)
            if name_node and module and name_node.type == "identifier":
                aliases[_text(name_node, source_bytes)] = module
        elif node.type == "import_statement":
            module = _module_from_import_source(node, source_bytes)
            if module:
                for binding in _import_bindings(node, source_bytes):
                    aliases[binding] = module
    return aliases


def _walk_all(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        for child in current.named_children:
            stack.append(child)


def _module_from_require(value_node, source_bytes: bytes) -> str | None:
    if value_node is None or value_node.type != "call_expression":
        return None
    fn_node = value_node.child_by_field_name("function")
    if fn_node is None or fn_node.type != "identifier" or _text(fn_node, source_bytes) != "require":
        return None
    args_node = value_node.child_by_field_name("arguments")
    if args_node is None:
        return None
    for arg in args_node.named_children:
        if arg.type == "string":
            return _string_literal(arg, source_bytes)
    return None


def _module_from_import_source(import_node, source_bytes: bytes) -> str | None:
    src = import_node.child_by_field_name("source")
    if src and src.type == "string":
        return _string_literal(src, source_bytes)
    for child in import_node.named_children:
        if child.type == "string":
            return _string_literal(child, source_bytes)
    return None


def _import_bindings(import_node, source_bytes: bytes) -> list[str]:
    bindings: list[str] = []
    for child in _iter(import_node):
        if child.type == "identifier":
            bindings.append(_text(child, source_bytes))
    return bindings


def _walk(node, source_bytes: bytes, rel: str, aliases: dict[str, str], findings: list[Finding]) -> None:
    for child in _walk_all(node):
        if child.type == "call_expression":
            _check_call(child, source_bytes, rel, aliases, findings)
        elif child.type == "new_expression":
            _check_new(child, source_bytes, rel, findings)
        elif child.type == "member_expression":
            _check_env_secret(child, source_bytes, rel, findings)


def _check_call(call_node, source_bytes: bytes, rel: str, aliases: dict[str, str], findings: list[Finding]) -> None:
    fn_node = call_node.child_by_field_name("function")
    if fn_node is None:
        return
    line = call_node.start_point[0] + 1
    detail = _truncate(_text(call_node, source_bytes), 200)
    args_node = call_node.child_by_field_name("arguments")
    if fn_node.type == "identifier":
        name = _text(fn_node, source_bytes)
        kind = _classify_bare(name)
        if kind:
            actual_kind, extras = _refine_egress(kind, args_node, source_bytes, {"fqn": name})
            findings.append(_finding(actual_kind, rel, line, detail, extras))
            if actual_kind in {SurfaceKind.OUTBOUND_NETWORK, SurfaceKind.OUTBOUND_DYNAMIC}:
                _check_exfil(args_node, source_bytes, rel, line, findings)
        return
    if fn_node.type == "member_expression":
        obj, prop = _member_parts(fn_node, source_bytes)
        if prop == "listen" and _looks_like_listen(args_node):
            findings.append(_finding(SurfaceKind.LISTENING_PORT, rel, line, detail, {"fqn": f"{obj or '?'}.listen"}))
            return
        if obj is None or prop is None:
            return
        module = aliases.get(obj)
        if module:
            kind = _classify_member(module, prop)
            if kind:
                actual_kind, extras = _refine_egress(kind, args_node, source_bytes, {"fqn": f"{module}.{prop}"})
                findings.append(_finding(actual_kind, rel, line, detail, extras))
                if actual_kind in {SurfaceKind.OUTBOUND_NETWORK, SurfaceKind.OUTBOUND_DYNAMIC}:
                    _check_exfil(args_node, source_bytes, rel, line, findings)


def _refine_egress(kind: SurfaceKind, args_node, source_bytes: bytes, base_extra: dict) -> tuple[SurfaceKind, dict]:
    if kind != SurfaceKind.OUTBOUND_NETWORK:
        return kind, base_extra
    host = _extract_static_host_js(args_node, source_bytes)
    extras = dict(base_extra)
    if host:
        extras["host"] = host
        return SurfaceKind.OUTBOUND_NETWORK, extras
    extras["host"] = None
    return SurfaceKind.OUTBOUND_DYNAMIC, extras


def _extract_static_host_js(args_node, source_bytes: bytes) -> str | None:
    if args_node is None or not args_node.named_children:
        return None
    first = args_node.named_children[0]
    if first.type != "string":
        return None
    raw = _string_literal(first, source_bytes)
    if not raw:
        return None
    return _host_from_url_js(raw)


def _host_from_url_js(url: str) -> str | None:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    return parsed.hostname or None


def _check_env_secret(member_node, source_bytes: bytes, rel: str, findings: list[Finding]) -> None:
    obj_node = member_node.child_by_field_name("object")
    prop_node = member_node.child_by_field_name("property")
    if obj_node is None or prop_node is None:
        return
    if obj_node.type != "member_expression":
        return
    inner_obj = obj_node.child_by_field_name("object")
    inner_prop = obj_node.child_by_field_name("property")
    if inner_obj is None or inner_prop is None:
        return
    if _text(inner_obj, source_bytes) != "process" or _text(inner_prop, source_bytes) != "env":
        return
    name = _text(prop_node, source_bytes)
    if not SECRET_NAME_PATTERN.search(name):
        return
    line = member_node.start_point[0] + 1
    findings.append(_finding(SurfaceKind.ENV_SECRET_READ, rel, line, f"process.env.{name}", {"env_name": name}))


def _looks_like_listen(args_node) -> bool:
    if args_node is None:
        return False
    for arg in args_node.named_children:
        if arg.type in {"number", "identifier", "binary_expression", "template_string"}:
            return True
    return False


def _check_exfil(args_node, source_bytes: bytes, rel: str, line: int, findings: list[Finding]) -> None:
    if args_node is None:
        return
    if not _args_reference_sensitive(args_node, source_bytes):
        return
    findings.append(_finding(SurfaceKind.DATA_EXFIL_HINT, rel, line, "network call with sensitive identifier in args", {}, confidence=Confidence.TRACED))


def _args_reference_sensitive(args_node, source_bytes: bytes) -> bool:
    for descendant in _walk_all(args_node):
        if descendant.type == "property_identifier" and SENSITIVE_VAR_HINT.search(_text(descendant, source_bytes)):
            return True
        if descendant.type == "identifier" and SENSITIVE_VAR_HINT.search(_text(descendant, source_bytes)):
            return True
        if descendant.type in {"string_fragment", "shorthand_property_identifier"} and SENSITIVE_VAR_HINT.search(_text(descendant, source_bytes)):
            return True
    return False


def _check_new(new_node, source_bytes: bytes, rel: str, findings: list[Finding]) -> None:
    ctor = new_node.child_by_field_name("constructor")
    if ctor is None or ctor.type != "identifier":
        return
    name = _text(ctor, source_bytes)
    line = new_node.start_point[0] + 1
    detail = _truncate(_text(new_node, source_bytes), 200)
    if name in NETWORK_CONSTRUCTORS:
        findings.append(_finding(SurfaceKind.OUTBOUND_NETWORK, rel, line, detail, {"fqn": name}))
    elif name == "Function":
        findings.append(_finding(SurfaceKind.OBFUSCATION, rel, line, detail, {"fqn": "Function"}))


def _classify_bare(name: str) -> SurfaceKind | None:
    if name in NETWORK_BARE_CALLS:
        return SurfaceKind.OUTBOUND_NETWORK
    if name in OBFUSCATION_BARE_CALLS:
        return SurfaceKind.OBFUSCATION
    return None


def _classify_member(module: str, method: str) -> SurfaceKind | None:
    if module in SUBPROCESS_MODULES and method in SUBPROCESS_METHODS:
        return SurfaceKind.SUBPROCESS
    if module in NETWORK_MODULES and method in NETWORK_METHODS:
        return SurfaceKind.OUTBOUND_NETWORK
    if module in FS_MODULES and method in FS_WRITE_METHODS:
        return SurfaceKind.FS_WRITE
    return None


def _member_parts(node, source_bytes: bytes) -> tuple[str | None, str | None]:
    obj_node = node.child_by_field_name("object")
    prop_node = node.child_by_field_name("property")
    obj = _text(obj_node, source_bytes) if obj_node and obj_node.type == "identifier" else None
    prop = _text(prop_node, source_bytes) if prop_node and prop_node.type == "property_identifier" else None
    return obj, prop


def _string_literal(node, source_bytes: bytes) -> str | None:
    for child in node.children:
        if child.type == "string_fragment":
            return _text(child, source_bytes)
    text = _text(node, source_bytes).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return None


def _text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _truncate(text: str, limit: int) -> str:
    cleaned = " ".join(text.split())
    return cleaned if len(cleaned) <= limit else cleaned[:limit] + "..."


def _iter(node):
    return node.named_children if hasattr(node, "named_children") else node.children


def _finding(kind: SurfaceKind, rel: str, line: int, detail: str, extra: dict, *, confidence: Confidence = Confidence.LITERAL) -> Finding:
    return Finding(kind=kind, file=rel, line=line, detail=detail, confidence=confidence, extra=extra)
