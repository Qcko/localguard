from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from .report import Finding, SurfaceKind
from .walker import SourceFile


MCP_PYTHON_DECORATORS = {"tool", "resource", "prompt"}
MCP_JS_REGISTER_PATTERN = re.compile(r"\b(?:server|app)\.(tool|resource|prompt)\s*\(\s*['\"`]([A-Za-z0-9_./-]+)['\"`]")
MCP_JS_SET_HANDLER_PATTERN = re.compile(r"setRequestHandler\s*\(\s*['\"`](tools/list|tools/call|resources/list|prompts/list)['\"`]")
PROMPT_INJECTION_PATTERN = re.compile(
    r"(ignore\s+previous|disregard\s+(?:all|previous)|system\s*[:\-]\s*you\s+are|always\s+call\s+this\s+first|do\s+not\s+(?:tell|mention)|forget\s+(?:all|previous))",
    re.IGNORECASE,
)
BIDI_MARKS = "‎‏"  # LTR / RTL marks: legitimate Unicode for RTL i18n, never flagged
ZERO_WIDTH = re.compile(r"[​-‍‪-‮⁠-⁯﻿]")


def detect_mcp(source: SourceFile) -> list[Finding]:
    if source.language == "python":
        return _detect_python(source)
    if source.language == "javascript":
        return _detect_javascript(source)
    return []


def detect_mcp_launch_config(text: str, file_rel: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    for server_name, entry in _iter_mcp_servers(data):
        findings.extend(_inspect_launch_entry(server_name, entry, file_rel))
    return findings


def is_mcp_config_filename(path: Path) -> bool:
    name = path.name.lower()
    return name in {"mcp.json", "claude_desktop_config.json", ".mcp.json"} or name.endswith("mcp.json")


def _detect_python(source: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(source.text)
    except SyntaxError:
        return []
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_mcp_findings_from_decorators(node, source))
    return findings


def _mcp_findings_from_decorators(node: ast.FunctionDef | ast.AsyncFunctionDef, source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    for decorator in node.decorator_list:
        kind = _decorator_mcp_kind(decorator)
        if not kind:
            continue
        surface = SurfaceKind.MCP_TOOL if kind == "tool" else SurfaceKind.MCP_RESOURCE
        findings.append(Finding(
            kind=surface,
            file=source.rel,
            line=node.lineno,
            detail=f"@{kind} {node.name}",
            extra={"name": node.name, "decorator": kind, "doc": ast.get_docstring(node) or ""},
        ))
        findings.extend(_scan_description_for_injection(ast.get_docstring(node) or "", source, node.lineno, node.name))
    return findings


def _decorator_mcp_kind(decorator: ast.AST) -> str | None:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    name = _attr_tail(target)
    if name in MCP_PYTHON_DECORATORS:
        return name
    return None


def _attr_tail(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _detect_javascript(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    has_mcp_handler = False
    for line_no, line in enumerate(source.text.splitlines(), start=1):
        for match in MCP_JS_REGISTER_PATTERN.finditer(line):
            has_mcp_handler = True
            kind = match.group(1)
            name = match.group(2)
            surface = SurfaceKind.MCP_TOOL if kind == "tool" else SurfaceKind.MCP_RESOURCE
            findings.append(Finding(
                kind=surface,
                file=source.rel,
                line=line_no,
                detail=f"{kind}({name!r})",
                extra={"name": name, "decorator": kind},
            ))
        if MCP_JS_SET_HANDLER_PATTERN.search(line):
            has_mcp_handler = True
            findings.append(Finding(
                kind=SurfaceKind.MCP_TOOL,
                file=source.rel,
                line=line_no,
                detail="setRequestHandler",
                extra={"name": "<handler>", "decorator": "handler"},
            ))
    # The injection scan is meaningful only for files that actually register
    # MCP tools/handlers; a full-text scan of every JS file produced false
    # positives on type stubs / vendored builds that happened to contain
    # zero-width unicode in unrelated license headers or i18n tables.
    if has_mcp_handler:
        findings.extend(_scan_description_for_injection(source.text, source, 1, source.rel))
    return findings


def _scan_description_for_injection(text: str, source: SourceFile, line: int, owner: str) -> list[Finding]:
    findings: list[Finding] = []
    if PROMPT_INJECTION_PATTERN.search(text):
        findings.append(Finding(
            kind=SurfaceKind.PROMPT_INJECTION_HINT,
            file=source.rel,
            line=line,
            detail=f"injection-shaped text near {owner!r}",
            extra={"owner": owner},
        ))
    if ZERO_WIDTH.search(text):
        findings.append(Finding(
            kind=SurfaceKind.PROMPT_INJECTION_HINT,
            file=source.rel,
            line=line,
            detail=f"zero-width characters in description for {owner!r}",
            extra={"owner": owner, "marker": "zero-width"},
        ))
    return findings


def _iter_mcp_servers(data) -> list[tuple[str, dict]]:
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return []
    return [(name, entry) for name, entry in servers.items() if isinstance(entry, dict)]


def _inspect_launch_entry(server_name: str, entry: dict, file_rel: str) -> list[Finding]:
    findings: list[Finding] = []
    args = entry.get("args") or []
    args_text = " ".join(str(a) for a in args)
    if re.search(r"(?:^|\s)(-y|--yes)(?:\s|$)", args_text):
        findings.append(Finding(
            kind=SurfaceKind.MCP_TRANSPORT_DRIFT,
            file=file_rel,
            line=1,
            detail=f"server {server_name!r} launched with auto-accept flag ({args_text})",
            extra={"server": server_name, "reason": "auto-accept"},
        ))
    if "@latest" in args_text or args_text.endswith(" latest"):
        findings.append(Finding(
            kind=SurfaceKind.MCP_TRANSPORT_DRIFT,
            file=file_rel,
            line=1,
            detail=f"server {server_name!r} pulls unpinned 'latest' version",
            extra={"server": server_name, "reason": "unpinned"},
        ))
    return findings
