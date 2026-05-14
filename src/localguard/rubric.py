from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from . import walker
from .report import Finding, ScoreBreakdown, SurfaceKind


@dataclass(frozen=True)
class Weight:
    per_finding: int
    cap: int


PLUGIN_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(5, 25),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(10, 40),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(15, 40),
    SurfaceKind.FS_WRITE: Weight(5, 15),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(2, 10),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# An MCP server's purpose is to expose tools to a model: spawning subprocesses
# (stdio transport), listening on ports (HTTP/SSE transport), reaching outbound
# (HTTP client tools, web-search tools), and writing files (filesystem servers)
# are all *features*, not red flags. Relax those surfaces; keep strict on the
# ones that signal supply-chain trouble regardless of role (obfuscation, secret
# reads, hardcoded C2-style hosts, prompt-injection-shaped tool descriptions,
# MCP transport config drift, data-exfil identifier patterns).
MCP_SERVER_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(2, 10),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(4, 20),
    SurfaceKind.LISTENING_PORT: Weight(0, 0),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(2, 10),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A CLI framework's whole purpose is to dispatch user-supplied commands to
# subprocesses and write user-requested output to disk. Relax those two surfaces.
# Stay strict on everything network-shaped (a CLI tool reaching the network
# unprompted is suspicious), on obfuscation (CLIs don't legitimately need eval),
# and on the strict-by-design surfaces (env_secret_read, telemetry, data-exfil).
CLI_FRAMEWORK_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(5, 25),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(10, 40),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(2, 10),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(2, 10),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A web server's purpose is to bind to a port, accept connections, fork worker
# processes (gunicorn/hypercorn), and write logs/pidfiles/unix sockets. Relax
# listening_port, subprocess, and fs_write. Stay strict on outbound (a web
# server reaching the network outbound is suspicious -- it's there to serve,
# not phone home), on obfuscation, and on the strict-by-design surfaces.
WEB_SERVER_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(5, 25),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(10, 40),
    SurfaceKind.LISTENING_PORT: Weight(0, 0),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(2, 10),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# An HTTP client library's whole purpose is making outbound network calls to
# arbitrary user-supplied hosts. Relax outbound_network, outbound_dynamic, and
# hardcoded_host (which fire on the bundled default-host constants and example
# URLs in docstrings). Stay strict on subprocess and listening_port (a client
# library has no business spawning shells or opening sockets), on obfuscation,
# and on the strict-by-design surfaces -- a network library exfiltrating env
# secrets or carrying prompt-injection-shaped strings is still suspicious.
NETWORK_LIBRARY_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(1, 5),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(2, 10),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(15, 40),
    SurfaceKind.FS_WRITE: Weight(5, 15),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

PROFILE_PLUGIN = "plugin"
PROFILE_MCP_SERVER = "mcp-server"
PROFILE_CLI_FRAMEWORK = "cli-framework"
PROFILE_NETWORK_LIBRARY = "network-library"
PROFILE_WEB_SERVER = "web-server"
DEFAULT_PROFILE = PROFILE_PLUGIN

PROFILE_WEIGHTS: dict[str, dict[SurfaceKind, Weight]] = {
    PROFILE_PLUGIN: PLUGIN_WEIGHTS,
    PROFILE_MCP_SERVER: MCP_SERVER_WEIGHTS,
    PROFILE_CLI_FRAMEWORK: CLI_FRAMEWORK_WEIGHTS,
    PROFILE_NETWORK_LIBRARY: NETWORK_LIBRARY_WEIGHTS,
    PROFILE_WEB_SERVER: WEB_SERVER_WEIGHTS,
}

# Backwards-compat alias for any external caller.
DEFAULT_WEIGHTS = PLUGIN_WEIGHTS

STARTING_SCORE = 100


def weights_for(profile: str) -> dict[SurfaceKind, Weight]:
    return PROFILE_WEIGHTS.get(profile, PLUGIN_WEIGHTS)


def detect_profile_from_content(findings: list[Finding]) -> tuple[str, str] | None:
    """Apply mcp-server profile when the package registers MCP tools or resources in runtime code.

    A package that exposes `@mcp.tool`, `@mcp.resource`, `server.tool(...)`, etc. in
    its runtime sources IS an MCP server by definition. Findings inside tests/docs/
    examples are filtered out via walker.find_context so the SDK's bundled examples
    don't falsely upgrade the SDK itself.
    """
    runtime_mcp = sum(
        1 for f in findings
        if f.kind in {SurfaceKind.MCP_TOOL, SurfaceKind.MCP_RESOURCE}
        and walker.find_context(f.file) == "runtime"
    )
    if runtime_mcp >= 1:
        return PROFILE_MCP_SERVER, f"content: {runtime_mcp} mcp_tool/resource registration(s)"
    return None


# Well-known CLI framework packages. Tight allowlist on purpose -- these are
# libraries whose entire purpose is dispatching subprocesses based on user input,
# they have no package-metadata signal (they don't declare scripts themselves),
# and they are widely depended-upon. Names check against canonical form.
CLI_FRAMEWORK_NAMES: set[str] = {
    "click", "typer", "cleo", "fire", "docopt", "docopt-ng", "rich-click",
}

# Well-known HTTP client libraries. Tight allowlist on purpose -- these are
# libraries whose entire purpose is making outbound calls to user-supplied
# hosts, and there is no metadata signal that distinguishes a network library
# from any other pure-Python package. Canonical (PEP 503) names.
NETWORK_LIBRARY_NAMES: set[str] = {
    "requests", "httpx", "httpcore", "urllib3", "aiohttp", "niquests",
}

# Well-known Python web servers / WSGI/ASGI runners. Tight allowlist on purpose
# -- these are short, well-known names; package metadata does not distinguish a
# web server from any other library that declares an entry point (gunicorn et
# al. would otherwise resolve as cli-framework, which would NOT relax
# listening_port). Canonical (PEP 503) names.
WEB_SERVER_NAMES: set[str] = {
    "uvicorn", "gunicorn", "hypercorn", "granian", "waitress", "daphne",
}


def detect_profile_from_name(name: str, ecosystem: str) -> tuple[str, str] | None:
    """Apply a role profile based on the canonical package name.

    Conservative on purpose -- prefix matches and tight allowlists only.
    Returns (profile, reason) or None.
    """
    if not name:
        return None
    if ecosystem == "pypi":
        if name.startswith("mcp-server-"):
            return PROFILE_MCP_SERVER, "name-convention: mcp-server-*"
        if name in CLI_FRAMEWORK_NAMES:
            return PROFILE_CLI_FRAMEWORK, f"name-allowlist: {name}"
        if name in NETWORK_LIBRARY_NAMES:
            return PROFILE_NETWORK_LIBRARY, f"name-allowlist: {name}"
        if name in WEB_SERVER_NAMES:
            return PROFILE_WEB_SERVER, f"name-allowlist: {name}"
        return None
    if ecosystem == "npm":
        if name.startswith("@modelcontextprotocol/server-"):
            return PROFILE_MCP_SERVER, "name-convention: @modelcontextprotocol/server-*"
        if name.startswith("mcp-server-"):
            return PROFILE_MCP_SERVER, "name-convention: mcp-server-*"
        return None
    return None


def detect_profile_from_metadata(audit_root, ecosystem: str) -> tuple[str, str] | None:
    """Apply cli-framework profile when the package declares executable entry points.

    pypi: pyproject.toml [project.scripts] OR [project.entry-points.console_scripts].
    npm: package.json `bin` (string or dict).

    Catches CLI *tools* (ruff, black, mypy) which declare console_scripts. Does NOT
    catch the underlying frameworks like click/typer themselves -- those are handled
    by the name allowlist in detect_profile_from_name.
    """
    from pathlib import Path
    import json
    import tomllib
    root = Path(audit_root)
    if ecosystem == "pypi":
        pyproject = root / "pyproject.toml"
        if not pyproject.exists():
            return None
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            return None
        project = data.get("project") or {}
        scripts = project.get("scripts") or {}
        console = ((project.get("entry-points") or {}).get("console_scripts")) or {}
        if scripts or console:
            n = len(scripts) + len(console)
            return PROFILE_CLI_FRAMEWORK, f"metadata: {n} console-script entry point(s)"
        return None
    if ecosystem == "npm":
        package_json = root / "package.json"
        if not package_json.exists():
            return None
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        bin_field = data.get("bin")
        if bin_field:
            n = len(bin_field) if isinstance(bin_field, dict) else 1
            return PROFILE_CLI_FRAMEWORK, f"metadata: {n} bin entry point(s)"
        return None
    return None


def score(findings: list[Finding], weights: dict[SurfaceKind, Weight] | None = None, *, profile: str = DEFAULT_PROFILE) -> ScoreBreakdown:
    weights = weights or weights_for(profile)
    runtime = [f for f in findings if walker.find_context(f.file) == "runtime"]
    counts = _count_by_kind(runtime)
    deductions = _build_deductions(counts, weights)
    total_deducted = sum(d["deducted"] for d in deductions)
    final = max(0, STARTING_SCORE - total_deducted)
    return ScoreBreakdown(final_score=final, deductions=deductions)


def _count_by_kind(findings: list[Finding]) -> dict[SurfaceKind, int]:
    counts: dict[SurfaceKind, int] = defaultdict(int)
    for finding in findings:
        counts[finding.kind] += 1
    return counts


def _build_deductions(counts: dict[SurfaceKind, int], weights: dict[SurfaceKind, Weight]) -> list[dict]:
    deductions = []
    for kind, count in counts.items():
        weight = weights.get(kind)
        if not weight or weight.cap == 0:
            continue
        raw = weight.per_finding * count
        deducted = min(raw, weight.cap)
        deductions.append({
            "kind": kind.value,
            "count": count,
            "per_finding": weight.per_finding,
            "cap": weight.cap,
            "deducted": deducted,
        })
    return deductions
