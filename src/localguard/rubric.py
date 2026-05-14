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

PROFILE_PLUGIN = "plugin"
PROFILE_MCP_SERVER = "mcp-server"
DEFAULT_PROFILE = PROFILE_PLUGIN

PROFILE_WEIGHTS: dict[str, dict[SurfaceKind, Weight]] = {
    PROFILE_PLUGIN: PLUGIN_WEIGHTS,
    PROFILE_MCP_SERVER: MCP_SERVER_WEIGHTS,
}

# Backwards-compat alias for any external caller.
DEFAULT_WEIGHTS = PLUGIN_WEIGHTS

STARTING_SCORE = 100


def weights_for(profile: str) -> dict[SurfaceKind, Weight]:
    return PROFILE_WEIGHTS.get(profile, PLUGIN_WEIGHTS)


def detect_profile_from_name(name: str, ecosystem: str) -> tuple[str, str] | None:
    """Apply mcp-server profile when the canonical package name follows the MCP-server convention.

    Conservative on purpose -- only prefix matches that are very unlikely to fire
    on a non-MCP-server library. Returns (profile, reason) or None.
    """
    if not name:
        return None
    if ecosystem == "pypi":
        if name.startswith("mcp-server-"):
            return PROFILE_MCP_SERVER, "name-convention: mcp-server-*"
        return None
    if ecosystem == "npm":
        if name.startswith("@modelcontextprotocol/server-"):
            return PROFILE_MCP_SERVER, "name-convention: @modelcontextprotocol/server-*"
        if name.startswith("mcp-server-"):
            return PROFILE_MCP_SERVER, "name-convention: mcp-server-*"
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
