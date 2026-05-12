from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from . import walker
from .report import Finding, ScoreBreakdown, SurfaceKind


@dataclass(frozen=True)
class Weight:
    per_finding: int
    cap: int


DEFAULT_WEIGHTS: dict[SurfaceKind, Weight] = {
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

STARTING_SCORE = 100


def score(findings: list[Finding], weights: dict[SurfaceKind, Weight] | None = None) -> ScoreBreakdown:
    weights = weights or DEFAULT_WEIGHTS
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
        if not weight:
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
