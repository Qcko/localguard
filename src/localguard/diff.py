from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .report import SurfaceKind


SIGNATURE_KEYS: dict[str, str] = {
    SurfaceKind.OUTBOUND_NETWORK.value: "host",
    SurfaceKind.OUTBOUND_DYNAMIC.value: "fqn",
    SurfaceKind.TELEMETRY_ENDPOINT.value: "host",
    SurfaceKind.HARDCODED_HOST.value: "host",
    SurfaceKind.LISTENING_PORT.value: "fqn",
    SurfaceKind.SUBPROCESS.value: "fqn",
    SurfaceKind.FS_WRITE.value: "method",
    SurfaceKind.ENV_SECRET_READ.value: "env_name",
    SurfaceKind.MCP_TOOL.value: "name",
    SurfaceKind.MCP_RESOURCE.value: "name",
    SurfaceKind.OBFUSCATION.value: None,
    SurfaceKind.DATA_EXFIL_HINT.value: None,
    SurfaceKind.MCP_TRANSPORT_DRIFT.value: "reason",
    SurfaceKind.PROMPT_INJECTION_HINT.value: "owner",
}


@dataclass
class DriftReport:
    score_before: int | None = None
    score_after: int | None = None
    new_findings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    removed_findings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    @property
    def has_drift(self) -> bool:
        return any(self.new_findings.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "score_before": self.score_before,
            "score_after": self.score_after,
            "score_delta": _score_delta(self.score_before, self.score_after),
            "has_drift": self.has_drift,
            "new_findings": self.new_findings,
            "removed_findings": self.removed_findings,
        }


def diff_reports(baseline: dict[str, Any], candidate: dict[str, Any]) -> DriftReport:
    baseline_sigs = _signatures(baseline)
    candidate_sigs = _signatures(candidate)
    drift = DriftReport(
        score_before=_score_of(baseline),
        score_after=_score_of(candidate),
    )
    drift.new_findings = _bucket_difference(candidate_sigs, baseline_sigs)
    drift.removed_findings = _bucket_difference(baseline_sigs, candidate_sigs)
    return drift


def _signatures(report: dict[str, Any]) -> dict[str, dict[str, dict]]:
    buckets: dict[str, dict[str, dict]] = {}
    for finding in report.get("findings", []):
        kind = finding["kind"]
        signature = _signature_of(finding)
        buckets.setdefault(kind, {})[signature] = finding
    return buckets


def _signature_of(finding: dict[str, Any]) -> str:
    kind = finding["kind"]
    key = SIGNATURE_KEYS.get(kind)
    if key:
        value = finding.get("extra", {}).get(key)
        if value:
            return f"{kind}:{value}"
    return f"{kind}:{finding['file']}:{finding['line']}:{finding['detail']}"


def _bucket_difference(left: dict[str, dict[str, dict]], right: dict[str, dict[str, dict]]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for kind, items in left.items():
        right_keys = set(right.get(kind, {}).keys())
        novel = [finding for sig, finding in items.items() if sig not in right_keys]
        if novel:
            out[kind] = novel
    return out


def _score_of(report: dict[str, Any]) -> int | None:
    score = report.get("score")
    return score.get("final_score") if score else None


def _score_delta(before: int | None, after: int | None) -> int | None:
    if before is None or after is None:
        return None
    return after - before
