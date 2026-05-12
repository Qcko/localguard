from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import diff, fetch, inspect, manifest


DEFAULT_MIN_SCORE = 50
DEFAULT_AUTO_ACCEPT_SCORE = 90
HIGH_RISK_KINDS = {
    "outbound_network",
    "listening_port",
    "subprocess",
    "data_exfil_hint",
    "obfuscation",
    "mcp_transport_drift",
    "prompt_injection_hint",
    "telemetry_endpoint",
}


@dataclass
class Verdict:
    status: str
    spec_name: str
    spec_version: str | None
    ecosystem: str
    score: int
    reasons: list[str] = field(default_factory=list)
    drift: dict[str, Any] | None = None

    @property
    def safe(self) -> bool:
        return self.status in {"safe", "first-encounter-accepted"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "safe": self.safe,
            "spec": {"name": self.spec_name, "version": self.spec_version, "ecosystem": self.ecosystem},
            "score": self.score,
            "reasons": self.reasons,
            "drift": self.drift,
        }

    def human_summary(self) -> str:
        prefix = "[localguard] OK" if self.safe else "[localguard] BLOCK"
        spec = f"{self.spec_name}{('==' + self.spec_version) if self.spec_version else ''}"
        head = f"{prefix} {spec} ({self.ecosystem}) score={self.score} status={self.status}"
        if not self.reasons:
            return head
        return head + "\n" + "\n".join(f"  - {r}" for r in self.reasons)


def preflight(
    raw_spec: str,
    ecosystem: str | None = None,
    *,
    min_score: int = DEFAULT_MIN_SCORE,
    accept_new: bool = False,
    auto_accept_score: int = DEFAULT_AUTO_ACCEPT_SCORE,
    cache_root: Path | None = None,
    library_root: Path | None = None,
) -> Verdict:
    cache_root = cache_root or fetch.DEFAULT_CACHE_ROOT
    report, spec, _ = inspect.inspect(raw_spec, ecosystem=ecosystem, cache_root=cache_root)
    return verdict_for_report(report.to_dict(), spec, min_score=min_score, accept_new=accept_new, auto_accept_score=auto_accept_score, library_root=library_root)


def verdict_for_report(report_dict: dict, spec: fetch.PackageSpec, *, min_score: int | None = None, accept_new: bool = False, auto_accept_score: int | None = None, library_root: Path | None = None) -> Verdict:
    library_root = library_root or manifest.DEFAULT_LIBRARY_ROOT
    min_score = DEFAULT_MIN_SCORE if min_score is None else min_score
    auto_accept_score = DEFAULT_AUTO_ACCEPT_SCORE if auto_accept_score is None else auto_accept_score
    score = (report_dict.get("score") or {}).get("final_score") or 0
    baseline = manifest.latest_known_good(spec.name, spec.ecosystem, library_root=library_root)
    if baseline is None:
        return _first_encounter_verdict(report_dict, spec, score, min_score, accept_new, auto_accept_score, library_root)
    return _diff_verdict(report_dict, baseline, spec, score, min_score)


def _first_encounter_verdict(report_dict, spec, score, min_score, accept_new, auto_accept_score, library_root) -> Verdict:
    reasons: list[str] = ["no prior baseline in library"]
    if score < min_score:
        reasons.append(f"score {score} below threshold {min_score}")
        return Verdict(status="low-score", spec_name=spec.name, spec_version=spec.version, ecosystem=spec.ecosystem, score=score, reasons=reasons)
    auto = accept_new or score >= auto_accept_score
    if not auto:
        reasons.append(f"first encounter — review and run `localguard accept {spec.name}{('==' + spec.version) if spec.version else ''}` to baseline it")
        return Verdict(status="first-encounter-needs-accept", spec_name=spec.name, spec_version=spec.version, ecosystem=spec.ecosystem, score=score, reasons=reasons)
    manifest.write_library_entry(report_dict, library_root=library_root)
    if accept_new:
        reasons.append("pinned into library as new baseline")
    else:
        reasons.append(f"auto-baselined (score {score} >= {auto_accept_score})")
    return Verdict(status="first-encounter-accepted", spec_name=spec.name, spec_version=spec.version, ecosystem=spec.ecosystem, score=score, reasons=reasons)


def _diff_verdict(report_dict, baseline, spec, score, min_score) -> Verdict:
    drift = diff.diff_reports(baseline, report_dict).to_dict()
    reasons: list[str] = []
    if score < min_score:
        reasons.append(f"score {score} below threshold {min_score}")
    novel_high_risk = _novel_high_risk(drift)
    if novel_high_risk:
        reasons.append("novel high-risk surfaces vs. baseline: " + ", ".join(sorted(novel_high_risk)))
    status = "safe" if not reasons else "drift"
    return Verdict(status=status, spec_name=spec.name, spec_version=spec.version, ecosystem=spec.ecosystem, score=score, reasons=reasons, drift=drift)


def _novel_high_risk(drift: dict[str, Any]) -> set[str]:
    new = drift.get("new_findings") or {}
    return {kind for kind in new.keys() if kind in HIGH_RISK_KINDS and new[kind]}
