from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import diff, fetch, inspect, manifest


_BUILTIN_MIN_SCORE = 50
_BUILTIN_AUTO_ACCEPT_SCORE = 90


def _env_int(name: str, default: int) -> int:
    """Read a positive integer override from the environment, fall back to
    the builtin default if unset or unparseable. Mirrors the existing
    LOCALGUARD_LIBRARY env-var pattern for installation roots.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        return default
    return value


DEFAULT_MIN_SCORE = _env_int("LOCALGUARD_MIN_SCORE", _BUILTIN_MIN_SCORE)
DEFAULT_AUTO_ACCEPT_SCORE = _env_int("LOCALGUARD_AUTO_ACCEPT_SCORE", _BUILTIN_AUTO_ACCEPT_SCORE)
HIGH_RISK_KINDS = {
    "outbound_network",
    "outbound_dynamic",
    "listening_port",
    "subprocess",
    "data_exfil_hint",
    "obfuscation",
    "mcp_transport_drift",
    "prompt_injection_hint",
    "telemetry_endpoint",
}

# Surfaces where a single finding overrides role-typicality entirely. If any
# of these fire, the blocked entry is suspicious regardless of how much of
# the rest of the deduction is "role-typical."
CRITICAL_STRICT_KINDS = {
    "data_exfil_hint",
    "mcp_transport_drift",
    "prompt_injection_hint",
}

ROLE_TYPICAL_THRESHOLD = 0.8


@dataclass
class Verdict:
    status: str
    spec_name: str
    spec_version: str | None
    ecosystem: str
    score: int
    reasons: list[str] = field(default_factory=list)
    drift: dict[str, Any] | None = None
    library_status: str | None = None
    role_typical_share: float = 0.0

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
            "library_status": self.library_status,
            "role_typical_share": self.role_typical_share,
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
    profile: str | None = None,
    profile_reason: str | None = None,
) -> Verdict:
    cache_root = cache_root or fetch.DEFAULT_CACHE_ROOT
    report, spec, _ = inspect.inspect(raw_spec, ecosystem=ecosystem, cache_root=cache_root, profile=profile, profile_reason=profile_reason)
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
    # Surface prior-blocked history for this package name (any version).
    # `latest_known_good` filters out blocked entries from baseline lookup,
    # so we land here on first-encounter even when we've previously
    # declined a different version. The user benefits from seeing the
    # history when deciding whether this version should be treated
    # differently.
    prior_blocked = manifest.prior_blocked_encounters(spec.name, spec.ecosystem, library_root=library_root)
    if prior_blocked:
        # Highest-share blocked entries first -- most informative for
        # comparing the current encounter to past review decisions.
        prior_blocked.sort(key=lambda e: e.get("role_typical_share", 0.0), reverse=True)
        summary = ", ".join(
            f"{e.get('version') or '?'} ({e.get('status')}, share={e.get('role_typical_share', 0.0):.0%})"
            for e in prior_blocked[:5]
        )
        reasons.append(f"prior blocked encounters for {spec.name}: {summary}")
    if score < min_score:
        # Auto-write a blocked entry classified by role-typicality so the next
        # encounter has prior review context. latest_known_good filters these
        # out so they cannot establish a trust baseline -- they're a journal
        # of "we saw this and declined," not "we accepted it."
        blocked_status = _classify_blocked_status(report_dict)
        stamped = dict(report_dict)
        stamped["status"] = blocked_status
        manifest.write_library_entry(stamped, library_root=library_root)
        role_share = (report_dict.get("score") or {}).get("role_typical_share", 0.0)
        reasons.append(f"score {score} below threshold {min_score}")
        reasons.append(f"library-status: {blocked_status} (role_typical_share={role_share:.2f})")
        return Verdict(status="low-score", spec_name=spec.name, spec_version=spec.version, ecosystem=spec.ecosystem, score=score, reasons=reasons, library_status=blocked_status, role_typical_share=role_share)
    auto = accept_new or score >= auto_accept_score
    if not auto:
        sep = "@" if spec.ecosystem == "npm" else "=="
        spec_str = f"{spec.name}{sep}{spec.version}" if spec.version else spec.name
        reasons.append(f"first encounter -- review and run `localguard accept {spec_str}` to baseline it")
        return Verdict(status="first-encounter-needs-accept", spec_name=spec.name, spec_version=spec.version, ecosystem=spec.ecosystem, score=score, reasons=reasons)
    stamped = dict(report_dict)
    stamped["status"] = "accepted"
    manifest.write_library_entry(stamped, library_root=library_root)
    if accept_new:
        reasons.append("pinned into library as new baseline")
    else:
        reasons.append(f"auto-baselined (score {score} >= {auto_accept_score})")
    return Verdict(status="first-encounter-accepted", spec_name=spec.name, spec_version=spec.version, ecosystem=spec.ecosystem, score=score, reasons=reasons)


def _classify_blocked_status(report_dict: dict) -> str:
    """Return `blocked-role-typical` or `blocked-suspicious` for a low-score report.

    A single critical-strict finding (data_exfil_hint, mcp_transport_drift,
    prompt_injection_hint) overrides role-typicality entirely -- these are
    "package is dangerous regardless of role" signals. Otherwise a
    role-typical share at or above the threshold is enough.
    """
    score_data = report_dict.get("score") or {}
    deductions = score_data.get("deductions") or []
    for d in deductions:
        if d.get("kind") in CRITICAL_STRICT_KINDS:
            return "blocked-suspicious"
    role_share = score_data.get("role_typical_share", 0.0)
    if role_share >= ROLE_TYPICAL_THRESHOLD:
        return "blocked-role-typical"
    return "blocked-suspicious"


def _diff_verdict(report_dict, baseline, spec, score, min_score) -> Verdict:
    drift = diff.diff_reports(baseline, report_dict).to_dict()
    reasons: list[str] = []
    if score < min_score:
        reasons.append(f"score {score} below threshold {min_score}")
    novel_high_risk = _novel_high_risk(drift, baseline, report_dict)
    if novel_high_risk:
        reasons.append("novel high-risk surfaces vs. baseline: " + ", ".join(sorted(novel_high_risk)))
    if drift.get("profile_changed"):
        reasons.append(f"profile changed: {drift.get('profile_before')} -> {drift.get('profile_after')}")
    status = "safe" if not reasons else "drift"
    return Verdict(status=status, spec_name=spec.name, spec_version=spec.version, ecosystem=spec.ecosystem, score=score, reasons=reasons, drift=drift)


def _novel_high_risk(drift: dict[str, Any], baseline: dict[str, Any] | None = None, candidate: dict[str, Any] | None = None) -> set[str]:
    """Surface kinds where the candidate has novel high-risk findings.

    Default: per-signature -- any new finding signature (kind+identifier)
    not present in the baseline counts as novel.

    Pinned override: if the baseline carries `expected_surface_counts`, a
    surface is novel only when the candidate's TOTAL count on that surface
    EXCEEDS the pinned count. This is the per-package surface-count
    relaxation that lets a user accept "transformers reads 8 env vars; up
    to 8 is fine, more triggers review" without flagging every refactor
    that changes which specific env-var names are read.
    """
    new = drift.get("new_findings") or {}
    novel = {kind for kind in new.keys() if kind in HIGH_RISK_KINDS and new[kind]}
    if not novel or baseline is None or candidate is None:
        return novel
    pinned = baseline.get("expected_surface_counts") or {}
    if not pinned:
        return novel
    candidate_counts = _surface_counts_from_findings(candidate)
    return {kind for kind in novel if candidate_counts.get(kind, 0) > pinned.get(kind, 0)}


def _surface_counts_from_findings(report: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in report.get("findings", []) or []:
        kind = finding.get("kind")
        if not kind:
            continue
        counts[kind] = counts.get(kind, 0) + 1
    return counts
