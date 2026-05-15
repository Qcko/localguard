"""Per-package surface-count drift relaxation (the `--pin-surfaces` semantics).

When an accepted library entry carries `expected_surface_counts`, the
verdict path's `_novel_high_risk` only flags a surface as drift when the
candidate's TOTAL count on that surface EXCEEDS the pinned count. New
finding identifiers (e.g. a renamed env var) are absorbed up to the pin.

This is the threat-model trade-off documented in SKILL.md / round 5: the
user explicitly accepts "transformers reads N env vars; up to N is fine,
N+1 triggers review." Tested here at the verdict layer.
"""
from __future__ import annotations

from typing import Any

from localguard import fetch, manifest, preflight
from localguard.preflight import _novel_high_risk
from localguard import diff as diff_mod


def _baseline_with_pin(*, pinned: dict[str, int], baseline_findings: list[dict]) -> dict[str, Any]:
    return {
        "name": "envy",
        "version": "1.0.0",
        "ecosystem": "pypi",
        "target_hash": "baseline-hash",
        "profile": "ml-framework",
        "status": "accepted",
        "expected_surface_counts": pinned,
        "score": {"final_score": 60, "role_typical_share": 0.7, "deductions": []},
        "findings": baseline_findings,
    }


def _candidate(version: str, findings: list[dict]) -> dict[str, Any]:
    return {
        "name": "envy",
        "version": version,
        "ecosystem": "pypi",
        "target_hash": f"candidate-{version}",
        "profile": "ml-framework",
        "score": {"final_score": 55, "role_typical_share": 0.6, "deductions": []},
        "findings": findings,
    }


def _env(name: str, line: int) -> dict:
    return {"kind": "env_secret_read", "file": "pkg/m.py", "line": line, "detail": f"os.environ[{name!r}]", "extra": {"env_name": name}}


def test_pin_absorbs_renamed_findings_within_count(tmp_path):
    """Baseline pins env_secret_read=2; candidate reads 2 env vars under
    different names. _novel_high_risk should NOT include env_secret_read."""
    baseline = _baseline_with_pin(
        pinned={"env_secret_read": 2},
        baseline_findings=[_env("A_TOKEN", 1), _env("B_TOKEN", 2)],
    )
    candidate = _candidate("1.0.1", [_env("X_TOKEN", 1), _env("Y_TOKEN", 2)])
    drift = diff_mod.diff_reports(baseline, candidate).to_dict()
    # env_secret_read isn't itself in HIGH_RISK_KINDS, but the same logic
    # applies to any pinned surface; use outbound_network for a clean check.
    novel = _novel_high_risk(drift, baseline, candidate)
    assert "env_secret_read" not in novel  # absorbed by pin


def test_pin_does_not_absorb_excess_findings(tmp_path):
    """Baseline pins outbound_network=2; candidate has 3 outbound calls.
    _novel_high_risk MUST flag outbound_network."""
    baseline = _baseline_with_pin(
        pinned={"outbound_network": 2},
        baseline_findings=[
            {"kind": "outbound_network", "file": "m.py", "line": 1, "detail": "a", "extra": {"host": "a.example"}},
            {"kind": "outbound_network", "file": "m.py", "line": 2, "detail": "b", "extra": {"host": "b.example"}},
        ],
    )
    candidate = _candidate("1.0.1", [
        {"kind": "outbound_network", "file": "m.py", "line": 1, "detail": "a", "extra": {"host": "a.example"}},
        {"kind": "outbound_network", "file": "m.py", "line": 2, "detail": "b", "extra": {"host": "b.example"}},
        {"kind": "outbound_network", "file": "m.py", "line": 3, "detail": "c", "extra": {"host": "evil.example"}},
    ])
    drift = diff_mod.diff_reports(baseline, candidate).to_dict()
    novel = _novel_high_risk(drift, baseline, candidate)
    assert "outbound_network" in novel  # exceeded pin


def test_unpinned_surface_flags_any_novel_signature(tmp_path):
    """Without `expected_surface_counts` on a surface, the strict per-
    signature behavior applies: ANY new signature counts as drift."""
    baseline = _baseline_with_pin(
        pinned={"env_secret_read": 5},  # pin only env_secret, NOT outbound_network
        baseline_findings=[
            {"kind": "outbound_network", "file": "m.py", "line": 1, "detail": "a", "extra": {"host": "a.example"}},
        ],
    )
    candidate = _candidate("1.0.1", [
        {"kind": "outbound_network", "file": "m.py", "line": 1, "detail": "a", "extra": {"host": "a.example"}},
        {"kind": "outbound_network", "file": "m.py", "line": 2, "detail": "b", "extra": {"host": "evil.example"}},  # new host
    ])
    drift = diff_mod.diff_reports(baseline, candidate).to_dict()
    novel = _novel_high_risk(drift, baseline, candidate)
    assert "outbound_network" in novel  # unpinned surface = strict


def test_no_pin_means_strict_per_signature(tmp_path):
    """A baseline with NO expected_surface_counts behaves strictly: any new
    host on a high-risk surface is drift."""
    baseline = {
        "name": "envy", "version": "1.0.0", "ecosystem": "pypi",
        "target_hash": "baseline-hash", "profile": "plugin", "status": "accepted",
        "score": {"final_score": 60, "deductions": []},
        "findings": [
            {"kind": "outbound_network", "file": "m.py", "line": 1, "detail": "a", "extra": {"host": "a.example"}},
        ],
    }
    candidate = _candidate("1.0.1", [
        {"kind": "outbound_network", "file": "m.py", "line": 1, "detail": "a", "extra": {"host": "a.example"}},
        {"kind": "outbound_network", "file": "m.py", "line": 2, "detail": "b", "extra": {"host": "new.example"}},
    ])
    drift = diff_mod.diff_reports(baseline, candidate).to_dict()
    novel = _novel_high_risk(drift, baseline, candidate)
    assert "outbound_network" in novel


def test_pin_zero_means_no_findings_allowed(tmp_path):
    """expected_surface_counts={subprocess: 0} = "no subprocess calls
    allowed." A single new subprocess finding exceeds the pin."""
    baseline = _baseline_with_pin(
        pinned={"subprocess": 0},
        baseline_findings=[],  # baseline has no subprocess
    )
    candidate = _candidate("1.0.1", [
        {"kind": "subprocess", "file": "m.py", "line": 5, "detail": "os.system('x')", "extra": {"fqn": "os.system"}},
    ])
    drift = diff_mod.diff_reports(baseline, candidate).to_dict()
    novel = _novel_high_risk(drift, baseline, candidate)
    assert "subprocess" in novel  # 1 > pinned 0


def test_pin_absorbs_same_signatures_unchanged(tmp_path):
    """Sanity: identical findings between baseline and candidate produce
    no novel surfaces (with or without pin)."""
    findings = [
        {"kind": "outbound_network", "file": "m.py", "line": 1, "detail": "a", "extra": {"host": "a.example"}},
    ]
    baseline = _baseline_with_pin(pinned={"outbound_network": 1}, baseline_findings=findings)
    candidate = _candidate("1.0.1", list(findings))
    drift = diff_mod.diff_reports(baseline, candidate).to_dict()
    assert _novel_high_risk(drift, baseline, candidate) == set()
