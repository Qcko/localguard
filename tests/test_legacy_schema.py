"""Legacy library-entry schema compatibility.

The session that introduced role-typicality added several new fields to the
on-disk library entry: top-level `status`, top-level
`expected_surface_counts`, `score.role_typical_share`, and per-deduction
`role_typical`. Entries written *before* that work should still be readable
by every consumer that touches them. This test hand-crafts a minimal JSON
shaped like a pre-role-typicality entry, drops it into a tmp library, and
exercises the read paths.
"""
from __future__ import annotations

import json
from pathlib import Path

from localguard import manifest
from localguard.diff import diff_reports


def _write_legacy_entry(library_root: Path, *, name: str, version: str, ecosystem: str, target_hash: str, score: int) -> Path:
    """Pre-role-typicality shape: no `status`, no `expected_surface_counts`,
    no `role_typical_share`, no per-deduction `role_typical`."""
    bucket = library_root / ecosystem / name / version
    bucket.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1,
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "target_hash": target_hash,
        "profile": "network-library",
        "profile_reason": "name-allowlist: requests",
        "score": {
            "final_score": score,
            "deductions": [
                {"surface": "outbound_network", "count": 2, "deducted": 0, "cap": 0},
            ],
        },
        "findings": [
            {"kind": "outbound_network", "file": "pkg/client.py", "line": 12, "detail": "requests.get(api.example.com)", "extra": {"host": "api.example.com"}},
        ],
        "baselined_at": "2025-01-01T00:00:00+00:00",
    }
    report_path = bucket / f"{target_hash}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    index_path = library_root / ecosystem / name / "_index.json"
    index = {
        "name": name,
        "ecosystem": ecosystem,
        "entries": [
            {
                "version": version,
                "target_hash": target_hash,
                "audited_at": "2025-01-01T00:00:00+00:00",
                "score": score,
            }
        ],
    }
    index_path.write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")
    return report_path


def test_iter_library_handles_legacy_entry(tmp_path):
    lib = tmp_path / "lib"
    _write_legacy_entry(lib, name="requests", version="2.31.0", ecosystem="pypi", target_hash="legacy-hash-1", score=92)
    rows = manifest.iter_library(library_root=lib)
    assert len(rows) == 1
    row = rows[0]
    assert row["name"] == "requests"
    assert row["version"] == "2.31.0"
    assert row["status"] == "accepted", "legacy entries without status default to accepted"
    assert row["profile"] == "network-library"
    assert row["score"] == 92


def test_latest_known_good_returns_legacy_entry(tmp_path):
    lib = tmp_path / "lib"
    _write_legacy_entry(lib, name="requests", version="2.31.0", ecosystem="pypi", target_hash="legacy-hash-1", score=92)
    report = manifest.latest_known_good("requests", "pypi", library_root=lib)
    assert report is not None
    assert report["target_hash"] == "legacy-hash-1"
    assert "status" not in report
    assert "expected_surface_counts" not in report
    assert "role_typical_share" not in report.get("score", {})


def test_library_lookup_finds_legacy_entry(tmp_path):
    lib = tmp_path / "lib"
    _write_legacy_entry(lib, name="requests", version="2.31.0", ecosystem="pypi", target_hash="legacy-hash-1", score=92)
    found = manifest.library_lookup("legacy-hash-1", "requests", "pypi", library_root=lib)
    assert found is not None
    assert found["name"] == "requests"


def test_prior_blocked_skips_legacy_entry(tmp_path):
    """Legacy entries default to 'accepted', so they must NOT appear in the
    blocked-encounters surface."""
    lib = tmp_path / "lib"
    _write_legacy_entry(lib, name="requests", version="2.31.0", ecosystem="pypi", target_hash="legacy-hash-1", score=92)
    blocked = manifest.prior_blocked_encounters("requests", "pypi", library_root=lib)
    assert blocked == []


def test_diff_reports_legacy_baseline_vs_modern_candidate(tmp_path):
    """Drift detection should not crash when the baseline lacks the new
    fields. The drift result reflects only what's diffable."""
    lib = tmp_path / "lib"
    _write_legacy_entry(lib, name="requests", version="2.31.0", ecosystem="pypi", target_hash="legacy-hash-1", score=92)
    baseline = manifest.latest_known_good("requests", "pypi", library_root=lib)
    assert baseline is not None

    candidate = {
        "name": "requests",
        "version": "2.31.1",
        "ecosystem": "pypi",
        "target_hash": "modern-hash-1",
        "profile": "network-library",
        "status": "accepted",
        "expected_surface_counts": {"outbound_network": 2},
        "score": {
            "final_score": 90,
            "role_typical_share": 1.0,
            "deductions": [
                {"surface": "outbound_network", "count": 2, "deducted": 0, "cap": 0, "role_typical": True},
            ],
        },
        "findings": [
            {"kind": "outbound_network", "file": "pkg/client.py", "line": 12, "detail": "requests.get(api.example.com)", "extra": {"host": "api.example.com"}},
            {"kind": "outbound_network", "file": "pkg/client.py", "line": 30, "detail": "requests.get(telemetry.evil.example)", "extra": {"host": "telemetry.evil.example"}},  # new host
        ],
    }
    drift = diff_reports(baseline, candidate)
    assert drift.score_before == 92
    assert drift.score_after == 90
    assert drift.profile_before == "network-library"
    assert drift.profile_after == "network-library"
    # The new host shows up as drift; the existing host does not.
    new_hosts = {(f.get("extra") or {}).get("host") for f in drift.new_findings.get("outbound_network", [])}
    assert "telemetry.evil.example" in new_hosts
    assert "api.example.com" not in new_hosts


def test_library_list_renders_legacy_entry(tmp_path, monkeypatch, capsys):
    """CLI `library list` formatting must not crash on legacy fields."""
    from localguard import cli
    lib = tmp_path / "lib"
    _write_legacy_entry(lib, name="requests", version="2.31.0", ecosystem="pypi", target_hash="legacy-hash-1", score=92)
    monkeypatch.setattr(manifest, "DEFAULT_LIBRARY_ROOT", lib)
    monkeypatch.setattr(cli.manifest, "DEFAULT_LIBRARY_ROOT", lib)
    rc = cli.main(["library", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "requests" in out
    assert "accepted" in out  # legacy defaults rendered


def test_blocked_legacy_entry_still_classified_when_status_present(tmp_path):
    """Sanity: a legacy-shaped entry that DOES carry an explicit blocked
    status (which can happen if someone hand-edits or if a recent-but-
    still-pre-pin-surfaces entry was blocked) is surfaced correctly."""
    lib = tmp_path / "lib"
    bucket = lib / "pypi" / "evilpkg" / "1.0.0"
    bucket.mkdir(parents=True)
    report = {
        "schema_version": 1,
        "name": "evilpkg",
        "version": "1.0.0",
        "ecosystem": "pypi",
        "target_hash": "evil-hash",
        "profile": "plugin",
        "status": "blocked-suspicious",
        # NOTE: no expected_surface_counts, no role_typical_share -- pre-pin-surfaces shape
        "score": {"final_score": 12, "deductions": []},
        "findings": [],
    }
    (bucket / "evil-hash.json").write_text(json.dumps(report), encoding="utf-8")
    (lib / "pypi" / "evilpkg" / "_index.json").write_text(json.dumps({
        "name": "evilpkg", "ecosystem": "pypi",
        "entries": [{"version": "1.0.0", "target_hash": "evil-hash", "audited_at": "2025-01-01T00:00:00+00:00", "score": 12}],
    }), encoding="utf-8")
    # latest_known_good must skip it (blocked).
    assert manifest.latest_known_good("evilpkg", "pypi", library_root=lib) is None
    # prior_blocked_encounters must surface it.
    blocked = manifest.prior_blocked_encounters("evilpkg", "pypi", library_root=lib)
    assert len(blocked) == 1
    assert blocked[0]["status"] == "blocked-suspicious"
    # The summary should tolerate missing role_typical_share.
    assert blocked[0]["role_typical_share"] == 0.0
