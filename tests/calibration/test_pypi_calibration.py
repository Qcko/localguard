"""Pinned calibration regression for pypi packages.

For each row in `pinned_scores.json`, fetch the cached tarball, run
`localguard inspect`-equivalent (audit_path against the unpacked source),
and assert the resulting (profile, score, role_typical_share,
library_status) match within tolerance.

Skipped entirely unless `LOCALGUARD_CALIBRATION_DEEP=1`. Within the
deep tier, individual rows skip (not fail) when the cached tarball is
missing or SHA-mismatched.
"""
from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
from pathlib import Path

import pytest

from localguard import audit, manifest, preflight, rubric

from .conftest import (
    cached_tarball_for,
    deep_tier_enabled,
    load_pinned,
)


pytestmark = pytest.mark.skipif(
    not deep_tier_enabled(),
    reason="deep calibration tier: set LOCALGUARD_CALIBRATION_DEEP=1 to run",
)


def _pypi_rows() -> list[dict]:
    return load_pinned().get("pypi", [])


def _ids(rows: list[dict]) -> list[str]:
    return [row["spec"] for row in rows]


def _unpack(tarball: Path, work_dir: Path) -> Path:
    """Unpack a pypi sdist tarball and return the package source root
    (the single top-level directory inside, by convention)."""
    work_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:*") as tar:
        tar.extractall(work_dir)
    entries = [p for p in work_dir.iterdir() if p.is_dir()]
    if len(entries) == 1:
        return entries[0]
    return work_dir


@pytest.mark.parametrize("row", _pypi_rows(), ids=_ids(_pypi_rows()))
def test_pypi_calibration(row, tmp_path, calibration_tolerance):
    spec = row["spec"]
    name, _, version = spec.partition("==")
    tarball = cached_tarball_for(spec, "pypi")
    if tarball is None:
        pytest.skip(f"no verified tarball for {spec} (run tools/seed_calibration_cache.py)")

    # Use a system-temp short path to dodge Windows MAX_PATH on packages
    # like ddtrace with deeply nested test fixtures (>260 chars).
    short_tmp = Path(tempfile.mkdtemp(prefix="lgcal-"))
    try:
        audit_root = _unpack(tarball, short_tmp)
        detected = rubric.detect_profile_from_name(name, "pypi")
        profile, profile_reason = detected if detected else (None, None)
        report = audit.audit_path(audit_root, profile=profile, profile_reason=profile_reason)
    finally:
        shutil.rmtree(short_tmp, ignore_errors=True)

    # Profile.
    expected_profile = row["profile"]
    actual_profile = report.profile or "plugin"
    assert actual_profile == expected_profile, (
        f"{spec}: profile mismatch -- expected {expected_profile}, got {actual_profile}"
    )

    # Score.
    expected_score = row["score"]
    actual_score = report.score.final_score
    score_tol = calibration_tolerance["score"]
    assert abs(actual_score - expected_score) <= score_tol, (
        f"{spec}: score {actual_score} not within +/-{score_tol} of pinned {expected_score}"
    )

    # role_typical_share (only when pinned).
    if "role_typical_share" in row:
        expected_share = row["role_typical_share"]
        actual_share = report.score.role_typical_share
        share_tol = calibration_tolerance["role_typical_share"]
        assert abs(actual_share - expected_share) <= share_tol, (
            f"{spec}: role_typical_share {actual_share:.3f} not within +/-{share_tol} of pinned {expected_share}"
        )

    # library_status (only when pinned -- typically when score < min_score).
    if "library_status" in row:
        expected_status = row["library_status"]
        # Recompute via the same path the verdict uses.
        report_dict = report.to_dict()
        actual_status = preflight._classify_blocked_status(report_dict)
        assert actual_status == expected_status, (
            f"{spec}: classified as {actual_status}, expected {expected_status}"
        )
