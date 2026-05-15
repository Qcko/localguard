"""Pinned calibration regression for npm packages.

Same shape as the pypi calibration test. The npm rows in
`pinned_scores.json` start empty in round 8 -- they get populated by
running the seed tool and then auditing the cached tarballs to observe
actual values (per TESTING_PLAN.md: "Round 8 needs to actually audit
these and either confirm the expected shape or flag where calibration
differs").

Skipped entirely unless `LOCALGUARD_CALIBRATION_DEEP=1`.
"""
from __future__ import annotations

import shutil
import tarfile
import tempfile
from pathlib import Path

import pytest

from localguard import audit, preflight, rubric
from localguard.walker import PACKAGE_AUDIT_SKIP_DIRS

from .conftest import (
    cached_tarball_for,
    deep_tier_enabled,
    load_pinned,
)


pytestmark = pytest.mark.skipif(
    not deep_tier_enabled(),
    reason="deep calibration tier: set LOCALGUARD_CALIBRATION_DEEP=1 to run",
)


def _npm_rows() -> list[dict]:
    return load_pinned().get("npm", [])


def _ids(rows: list[dict]) -> list[str]:
    return [row["spec"] for row in rows]


def _unpack(tarball: Path, work_dir: Path) -> Path:
    """Unpack an npm tarball. The canonical convention is a `package/`
    top-level directory; fall back to first dir otherwise."""
    work_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:*") as tar:
        tar.extractall(work_dir)
    package_dir = work_dir / "package"
    if package_dir.is_dir():
        return package_dir
    entries = [p for p in work_dir.iterdir() if p.is_dir()]
    if len(entries) == 1:
        return entries[0]
    return work_dir


_rows = _npm_rows()
if not _rows:
    @pytest.mark.skip(reason="no npm rows pinned yet -- run the seed tool and add rows to pinned_scores.json")
    def test_npm_calibration_placeholder():
        pass
else:
    @pytest.mark.parametrize("row", _rows, ids=_ids(_rows))
    def test_npm_calibration(row, tmp_path, calibration_tolerance):
        spec = row["spec"]
        # Split "@scope/pkg@version" or "name@version".
        if spec.startswith("@"):
            scope_path, _, version = spec.rpartition("@")
            name = scope_path
        else:
            name, _, version = spec.partition("@")
        tarball = cached_tarball_for(spec, "npm")
        if tarball is None:
            pytest.skip(f"no verified tarball for {spec} (run tools/seed_calibration_cache.py)")

        short_tmp = Path(tempfile.mkdtemp(prefix="lgcal-"))
        try:
            audit_root = _unpack(tarball, short_tmp)
            detected = rubric.detect_profile_from_name(name, "npm")
            profile, profile_reason = detected if detected else (None, None)
            report = audit.audit_path(audit_root, profile=profile, profile_reason=profile_reason, skip_dirs=PACKAGE_AUDIT_SKIP_DIRS)
        finally:
            shutil.rmtree(short_tmp, ignore_errors=True)

        expected_profile = row["profile"]
        actual_profile = report.profile or "plugin"
        assert actual_profile == expected_profile, (
            f"{spec}: profile {actual_profile} != pinned {expected_profile}"
        )

        expected_score = row["score"]
        actual_score = report.score.final_score
        score_tol = calibration_tolerance["score"]
        assert abs(actual_score - expected_score) <= score_tol, (
            f"{spec}: score {actual_score} not within +/-{score_tol} of pinned {expected_score}"
        )

        if "role_typical_share" in row:
            expected_share = row["role_typical_share"]
            actual_share = report.score.role_typical_share
            share_tol = calibration_tolerance["role_typical_share"]
            assert abs(actual_share - expected_share) <= share_tol, (
                f"{spec}: role_typical_share {actual_share:.3f} not within +/-{share_tol} of pinned {expected_share}"
            )

        if "library_status" in row:
            expected_status = row["library_status"]
            report_dict = report.to_dict()
            actual_status = preflight._classify_blocked_status(report_dict)
            assert actual_status == expected_status, (
                f"{spec}: classified as {actual_status}, expected {expected_status}"
            )
