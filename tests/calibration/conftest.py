"""Calibration-suite test infrastructure.

Two tiers:

- **Fast tier** -- always runs. Reuses the existing tests/fixtures/*
  synthetic packages for hermetic coverage. Skipped here; pinned in the
  regular unit tests under tests/test_audit.py and tests/test_rubric.py.

- **Deep tier** -- opt-in via env var `LOCALGUARD_CALIBRATION_DEEP=1`.
  Audits cached real-package tarballs and asserts pinned
  `(profile, score+/-tolerance, role_typical_share+/-tolerance, library_status)`
  against `pinned_scores.json`.

The deep tier never makes network calls during the test run. Tarballs are
fetched by a separate seed script (`tools/seed_calibration_cache.py`)
which records SHA256 hashes in `data_index.json`. The conftest verifies
the cached tarball matches the recorded hash before audit.

Skip semantics:

- If `LOCALGUARD_CALIBRATION_DEEP != "1"`, the whole tier is skipped.
- If the env var IS set but a particular package's tarball is missing
  or its SHA doesn't match `data_index.json`, that one row is skipped
  (with a clear message) instead of failing -- this keeps the deep tier
  runnable against a partial cache.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest


CALIBRATION_DIR = Path(__file__).parent
PINNED_SCORES_PATH = CALIBRATION_DIR / "pinned_scores.json"
DATA_INDEX_PATH = CALIBRATION_DIR / "data_index.json"
DEEP_TIER_ENV = "LOCALGUARD_CALIBRATION_DEEP"


def deep_tier_enabled() -> bool:
    return os.environ.get(DEEP_TIER_ENV) == "1"


def load_pinned() -> dict[str, Any]:
    return json.loads(PINNED_SCORES_PATH.read_text(encoding="utf-8"))


def load_data_index() -> dict[str, dict[str, str]]:
    """{ecosystem: {spec: {sha256, path}}} -- populated by the seed tool."""
    if not DATA_INDEX_PATH.exists():
        return {}
    return json.loads(DATA_INDEX_PATH.read_text(encoding="utf-8"))


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cached_tarball_for(spec: str, ecosystem: str) -> Path | None:
    """Return the verified tarball path for a spec, or None if missing /
    SHA mismatch. Never raises -- callers should `pytest.skip` on None."""
    index = load_data_index()
    eco_index = index.get(ecosystem, {})
    entry = eco_index.get(spec)
    if not entry:
        return None
    path = CALIBRATION_DIR / "data" / entry["path"]
    if not path.exists():
        return None
    expected_sha = entry.get("sha256")
    if not expected_sha:
        return None
    actual_sha = sha256_of(path)
    if actual_sha != expected_sha:
        return None
    return path


@pytest.fixture(scope="session")
def pinned_scores() -> dict[str, Any]:
    return load_pinned()


@pytest.fixture(scope="session")
def calibration_tolerance(pinned_scores) -> dict[str, float]:
    return pinned_scores.get("tolerance", {"score": 2, "role_typical_share": 0.05})
