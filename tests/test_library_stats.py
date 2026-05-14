from __future__ import annotations

import json
from pathlib import Path

from localguard import manifest


def _write(library: Path, eco: str, name: str, version: str, score: int, audited_at: str, target_hash: str | None = None):
    target_hash = target_hash or f"{name}-{version}-hash"
    bucket = library / eco / name / version
    bucket.mkdir(parents=True, exist_ok=True)
    report = {"name": name, "version": version, "ecosystem": eco, "target_hash": target_hash, "schema_version": 1, "score": {"final_score": score}}
    (bucket / f"{target_hash}.json").write_text(json.dumps(report), encoding="utf-8")
    idx_path = library / eco / name / "_index.json"
    idx = json.loads(idx_path.read_text(encoding="utf-8")) if idx_path.exists() else {"name": name, "ecosystem": eco, "entries": []}
    idx["entries"].append({"version": version, "target_hash": target_hash, "audited_at": audited_at, "score": score})
    idx_path.write_text(json.dumps(idx), encoding="utf-8")


def test_library_stats_empty(tmp_path):
    stats = manifest.library_stats(library_root=tmp_path / "library")
    assert stats["total"] == 0
    assert stats["by_ecosystem"] == {}
    assert stats["oldest"] is None


def test_library_stats_buckets_and_extremes(tmp_path):
    library = tmp_path / "library"
    _write(library, "pypi", "alpha", "1.0", 95, "2026-01-01T00:00:00+00:00")
    _write(library, "pypi", "beta", "1.0", 70, "2026-03-01T00:00:00+00:00")
    _write(library, "npm", "gamma", "1.0", 30, "2026-05-01T00:00:00+00:00")

    stats = manifest.library_stats(library_root=library)
    assert stats["total"] == 3
    assert stats["by_ecosystem"] == {"npm": 1, "pypi": 2}
    assert stats["score_bands"] == {"high": 1, "mid": 1, "low": 1, "unscored": 0}
    assert stats["mean_score"] == 65.0
    assert stats["oldest"]["name"] == "alpha"
    assert stats["newest"]["name"] == "gamma"
    assert stats["size_bytes"] > 0


def test_library_stats_handles_unscored(tmp_path):
    library = tmp_path / "library"
    _write(library, "pypi", "alpha", "1.0", 95, "2026-01-01T00:00:00+00:00")
    # Write a second entry with score missing.
    bucket = library / "pypi" / "alpha" / "2.0"
    bucket.mkdir(parents=True)
    (bucket / "noscore.json").write_text(json.dumps({"name": "alpha", "version": "2.0", "ecosystem": "pypi", "target_hash": "noscore", "schema_version": 1}), encoding="utf-8")
    idx_path = library / "pypi" / "alpha" / "_index.json"
    idx = json.loads(idx_path.read_text(encoding="utf-8"))
    idx["entries"].append({"version": "2.0", "target_hash": "noscore", "audited_at": "2026-04-01T00:00:00+00:00", "score": None})
    idx_path.write_text(json.dumps(idx), encoding="utf-8")

    stats = manifest.library_stats(library_root=library)
    assert stats["score_bands"]["unscored"] == 1
