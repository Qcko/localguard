import os
import time
from pathlib import Path

from localguard import cache, cli, fetch


def _seed_cache_entry(cache_root: Path, ecosystem: str, name: str, version: str, age_days: float = 0.0) -> Path:
    version_dir = cache_root / ecosystem / name / version
    src_dir = version_dir / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "marker.txt").write_text("hello", encoding="utf-8")
    if age_days > 0:
        old = time.time() - age_days * 86400
        os.utime(version_dir, (old, old))
        os.utime(src_dir, (old, old))
    return version_dir


def test_prune_skips_recent_entries(tmp_path):
    cache_root = tmp_path / "cache"
    _seed_cache_entry(cache_root, "pypi", "fresh", "1.0", age_days=2)
    result = cache.prune(older_than_days=30, cache_root=cache_root)
    assert result.candidates == []
    assert result.removed == []


def test_prune_removes_stale_entries(tmp_path):
    cache_root = tmp_path / "cache"
    fresh = _seed_cache_entry(cache_root, "pypi", "fresh", "1.0", age_days=2)
    stale = _seed_cache_entry(cache_root, "npm", "stale", "0.5", age_days=120)
    result = cache.prune(older_than_days=30, cache_root=cache_root)
    assert {c.name for c in result.candidates} == {"stale"}
    assert not stale.exists()
    assert fresh.exists()
    assert result.bytes_freed > 0


def test_prune_dry_run_leaves_disk_untouched(tmp_path):
    cache_root = tmp_path / "cache"
    stale = _seed_cache_entry(cache_root, "pypi", "stale", "0.5", age_days=120)
    result = cache.prune(older_than_days=30, dry_run=True, cache_root=cache_root)
    assert len(result.candidates) == 1
    assert result.removed == []
    assert stale.exists()


def test_fetch_touches_mtime_on_cache_hit(tmp_path, monkeypatch):
    cache_root = tmp_path / "cache"
    spec = fetch.PackageSpec(name="demo", version="1.0", ecosystem="pypi")
    version_dir = _seed_cache_entry(cache_root, "pypi", "demo", "1.0", age_days=60)
    before = version_dir.stat().st_mtime
    fetch.fetch_package(spec, cache_root=cache_root)
    after = version_dir.stat().st_mtime
    assert after > before


def test_cli_cache_prune_dry_run(tmp_path, monkeypatch, capsys):
    cache_root = tmp_path / "cache"
    _seed_cache_entry(cache_root, "pypi", "stale", "0.5", age_days=120)
    monkeypatch.setattr(fetch, "DEFAULT_CACHE_ROOT", cache_root)

    rc = cli.main(["cache", "prune", "--older-than", "30", "--dry-run"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "would remove" in out
    assert "stale" in out


def test_cli_cache_prune_nothing_to_remove(tmp_path, monkeypatch, capsys):
    cache_root = tmp_path / "cache"
    _seed_cache_entry(cache_root, "pypi", "fresh", "1.0", age_days=2)
    monkeypatch.setattr(fetch, "DEFAULT_CACHE_ROOT", cache_root)

    rc = cli.main(["cache", "prune", "--older-than", "30"])
    assert rc == 0
    assert "nothing older than" in capsys.readouterr().out
