import tarfile
from pathlib import Path

from localguard import cli, fetch, library_refresh, manifest


FIXTURES = Path(__file__).parent / "fixtures"


def _seed_old_baseline(library_root: Path, fixture: Path, name: str, version: str, ecosystem: str = "pypi") -> None:
    from localguard import audit
    report = audit.audit_path(fixture).to_dict()
    report["name"] = name
    report["version"] = version
    report["ecosystem"] = ecosystem
    # Simulate "old" entry: no schema_version, no refreshed_at.
    manifest.write_library_entry(report, library_root=library_root)


def _seed_cache(cache_root: Path, fixture: Path, name: str, version: str, ecosystem: str = "pypi") -> None:
    archive = cache_root.parent / f"{name}-{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(fixture, arcname=f"{name}-{version}")
    src_dir = cache_root / ecosystem / name / version / "src"
    src_dir.mkdir(parents=True)
    fetch._unpack_into(archive, src_dir)


def _patch_roots(monkeypatch, tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    library_root = tmp_path / "lib"
    library_root.mkdir(exist_ok=True)
    monkeypatch.setattr(fetch, "DEFAULT_CACHE_ROOT", cache_root)
    monkeypatch.setattr(manifest, "DEFAULT_LIBRARY_ROOT", library_root)
    from localguard import cli as cli_mod
    monkeypatch.setattr(cli_mod.manifest, "DEFAULT_LIBRARY_ROOT", library_root)


def test_refresh_rewrites_entry_and_stamps_refreshed_at(tmp_path, monkeypatch):
    _patch_roots(monkeypatch, tmp_path)
    _seed_cache(tmp_path / "cache", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")
    _seed_old_baseline(tmp_path / "lib", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")

    summary = library_refresh.refresh(library_root=tmp_path / "lib")

    assert summary.refreshed == 1
    assert summary.errors == 0
    refreshed = manifest.find_library_entry("clean-pkg", "pypi", version="0.1.0", library_root=tmp_path / "lib")
    assert refreshed["schema_version"] == manifest.SCHEMA_VERSION
    assert "refreshed_at" in refreshed
    assert "baselined_at" in refreshed


def test_refresh_dry_run_does_not_write(tmp_path, monkeypatch):
    _patch_roots(monkeypatch, tmp_path)
    _seed_cache(tmp_path / "cache", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")
    _seed_old_baseline(tmp_path / "lib", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")
    before = manifest.find_library_entry("clean-pkg", "pypi", version="0.1.0", library_root=tmp_path / "lib")

    summary = library_refresh.refresh(library_root=tmp_path / "lib", dry_run=True)

    assert summary.refreshed == 1
    after = manifest.find_library_entry("clean-pkg", "pypi", version="0.1.0", library_root=tmp_path / "lib")
    assert "refreshed_at" not in after
    assert after.keys() == before.keys()


def test_refresh_redetect_profile_overrides_stored(tmp_path, monkeypatch):
    _patch_roots(monkeypatch, tmp_path)
    _seed_cache(tmp_path / "cache", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")
    # Seed with WRONG profile stored (simulating legacy/bug-era entry).
    from localguard import audit
    report = audit.audit_path(FIXTURES / "clean_pkg", profile="mcp-server", profile_reason="legacy-bug").to_dict()
    report["name"] = "clean-pkg"
    report["version"] = "0.1.0"
    report["ecosystem"] = "pypi"
    manifest.write_library_entry(report, library_root=tmp_path / "lib")

    summary = library_refresh.refresh(library_root=tmp_path / "lib", redetect_profile=True)
    assert summary.refreshed == 1
    refreshed = manifest.find_library_entry("clean-pkg", "pypi", version="0.1.0", library_root=tmp_path / "lib")
    # clean-pkg has no MCP findings and doesn't match the mcp-server-* name convention, so re-detection falls back to plugin.
    assert refreshed["profile"] == "plugin"


def test_refresh_preserves_stored_profile(tmp_path, monkeypatch):
    _patch_roots(monkeypatch, tmp_path)
    _seed_cache(tmp_path / "cache", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")
    # Seed with mcp-server profile explicitly stored.
    from localguard import audit
    report = audit.audit_path(FIXTURES / "clean_pkg", profile="mcp-server", profile_reason="manual: --profile mcp-server").to_dict()
    report["name"] = "clean-pkg"
    report["version"] = "0.1.0"
    report["ecosystem"] = "pypi"
    manifest.write_library_entry(report, library_root=tmp_path / "lib")

    summary = library_refresh.refresh(library_root=tmp_path / "lib")
    assert summary.refreshed == 1
    refreshed = manifest.find_library_entry("clean-pkg", "pypi", version="0.1.0", library_root=tmp_path / "lib")
    assert refreshed["profile"] == "mcp-server"
    assert refreshed["profile_reason"] == "manual: --profile mcp-server"


def test_refresh_filters_by_ecosystem_and_name(tmp_path, monkeypatch):
    _patch_roots(monkeypatch, tmp_path)
    _seed_cache(tmp_path / "cache", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")
    _seed_cache(tmp_path / "cache", FIXTURES / "tampered_v2", "drifty-pkg", "0.2.0")
    _seed_old_baseline(tmp_path / "lib", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")
    _seed_old_baseline(tmp_path / "lib", FIXTURES / "tampered_v2", "drifty-pkg", "0.2.0")

    only_clean = library_refresh.refresh(library_root=tmp_path / "lib", name_pattern="clean")
    assert only_clean.refreshed == 1
    assert {o.name for o in only_clean.outcomes if o.status == "refreshed"} == {"clean-pkg"}

    only_npm = library_refresh.refresh(library_root=tmp_path / "lib", ecosystem="npm")
    assert only_npm.refreshed == 0


def test_refresh_records_score_changes(tmp_path, monkeypatch):
    _patch_roots(monkeypatch, tmp_path)
    _seed_cache(tmp_path / "cache", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")
    _seed_old_baseline(tmp_path / "lib", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")

    summary = library_refresh.refresh(library_root=tmp_path / "lib")

    outcome = summary.outcomes[0]
    assert outcome.old_score is not None
    assert outcome.new_score is not None


def test_cli_refresh_smoke(tmp_path, monkeypatch, capsys):
    _patch_roots(monkeypatch, tmp_path)
    _seed_cache(tmp_path / "cache", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")
    _seed_old_baseline(tmp_path / "lib", FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")

    rc = cli.main(["library", "refresh", "--dry-run"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "would refresh" in out
    assert "1 refreshed" in out
