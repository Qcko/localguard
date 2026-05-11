import tarfile
from pathlib import Path

import pytest

from localguard import fetch, inspect
from localguard.report import SurfaceKind


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_spec_pypi_with_version():
    spec = fetch.parse_spec("requests==2.31.0")
    assert spec == fetch.PackageSpec(name="requests", version="2.31.0", ecosystem="pypi")


def test_parse_spec_pypi_without_version():
    spec = fetch.parse_spec("requests")
    assert spec == fetch.PackageSpec(name="requests", version=None, ecosystem="pypi")


def test_parse_spec_scoped_npm():
    spec = fetch.parse_spec("@modelcontextprotocol/server-filesystem@0.6.0")
    assert spec == fetch.PackageSpec(
        name="@modelcontextprotocol/server-filesystem",
        version="0.6.0",
        ecosystem="npm",
    )


def test_parse_spec_bare_npm_with_version():
    spec = fetch.parse_spec("left-pad@1.3.0", ecosystem_override="npm")
    assert spec == fetch.PackageSpec(name="left-pad", version="1.3.0", ecosystem="npm")


def test_parse_spec_invalid_pypi_raises():
    with pytest.raises(fetch.FetchError):
        fetch.parse_spec("not a valid spec!")


def test_fetch_returns_cached_dir_without_redownload(tmp_path: Path):
    cache_root = tmp_path / "cache"
    spec = fetch.PackageSpec(name="drifty-pkg", version="0.1.0", ecosystem="pypi")
    cache_dir = cache_root / "pypi" / "drifty-pkg" / "0.1.0" / "src"
    cache_dir.mkdir(parents=True)
    (cache_dir / "marker.py").write_text("# already here\n", encoding="utf-8")

    result = fetch.fetch_package(spec, cache_root=cache_root)

    assert result == cache_dir
    assert (cache_dir / "marker.py").exists()


def test_inspect_audits_synthetic_pypi_tarball(tmp_path: Path, monkeypatch):
    cache_root = tmp_path / "cache"
    tarball = _make_pypi_sdist(FIXTURES / "tampered_v2", tmp_path / "build", "drifty-pkg", "0.2.0")
    _stub_pypi_fetcher(monkeypatch, tarball)

    report, spec, root = inspect.inspect("drifty-pkg==0.2.0", cache_root=cache_root)

    assert spec.ecosystem == "pypi"
    assert spec.name == "drifty-pkg"
    assert spec.version == "0.2.0"
    assert "drifty_pkg" in {p.name for p in root.iterdir()} or root.name == "drifty-pkg-0.2.0"
    kinds = {f.kind for f in report.findings}
    assert SurfaceKind.OUTBOUND_NETWORK in kinds
    assert SurfaceKind.SUBPROCESS in kinds
    assert report.score.final_score < 100


def _make_pypi_sdist(source: Path, build_dir: Path, name: str, version: str) -> Path:
    build_dir.mkdir(parents=True, exist_ok=True)
    archive = build_dir / f"{name}-{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(source, arcname=f"{name}-{version}")
    return archive


def _stub_pypi_fetcher(monkeypatch, tarball: Path) -> None:
    def fake_fetch(spec, dest):
        import shutil
        staging = dest.parent / "_download"
        staging.mkdir(parents=True, exist_ok=True)
        target = staging / tarball.name
        shutil.copy(tarball, target)
        fetch._unpack_into(target, dest)
        shutil.rmtree(staging, ignore_errors=True)

    monkeypatch.setattr(fetch, "_fetch_pypi", fake_fetch)
