import tarfile
from pathlib import Path

from localguard import cli, fetch, manifest


FIXTURES = Path(__file__).parent / "fixtures"


def test_accept_pins_to_library(tmp_path, monkeypatch, capsys):
    _seed_cache(tmp_path, "clean-pkg", "0.1.0", FIXTURES / "clean_pkg")
    _patch_roots(monkeypatch, tmp_path)

    rc = cli.main(["accept", "clean-pkg==0.1.0", "--yes"])

    assert rc == 0
    captured = capsys.readouterr()
    assert "score:" in captured.out
    assert "baselined:" in captured.out
    assert manifest.latest_known_good("clean-pkg", "pypi", library_root=tmp_path / "lib") is not None


def test_accept_aborts_without_confirmation(tmp_path, monkeypatch, capsys):
    _seed_cache(tmp_path, "clean-pkg", "0.1.0", FIXTURES / "clean_pkg")
    _patch_roots(monkeypatch, tmp_path)
    monkeypatch.setattr("sys.stdin", _Stdin("no\n"))

    rc = cli.main(["accept", "clean-pkg==0.1.0"])

    assert rc == 1
    captured = capsys.readouterr()
    assert "aborted" in captured.out
    assert manifest.latest_known_good("clean-pkg", "pypi", library_root=tmp_path / "lib") is None


def test_accept_with_deps_baselines_closure(tmp_path, monkeypatch, capsys):
    _seed_synthetic(tmp_path, "parent", "1.0", deps=["child"])
    _seed_synthetic(tmp_path, "child", "2.0", deps=[])
    _patch_roots(monkeypatch, tmp_path)
    _stub_latest(monkeypatch, {"child": "2.0"})

    rc = cli.main(["accept", "parent==1.0", "--with-deps", "--yes"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "parent==1.0" in out
    assert "child==2.0" in out
    assert "baselined 2 entries" in out
    library_root = tmp_path / "lib"
    assert manifest.latest_known_good("parent", "pypi", library_root=library_root) is not None
    assert manifest.latest_known_good("child", "pypi", library_root=library_root) is not None


def test_accept_with_deps_refuses_on_low_score(tmp_path, monkeypatch, capsys):
    _seed_synthetic(tmp_path, "parent", "1.0", deps=["nasty"])
    _seed_tarball(tmp_path, "nasty", "0.2.0", FIXTURES / "tampered_v2")
    _patch_roots(monkeypatch, tmp_path)
    _stub_latest(monkeypatch, {"nasty": "0.2.0"})

    rc = cli.main(["accept", "parent==1.0", "--with-deps", "--yes"])

    assert rc == 1
    out = capsys.readouterr().out
    assert "refusing" in out
    assert "low-score" in out or "drift" in out
    library_root = tmp_path / "lib"
    assert manifest.latest_known_good("parent", "pypi", library_root=library_root) is None


def _seed_synthetic(tmp_path: Path, name: str, version: str, *, deps: list) -> None:
    src = tmp_path / "cache" / "pypi" / name / version / "src" / f"{name}-{version}"
    src.mkdir(parents=True)
    deps_str = "[" + ", ".join(f'"{d}"' for d in deps) + "]"
    (src / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "{version}"\ndependencies = {deps_str}\n',
        encoding="utf-8",
    )
    (src / "__init__.py").write_text("", encoding="utf-8")


def _seed_tarball(tmp_path: Path, name: str, version: str, fixture: Path) -> None:
    archive = tmp_path / f"{name}-{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(fixture, arcname=f"{name}-{version}")
    src_dir = tmp_path / "cache" / "pypi" / name / version / "src"
    src_dir.mkdir(parents=True)
    fetch._unpack_into(archive, src_dir)


def _stub_latest(monkeypatch, mapping: dict) -> None:
    def fake(name: str, ecosystem: str):
        return mapping.get(name)
    monkeypatch.setattr(fetch, "resolve_latest_version", fake)


class _Stdin:
    def __init__(self, text: str) -> None:
        self._text = text

    def readline(self) -> str:
        return self._text


def _seed_cache(tmp_path: Path, name: str, version: str, fixture: Path) -> None:
    archive = tmp_path / f"{name}-{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(fixture, arcname=f"{name}-{version}")
    src_dir = tmp_path / "cache" / "pypi" / name / version / "src"
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
    from localguard import inspect as inspect_mod
    monkeypatch.setattr(inspect_mod.fetch, "DEFAULT_CACHE_ROOT", cache_root)
