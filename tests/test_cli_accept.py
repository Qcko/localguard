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
