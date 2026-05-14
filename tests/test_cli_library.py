import json
from pathlib import Path

from localguard import cli, manifest


FIXTURES = Path(__file__).parent / "fixtures"


def _seed_entry(library_root: Path, name: str, version: str, score: int) -> None:
    report = {
        "name": name,
        "version": version,
        "ecosystem": "pypi",
        "target_hash": f"hash-{name}-{version}",
        "score": {"final_score": score, "deductions": []},
        "findings": [],
    }
    manifest.write_library_entry(report, library_root=library_root)


def _patch_lib(monkeypatch, library_root: Path) -> None:
    monkeypatch.setattr(manifest, "DEFAULT_LIBRARY_ROOT", library_root)
    from localguard import cli as cli_mod
    monkeypatch.setattr(cli_mod.manifest, "DEFAULT_LIBRARY_ROOT", library_root)


def test_iter_library_finds_scoped_npm_entries(tmp_path):
    library = tmp_path / "lib"
    manifest.write_library_entry({
        "name": "@scope/pkg", "version": "1.0.0", "ecosystem": "npm",
        "target_hash": "scoped-hash",
        "score": {"final_score": 95, "deductions": []}, "findings": [],
    }, library_root=library)
    manifest.write_library_entry({
        "name": "bare", "version": "2.0.0", "ecosystem": "npm",
        "target_hash": "bare-hash",
        "score": {"final_score": 90, "deductions": []}, "findings": [],
    }, library_root=library)
    rows = manifest.iter_library(library_root=library)
    names = {(r["name"], r["version"]) for r in rows}
    assert ("@scope/pkg", "1.0.0") in names
    assert ("bare", "2.0.0") in names


def test_library_list_empty(tmp_path, monkeypatch, capsys):
    _patch_lib(monkeypatch, tmp_path / "lib")
    rc = cli.main(["library", "list"])
    assert rc == 0
    assert "empty" in capsys.readouterr().out


def test_library_list_filters_by_profile(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    manifest.write_library_entry({
        "name": "lib-foo", "version": "1.0", "ecosystem": "pypi",
        "target_hash": "lib-foo-hash", "profile": "plugin",
        "score": {"final_score": 95, "deductions": []}, "findings": [],
    }, library_root=lib)
    manifest.write_library_entry({
        "name": "mcp-server-foo", "version": "1.0", "ecosystem": "pypi",
        "target_hash": "mcp-server-foo-hash", "profile": "mcp-server",
        "score": {"final_score": 80, "deductions": []}, "findings": [],
    }, library_root=lib)
    _patch_lib(monkeypatch, lib)

    cli.main(["library", "list", "--profile", "mcp-server"])
    out = capsys.readouterr().out
    assert "mcp-server-foo" in out
    assert "lib-foo" not in out
    assert "1 entries" in out


def test_library_list_renders_entries(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    _seed_entry(lib, "alpha", "1.0", 95)
    _seed_entry(lib, "beta", "2.0", 80)
    _patch_lib(monkeypatch, lib)

    rc = cli.main(["library", "list"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "alpha" in out and "beta" in out
    assert "2 entries" in out


def test_library_list_json(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    _seed_entry(lib, "alpha", "1.0", 95)
    _patch_lib(monkeypatch, lib)

    rc = cli.main(["library", "list", "--json"])
    out = capsys.readouterr().out

    assert rc == 0
    parsed = json.loads(out)
    assert len(parsed) == 1
    assert parsed[0]["name"] == "alpha"
    assert parsed[0]["score"] == 95


def test_library_show_finds_entry(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    _seed_entry(lib, "alpha", "1.0", 95)
    _patch_lib(monkeypatch, lib)

    rc = cli.main(["library", "show", "alpha==1.0"])
    out = capsys.readouterr().out

    assert rc == 0
    parsed = json.loads(out)
    assert parsed["name"] == "alpha"
    assert parsed["score"]["final_score"] == 95


def test_library_show_missing_returns_error(tmp_path, monkeypatch, capsys):
    _patch_lib(monkeypatch, tmp_path / "lib")
    rc = cli.main(["library", "show", "ghost==9.9"])
    assert rc == 1
    assert "no library entry" in capsys.readouterr().err


def test_library_forget_removes_entry(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    _seed_entry(lib, "alpha", "1.0", 95)
    _patch_lib(monkeypatch, lib)

    rc = cli.main(["library", "forget", "alpha==1.0", "--yes"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "removed alpha==1.0" in out
    assert manifest.find_library_entry("alpha", "pypi", version="1.0", library_root=lib) is None


def test_library_forget_requires_version(tmp_path, monkeypatch, capsys):
    _patch_lib(monkeypatch, tmp_path / "lib")
    rc = cli.main(["library", "forget", "alpha", "--yes"])
    assert rc == 2
    assert "requires name==version" in capsys.readouterr().err


def test_library_forget_missing_entry(tmp_path, monkeypatch, capsys):
    _patch_lib(monkeypatch, tmp_path / "lib")
    rc = cli.main(["library", "forget", "ghost==9.9", "--yes"])
    assert rc == 1
    assert "no entry found" in capsys.readouterr().err
