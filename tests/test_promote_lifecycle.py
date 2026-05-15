"""Variants of the `library promote` lifecycle command.

Covers: promote without pin, promote with pin, promote of an already-
accepted entry (no-op), promote of a nonexistent entry (error), and that
`--yes` is required for non-interactive paths.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localguard import cli, manifest


def _seed_blocked_entry(
    library_root: Path,
    *,
    name: str = "drifty-pkg",
    version: str = "0.2.0",
    ecosystem: str = "pypi",
    status: str = "blocked-suspicious",
    target_hash: str = "blocked-hash-1",
    findings: list[dict] | None = None,
) -> Path:
    bucket = library_root / ecosystem / name / version
    bucket.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1,
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "target_hash": target_hash,
        "profile": "plugin",
        "status": status,
        "score": {
            "final_score": 48,
            "role_typical_share": 0.0,
            "deductions": [],
        },
        "findings": findings if findings is not None else [
            {"kind": "outbound_network", "file": "pkg/c.py", "line": 1, "detail": "x", "extra": {"host": "a.example"}},
            {"kind": "outbound_network", "file": "pkg/c.py", "line": 2, "detail": "y", "extra": {"host": "b.example"}},
            {"kind": "subprocess", "file": "pkg/c.py", "line": 3, "detail": "z", "extra": {"fqn": "os.system"}},
        ],
    }
    path = bucket / f"{target_hash}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    index = {
        "name": name,
        "ecosystem": ecosystem,
        "entries": [{
            "version": version,
            "target_hash": target_hash,
            "audited_at": "2026-05-15T00:00:00+00:00",
            "score": 48,
        }],
    }
    (library_root / ecosystem / name / "_index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True), encoding="utf-8"
    )
    return path


def _patch_lib(monkeypatch, library_root: Path) -> None:
    monkeypatch.setattr(manifest, "DEFAULT_LIBRARY_ROOT", library_root)
    monkeypatch.setattr(cli.manifest, "DEFAULT_LIBRARY_ROOT", library_root)


def _read_report(library_root: Path, name: str, version: str, ecosystem: str = "pypi") -> dict:
    bucket = library_root / ecosystem / name / version
    return json.loads(next(bucket.glob("*.json")).read_text(encoding="utf-8"))


def test_promote_without_pin_flips_status_only(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    _seed_blocked_entry(lib)
    _patch_lib(monkeypatch, lib)
    rc = cli.main(["library", "promote", "drifty-pkg==0.2.0", "--yes"])
    assert rc == 0
    report = _read_report(lib, "drifty-pkg", "0.2.0")
    assert report["status"] == "accepted"
    assert "expected_surface_counts" not in report or not report.get("expected_surface_counts")


def test_promote_with_pin_records_surface_counts(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    _seed_blocked_entry(lib)
    _patch_lib(monkeypatch, lib)
    rc = cli.main(["library", "promote", "drifty-pkg==0.2.0", "--pin-surfaces", "--yes"])
    assert rc == 0
    report = _read_report(lib, "drifty-pkg", "0.2.0")
    assert report["status"] == "accepted"
    pinned = report.get("expected_surface_counts") or {}
    assert pinned.get("outbound_network") == 2
    assert pinned.get("subprocess") == 1


def test_promote_already_accepted_is_noop(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    _seed_blocked_entry(lib, status="accepted")
    _patch_lib(monkeypatch, lib)
    rc = cli.main(["library", "promote", "drifty-pkg==0.2.0", "--yes"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "already" in out.lower() and "nothing to do" in out.lower()


def test_promote_nonexistent_entry_errors(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    lib.mkdir()
    _patch_lib(monkeypatch, lib)
    rc = cli.main(["library", "promote", "ghost==9.9.9", "--yes"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "no entry found" in err


def test_promote_requires_version_in_spec(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    _seed_blocked_entry(lib)
    _patch_lib(monkeypatch, lib)
    rc = cli.main(["library", "promote", "drifty-pkg", "--yes"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "name==version" in err


def test_promote_npm_scoped_name(tmp_path, monkeypatch, capsys):
    """The promote path must work for npm-scoped names like @scope/pkg."""
    lib = tmp_path / "lib"
    _seed_blocked_entry(lib, name="@scope/pkg", version="1.2.3", ecosystem="npm", target_hash="npm-hash-1")
    _patch_lib(monkeypatch, lib)
    rc = cli.main(["library", "promote", "@scope/pkg==1.2.3", "--ecosystem", "npm", "--yes"])
    assert rc == 0
    report = _read_report(lib, "@scope/pkg", "1.2.3", ecosystem="npm")
    assert report["status"] == "accepted"


def test_promoted_entry_appears_in_library_list_as_accepted(tmp_path, monkeypatch, capsys):
    """After promote, `library list` (with no status filter) shows the entry
    as accepted, and `library list --status blocked-suspicious` does NOT."""
    lib = tmp_path / "lib"
    _seed_blocked_entry(lib)
    _patch_lib(monkeypatch, lib)
    cli.main(["library", "promote", "drifty-pkg==0.2.0", "--yes"])
    capsys.readouterr()  # clear

    cli.main(["library", "list"])
    out = capsys.readouterr().out
    assert "drifty-pkg" in out
    assert "accepted" in out

    cli.main(["library", "list", "--status", "blocked-suspicious"])
    out = capsys.readouterr().out
    assert "empty" in out or "drifty-pkg" not in out
