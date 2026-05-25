"""Golden-file snapshots for read-only CLI subcommands.

Catches accidental UX regressions in the text layout of `config show`,
`profiles list`, and `profiles show <name>`. To intentionally update a
snapshot, regenerate the corresponding file under tests/snapshots/ from
the live CLI output.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from localguard import cli, manifest, preflight


SNAPSHOT_DIR = Path(__file__).parent / "snapshots"


def _normalize(text: str) -> str:
    """Normalize platform-specific line endings and trim trailing whitespace
    on each line so Windows CRLF vs LF doesn't trigger spurious diffs."""
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").splitlines())


def _assert_snapshot(got: str, name: str) -> None:
    expected = (SNAPSHOT_DIR / name).read_text(encoding="utf-8")
    assert _normalize(got) == _normalize(expected), f"snapshot mismatch for {name}\n\nGOT:\n{got}\n\nEXPECTED:\n{expected}"


@pytest.fixture
def _clean_env(monkeypatch):
    monkeypatch.delenv("LOCALGUARD_MIN_SCORE", raising=False)
    monkeypatch.delenv("LOCALGUARD_AUTO_ACCEPT_SCORE", raising=False)
    monkeypatch.delenv("LOCALGUARD_LIBRARY", raising=False)
    monkeypatch.delenv("LOCALGUARD_CACHE", raising=False)
    monkeypatch.setattr(preflight, "DEFAULT_MIN_SCORE", preflight._BUILTIN_MIN_SCORE)
    monkeypatch.setattr(preflight, "DEFAULT_AUTO_ACCEPT_SCORE", preflight._BUILTIN_AUTO_ACCEPT_SCORE)


def test_config_show_snapshot(_clean_env, capsys):
    rc = cli.main(["config", "show"])
    assert rc == 0
    _assert_snapshot(capsys.readouterr().out, "config_show.txt")


def test_profiles_list_snapshot(capsys):
    rc = cli.main(["profiles", "list"])
    assert rc == 0
    _assert_snapshot(capsys.readouterr().out, "profiles_list.txt")


def test_profiles_show_plugin_snapshot(capsys):
    rc = cli.main(["profiles", "show", "plugin"])
    assert rc == 0
    _assert_snapshot(capsys.readouterr().out, "profiles_show_plugin.txt")


def test_profiles_show_network_library_snapshot(capsys):
    rc = cli.main(["profiles", "show", "network-library"])
    assert rc == 0
    _assert_snapshot(capsys.readouterr().out, "profiles_show_network_library.txt")
