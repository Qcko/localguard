import json
from pathlib import Path, PureWindowsPath

import pytest

from localguard import init_hook


def test_windows_to_bash_converts_drive_letter():
    raw = PureWindowsPath("X:/uv/tools/bin/localguard.exe")
    assert init_hook._windows_to_bash(raw) == "/x/uv/tools/bin/localguard.exe"


def test_windows_to_bash_lowercases_drive():
    raw = PureWindowsPath("C:/Users/k/localguard.exe")
    assert init_hook._windows_to_bash(raw) == "/c/Users/k/localguard.exe"


def test_install_hook_adds_block_when_missing(tmp_path, monkeypatch):
    settings = tmp_path / "settings.json"
    binary = tmp_path / "localguard.exe"
    binary.write_text("", encoding="utf-8")
    monkeypatch.setattr("os.name", "posix")

    result = init_hook.install_hook(settings=settings, binary=binary)

    assert result.status == "added"
    data = json.loads(settings.read_text(encoding="utf-8"))
    pre = data["hooks"]["PreToolUse"]
    assert pre[0]["matcher"] == "Bash"
    hook_cmd = pre[0]["hooks"][0]["command"]
    assert hook_cmd.endswith("localguard.exe hook-bash")
    assert pre[0]["hooks"][0]["type"] == "command"


def test_install_hook_preserves_other_matchers(tmp_path, monkeypatch):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": "echo read"}]}],
            "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "powershell route-hint.ps1"}]}],
        }
    }), encoding="utf-8")
    binary = tmp_path / "localguard.exe"
    binary.write_text("", encoding="utf-8")
    monkeypatch.setattr("os.name", "posix")

    init_hook.install_hook(settings=settings, binary=binary)
    data = json.loads(settings.read_text(encoding="utf-8"))

    pre = data["hooks"]["PreToolUse"]
    assert any(b.get("matcher") == "Read" for b in pre)
    assert any(b.get("matcher") == "Bash" for b in pre)
    assert data["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"] == "powershell route-hint.ps1"


def test_install_hook_idempotent(tmp_path, monkeypatch):
    settings = tmp_path / "settings.json"
    binary = tmp_path / "localguard.exe"
    binary.write_text("", encoding="utf-8")
    monkeypatch.setattr("os.name", "posix")

    first = init_hook.install_hook(settings=settings, binary=binary)
    second = init_hook.install_hook(settings=settings, binary=binary)

    assert first.status == "added"
    assert second.status == "already-present"
    data = json.loads(settings.read_text(encoding="utf-8"))
    bash_block = next(b for b in data["hooks"]["PreToolUse"] if b.get("matcher") == "Bash")
    assert len(bash_block["hooks"]) == 1


def test_install_hook_force_replaces_stale_command(tmp_path, monkeypatch):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "old/path/localguard hook-bash"}]}
            ]
        }
    }), encoding="utf-8")
    binary = tmp_path / "localguard.exe"
    binary.write_text("", encoding="utf-8")
    monkeypatch.setattr("os.name", "posix")

    no_force = init_hook.install_hook(settings=settings, binary=binary, force=False)
    assert no_force.status == "already-present"
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"].startswith("old/path")

    forced = init_hook.install_hook(settings=settings, binary=binary, force=True)
    assert forced.status == "replaced"
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert "old/path" not in data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]


def test_resolve_binary_path_falls_back_to_which(tmp_path, monkeypatch):
    fake_exe = tmp_path / "localguard.exe"
    fake_exe.write_text("", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["python", "-c", "..."])
    monkeypatch.setattr("shutil.which", lambda name: str(fake_exe))

    result = init_hook.resolve_binary_path()
    assert result == fake_exe.resolve()


def test_resolve_binary_path_raises_when_missing(monkeypatch):
    monkeypatch.setattr("sys.argv", ["python"])
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(FileNotFoundError):
        init_hook.resolve_binary_path()
