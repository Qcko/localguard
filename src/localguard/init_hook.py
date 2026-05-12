from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


HOOK_COMMAND_SUFFIX = "hook-bash"
HOOK_MATCHER = "Bash"
HOOK_EVENT = "PreToolUse"


@dataclass
class InitResult:
    settings_path: Path
    hook_command: str
    status: str  # "added" | "already-present" | "replaced"


def settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"


def resolve_binary_path() -> Path:
    candidate = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
    if candidate and candidate.name.lower().startswith("localguard") and candidate.exists():
        return candidate.resolve()
    located = shutil.which("localguard")
    if located:
        return Path(located).resolve()
    raise FileNotFoundError("could not locate the localguard executable on PATH")


def hook_command_for(binary: Path) -> str:
    return f"{_executable_path_for_shell(binary)} {HOOK_COMMAND_SUFFIX}"


def _executable_path_for_shell(binary: Path) -> str:
    if os.name != "nt":
        return str(binary)
    return _windows_to_bash(binary)


def _windows_to_bash(binary: Path) -> str:
    raw = str(binary).replace("\\", "/")
    if len(raw) >= 2 and raw[1] == ":":
        drive = raw[0].lower()
        return f"/{drive}{raw[2:]}"
    return raw


def install_hook(*, settings: Path | None = None, binary: Path | None = None, force: bool = False) -> InitResult:
    target = settings or settings_path()
    exe = binary or resolve_binary_path()
    command = hook_command_for(exe)
    data = _read_settings(target)
    status = _upsert_hook(data, command, force=force)
    _write_settings(target, data)
    return InitResult(settings_path=target, hook_command=command, status=status)


def _read_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if not text.strip():
        return {}
    return json.loads(text)


def _write_settings(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _upsert_hook(data: dict, command: str, *, force: bool) -> str:
    hooks_root = data.setdefault("hooks", {})
    events = hooks_root.setdefault(HOOK_EVENT, [])
    matcher_block = _find_matcher_block(events, HOOK_MATCHER)
    if matcher_block is None:
        matcher_block = {"matcher": HOOK_MATCHER, "hooks": []}
        events.append(matcher_block)
    hooks_list = matcher_block.setdefault("hooks", [])
    existing = _find_localguard_hook(hooks_list)
    if existing is None:
        hooks_list.append({"type": "command", "command": command})
        return "added"
    if existing.get("command") == command:
        return "already-present"
    if not force:
        return "already-present"
    existing["command"] = command
    existing["type"] = "command"
    return "replaced"


def _find_matcher_block(events: list, matcher: str) -> dict | None:
    for block in events:
        if isinstance(block, dict) and block.get("matcher") == matcher:
            return block
    return None


def _find_localguard_hook(hooks_list: list) -> dict | None:
    for hook in hooks_list:
        if isinstance(hook, dict) and HOOK_COMMAND_SUFFIX in (hook.get("command") or ""):
            return hook
    return None
