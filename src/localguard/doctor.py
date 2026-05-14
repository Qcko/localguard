from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from . import cache as cache_mod, fetch, init_hook, manifest


@dataclass
class Check:
    name: str
    status: str  # "ok" | "warn" | "fail"
    detail: str


@dataclass
class DoctorReport:
    checks: list[Check]

    @property
    def ok(self) -> int:
        return sum(1 for c in self.checks if c.status == "ok")

    @property
    def warn(self) -> int:
        return sum(1 for c in self.checks if c.status == "warn")

    @property
    def fail(self) -> int:
        return sum(1 for c in self.checks if c.status == "fail")

    @property
    def healthy(self) -> bool:
        return self.fail == 0


def run(
    *,
    settings_path: Path | None = None,
    library_root: Path | None = None,
    cache_root: Path | None = None,
) -> DoctorReport:
    settings = settings_path or init_hook.settings_path()
    library = library_root or manifest.DEFAULT_LIBRARY_ROOT
    cache_dir = cache_root or fetch.DEFAULT_CACHE_ROOT

    binary_check, binary_path = _check_binary()
    return DoctorReport(checks=[
        binary_check,
        _check_hook_settings(settings, binary_path),
        _check_library_root(library),
        _check_library_index(library),
        _check_library_schema(library),
        _check_library_profiles(library),
        _check_cache_root(cache_dir),
    ])


def _check_binary() -> tuple[Check, Path | None]:
    located = shutil.which("localguard")
    if not located:
        return Check("binary", "fail", "localguard not on PATH (install with `uv tool install --editable .`)"), None
    path = Path(located).resolve()
    return Check("binary", "ok", str(path)), path


def _check_hook_settings(settings: Path, binary: Path | None) -> Check:
    if not settings.exists():
        return Check("hook", "fail", f"{settings} does not exist (run `localguard init-hook`)")
    try:
        data = json.loads(settings.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return Check("hook", "fail", f"could not parse {settings}: {exc}")
    events = (data.get("hooks") or {}).get(init_hook.HOOK_EVENT) or []
    bash_block = next((b for b in events if isinstance(b, dict) and b.get("matcher") == init_hook.HOOK_MATCHER), None)
    if not bash_block:
        return Check("hook", "fail", f"no PreToolUse:Bash matcher in {settings} (run `localguard init-hook`)")
    command = _find_localguard_command(bash_block.get("hooks") or [])
    if not command:
        return Check("hook", "fail", f"PreToolUse:Bash has no localguard hook-bash command (run `localguard init-hook`)")
    referenced = _resolve_bash_executable_path(command)
    if referenced is None:
        return Check("hook", "warn", f"hook command not introspectable: {command}")
    if not referenced.exists():
        return Check("hook", "fail", f"hook references {referenced} which does not exist (run `localguard init-hook --force`)")
    if binary and referenced.resolve() != binary:
        return Check("hook", "warn", f"hook -> {referenced}, PATH -> {binary} (mismatched installs)")
    return Check("hook", "ok", command)


def _find_localguard_command(hooks_list: list) -> str | None:
    for entry in hooks_list:
        if not isinstance(entry, dict):
            continue
        cmd = entry.get("command") or ""
        if init_hook.HOOK_COMMAND_SUFFIX in cmd:
            return cmd
    return None


def _resolve_bash_executable_path(command: str) -> Path | None:
    head = command.split(None, 1)[0] if command.strip() else ""
    if not head:
        return None
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])/(.*)$", head)
        if m:
            return Path(f"{m.group(1).upper()}:/{m.group(2)}")
    return Path(head)


def _check_library_root(library: Path) -> Check:
    if not library.exists():
        return Check("library-root", "warn", f"{library} does not exist yet (no baselines written)")
    rows = manifest.iter_library(library_root=library)
    size = _dir_size(library)
    return Check("library-root", "ok", f"{library} ({len(rows)} entries, {size/1024/1024:.2f} MiB)")


def _check_library_index(library: Path) -> Check:
    if not library.exists():
        return Check("library-index", "ok", "(no library yet)")
    orphans: list[str] = []
    missing: list[str] = []
    for index_path in library.rglob("_index.json"):
        name_dir = index_path.parent
        eco = name_dir.relative_to(library).parts[0]
        label = "/".join(name_dir.relative_to(library).parts)
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            orphans.append(f"{label}/_index.json (unreadable)")
            continue
        indexed_files: set[Path] = set()
        for entry in index.get("entries", []):
            version = entry.get("version") or "unversioned"
            target = entry.get("target_hash") or ""
            report_file = name_dir / version / f"{target}.json"
            indexed_files.add(report_file)
            if not report_file.exists():
                missing.append(f"{eco}/{label}=={version} (index points at missing {target}.json)")
        for version_dir in name_dir.iterdir():
            if not version_dir.is_dir():
                continue
            for report_file in version_dir.glob("*.json"):
                if report_file not in indexed_files:
                    orphans.append(f"{label}/{version_dir.name}/{report_file.name} (not in index)")
    if missing:
        return Check("library-index", "fail", "; ".join(missing[:3]) + (f"  (+{len(missing)-3} more)" if len(missing) > 3 else ""))
    if orphans:
        return Check("library-index", "warn", f"{len(orphans)} orphan(s): " + "; ".join(orphans[:3]))
    return Check("library-index", "ok", "no orphans, no missing reports")


def _check_library_schema(library: Path) -> Check:
    if not library.exists():
        return Check("library-schema", "ok", "(no library yet)")
    stale: list[str] = []
    total = 0
    for report_file in library.rglob("*.json"):
        if report_file.name == "_index.json":
            continue
        total += 1
        try:
            report = json.loads(report_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if report.get("schema_version") != manifest.SCHEMA_VERSION:
            stale.append(str(report_file.relative_to(library)))
    if not total:
        return Check("library-schema", "ok", "(no library entries)")
    if stale:
        msg = f"{len(stale)}/{total} entries on old/missing schema (run `localguard library refresh`)"
        return Check("library-schema", "warn", msg)
    return Check("library-schema", "ok", f"{total}/{total} entries at schema_version {manifest.SCHEMA_VERSION}")


def _check_library_profiles(library: Path) -> Check:
    if not library.exists():
        return Check("library-profiles", "ok", "(no library yet)")
    rows = manifest.iter_library(library_root=library)
    if not rows:
        return Check("library-profiles", "ok", "(no library entries)")
    by_profile: dict[str, int] = {}
    for r in rows:
        key = r.get("profile") or "<unset>"
        by_profile[key] = by_profile.get(key, 0) + 1
    parts = [f"{k}={v}" for k, v in sorted(by_profile.items())]
    if "<unset>" in by_profile:
        return Check("library-profiles", "warn", " ".join(parts) + "  (run `localguard library refresh` to stamp profile on legacy entries)")
    return Check("library-profiles", "ok", " ".join(parts))


def _check_cache_root(cache_dir: Path) -> Check:
    if not cache_dir.exists():
        return Check("cache-root", "ok", f"{cache_dir} (empty)")
    size = _dir_size(cache_dir)
    return Check("cache-root", "ok", f"{cache_dir} ({size/1024/1024:.1f} MiB)")


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                continue
    return total
