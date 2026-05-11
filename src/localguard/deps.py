from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path


REQUIREMENT_NAME_RE = re.compile(r"^([A-Za-z0-9._-]+|@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)")


def extract_deps(audit_root: Path, ecosystem: str) -> list[str]:
    if ecosystem == "pypi":
        return _python_deps(audit_root)
    if ecosystem == "npm":
        return _npm_deps(audit_root)
    return []


def _python_deps(audit_root: Path) -> list[str]:
    pyproject = audit_root / "pyproject.toml"
    if pyproject.exists():
        deps = _deps_from_pyproject(pyproject)
        if deps:
            return deps
    pkg_info_deps = _deps_from_pkg_info(audit_root)
    if pkg_info_deps:
        return pkg_info_deps
    return _deps_from_egg_info(audit_root)


def _deps_from_egg_info(audit_root: Path) -> list[str]:
    for requires_txt in audit_root.glob("*.egg-info/requires.txt"):
        return _parse_egg_requires(requires_txt)
    return []


def _parse_egg_requires(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    names: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("["):
            break  # extras section — stop at first [extra] header
        parsed = parse_requirement(line)
        if parsed:
            names.append(parsed)
    return _dedupe(names)


def _deps_from_pyproject(path: Path) -> list[str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    raw = (data.get("project") or {}).get("dependencies") or []
    return _dedupe([parsed for req in raw if (parsed := parse_requirement(req))])


def _deps_from_pkg_info(audit_root: Path) -> list[str]:
    candidates = list(audit_root.glob("*.dist-info/METADATA")) + list(audit_root.glob("PKG-INFO"))
    names: list[str] = []
    for path in candidates:
        names.extend(_parse_requires_dist(path))
        if names:
            break
    return _dedupe(names)


def _parse_requires_dist(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    names: list[str] = []
    for line in text.splitlines():
        if not line.startswith("Requires-Dist:"):
            continue
        req = line.split(":", 1)[1].strip()
        parsed = parse_requirement(req)
        if parsed:
            names.append(parsed)
    return names


def _npm_deps(audit_root: Path) -> list[str]:
    package_json = audit_root / "package.json"
    if not package_json.exists():
        return []
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    deps = data.get("dependencies") or {}
    return _dedupe([name for name in deps.keys() if _looks_like_npm_name(name)])


def parse_requirement(req_str: str) -> str | None:
    req = req_str.strip()
    if not req:
        return None
    marker_part = ""
    if ";" in req:
        req, marker_part = req.split(";", 1)
        req = req.strip()
    if _marker_is_extra_only(marker_part):
        return None
    match = REQUIREMENT_NAME_RE.match(req)
    if not match:
        return None
    return match.group(1).lower()


def _marker_is_extra_only(marker: str) -> bool:
    return "extra" in marker and "==" in marker


def _looks_like_npm_name(name: str) -> bool:
    if not name:
        return False
    if name.startswith("@"):
        return "/" in name
    return bool(re.match(r"^[a-z0-9._-]+$", name))


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
