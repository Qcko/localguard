from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import fetch, inspect as inspect_mod, preflight as preflight_mod


DEFAULT_MAX_DEPTH = 5


def _format_spec(spec: "fetch.PackageSpec") -> str:
    if not spec.version:
        return spec.name
    separator = "@" if spec.ecosystem == "npm" else "=="
    return f"{spec.name}{separator}{spec.version}"


@dataclass
class TreeNode:
    name: str
    version: str | None
    ecosystem: str
    verdict: preflight_mod.Verdict | None = None
    children: list["TreeNode"] = field(default_factory=list)
    cycle: bool = False
    error: str | None = None
    truncated: bool = False

    @property
    def composed_status(self) -> str:
        if self.cycle or self.truncated:
            return "safe"  # cycles/truncations were audited elsewhere or capped by policy
        own = self.verdict.status if self.verdict else ("error" if self.error else "unknown")
        if own not in {"safe", "first-encounter-accepted"}:
            return own
        for child in self.children:
            cs = child.composed_status
            if cs not in {"safe", "first-encounter-accepted"}:
                return f"blocked-via:{child.name}={cs}"
        return "safe"

    @property
    def blocked(self) -> bool:
        return self.composed_status not in {"safe", "first-encounter-accepted"}


def audit_tree(raw_spec: str, ecosystem: str | None = None, *, max_depth: int = DEFAULT_MAX_DEPTH, cache_root: Path | None = None, library_root: Path | None = None, visited: set[tuple[str, str, str]] | None = None, specifier: str | None = None, _depth: int = 0) -> TreeNode:
    visited = visited if visited is not None else set()
    cache_root = cache_root or fetch.DEFAULT_CACHE_ROOT
    spec = _resolve_spec_with_version(raw_spec, ecosystem, specifier=specifier)
    if spec is None:
        return TreeNode(name=raw_spec, version=None, ecosystem=ecosystem or "unknown", error="could not resolve version")
    key = (spec.ecosystem, fetch.canonical_name(spec.name, spec.ecosystem), spec.version or "")
    if key in visited:
        return TreeNode(name=spec.name, version=spec.version, ecosystem=spec.ecosystem, cycle=True)
    visited.add(key)
    try:
        report, _spec_back, audit_root = inspect_mod.inspect(_format_spec(spec), ecosystem=spec.ecosystem, cache_root=cache_root)
    except Exception as exc:
        return TreeNode(name=spec.name, version=spec.version, ecosystem=spec.ecosystem, error=str(exc))
    verdict = preflight_mod.verdict_for_report(report.to_dict(), spec, library_root=library_root)
    node = TreeNode(name=spec.name, version=spec.version, ecosystem=spec.ecosystem, verdict=verdict)
    if _depth >= max_depth:
        node.truncated = True
        return node
    for dep in extract_deps(audit_root, spec.ecosystem):
        child = audit_tree(dep.name, ecosystem=spec.ecosystem, max_depth=max_depth, cache_root=cache_root, library_root=library_root, visited=visited, specifier=dep.specifier, _depth=_depth + 1)
        node.children.append(child)
    return node


def _resolve_spec_with_version(raw_spec: str, ecosystem: str | None, *, specifier: str | None = None) -> fetch.PackageSpec | None:
    spec = fetch.parse_spec(raw_spec, ecosystem_override=ecosystem)
    if spec.version:
        return spec
    try:
        version = fetch.resolve_matching_version(spec.name, spec.ecosystem, specifier) if specifier else fetch.resolve_latest_version(spec.name, spec.ecosystem)
    except fetch.FetchError:
        return None
    if not version:
        return None
    return fetch.PackageSpec(name=spec.name, version=version, ecosystem=spec.ecosystem)


def render_tree(node: TreeNode) -> str:
    lines: list[str] = []
    _render(node, lines, prefix="", is_last=True, is_root=True)
    return "\n".join(lines)


def _render(node: TreeNode, lines: list[str], *, prefix: str, is_last: bool, is_root: bool) -> None:
    connector = "" if is_root else ("`- " if is_last else "|- ")
    lines.append(prefix + connector + _node_label(node))
    if is_root:
        child_prefix = ""
    else:
        child_prefix = prefix + ("   " if is_last else "|  ")
    for i, child in enumerate(node.children):
        _render(child, lines, prefix=child_prefix, is_last=(i == len(node.children) - 1), is_root=False)


def _node_label(node: TreeNode) -> str:
    spec = f"{node.name}=={node.version or '?'} ({node.ecosystem})"
    if node.cycle:
        return f"{spec} [cycle]"
    if node.error:
        return f"{spec} [ERROR: {node.error}]"
    status = node.composed_status
    own = node.verdict.status if node.verdict else status
    tag = "OK" if status in {"safe", "first-encounter-accepted"} else "BLOCK"
    suffix = f" [{tag}: {own}]"
    if node.truncated:
        suffix += " [truncated: max-depth]"
    return spec + suffix


REQUIREMENT_NAME_RE = re.compile(r"^([A-Za-z0-9._-]+|@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)")


@dataclass(frozen=True)
class DepRequirement:
    name: str
    specifier: str | None = None

    def as_spec(self) -> str:
        return self.name


def extract_deps(audit_root: Path, ecosystem: str) -> list[DepRequirement]:
    if ecosystem == "pypi":
        return _python_deps(audit_root)
    if ecosystem == "npm":
        return _npm_deps(audit_root)
    return []


def _python_deps(audit_root: Path) -> list[DepRequirement]:
    pyproject = audit_root / "pyproject.toml"
    if pyproject.exists():
        deps = _deps_from_pyproject(pyproject)
        if deps:
            return deps
    pkg_info_deps = _deps_from_pkg_info(audit_root)
    if pkg_info_deps:
        return pkg_info_deps
    return _deps_from_egg_info(audit_root)


def _deps_from_egg_info(audit_root: Path) -> list[DepRequirement]:
    for requires_txt in audit_root.glob("*.egg-info/requires.txt"):
        return _parse_egg_requires(requires_txt)
    return []


def _parse_egg_requires(path: Path) -> list[DepRequirement]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    reqs: list[DepRequirement] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("["):
            break  # extras section — stop at first [extra] header
        parsed = parse_requirement(line)
        if parsed:
            reqs.append(parsed)
    return _dedupe(reqs)


def _deps_from_pyproject(path: Path) -> list[DepRequirement]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    raw = (data.get("project") or {}).get("dependencies") or []
    return _dedupe([parsed for req in raw if (parsed := parse_requirement(req))])


def _deps_from_pkg_info(audit_root: Path) -> list[DepRequirement]:
    candidates = list(audit_root.glob("*.dist-info/METADATA")) + list(audit_root.glob("PKG-INFO"))
    reqs: list[DepRequirement] = []
    for path in candidates:
        reqs.extend(_parse_requires_dist(path))
        if reqs:
            break
    return _dedupe(reqs)


def _parse_requires_dist(path: Path) -> list[DepRequirement]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    reqs: list[DepRequirement] = []
    for line in text.splitlines():
        if not line.startswith("Requires-Dist:"):
            continue
        req = line.split(":", 1)[1].strip()
        parsed = parse_requirement(req)
        if parsed:
            reqs.append(parsed)
    return reqs


def _npm_deps(audit_root: Path) -> list[DepRequirement]:
    package_json = audit_root / "package.json"
    if not package_json.exists():
        return []
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    deps = data.get("dependencies") or {}
    out = [DepRequirement(name=name, specifier=str(spec) if spec else None) for name, spec in deps.items() if _looks_like_npm_name(name)]
    return _dedupe(out)


def parse_requirement(req_str: str) -> DepRequirement | None:
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
    raw_name = match.group(1)
    name = fetch.canonical_name(raw_name, "npm" if raw_name.startswith("@") else "pypi")
    rest = req[match.end():].strip()
    if rest.startswith("["):
        close = rest.find("]")
        if close != -1:
            rest = rest[close + 1:].strip()
    specifier = _normalise_specifier(rest)
    return DepRequirement(name=name, specifier=specifier)


def _normalise_specifier(raw: str) -> str | None:
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("(") and raw.endswith(")"):
        raw = raw[1:-1].strip()
    return raw or None


def _marker_is_extra_only(marker: str) -> bool:
    return "extra" in marker and "==" in marker


def _looks_like_npm_name(name: str) -> bool:
    if not name:
        return False
    if name.startswith("@"):
        return "/" in name
    return bool(re.match(r"^[a-z0-9._-]+$", name))


def _dedupe(items: list[DepRequirement]) -> list[DepRequirement]:
    seen: set[str] = set()
    out: list[DepRequirement] = []
    for item in items:
        if item.name not in seen:
            seen.add(item.name)
            out.append(item)
    return out
