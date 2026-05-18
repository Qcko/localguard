from __future__ import annotations

import json
import os
import re
import shlex
import sys
import tomllib
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

from . import deps as deps_mod


SPEC_PATTERN = re.compile(r"^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+(?:[@=]{1,2}[A-Za-z0-9._+\-]+)?$")

_GATED_TOOLS = {"Bash", "PowerShell"}


@dataclass(frozen=True)
class ExtractedInstall:
    ecosystem: str
    specs: list[str]
    profile_hint: str | None = None
    profile_reason: str | None = None
    block_reason: str | None = None


def _parse_payload(text: str) -> dict | None:
    text = text.strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def run_hook(stdin_text: str, stderr=sys.stderr, stdout=sys.stdout) -> int:
    payload = _parse_payload(stdin_text)
    if payload is None or payload.get("tool_name") not in _GATED_TOOLS:
        return 0
    command = (payload.get("tool_input") or {}).get("command") or ""
    cwd = payload.get("cwd") or os.getcwd()
    installs = extract_installs(command, cwd=cwd)
    if not installs:
        return 0
    blockers: list[str] = []
    for install in installs:
        if install.block_reason and not install.specs:
            stderr.write(f"[localguard] BLOCK ({install.ecosystem}): {install.block_reason}\n")
            blockers.append(f"({install.ecosystem}): {install.block_reason}")
            continue
        for spec in install.specs:
            try:
                node = deps_mod.audit_tree(spec, ecosystem=install.ecosystem, profile=install.profile_hint, profile_reason=install.profile_reason)
            except Exception as exc:
                stderr.write(f"[localguard] BLOCK {spec} ({install.ecosystem}): preflight error: {exc}\n")
                blockers.append(f"{spec} ({install.ecosystem}): preflight-error")
                continue
            status = node.composed_status
            if node.blocked:
                stderr.write(f"[localguard] BLOCK {spec} ({install.ecosystem}) status={status}\n")
                stderr.write(deps_mod.render_tree(node) + "\n")
                role_typicality_line = _role_typicality_summary(node)
                if role_typicality_line:
                    stderr.write(role_typicality_line + "\n")
                if _has_only_first_encounter_blockers(node):
                    stderr.write(f"  -> run `localguard accept --with-deps {spec}` to baseline this closure\n")
                blockers.append(f"{spec} ({install.ecosystem}): {status}")
            else:
                stdout.write(f"[localguard] OK {spec} ({install.ecosystem}) status={status}\n")
    if blockers:
        stderr.write("[localguard] blocked install: " + "; ".join(blockers) + "\n")
        return 2
    return 0


def _role_typicality_summary(node) -> str:
    """One-line breakdown of role-typicality for low-score blocked nodes.

    Helps the user decide whether to force-accept: a high share with a
    blocked-role-typical library status means the findings match the
    package's documented role and force-acceptance is likely safe after
    a quick look at any role-atypical findings. A low share or a
    blocked-suspicious status means the deductions land on strict
    surfaces and warrant real review.
    """
    fragments: list[str] = []
    for n in _walk_tree(node):
        v = n.verdict
        if not v or v.status != "low-score":
            continue
        if v.library_status is None:
            continue
        spec = f"{n.name}=={n.version or '?'}"
        if v.library_status == "blocked-role-typical":
            advice = (
                f"most deductions are surfaces this role inherently uses -- "
                f"`localguard accept {spec}` is likely safe after a quick read of "
                f"the strict-surface findings"
            )
        else:
            advice = (
                f"role-atypical deductions dominate -- read the report carefully "
                f"before considering `localguard accept {spec}`"
            )
        fragments.append(
            f"  -> {spec}: {v.library_status} "
            f"(role_typical_share={v.role_typical_share:.0%}); "
            f"`localguard inspect {spec} --pretty` to review. "
            f"{advice}."
        )
    return "\n".join(fragments)


def _has_only_first_encounter_blockers(node) -> bool:
    for n in _walk_tree(node):
        if n.cycle or n.truncated:
            continue
        own = n.verdict.status if n.verdict else None
        if own in {"safe", "first-encounter-accepted", "first-encounter-needs-accept", None}:
            continue
        return False
    return True


def _walk_tree(node):
    yield node
    for c in node.children:
        yield from _walk_tree(c)


def extract_installs(command: str, cwd: str | None = None) -> list[ExtractedInstall]:
    installs: list[ExtractedInstall] = []
    for fragment in _split_chained(command):
        try:
            tokens = shlex.split(fragment, posix=False)
        except ValueError:
            continue
        if not tokens:
            continue
        install = _classify(tokens, cwd)
        if install is None:
            continue
        if install.specs or install.block_reason:
            installs.append(install)
    return installs


def _split_chained(command: str) -> list[str]:
    parts = re.split(r"\s*(?:&&|\|\||\||;)\s*", command)
    return [p.strip() for p in parts if p.strip()]


_REDIRECT_TOKEN = re.compile(r"^\d*[<>]+&?\d*$")


def _classify(tokens: list[str], cwd: str | None = None) -> ExtractedInstall | None:
    head = tokens[0].lower()
    # Runner-style verbs imply "fetch and run as a standalone tool" -- the
    # user's deliberate choice of invocation is a strong signal that the
    # target is a server/tool, not a library import. Apply mcp-server profile.
    if head == "uvx":
        return ExtractedInstall(ecosystem="pypi", specs=_specs_after_flags(tokens[1:]), profile_hint="mcp-server", profile_reason="install-verb: uvx")
    if head == "pipx" and len(tokens) >= 2 and tokens[1].lower() in {"install", "run"}:
        verb = f"pipx {tokens[1].lower()}"
        return ExtractedInstall(ecosystem="pypi", specs=_specs_after_flags(tokens[2:]), profile_hint="mcp-server", profile_reason=f"install-verb: {verb}")
    if head == "uv" and len(tokens) >= 3 and tokens[1].lower() == "tool" and tokens[2].lower() in {"install", "run"}:
        verb = f"uv tool {tokens[2].lower()}"
        return ExtractedInstall(ecosystem="pypi", specs=_specs_after_flags(tokens[3:]), profile_hint="mcp-server", profile_reason=f"install-verb: {verb}")
    if head == "npx" and len(tokens) >= 2 and _has_yes_flag(tokens[1:]):
        return ExtractedInstall(ecosystem="npm", specs=_specs_after_flags(tokens[1:]), profile_hint="mcp-server", profile_reason="install-verb: npx -y")
    # Regular install verbs -- profile defaults to plugin; later auto-detect
    # passes (name convention, content) may still upgrade to mcp-server.
    if head in {"pip", "pip3"} and len(tokens) >= 2 and tokens[1].lower() == "install":
        return ExtractedInstall(ecosystem="pypi", specs=_specs_after_flags(tokens[2:]))
    if head == "uv" and len(tokens) >= 2:
        sub = tokens[1].lower()
        if sub == "add":
            return ExtractedInstall(ecosystem="pypi", specs=_specs_after_flags(tokens[2:]))
        if sub == "pip" and len(tokens) >= 3 and tokens[2].lower() == "install":
            return ExtractedInstall(ecosystem="pypi", specs=_specs_after_flags(tokens[3:]))
        if sub == "pip" and len(tokens) >= 3 and tokens[2].lower() == "sync":
            files = _requirement_file_args(tokens[3:])
            if not files:
                return ExtractedInstall(
                    ecosystem="pypi",
                    specs=[],
                    block_reason=(
                        "`uv pip sync` invoked without a requirements file "
                        "argument -- nothing to audit"
                    ),
                )
            specs = _resolve_requirements_specs(cwd, files)
            if specs is None:
                return ExtractedInstall(
                    ecosystem="pypi",
                    specs=[],
                    block_reason=(
                        f"`uv pip sync` requirements file(s) "
                        f"{files!r} not readable from cwd={cwd!r} -- "
                        f"audit manually before running"
                    ),
                )
            if not specs:
                return None
            return ExtractedInstall(ecosystem="pypi", specs=specs, profile_reason="install-verb: uv pip sync")
        if sub in {"sync", "lock"}:
            verb = f"uv {sub}"
            specs = _resolve_uv_project_specs(cwd, tokens[1:])
            if specs is None:
                return ExtractedInstall(
                    ecosystem="pypi",
                    specs=[],
                    block_reason=(
                        f"`{verb}` invoked but no readable pyproject.toml "
                        f"found from cwd={cwd!r} -- audit declared "
                        f"dependencies manually before running"
                    ),
                )
            if not specs:
                return None
            return ExtractedInstall(ecosystem="pypi", specs=specs, profile_reason=f"install-verb: {verb}")
    if head in {"npm", "pnpm"} and len(tokens) >= 2:
        sub = tokens[1].lower()
        if sub in {"install", "i", "add"}:
            return ExtractedInstall(ecosystem="npm", specs=_specs_after_flags(tokens[2:]))
    if head == "yarn" and len(tokens) >= 2 and tokens[1].lower() == "add":
        return ExtractedInstall(ecosystem="npm", specs=_specs_after_flags(tokens[2:]))
    return None


_PEP508_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

_REQ_FLAGS_WITH_VALUE = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable"}


def _requirement_file_args(tokens: list[str]) -> list[str]:
    """Positional arguments to `uv pip sync` are requirements files.
    Skip flag values and flags that don't name files."""
    files: list[str] = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in _REQ_FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if tok.startswith("--") and "=" in tok:
            continue
        if tok.startswith("-"):
            continue
        files.append(tok)
    return files


def _resolve_requirements_specs(cwd: str | None, files: list[str], *, _seen: set[Path] | None = None) -> list[str] | None:
    """Read requirements files and return declared package names.
    Recurses one level into `-r other.txt` includes. Returns None if any
    listed file is unreadable (conservative BLOCK)."""
    if _seen is None:
        _seen = set()
    base = Path(cwd) if cwd else Path.cwd()
    names: list[str] = []
    seen_names: set[str] = set()

    def _add(name: str) -> None:
        key = name.lower()
        if key in seen_names:
            return
        seen_names.add(key)
        names.append(name)

    for raw in files:
        path = Path(raw)
        if not path.is_absolute():
            path = base / path
        try:
            path = path.resolve()
        except OSError:
            return None
        if path in _seen:
            continue
        _seen.add(path)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith(("-r ", "--requirement ")):
                nested = line.split(None, 1)[1].strip()
                nested_specs = _resolve_requirements_specs(str(path.parent), [nested], _seen=_seen)
                if nested_specs is None:
                    return None
                for n in nested_specs:
                    _add(n)
                continue
            if line.startswith("-"):
                continue
            spec = line.split(";", 1)[0].strip()  # drop env marker
            m = _PEP508_NAME.match(spec)
            if m:
                _add(m.group(1))
    return names


def _resolve_uv_project_specs(cwd: str | None, sub_tokens: list[str]) -> list[str] | None:
    """Read pyproject.toml from `cwd` (or --project / --directory override)
    and return the declared dependency names. Returns None if no pyproject
    is found or it cannot be parsed -- callers convert that into a BLOCK.
    """
    project_root = _find_uv_project_root(cwd, sub_tokens)
    if project_root is None:
        return None
    pyproject = project_root / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    names: list[str] = []
    seen: set[str] = set()

    def _collect(entries):
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, str):
                continue
            m = _PEP508_NAME.match(entry)
            if not m:
                continue
            key = m.group(1).lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(m.group(1))

    project = data.get("project") or {}
    _collect(project.get("dependencies"))
    for group in (project.get("optional-dependencies") or {}).values():
        _collect(group)
    for group in (data.get("dependency-groups") or {}).values():
        _collect(group)
    return names


def _find_uv_project_root(cwd: str | None, sub_tokens: list[str]) -> Path | None:
    override = _extract_uv_project_override(sub_tokens)
    if override is not None:
        candidate = Path(override)
        if not candidate.is_absolute() and cwd:
            candidate = Path(cwd) / candidate
        return candidate if (candidate / "pyproject.toml").is_file() else None
    start = Path(cwd) if cwd else Path.cwd()
    for parent in (start, *start.parents):
        if (parent / "pyproject.toml").is_file():
            return parent
    return None


def _extract_uv_project_override(sub_tokens: list[str]) -> str | None:
    i = 0
    while i < len(sub_tokens):
        tok = sub_tokens[i]
        if tok in {"--project", "--directory"} and i + 1 < len(sub_tokens):
            return sub_tokens[i + 1]
        if tok.startswith("--project=") or tok.startswith("--directory="):
            return tok.split("=", 1)[1]
        i += 1
    return None


def _has_yes_flag(args: list[str]) -> bool:
    return any(t in {"-y", "--yes"} for t in args)


def _specs_after_flags(args: list[str]) -> list[str]:
    specs: list[str] = []
    skip_next = False
    for token in args:
        if skip_next:
            skip_next = False
            continue
        if _REDIRECT_TOKEN.match(token):
            break  # shell redirection — anything after is not pkg args
        token = _strip_surrounding_quotes(token)
        if token.startswith("-"):
            if token in {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target"}:
                skip_next = True
            continue
        normalized = _normalize_spec(token)
        if normalized is None:
            continue
        specs.append(normalized)
    return specs


def _strip_surrounding_quotes(token: str) -> str:
    # shlex.split(posix=False) preserves surrounding quotes -- callers
    # quote PEP 508 specs like "piper-tts>=1.4.2" to keep the shell from
    # eating the `>`, and the quotes ride along into the token.
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ('"', "'"):
        return token[1:-1]
    return token


_NAME_END_RE = re.compile(r"[=<>~^!@]")
_VERSION_OPERATOR_CHARS = set("=<>~^!")


def _normalize_spec(token: str) -> str | None:
    """Return the form to pass downstream, or None if the token is not a
    registry identifier. Exact-pin forms (`pkg==X`, npm `pkg@1.2.3`) are
    preserved so audit_tree pins the audited version; range / inequality
    forms (`>=`, `^`, `~`, ...) are stripped to the bare name and
    audit_tree resolves the latest matching version."""
    name, version = _split_name_version(token)
    if not _looks_like_registry_spec(name):
        return None
    if version is None:
        return name
    if _is_literal_version(version):
        return token
    return name


def _split_name_version(token: str) -> tuple[str, str | None]:
    if token.startswith("@"):
        at_idx = token.find("@", 1)
        if at_idx == -1:
            return token, None
        return token[:at_idx], token[at_idx + 1 :]
    m = _NAME_END_RE.search(token)
    if not m:
        return token, None
    return token[: m.start()], token[m.start() :]


def _is_literal_version(version: str) -> bool:
    """A literal version part has no range operators. npm: bare `X.Y.Z`.
    pypi exact pin: leading `==` followed by no further operator chars."""
    if not any(c in _VERSION_OPERATOR_CHARS for c in version):
        return True  # npm `pkg@1.2.3` form
    if version.startswith("==") and not any(c in _VERSION_OPERATOR_CHARS for c in version[2:]):
        return True  # pypi exact pin
    return False


def _looks_like_registry_spec(token: str) -> bool:
    if any(sep in token for sep in ("/", "\\", ":")) and not token.startswith("@"):
        return False
    if token.endswith((".txt", ".whl", ".tar.gz", ".tgz")):
        return False
    if token in {".", ".."}:
        return False
    return bool(SPEC_PATTERN.match(token))


def main_entry() -> int:
    return run_hook(sys.stdin.read())


def render_to_string(stdin_text: str) -> tuple[int, str, str]:
    out, err = StringIO(), StringIO()
    code = run_hook(stdin_text, stderr=err, stdout=out)
    return code, out.getvalue(), err.getvalue()
