from __future__ import annotations

import json
import re
import shlex
import sys
from dataclasses import dataclass
from io import StringIO

from . import deps as deps_mod


SPEC_PATTERN = re.compile(r"^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+(?:[@=]{1,2}[A-Za-z0-9._+\-]+)?$")


@dataclass(frozen=True)
class ExtractedInstall:
    ecosystem: str
    specs: list[str]
    profile_hint: str | None = None
    profile_reason: str | None = None


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
    if payload is None or payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command") or ""
    installs = extract_installs(command)
    if not installs:
        return 0
    blockers: list[str] = []
    for install in installs:
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
                if _has_only_first_encounter_blockers(node):
                    stderr.write(f"  -> run `localguard accept --with-deps {spec}` to baseline this closure\n")
                blockers.append(f"{spec} ({install.ecosystem}): {status}")
            else:
                stdout.write(f"[localguard] OK {spec} ({install.ecosystem}) status={status}\n")
    if blockers:
        stderr.write("[localguard] blocked install: " + "; ".join(blockers) + "\n")
        return 2
    return 0


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


def extract_installs(command: str) -> list[ExtractedInstall]:
    installs: list[ExtractedInstall] = []
    for fragment in _split_chained(command):
        try:
            tokens = shlex.split(fragment, posix=False)
        except ValueError:
            continue
        if not tokens:
            continue
        install = _classify(tokens)
        if install and install.specs:
            installs.append(install)
    return installs


def _split_chained(command: str) -> list[str]:
    parts = re.split(r"\s*(?:&&|\|\||\||;)\s*", command)
    return [p.strip() for p in parts if p.strip()]


_REDIRECT_TOKEN = re.compile(r"^\d*[<>]+&?\d*$")


def _classify(tokens: list[str]) -> ExtractedInstall | None:
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
    if head in {"npm", "pnpm"} and len(tokens) >= 2:
        sub = tokens[1].lower()
        if sub in {"install", "i", "add"}:
            return ExtractedInstall(ecosystem="npm", specs=_specs_after_flags(tokens[2:]))
    if head == "yarn" and len(tokens) >= 2 and tokens[1].lower() == "add":
        return ExtractedInstall(ecosystem="npm", specs=_specs_after_flags(tokens[2:]))
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
        if token.startswith("-"):
            if token in {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target"}:
                skip_next = True
            continue
        if not _looks_like_registry_spec(token):
            continue
        specs.append(token)
    return specs


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
