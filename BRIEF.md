# LocalGuard — project brief

Hand this file to a fresh Claude Code session started in the LocalGuard
working directory. It is self-contained; the new session has no memory
of the conversation that produced it.

## Why this exists

A sibling project (the maintainer's GLaDOS repo) is a local-first home assistant that will
integrate a growing list of third-party MCP servers, Python packages, and
local models. The threat we care about is **supply-chain drift**: a dependency
or MCP server that was locally-scoped on day one quietly starts phoning home,
spawning subprocesses, or pulling new hosts after an update. Classic npm /
PyPI takeover pattern.

LocalGuard is the auditing tool that gates installs and updates on a
"locality score" + a diff against a pinned-good baseline. GLaDOS is the
first consumer, but the tool should be project-agnostic.

## Goals

1. **Audit a candidate** (a Python package, an MCP server repo, a model card,
   eventually an arbitrary directory) and emit a structured JSON report:
   - outbound network surface (imports of `httpx`/`requests`/`socket`/`urllib`,
     hardcoded URLs/domains, env vars that look like API keys)
   - filesystem writes outside CWD/tmp
   - subprocess spawns (`subprocess`, `os.system`, `os.exec*`)
   - declared MCP permissions / scopes (when applicable)
   - bundled secrets, telemetry beacons, obvious obfuscation
   - a **locality score** (0–100, higher = more local) with the rubric
     visible in the report so a human can sanity-check.
2. **Diff against a pinned baseline.** Each audited artifact gets a manifest
   entry (hash + report summary). On update, re-audit and flag *new* network
   calls, *new* hosts, *new* subprocess calls, *new* deps. Most real attacks
   show up as a sudden delta, not as already-suspicious day-one code.
3. **Gate installs.** A small CLI / pre-install hook that refuses to proceed
   if the diff exceeds a threshold, with a `--review` mode for the human.

## Non-goals (for v0)

- Catching obfuscated or runtime-loaded payloads. v0 is static analysis on
  source. A determined attacker will defeat it; the goal is to catch the
  obvious 80% of supply-chain incidents (the ones that look like the
  `event-stream`, `colors.js`, `ua-parser-js`, `xz` patterns).
- Sandboxing or runtime monitoring. That is a separate, harder project.
- Cross-language support beyond Python + JS/TS source. Add others when
  needed.

## Suggested first slice (a session-sized chunk)

- `localguard audit <path>` — walks a directory, runs the static checks
  above using Python's `ast` module + regex sweep for domains/URLs, prints
  JSON.
- `localguard pin <path>` — stores the report under `.localguard/manifest/`
  keyed by content hash.
- `localguard diff <path>` — re-audits and diffs against the pinned report,
  exits non-zero if novel network/subprocess/fs surface appeared.
- Tests: a handful of fixture packages (one clean, one with a hidden
  `requests.post` to a new host, one with a new `subprocess.Popen`, one with
  obfuscated base64) that the diff command must catch.

Skip CLI polish, packaging, and a config file system until the core works.

## Conventions inherited from the user's setup

- **Prefer routing caches, models, and virtualenvs off the system drive.**
  Use the relevant env vars (`UV_CACHE_DIR`, `UV_PYTHON_INSTALL_DIR`,
  `LOCALGUARD_LIBRARY`, `LOCALGUARD_CACHE`, …) instead of hardcoding
  paths anywhere committed.
- **Tooling**: prefer `uv` for Python env + deps. Python 3.12+.
- **Code style**: Clean Code (Robert C. Martin). Rule of 7. Intent-revealing
  names. Stepdown rule for function order. Avoid comments — extract a
  well-named private function instead. Exception: niche cases where the
  extraction would be more verbose than the comment.
- **Commits**: no `Co-Authored-By` trailer, no "Generated with Claude Code"
  footer. End at the last content line.
- **Shell**: Windows 11, PowerShell primary. Use PowerShell syntax in
  examples (`$env:VAR`, not `$VAR`).

## First steps for the new session

1. Confirm scope with the user (this brief is a sketch, not a contract).
2. `uv init`, lock Python version, set up `pytest`.
3. Build the `audit` command against a tiny clean fixture, then add a
   "tampered" fixture and write the assertion.
4. Layer `pin` and `diff` on top.
5. Open the door to plug LocalGuard into GLaDOS's MCP-server install path
   once the core is green — but do not couple to GLaDOS internals; keep it
   a standalone CLI consumed via subprocess.

## Out of scope for the new session

Anything in the sibling GLaDOS repo. LocalGuard is its own repo, own
venv, own commits. GLaDOS will adopt it later as an external tool.
