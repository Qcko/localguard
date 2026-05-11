# LocalGuard — session log

Cross-session memory. Newest entry at top. See global CLAUDE.md (§ "Session
handoff") for the convention. `BRIEF.md` is the immutable charter; this file
is the running log on top of it.

---

## 2026-05-11 — v0 scaffold, all detectors green, repo live

**Goal:** stand up LocalGuard from the BRIEF: `audit` → `pin` → `diff` over
Python sources, plus MCP-specific checks, with a transparent locality score
and a project-pin + global-library manifest split.

**Landed:**
- Package layout under `src/localguard/`:
  - `walker.py` — directory walk, file classification, content hash.
  - `python_ast.py` — AST detector: outbound network, listening ports,
    subprocess, FS writes, env-secret reads, `exec`/`eval` on non-literals,
    data-exfil hints (sensitive identifiers in `json=`/`data=`/`files=`/`params=`
    kwargs of outbound calls, AST-traced).
  - `text_sweep.py` — regex sweep: URLs, IPv4, env-secret references in any
    language, high-entropy long base64 blobs; dedupes hardcoded hosts.
  - `mcp_detector.py` — Python `@mcp.tool/.resource/.prompt` decorators,
    JS `server.tool(...)` / `setRequestHandler(...)`, prompt-injection-shaped
    descriptions, zero-width chars, MCP launch-config drift (`-y`, `@latest`,
    `latest` tag).
  - `rubric.py` — transparent additive deductions from 100, weights as data
    (`DEFAULT_WEIGHTS`), every deduction emitted in the report with
    `kind`/`count`/`per_finding`/`cap`/`deducted`.
  - `manifest.py` — project pin at `<project>/.localguard/pinned.json`;
    global library at `E:\localguard\library\{ecosystem}\{name}\{version}\{sha256}.json`
    with per-name `_index.json`; override path via `LOCALGUARD_LIBRARY` env var.
  - `diff.py` — novel-surface diff using signatures keyed on host/fqn/tool-name
    (refactors don't trigger drift, new hosts/tools/subprocess do).
  - `audit.py` — orchestrator; reads `pyproject.toml` / `package.json` for
    name/version/ecosystem metadata.
  - `cli.py` — argparse `audit` / `pin` / `diff` subcommands; `diff` exits 1
    when drift is present, 2 when no baseline exists.
- Fixtures under `tests/fixtures/`: `clean_pkg`, `tampered_v1` (clean),
  `tampered_v2` (network + subprocess + secret read), `mcp_clean`,
  `mcp_tampered` (new tool with injection-shaped docstring + bad mcp.json).
- 9 tests passing across audit, diff, MCP.
- Initial commit on `master`, pushed to https://github.com/Qcko/localguard
  (private). `master` tracks `origin/master`.

**State:**
- `uv run pytest` → 9/9 green.
- `uv run localguard audit tests/fixtures/tampered_v2 --pretty` produces a
  full report; tampered fixture scores 48/100 with visible deduction breakdown.
- CLI healthy (`exit=0` on clean audit, `exit=1` on drift, `exit=2` on
  missing baseline).
- Python 3.12, `uv` for env. `UV_CACHE_DIR=E:\uv\cache`.

**Open threads:**
- JS/TS detection is regex-only — works for MCP registrations, weak for
  general JS surface. Next time we touch a JS-heavy target, lift to a real
  parser (likely `tree-sitter-typescript`).
- No `localguard inspect <pkg==version>` yet — fetching from PyPI/npm into
  a tempdir and auditing was discussed but not built.
- GLaDOS integration (the original consumer) deliberately deferred — keep
  LocalGuard standalone, consumed via subprocess from GLaDOS later.
- Rubric weights are best-guess starting values; will need real-world
  calibration once we audit actual packages.

**Next:**
1. Audit a real third-party Python package (e.g. an MCP server we'd actually
   install) end-to-end; eyeball whether the score and findings make sense;
   tune weights if obvious mis-rankings appear.
2. Decide whether to build `localguard inspect <pkg==version>` or wait until
   GLaDOS install-hook integration forces the question.
