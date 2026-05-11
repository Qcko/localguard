# LocalGuard — session log

Cross-session memory. Newest entry at top. See global CLAUDE.md (§ "Session
handoff") for the convention. `BRIEF.md` is the immutable charter; this file
is the running log on top of it.

---

## 2026-05-11 — v0.2: `localguard inspect <pkg>` against real PyPI/npm

**Goal:** make LocalGuard usable against the real world — fetch a package
from PyPI or npm by name+version, audit it in a cache dir, without the user
having to `pip download` manually first.

**Landed:**
- `fetch.py` — spec parsing (`pkg`, `pkg==ver`, `@scope/pkg@ver`), ecosystem
  auto-detection (scoped names → npm), download via PyPI/npm JSON registries
  using stdlib `urllib` (no `pip`/`npm`/`uv pip download` dependency — easier
  to reason about, fewer moving parts). Path-traversal-safe tar extraction
  via `filter="data"` and pre-check. Cache at
  `E:\localguard\cache\{ecosystem}\{name}\{version}\src\`, override via
  `LOCALGUARD_CACHE`. Cache hits short-circuit the download.
- `inspect.py` — orchestrator; fetches, picks the right audit root
  (`package/` inside npm tarballs, single-dir inside PyPI sdists), reuses
  `audit.audit_path`, overrides metadata from the spec so name/ecosystem are
  authoritative even if the tarball lacks pyproject.toml.
- CLI: `localguard inspect <spec> [--ecosystem pypi|npm] [--pretty]`.
- Tests: spec parsing (pypi versioned/unversioned, npm scoped, npm bare,
  invalid), cache-hit short-circuit, end-to-end audit via synthetic tarball
  (no network in tests). 16/16 green.

**State:**
- Real-world smoke tests pass:
  - `six==1.16.0` → 96/100 (two hardcoded URLs in setup.py / docs).
  - `requests==2.31.0` → 0/100 (118 outbound calls, 60 hosts, 3 obfuscation
    hits, 2 subprocess — all caps kicked in correctly).
- Cache works: re-running on a fetched spec skips download.

**Open threads / roadmap (deferred slices):**
- **Dependency recursion** — `inspect` audits only the named package, not
  its declared dependencies (`[project] dependencies` / `package.json
  dependencies`). This is *important for the finished product*: most
  supply-chain attacks come in through transitive deps. Own slice. Needs a
  design pass on cycles, version ranges, lockfile semantics, and how the
  aggregated score / drift report composes across the tree.
- **Pre-install hook** — wrap `uv add` / `pip install` / `npm install` so
  installs are actually gated on a clean diff. Depends on `inspect` +
  dependency recursion.
- **JS/TS proper parser** — current JS detection is regex-only; works for
  MCP registrations, weak for general surface. Lift to `tree-sitter-typescript`
  next time we touch a JS-heavy target.
- **`requests` obfuscation hits** — three base64-blob flags on `requests`
  worth eyeballing before next calibration pass; could be test fixtures or
  cert bundles → false positives.
- **GLaDOS integration** — deliberately deferred. Keep LocalGuard standalone,
  consumed via subprocess from GLaDOS later.
- **Rubric calibration** — now possible via `inspect`; eyeball a handful of
  packages we'd actually install and tune. `requests` at 0/100 is correct
  for a network library but suggests we may want an "intended-network"
  baseline flag for libraries whose purpose *is* the network.

**Next:**
1. Calibration pass: run `inspect` on ~5 real MCP servers + commonly-installed
   Python deps; eyeball whether scores rank them sensibly. Tune weights or
   add an `intended-network` baseline if needed.
2. Decide: dependency recursion next, or pre-install hook for the
   single-package case first?

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

**Open threads / roadmap (deferred slices):**
- **Dependency recursion** — `inspect` audits only the named package, not
  its declared dependencies (`[project] dependencies` / `package.json
  dependencies`). This is *important for the finished product*: most
  supply-chain attacks come in through transitive deps. Own slice. Needs a
  design pass on cycles, version ranges, lockfile semantics, and how the
  aggregated score / drift report composes across the tree.
- **Pre-install hook** — wrap `uv add` / `pip install` / `npm install` so
  installs are actually gated on a clean diff. Depends on `inspect` +
  dependency recursion.
- **JS/TS proper parser** — current JS detection is regex-only; works for
  MCP registrations, weak for general surface. Lift to `tree-sitter-typescript`
  next time we touch a JS-heavy target.
- **GLaDOS integration** — deliberately deferred. Keep LocalGuard standalone,
  consumed via subprocess from GLaDOS later.
- **Rubric calibration** — current weights are best-guess. Once `inspect`
  exists, run it on a handful of real MCP servers / Python packages, eyeball
  rankings, tune.

**Next:**
1. Audit a real third-party Python package (e.g. an MCP server we'd actually
   install) end-to-end; eyeball whether the score and findings make sense;
   tune weights if obvious mis-rankings appear.
2. Decide whether to build `localguard inspect <pkg==version>` or wait until
   GLaDOS install-hook integration forces the question.
