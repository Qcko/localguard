# LocalGuard testing plan (round 8)

The work landed across rounds 1-7 is at a clean resting state: 24 role profiles ×
2 ecosystems, role-typicality system end-to-end, library-as-journal lifecycle
wired, 295/295 tests green. But the testing surface has known gaps that mean
silent regressions could ship — particularly around calibration drift. This
document is the executable plan for the round-8 work to harden coverage.

## Inventory of current coverage (295 tests, ~2.3s wall)

| file | what it covers | gaps |
|------|---------------|------|
| `test_audit.py` | end-to-end audit on synthetic fixtures | doesn't pin scores; doesn't exercise multi-surface stacking |
| `test_cache.py` | cache prune + mtime touch on hits | hermetic |
| `test_deps.py` | dependency-list extraction from manifests | covers shape, not deep audit consequences |
| `test_egress.py` | egress-profile generation | static-host vs dynamic-callsite split |
| `test_hook.py` | command-parsing + block-flow logic | mocks `deps.audit_tree`; never tests the full pipeline |
| `test_init_hook.py` | hook installation in claude settings | configuration plumbing |
| `test_inspect.py` | `inspect()` API surface | one fixture path |
| `test_mcp.py` | MCP detection + file-context filter (`runtime`/`tests`/`vendored`/`generated`/etc.) | thorough |
| `test_preflight.py` | verdict path, drift, blocked auto-write, latest_known_good, pinned surfaces | thorough at unit level |
| `test_profile_detection.py` | name-to-profile resolution (50+ tests across pypi+npm) | exhaustive for detection itself |
| `test_rubric.py` | per-profile relaxation rules + role-typicality computation | covers every profile's distinctive surface |
| `test_text_sweep.py` | text walker: RFC IP ranges, RFC hosts, docstrings, comments | thorough |

## Identified gaps (ranked by leverage)

**GAP 1 — Calibration regression suite (highest leverage)**

The session shipped 24 profiles with smoke-tested calibration numbers (selenium
17→62 with role_typical_share 1.0; transformers 0/100 with share 0.69 →
classified `blocked-suspicious`; ipython 0→31 with share 1.0 → classified
`blocked-role-typical`; lxml 0→17 because XXE outbound stays strict; pip 35→65
because vendored filter; etc.). These exist only in commit messages and SKILL.md.

If a future rubric change accidentally tweaks a weight or detector, every
existing unit test will still pass, but the calibration silently drifts. The
profile coverage is only useful if the numbers stay stable.

**Fix:** A `tests/calibration/` suite that audits cached real packages and
asserts pinned `(profile, score±2, role_typical_share±0.05, library_status)`.

**GAP 2 — End-to-end integration tests**

Full hook→block→library-auto-write→inspect→promote→re-install loop never tested
as a continuous flow. Promote's state transition (writing back with
`status: "accepted"`) is untested. `--pin-surfaces` at CLI level → drift behavior
on subsequent encounter is tested only at preflight unit level, not via the CLI.

**Fix:** A `tests/e2e/` suite that runs the full lifecycle on synthetic
fixtures.

**GAP 3 — NPM realism**

14 NPM categories shipped in round 7 trusting that pypi calibration transfers.
No real npm package was actually audited end-to-end. If the JS AST walker or
JS-specific patterns have a regression, no test would catch it.

**Fix:** Cached fixtures for 5-10 representative npm packages, parallel to the
pypi calibration suite.

**GAP 4 — CLI command output tests**

New commands `config show`, `profiles list`, `profiles show`, `library
blocked-review`, `library promote` have no test coverage. They're thin wrappers
around tested logic, but their text formatting and JSON output are part of the
UX contract.

**Fix:** Snapshot-style tests via `capsys`.

**GAP 5 — Allowlist hygiene**

24 PYPI_NAMES sets + 14 NPM_NAMES sets + 6 NPM_PREFIXES tuples. Easy to
accidentally add the same name to two profile allowlists; detection-order then
silently determines which one wins.

**Fix:** A `test_allowlist_hygiene.py` that asserts:
- Every pypi name is canonical PEP 503 (lowercase, hyphens not underscores).
- No name appears in two NAMES sets (would imply ambiguous classification).
- No npm prefix overlaps a name (a name on its own AND covered by a prefix).
- Every detection chain reaches the same profile regardless of order (round-trip
  through `detect_profile_from_name` for every name in every set).

**GAP 6 — Schema migration**

`AuditReport` gained four fields over the session: `status`,
`expected_surface_counts`, `ScoreBreakdown.role_typical_share`, and per-
deduction `role_typical`. Legacy library entries (written before these existed)
should still work, but only `latest_known_good_skips_blocked_entries` indirectly
covers schema compat.

**Fix:** Explicit "load legacy report" tests with handcrafted minimal JSON.

**GAP 7 — Property tests (cheap, broad)**

Pure-function invariants that should hold for every profile and every input:
- `0.0 <= role_typical_share <= 1.0` always
- `role_typical_share == 0.0` for plugin (no surface relaxed vs itself)
- Sum of (encoded + dynamic) finding counts == total OBFUSCATION findings
- `deducted` on any surface is `<= cap`
- `final_score` is in `[0, 100]`
- For any profile, the obfuscation total deduction never exceeds the profile's
  obfuscation cap

**Fix:** Add to `test_rubric.py` using hypothesis or hand-rolled coverage.

**GAP 8 — Hook block message snapshot**

The hook output is sensitive UX. The current `test_hook_blocks_low_score_install`
asserts substrings but not full layout. A snapshot of "what the user actually
sees" would catch wording / spacing / order regressions.

**Fix:** Snapshot the hook block message for two scenarios (role-typical and
suspicious).

**GAP 9 — Walker edge cases**

Triple-quoted strings with nested triple-quotes; files with BOM; mixed
encodings; syntax errors; very large files. Most edge cases are graceful, but
some might fail loudly.

**Fix:** Targeted edge-case tests in `test_text_sweep.py` and `test_audit.py`.

**GAP 10 — Concurrency**

Concurrent library writes during parallel installs. Out of scope for a single-
user CLI but worth documenting.

## Proposed test suite structure

```
tests/
├── calibration/                  # GAP 1 + GAP 3
│   ├── __init__.py
│   ├── conftest.py               # seeds cache from data/, downloads on miss with hash verify
│   ├── pinned_scores.json        # the calibration table (machine-readable, see below)
│   ├── data/                     # cached package tarballs (gitignored after first download)
│   │   ├── pypi/
│   │   └── npm/
│   ├── test_pypi_calibration.py  # parametrized over rows in pinned_scores.json
│   └── test_npm_calibration.py
├── e2e/                          # GAP 2
│   ├── __init__.py
│   ├── test_hook_to_library_loop.py
│   ├── test_promote_lifecycle.py
│   └── test_pin_surfaces_drift.py
├── snapshots/                    # GAP 4 + GAP 8
│   ├── hook_block_role_typical.txt
│   ├── hook_block_suspicious.txt
│   ├── profiles_list.txt
│   └── ...
├── test_allowlist_hygiene.py     # GAP 5 (root-level, fast)
├── test_legacy_schema.py         # GAP 6
├── test_role_typicality_properties.py  # GAP 7
└── (existing test_*.py files)
```

## The calibration table (data for GAP 1, lives in `pinned_scores.json`)

Each row is one test. Tolerance: `score ± 2`, `role_typical_share ± 0.05`.

### pypi

| spec | profile | score | role_typical_share | library_status_if_blocked |
|------|---------|-------|---------------------|---------------------------|
| `requests==2.31.0` | network-library | 100 | 0.0 | n/a (auto-accept) |
| `httpx==0.27.0` | network-library | 95 | n/a | n/a |
| `selenium==4.27.1` | scraping | 62 | 1.0 | n/a (manual-accept band) |
| `scrapy==2.12.0` | scraping | 64 | 0.83 | n/a |
| `playwright==1.49.1` | scraping | 0 | ~0.55 | blocked-suspicious |
| `transformers==4.46.3` | ml-framework | 0 | 0.69 | blocked-suspicious |
| `huggingface-hub==0.26.5` | ml-framework | 41 | n/a | n/a |
| `safetensors==0.4.5` | ml-framework | 89 | n/a | n/a |
| `accelerate==1.1.1` | ml-framework | 45 | n/a | n/a |
| `sqlalchemy==2.0.36` | database-driver | 52 | 0.19 | n/a |
| `psycopg2-binary==2.9.10` | database-driver | 80 | n/a | n/a |
| `redis==5.2.1` | database-driver | 87 | n/a | n/a |
| `pymongo==4.10.1` | database-driver | 13 | n/a | blocked-suspicious |
| `jinja2==3.1.4` | template-engine | 66 | n/a | n/a |
| `mako==1.3.6` | template-engine | 66 | n/a | n/a |
| `tox==4.23.2` | test-framework | 70 | n/a | n/a |
| `hypothesis==6.122.1` | test-framework | 18 | n/a | blocked-suspicious |
| `pytest==8.3.4` | test-framework | 21 | n/a | blocked-suspicious |
| `boto3==1.35.71` | cloud-sdk | 98 | n/a | n/a |
| `kubernetes==31.0.0` | cloud-sdk | 58 | n/a | n/a |
| `botocore==1.35.71` | cloud-sdk | 35 | n/a | blocked-suspicious |
| `sentry-sdk==2.19.0` | observability | 68 | n/a | n/a |
| `structlog==24.4.0` | observability | 95 | n/a | n/a |
| `ddtrace==2.17.3` | observability | 0 | n/a | blocked-suspicious |
| `pillow==11.0.0` | format-codec | 49 | 0.69 | n/a |
| `lxml==5.3.0` | format-codec | 17 | n/a | blocked-suspicious (XXE) |
| `pypdf==5.1.0` | format-codec | 85 | n/a | n/a |
| `django==5.1.4` | web-framework | 27 | 0.48 | blocked-suspicious |
| `fastapi==0.115.6` | web-framework | 45 | 1.0 | n/a |
| `flask==3.1.0` | web-framework | 87 | n/a | n/a |
| `gevent==24.11.1` | async-runtime | 47 | 0.89 | n/a |
| `trio==0.27.0` | async-runtime | 74 | 1.0 | n/a |
| `celery==5.4.0` | task-queue | 70 | 0.9 | n/a |
| `dramatiq==1.17.1` | task-queue | 83 | 1.0 | n/a |
| `ipython==8.30.0` | notebook-runtime | 31 | 1.0 | blocked-role-typical |
| `ipykernel==6.29.5` | notebook-runtime | 73 | 1.0 | n/a |
| `nbconvert==7.16.4` | notebook-runtime | 61 | 1.0 | n/a |
| `gradio==5.8.0` | data-app | 0 | 0.40 | blocked-suspicious |
| `streamlit==1.41.1` | data-app | 0 | 0.39 | blocked-suspicious |
| `reflex==0.6.6` | data-app | 0 | 0.67 | blocked-suspicious |
| `dagster==1.9.5` | workflow-orchestrator | 30 | 0.67 | blocked-suspicious |
| `prefect==3.1.6` | workflow-orchestrator | 0 | 0.57 | blocked-suspicious |
| `sphinx==8.1.3` | doc-builder | 33 | 0.64 | blocked-suspicious |
| `mkdocs==1.6.1` | doc-builder | 25 | 0.56 | blocked-suspicious |
| `langchain==0.3.13` | agentic-framework | 83 | 1.0 | n/a |
| `crewai==0.86.0` | agentic-framework | 0 | 0.25 | blocked-suspicious |
| `kivy==2.3.1` | gui-toolkit | 30 | 0.49 | blocked-suspicious |
| `setuptools==75.6.0` | build-tool | 26 | n/a | blocked-suspicious |
| `numpy==2.1.3` | data-science | 33 | n/a | blocked-suspicious |
| `pandas==2.2.3` | data-science | 57 | n/a | n/a |
| `pip==24.3.1` | build-tool | 65 | n/a | n/a |

### npm (round 7 — needs first-time calibration)

These are TBD — the npm allowlists shipped trusting that pypi weights transfer.
Round 8 needs to actually audit these and either confirm the expected shape or
flag where calibration differs. Suggested initial set:

| spec | profile | what we EXPECT (to be confirmed) |
|------|---------|----------------------------------|
| `express@5.0.1` | web-framework | likely manageable, similar to flask |
| `axios@1.7.9` | network-library | likely high, similar to requests |
| `jest@29.7.0` | test-framework | likely manual-accept band |
| `mongoose@8.8.4` | database-driver | likely manual-accept |
| `webpack@5.97.1` | build-tool | likely 0 or low (similar to setuptools) |
| `@aws-sdk/client-s3@3.704.0` | cloud-sdk | likely manageable |
| `@sentry/node@8.45.0` | observability | likely 60-80 band |
| `@langchain/core@0.3.27` | agentic-framework | likely manual-accept |
| `puppeteer@23.10.4` | scraping | likely manual-accept |
| `sharp@0.33.5` | format-codec | likely manual-accept |

Round 8 actions: audit each, pin the observed values, commit the JSON.

## Fixture strategy

Real package tarballs are too big to commit (~5MB each × 60 = 300MB). Two-tier
approach:

1. **Fast tier** (committed, always runs in CI):
   - Reuses existing `tests/fixtures/{clean_pkg,tampered_v1,tampered_v2}` for
     synthetic coverage of every profile category. Add 5-10 more synthetic
     fixtures designed to exercise specific role surfaces (e.g.,
     `fixtures/network_lib_shape/` with one outbound + one DSN), one per major
     profile family.
   - Calibration runs against these. Pinned scores cover the synthetic shapes
     not the real packages.

2. **Deep tier** (cached, opt-in via env var):
   - `tests/calibration/data/` downloaded on first run, cached locally.
   - Calibration runs against real packages. Pinned scores from the table
     above.
   - Skipped unless `LOCALGUARD_CALIBRATION_DEEP=1`. The user runs this
     manually after rubric changes to confirm real-world calibration is
     preserved.
   - Tarball integrity verified via SHA256 against
     `tests/calibration/data_index.json` to prevent fixture-tampering.

Fast tier becomes part of `pytest -q`. Deep tier is documented as `pytest
-q tests/calibration -m deep` or similar.

## Suggested implementation order

### Phase 1 — Quick wins (one session, ~3 hours)

Goal: ship Gaps 5, 6, 7, 4 (partial). All pure-Python, no external fixtures.

1. `test_allowlist_hygiene.py`
   - Iterates `PROFILE_WEIGHTS.keys()` and the `*_NAMES` / `*_NPM_NAMES` sets.
   - Asserts pypi names match PEP 503 canonical form.
   - Asserts no name appears in two NAMES sets in the same ecosystem.
   - Asserts every name in every set round-trips through
     `detect_profile_from_name` and resolves to its expected profile.

2. `test_legacy_schema.py`
   - Hand-crafted minimal JSON without `status`, `expected_surface_counts`,
     `role_typical_share`, `role_typical` per-deduction. Asserts
     `iter_library` produces a row, `latest_known_good` returns it (as
     accepted by legacy default), `library show` succeeds, `diff_reports`
     handles it.

3. `test_role_typicality_properties.py`
   - Parametrized over every profile and a small set of synthetic finding
     mixes (one all-strict, one all-relaxed, one mixed, one empty).
   - Asserts `0.0 <= share <= 1.0`, share is 0.0 for plugin, encoded+dynamic
     count consistency, per-surface deduction ≤ cap.

4. Snapshot tests for `config show`, `profiles list`, `profiles show plugin`
   - Use `capsys` to capture stdout.
   - Compare against `tests/snapshots/*.txt`.

### Phase 2 — E2E integration (one session, ~3 hours)

Goal: Gap 2.

1. `test_hook_to_library_loop.py`
   - Synthetic library_root in tmp_path.
   - Simulate `localguard install transformers-shaped-pkg==0.1.0` via the
     hook. Assert: block message contains role_typical_share + library_status
     + accept hint; library has a blocked-suspicious entry.
   - Simulate `localguard library blocked-review`. Assert: the entry is
     listed.
   - Simulate `localguard library promote transformers-shaped-pkg==0.1.0
     --pin-surfaces --yes`. Assert: entry now has status=accepted and
     expected_surface_counts set.
   - Simulate another install of the same package. Assert: no block.

2. `test_promote_lifecycle.py`
   - Variants: promote-without-pin, promote-with-pin, promote of
     already-accepted (no-op), promote of nonexistent (error).

3. `test_pin_surfaces_drift.py`
   - Already-accepted package with `expected_surface_counts: {env_secret_read:
     8}`. Install new version with 7 findings (within pin) -> safe. With 10
     (exceeds pin) -> drift. With same 8 but renamed identifiers -> safe under
     pin, would have been drift without pin.

### Phase 3 — Calibration regression suite (1-2 sessions)

Goal: Gap 1 + Gap 3.

1. Build `tests/calibration/conftest.py` with the two-tier fixture
   infrastructure.
2. Populate `pinned_scores.json` from the table above.
3. Implement `test_pypi_calibration.py` parametrized over the JSON rows.
4. For deep-tier, write a small `tools/seed_calibration_cache.py` that
   downloads + verifies tarballs once.
5. Run the suite, fix any pinned values that drift (i.e., the table was
   wrong for a particular package; update the JSON, not the code).
6. NPM tier: audit the 10 representative npm packages, observe the actual
   shape, write that into `pinned_scores.json` (no pre-existing expectations
   to confirm here; this IS the round-7 calibration step that was deferred).

### Phase 4 — Polish (small)

Goal: Gaps 8, 9.

1. Hook block message snapshot tests for two scenarios.
2. Walker edge case tests: BOM, nested triple-quotes, syntax errors.

## Effort estimate

| phase | sessions | wall time | risk |
|-------|----------|-----------|------|
| 1 (quick wins) | 1 | ~3 hours | low |
| 2 (e2e) | 1 | ~3 hours | medium (touches state machines) |
| 3 (calibration) | 1-2 | ~6 hours | medium (real-package shape may drift; expect to update the JSON during the session) |
| 4 (polish) | 0.5 | ~1.5 hours | low |
| **total** | **3-4** | **~13 hours** | |

## Non-goals

- Network fetching itself stays mocked at the `fetch.fetch_package` boundary.
- Real npm / pypi registry queries are NOT in test scope (cached fixtures only).
- Concurrent library writes (single-user tool).
- Performance benchmarks (the suite is fast enough; profile if it slows).

## Open questions for the next session

1. **Should `pinned_scores.json` be the source of truth, or should the
   calibration test be hardcoded?** JSON is editable; hardcoded is grep-able.
   Recommend JSON — the table is data, not logic.

2. **Tarball storage**: cached locally only (`LOCALGUARD_CALIBRATION_CACHE`
   env var pointing at a local dir), or check in to git LFS, or rely on a
   separate fixture-build step? Recommend local cache + SHA verify; no LFS;
   no commits. Same UX as the existing `$LOCALGUARD_CACHE` runtime cache.

3. **Snapshot test framework**: roll our own with `capsys.readouterr()` and
   golden-file compare, or pull in `pytest-snapshot` / `syrupy`? Recommend
   roll-our-own — keeps the dep tree clean.

4. **How tight should calibration tolerances be?** Score ±2 is generous;
   share ±0.05 ditto. Could tighten after Phase 3 if drift never exceeds ±1.

## What this WON'T catch

Even after Phase 4, the following remain uncovered:

- A profile relaxation that makes scores correct for the calibration table
  but is fundamentally too loose for novel packages (e.g., a new profile
  that absorbs all subprocess findings -- the calibration table would still
  match but the real-world threat model would be broken).
- AST walker false negatives (the walker missing a finding the rubric would
  have weighted heavily).
- Bugs in profiles where the failing target doesn't exist yet (e.g., we have
  no failing crypto-lib targets; if one emerges, no test will flag it).

These are inherent to any test suite — calibration catches drift on KNOWN
behavior, not unknown unknowns. Real-world install attempts plus the
role-typicality / journal UX is how those get surfaced.
