# Investigation note: npm `dist/` and vendored-code attribution

**Issue 4** from the GLaDOS web-client audit (2026-05-15).
**Decision: do NOT ship; keep current behavior.**

## The question

Should the audit walker classify npm `dist/` (and CJS `lib/` mirroring a
TS `src/`) as **vendored** — i.e. treat findings inside as belonging to
"some other package" rather than the package being scored?

The motivation: in `vite@5.4.21`, eight `obfuscation` (all `dynamic` shape)
findings live inside `dist/node/chunks/dep-*.js` and `dist/client/env.mjs`.
Under the new `dev-server-bundler` profile vite scores 53; that 24-point
obfuscation deduction is the largest remaining drag. Attributing the
`dist/` findings to vite's bundled deps (rollup, esbuild, picomatch, etc.)
would lift the score further.

## Why this would be wrong

1. **`dist/` IS the runtime in npm's distribution model.** When the user
   installs vite, the only code that executes at runtime is the contents
   of `dist/`. Compare to pypi where `src/<package>/*.py` is the runtime
   and `_vendor/`, `_distutils/` are clearly-marked "we bundled someone
   else's source verbatim." npm's `dist/` is bundled OUTPUT — it has been
   linked, tree-shaken, renamed, and is no longer separately attributable
   to its inputs.

2. **The bundle inlines code from many sources.** `dep-BK3b2jBa.js`
   imports `node:fs`, `node:path`, `node:url`, etc. and re-exports a
   mixed surface from several upstream packages. There is no single
   package to attribute these findings to. Any vendored-style filter would
   need to either (a) skip all `dist/` entirely (free pass on bundled
   payloads) or (b) attempt provenance recovery across a minified
   bundle (intractable without source maps and even then unreliable).

3. **The threat model says this is exactly what to flag.** A bundler-
   shaped malware would also use dynamic imports and `eval`/`Function`
   patterns; the obfuscation deduction is calibrated to "is this
   bundler-shaped, or attacker-shaped?" The same patterns appear in
   either case. Asking the human "look at the 8 dynamic findings before
   you accept" is the correct prompt; a free pass on `dist/` would
   subvert that.

4. **Round-8 phase 4 already addressed the `dist/` blind-spot in the
   other direction.** Before that fix, the walker skipped `dist/` entirely
   and audited zero files for jest / @sentry/node / @langchain/core.
   Re-adding a vendored-style filter would partially undo that fix.

## What the right answer actually is

The original audit's score of 8 was wrong because the **profile was
wrong**, not because the findings were wrong. Vite was being scored under
`build-tool` (correct for rollup/esbuild) but vite also runs a dev server,
and `build-tool` rightly treats `listening_port` as suspicious for pure
compilers. Issue 3 fixed this by introducing `dev-server-bundler`. Vite
now scores 53 — manual-accept band — with `listening_port` and friends
relaxed.

The remaining 24-point obfuscation deduction is correct under the
threat model and should stay. If repeated calibration on other dev-server-
bundlers (parcel, snowpack, rspack) shows that they also legitimately
have ~8 dynamic obfuscation findings, a per-profile obfuscation cap
relaxation could be considered as a follow-up — but that's a tuning
decision based on data, not a fix to this issue.

## Smoke-test reference

| package | profile | score before R9 | score after R9 |
|---|---|---:|---:|
| vite@5.4.21 | dev-server-bundler | 8 (build-tool) | 53 |
| webpack@5.97.1 | build-tool | 65 | 65 (unchanged) |
| rollup@4.60.4 | build-tool | (high) | (unchanged, pure bundler) |
| esbuild@0.21.5 | build-tool | (high) | (unchanged) |
