# LocalGuard

Static-analysis auditor that gates third-party Python / JS packages and MCP servers
on a transparent **locality score** and a **diff against a pinned baseline**.
The threat model is *supply-chain drift*: a dependency that was local on day one
quietly grows network calls, subprocesses, or new MCP tools on update.

## CLI

```powershell
uv run localguard audit <path> [--pretty]   # JSON report
uv run localguard pin   <path>              # write .localguard/pinned.json + global library entry
uv run localguard diff  <path> [--pretty]   # exit 1 if novel surface appeared
```

Global library location is required via `LOCALGUARD_LIBRARY`; cache via
`LOCALGUARD_CACHE`. Both should point at writeable directories outside
your project tree (e.g. `%USERPROFILE%\.localguard\library`). Project
pin lives at `<project>/.localguard/pinned.json`.

## Surfaces detected (v0)

- Outbound network (`requests`, `httpx`, `urllib`, `socket.connect`, `aiohttp`, `websockets`)
- **Listening ports** (`socket.bind/listen`, `socketserver`, `http.server`, `asyncio.start_server`, `uvicorn.run`)
- Subprocess (`subprocess.*`, `os.system`, `os.exec*`, `os.spawn*`, `pty.spawn`)
- Filesystem writes (`open(w/a/x)`, `Path.write_*`, `shutil.copy*`)
- Secret-shaped env reads (`os.getenv("API_KEY")`, `process.env.TOKEN`, …)
- Hardcoded hosts / telemetry endpoints (Sentry, Mixpanel, Segment, PostHog, GA, Datadog, …)
- Obfuscation (`exec`/`eval`/`compile` on non-literal, long high-entropy base64 blobs)
- **Data-exfil hints** (outbound `json=`/`data=`/`files=` referencing token/password/env)
- **MCP** tools/resources, prompt-injection-shaped descriptions, zero-width chars,
  launch-config drift (`-y`, `@latest`)

## Locality score

Starts at 100, deducted by transparent weights (see `rubric.DEFAULT_WEIGHTS`).
Every deduction appears in the report with `kind`, `count`, `per_finding`, `cap`, `deducted`.
The weights are data, not magic numbers — argue with them in code review.

## Layout

```
src/localguard/
  walker.py        directory walk + content hash
  python_ast.py    AST detector for Python sources
  text_sweep.py    regex sweep (URLs, IPs, env secrets, base64 blobs)
  mcp_detector.py  MCP tool registrations + injection + launch config
  rubric.py        weighted scoring with visible breakdown
  manifest.py      project pin + global library (per-ecosystem)
  diff.py          novel-surface diff between two reports
  audit.py         orchestrator
  cli.py           argparse: audit / pin / diff
tests/
  fixtures/clean_pkg, tampered_v1, tampered_v2, mcp_clean, mcp_tampered
```

## Non-goals (v0)

- Sandboxing / runtime monitoring.
- Catching obfuscated or runtime-loaded payloads beyond obvious markers.
- Cross-language support beyond Python + JS/TS surfaces.
