from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from . import walker
from .report import Finding, ScoreBreakdown, SurfaceKind


@dataclass(frozen=True)
class Weight:
    per_finding: int
    cap: int


PLUGIN_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(5, 25),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(10, 40),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(15, 40),
    SurfaceKind.FS_WRITE: Weight(5, 15),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(2, 10),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# An MCP server's purpose is to expose tools to a model: spawning subprocesses
# (stdio transport), listening on ports (HTTP/SSE transport), reaching outbound
# (HTTP client tools, web-search tools), and writing files (filesystem servers)
# are all *features*, not red flags. Relax those surfaces; keep strict on the
# ones that signal supply-chain trouble regardless of role (obfuscation, secret
# reads, hardcoded C2-style hosts, prompt-injection-shaped tool descriptions,
# MCP transport config drift, data-exfil identifier patterns).
MCP_SERVER_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(2, 10),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(4, 20),
    SurfaceKind.LISTENING_PORT: Weight(0, 0),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(2, 10),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A CLI framework's whole purpose is to dispatch user-supplied commands to
# subprocesses and write user-requested output to disk. Relax those two surfaces.
# Stay strict on everything network-shaped (a CLI tool reaching the network
# unprompted is suspicious), on obfuscation (CLIs don't legitimately need eval),
# and on the strict-by-design surfaces (env_secret_read, telemetry, data-exfil).
CLI_FRAMEWORK_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(5, 25),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(10, 40),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(2, 10),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(2, 10),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A web application framework (django, flask, fastapi, starlette, sanic,
# tornado, ...) is a full-stack monolith: it runs management commands
# (subprocess), writes sessions / file uploads / migrations / static
# assets (fs_write), binds a dev-server port (listening_port), and
# occasionally reaches out to test fixtures or service-discovery endpoints
# (outbound). Distinct from web-server (uvicorn/gunicorn -- pure HTTP
# runners): a web-framework is the app layer that holds routing,
# middleware, ORM helpers, template integration, and the dev workflow.
# Relax subprocess + fs_write + listening_port + outbound + hardcoded_host.
# Stay strict on obfuscation (django legitimately compile()s URL patterns,
# but that surface is exactly where an attacker would hide too) and on
# env_secret_read (SECRET_KEY / DATABASE_URL / JWT_SECRET reads are the
# supply-chain target -- "django legitimately reads SECRET_KEY" and
# "compromised django exfiltrates SECRET_KEY" are indistinguishable).
WEB_FRAMEWORK_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(2, 10),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(4, 20),
    SurfaceKind.LISTENING_PORT: Weight(5, 20),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A browser-automation / scraping library's purpose is fetching arbitrary
# user-supplied URLs (outbound_dynamic IS the role), launching browser
# binaries or spider workers (subprocess), running a browser control
# protocol locally (listening_port -- playwright's CDP/WebSocket inspector),
# and writing scraped output or screenshots to disk (fs_write). Relax all
# of those. Stay strict on obfuscation, env_secret_read (real credentials
# remain credentials), telemetry, data_exfil, and the strict-by-design
# surfaces -- a malicious scraping lib that wants to exfiltrate creds still
# pays full price on those.
SCRAPING_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(2, 10),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(2, 10),
    SurfaceKind.LISTENING_PORT: Weight(5, 20),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A format / codec library's purpose is parsing or emitting file formats
# (images, XML/HTML, spreadsheets, PDFs, audio) -- they shell out to native
# decoders (libjpeg, libxml2, pandoc, ffmpeg), write tempfiles and decoded
# output to disk. Relax subprocess and fs_write. KEEP STRICT OUTBOUND
# (XML/HTML parsers fetching external entities is the XXE attack surface --
# lxml's outbound findings are legitimately suspicious and the right answer
# is manual review or `defusedxml`). Keep strict env_secret_read and the
# strict-by-design surfaces.
FORMAT_CODEC_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(5, 25),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(10, 40),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A template engine's whole job is to compile() user-supplied template
# strings into Python bytecode. Obfuscation findings will be high by
# construction. Lower the obfuscation cap (30 vs plugin's 60) so a
# template engine doesn't auto-zero, but DO NOT lower per-finding -- a
# template lib with 20 distinct compile() callsites is still a stronger
# signal than one with 5, and an attacker payload would add new
# callsites just like legitimate template features. Stay strict on
# everything else: a template engine should not network, listen, or shell.
TEMPLATE_ENGINE_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(5, 25),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(10, 40),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(15, 40),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(2, 10),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 30),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A test framework's purpose is forking worker processes (xdist), writing
# coverage reports / cache / junit XML, and parsing argv. Relax subprocess,
# fs_write, hardcoded_host (CI URLs in default templates). Stay strict on
# outbound (a test framework reaching the network unprompted is suspicious),
# obfuscation (pytest's plugin magic is suspicious-shaped but a real attacker
# could hide payloads in the same surface), listening_port, and the
# strict-by-design surfaces.
TEST_FRAMEWORK_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(5, 25),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(10, 40),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A cloud SDK's purpose is making API calls to provider endpoints (regional
# hostnames built from region + service), reading credentials from env vars
# (AWS_*, GOOGLE_*, AZURE_*), and writing credential / cache files to disk.
# Relax outbound + outbound_dynamic + hardcoded_host + fs_write. Stay strict
# on subprocess (a cloud SDK should not shell out), listening_port, and on
# env_secret_read (the credentials a cloud SDK reads are EXACTLY what an
# attacker wants -- "boto3 legitimately reads AWS_SECRET_ACCESS_KEY" and
# "compromised boto3 exfiltrates AWS_SECRET_ACCESS_KEY" are observationally
# indistinguishable; manual accept is the right answer for high-count cases).
CLOUD_SDK_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(2, 10),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(4, 20),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(15, 40),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# An observability library's purpose is to send telemetry to a backend --
# the TELEMETRY_ENDPOINT surface IS the role. Without relaxing it, sentry-sdk
# / opentelemetry-* / datadog all sit at low scores by default. Relax
# telemetry_endpoint (2/cap 10), outbound_network, outbound_dynamic,
# hardcoded_host, and fs_write (buffer / span files). Stay strict on
# subprocess, listening_port, env_secret_read (DSN tokens are credentials),
# obfuscation, and the strict-by-design surfaces.
OBSERVABILITY_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(2, 10),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(4, 20),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(15, 40),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(2, 10),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A database driver / ORM's purpose is to open outbound connections to a
# specific protocol on a user-supplied host (DSN parsing -> outbound_dynamic),
# to read connection credentials from env vars (DATABASE_URL et al), and to
# parse/execute SQL or DSL (sqlalchemy compiles expression trees via
# compile()). Relax outbound_network, outbound_dynamic, hardcoded_host, and
# fs_write (SQLite spool files, connection caches). Stay strict on
# listening_port (drivers are clients, not servers), subprocess (a database
# *driver* spawning shells is suspicious), obfuscation (sqlalchemy's
# legitimate compile() usage would mask attacker payloads on the same
# surface), env_secret_read (connection strings ARE credentials), and the
# strict-by-design surfaces.
DATABASE_DRIVER_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(2, 10),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(4, 20),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(15, 40),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# An ML framework's purpose stretches data-science relaxations further:
# training forks worker processes (subprocess), opens NCCL/Gloo sockets
# for distributed training (listening_port), writes checkpoints + logs +
# tensorboard runs (fs_write), downloads model weights and datasets from
# HuggingFace / model hubs (outbound_network + outbound_dynamic +
# hardcoded_host), and links CUDA / mmaps GPU shared memory at import.
# Relax those six surfaces. Stay strict on obfuscation (same reasoning as
# setuptools/numpy: legitimate eval in framework code would mask attacker
# payloads in the same surface) and on the strict-by-design surfaces.
ML_FRAMEWORK_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(2, 10),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(4, 20),
    SurfaceKind.LISTENING_PORT: Weight(5, 20),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A numerical/data-science library's purpose is parallel compute (joblib /
# multiprocessing forks -> subprocess), saving arrays/dataframes/models/plots
# (fs_write), and optionally downloading reference datasets (outbound_dynamic
# pointing at well-known dataset hosts). Relax those surfaces.
# Stay strict on outbound_network at the plugin baseline (a numerical library
# making unsolicited calls is still suspicious), on listening_port, on
# obfuscation (numpy/pandas DO have legitimate eval -- df.eval, df.query,
# ufunc string compilation -- but so might an attacker; force manual review),
# and on the strict-by-design surfaces.
DATA_SCIENCE_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(5, 25),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(4, 20),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A Python build backend / packaging tool's purpose is to invoke compilers and
# linkers (subprocess), write wheels and source distributions to disk
# (fs_write), and fetch build dependencies / index metadata over the network
# (outbound, hardcoded_host pointing at pypi.org). Relax those four surfaces.
# Keep obfuscation strict -- vendored eval in a build tool is the
# supply-chain holy grail; the cost of false-positives on legacy vendored
# helpers is the right side of "be paranoid about build infrastructure". Also
# keep listening_port strict (build tools have no business binding to ports).
BUILD_TOOL_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(2, 10),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(4, 20),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# A web server's purpose is to bind to a port, accept connections, fork worker
# processes (gunicorn/hypercorn), and write logs/pidfiles/unix sockets. Relax
# listening_port, subprocess, and fs_write. Stay strict on outbound (a web
# server reaching the network outbound is suspicious -- it's there to serve,
# not phone home), on obfuscation, and on the strict-by-design surfaces.
WEB_SERVER_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(5, 25),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(10, 40),
    SurfaceKind.LISTENING_PORT: Weight(0, 0),
    SurfaceKind.SUBPROCESS: Weight(5, 20),
    SurfaceKind.FS_WRITE: Weight(2, 10),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(2, 10),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

# An HTTP client library's whole purpose is making outbound network calls to
# arbitrary user-supplied hosts. Relax outbound_network, outbound_dynamic, and
# hardcoded_host (which fire on the bundled default-host constants and example
# URLs in docstrings). Stay strict on subprocess and listening_port (a client
# library has no business spawning shells or opening sockets), on obfuscation,
# and on the strict-by-design surfaces -- a network library exfiltrating env
# secrets or carrying prompt-injection-shaped strings is still suspicious.
NETWORK_LIBRARY_WEIGHTS: dict[SurfaceKind, Weight] = {
    SurfaceKind.OUTBOUND_NETWORK: Weight(1, 5),
    SurfaceKind.OUTBOUND_DYNAMIC: Weight(2, 10),
    SurfaceKind.LISTENING_PORT: Weight(15, 45),
    SurfaceKind.SUBPROCESS: Weight(15, 40),
    SurfaceKind.FS_WRITE: Weight(5, 15),
    SurfaceKind.ENV_SECRET_READ: Weight(10, 20),
    SurfaceKind.HARDCODED_HOST: Weight(1, 5),
    SurfaceKind.TELEMETRY_ENDPOINT: Weight(10, 20),
    SurfaceKind.OBFUSCATION: Weight(8, 60),
    SurfaceKind.DATA_EXFIL_HINT: Weight(20, 40),
    SurfaceKind.MCP_TRANSPORT_DRIFT: Weight(30, 30),
    SurfaceKind.PROMPT_INJECTION_HINT: Weight(15, 30),
}

PROFILE_PLUGIN = "plugin"
PROFILE_MCP_SERVER = "mcp-server"
PROFILE_CLI_FRAMEWORK = "cli-framework"
PROFILE_NETWORK_LIBRARY = "network-library"
PROFILE_WEB_SERVER = "web-server"
PROFILE_BUILD_TOOL = "build-tool"
PROFILE_DATA_SCIENCE = "data-science"
PROFILE_ML_FRAMEWORK = "ml-framework"
PROFILE_DATABASE_DRIVER = "database-driver"
PROFILE_TEMPLATE_ENGINE = "template-engine"
PROFILE_TEST_FRAMEWORK = "test-framework"
PROFILE_CLOUD_SDK = "cloud-sdk"
PROFILE_OBSERVABILITY = "observability"
PROFILE_FORMAT_CODEC = "format-codec"
PROFILE_SCRAPING = "scraping"
PROFILE_WEB_FRAMEWORK = "web-framework"
DEFAULT_PROFILE = PROFILE_PLUGIN

PROFILE_WEIGHTS: dict[str, dict[SurfaceKind, Weight]] = {
    PROFILE_PLUGIN: PLUGIN_WEIGHTS,
    PROFILE_MCP_SERVER: MCP_SERVER_WEIGHTS,
    PROFILE_CLI_FRAMEWORK: CLI_FRAMEWORK_WEIGHTS,
    PROFILE_NETWORK_LIBRARY: NETWORK_LIBRARY_WEIGHTS,
    PROFILE_WEB_SERVER: WEB_SERVER_WEIGHTS,
    PROFILE_BUILD_TOOL: BUILD_TOOL_WEIGHTS,
    PROFILE_DATA_SCIENCE: DATA_SCIENCE_WEIGHTS,
    PROFILE_ML_FRAMEWORK: ML_FRAMEWORK_WEIGHTS,
    PROFILE_DATABASE_DRIVER: DATABASE_DRIVER_WEIGHTS,
    PROFILE_TEMPLATE_ENGINE: TEMPLATE_ENGINE_WEIGHTS,
    PROFILE_TEST_FRAMEWORK: TEST_FRAMEWORK_WEIGHTS,
    PROFILE_CLOUD_SDK: CLOUD_SDK_WEIGHTS,
    PROFILE_OBSERVABILITY: OBSERVABILITY_WEIGHTS,
    PROFILE_FORMAT_CODEC: FORMAT_CODEC_WEIGHTS,
    PROFILE_SCRAPING: SCRAPING_WEIGHTS,
    PROFILE_WEB_FRAMEWORK: WEB_FRAMEWORK_WEIGHTS,
}

# Backwards-compat alias for any external caller.
DEFAULT_WEIGHTS = PLUGIN_WEIGHTS

STARTING_SCORE = 100

# Split the obfuscation deduction by finding shape (see python_ast.py):
# - "encoded" findings (exec/eval/compile of base64.b64decode/zlib.decompress/
#   marshal.loads/etc. -- the canonical supply-chain attack pattern) keep the
#   profile's full per_finding + cap.
# - "dynamic" findings (plain `exec(<var>)` -- the legitimate code-gen pattern
#   in numpy, setuptools, sqlalchemy, jinja2, pytest assertion rewriting) get
#   weighted at these fractions.
# Numbers chosen so that a library with 20+ legitimate dynamic findings stops
# pinning to the full obfuscation cap, while a real attacker payload with
# even a single encoded finding still contributes full severity.
OBFUSCATION_DYNAMIC_PER_FINDING_RATIO = 0.4
OBFUSCATION_DYNAMIC_CAP_RATIO = 0.4


def weights_for(profile: str) -> dict[SurfaceKind, Weight]:
    return PROFILE_WEIGHTS.get(profile, PLUGIN_WEIGHTS)


def detect_profile_from_content(findings: list[Finding]) -> tuple[str, str] | None:
    """Apply mcp-server profile when the package registers MCP tools or resources in runtime code.

    A package that exposes `@mcp.tool`, `@mcp.resource`, `server.tool(...)`, etc. in
    its runtime sources IS an MCP server by definition. Findings inside tests/docs/
    examples are filtered out via walker.find_context so the SDK's bundled examples
    don't falsely upgrade the SDK itself.
    """
    runtime_mcp = sum(
        1 for f in findings
        if f.kind in {SurfaceKind.MCP_TOOL, SurfaceKind.MCP_RESOURCE}
        and walker.find_context(f.file) == "runtime"
    )
    if runtime_mcp >= 1:
        return PROFILE_MCP_SERVER, f"content: {runtime_mcp} mcp_tool/resource registration(s)"
    return None


# Well-known CLI framework packages. Tight allowlist on purpose -- these are
# libraries whose entire purpose is dispatching subprocesses based on user input,
# they have no package-metadata signal (they don't declare scripts themselves),
# and they are widely depended-upon. Names check against canonical form.
CLI_FRAMEWORK_NAMES: set[str] = {
    "click", "typer", "cleo", "fire", "docopt", "docopt-ng", "rich-click",
}

# Well-known HTTP client libraries. Tight allowlist on purpose -- these are
# libraries whose entire purpose is making outbound calls to user-supplied
# hosts, and there is no metadata signal that distinguishes a network library
# from any other pure-Python package. Canonical (PEP 503) names.
NETWORK_LIBRARY_NAMES: set[str] = {
    "requests", "httpx", "httpcore", "urllib3", "aiohttp", "niquests",
}

# Well-known Python web servers / WSGI/ASGI runners. Tight allowlist on purpose
# -- these are short, well-known names; package metadata does not distinguish a
# web server from any other library that declares an entry point (gunicorn et
# al. would otherwise resolve as cli-framework, which would NOT relax
# listening_port). Canonical (PEP 503) names.
WEB_SERVER_NAMES: set[str] = {
    "uvicorn", "gunicorn", "hypercorn", "granian", "waitress", "daphne",
}

# Well-known Python build backends and packaging tools. Tight allowlist on
# purpose. These are transitive deps of essentially every pypi install and the
# 0-score-blocks-everything outcome under plugin is a real friction point.
# Canonical (PEP 503) names.
# Well-known numerical / data-science libraries. Tight allowlist on purpose.
# Excludes ML frameworks (torch, tensorflow, jax, transformers) which deserve
# their own profile (GPU binding, CUDA linking, training process forks differ
# from plain numerical compute). Canonical (PEP 503) names.
# Well-known ML frameworks and the HuggingFace ecosystem. Wider relaxations
# than data-science because training surfaces (distributed sockets, CUDA
# linking, model-hub downloads) are core to the role. Canonical (PEP 503)
# names.
# Well-known database drivers, ORMs, and message-broker clients. Tight
# allowlist on purpose -- there are MANY niche DB clients and the goal is to
# cover the high-volume cases without overreaching. Canonical (PEP 503)
# names.
# Well-known Python template engines. Tight allowlist; their entire job
# is compile() of template ASTs. Excludes Django/Tornado/Flask -- those
# are web frameworks where templating is one subsystem.
# File-format / codec libraries -- image, XML/HTML, spreadsheet, PDF, audio
# parsers and writers. Most shell out to native decoders for the heavy work
# and write decoded output to disk; both surfaces are role-typical.
# Scraping and browser-automation libraries. Browser drivers (selenium,
# playwright) and HTML/JS scrapers (scrapy, requests-html, mechanize).
# Tight allowlist on purpose; the relaxations here are wide.
# Web application frameworks -- the app-layer monoliths that hold routing,
# middleware, templating integration, dev workflow. Distinct from
# web-server (uvicorn/gunicorn, pure HTTP runners). Tight allowlist.
WEB_FRAMEWORK_NAMES: set[str] = {
    "django",
    "fastapi", "starlette",
    "flask", "quart",
    "sanic", "falcon", "bottle", "pyramid",
    "tornado",
    "litestar",
}


SCRAPING_NAMES: set[str] = {
    "scrapy", "selenium", "playwright",
    "splinter", "requests-html",
    "mechanize", "mechanicalsoup",
    "pyppeteer", "playwright-stealth",
    "scrapy-playwright", "scrapy-selenium",
    "selenium-wire", "undetected-chromedriver",
    "twisted",  # scrapy's async runtime dependency, hard to use outside this role
}


FORMAT_CODEC_NAMES: set[str] = {
    # Images
    "pillow", "pillow-heif", "pillow-simd",
    "imageio", "imageio-ffmpeg",
    # XML / HTML
    "lxml", "defusedxml", "beautifulsoup4", "html5lib",
    # Spreadsheets
    "openpyxl", "xlrd", "xlwt", "xlsxwriter",
    # Office documents
    "python-docx", "python-pptx",
    # PDF
    "pypdf", "pypdf2", "pikepdf", "pdfplumber", "reportlab",
    # Audio / video
    "pydub", "ffmpeg-python", "av", "moviepy",
    # Markdown / lightweight markup
    "markdown", "markdown-it-py", "mistune",
    # Encoding detection + magic
    "chardet", "charset-normalizer", "python-magic", "filetype",
}


TEMPLATE_ENGINE_NAMES: set[str] = {
    "jinja2", "mako", "chevron", "genshi", "cheetah3",
    "pystache", "wheezy.template",
}

# Test frameworks and the test-tool ecosystem. Excludes mock/responses
# (these are unit-test helper libs, not frameworks).
TEST_FRAMEWORK_NAMES: set[str] = {
    "pytest", "hypothesis", "tox", "nox",
    "coverage", "pytest-cov", "pytest-xdist", "pytest-asyncio",
    "pytest-mock", "pytest-django", "pytest-flask", "pytest-benchmark",
    "pytest-timeout", "pytest-randomly", "pytest-rerunfailures",
    "pytest-sugar", "pytest-html",
    "parameterized", "freezegun", "vcrpy",
}

# Major cloud SDK families. AWS (boto3 + botocore + transfer + cli),
# Google Cloud client libraries + auth, Azure SDK core + identity +
# common services, Kubernetes / OpenShift, HashiCorp Vault.
CLOUD_SDK_NAMES: set[str] = {
    # AWS
    "boto3", "botocore", "s3transfer", "awscli", "aiobotocore",
    # GCP
    "google-cloud-storage", "google-cloud-core", "google-cloud-bigquery",
    "google-cloud-pubsub", "google-cloud-firestore",
    "google-cloud-secret-manager", "google-auth",
    "google-api-python-client", "google-api-core",
    "google-resumable-media",
    # Azure
    "azure-core", "azure-identity",
    "azure-storage-blob", "azure-storage-file-share",
    "azure-keyvault-secrets", "azure-keyvault-keys",
    "azure-keyvault-certificates",
    # K8s + secrets backends
    "kubernetes", "openshift", "hvac",
}

# Observability libraries -- error tracking, distributed tracing, APMs,
# structured logging that ships to a backend. OpenTelemetry is sprawling;
# the allowlist covers the SDK and the common exporters.
OBSERVABILITY_NAMES: set[str] = {
    "sentry-sdk",
    "opentelemetry-api", "opentelemetry-sdk",
    "opentelemetry-instrumentation",
    "opentelemetry-exporter-otlp",
    "opentelemetry-exporter-otlp-proto-grpc",
    "opentelemetry-exporter-otlp-proto-http",
    "opentelemetry-exporter-prometheus",
    "opentelemetry-distro",
    "structlog", "loguru", "python-json-logger",
    "ddtrace", "datadog",
    "newrelic", "scout-apm", "elastic-apm",
    "prometheus-client", "statsd",
}

DATABASE_DRIVER_NAMES: set[str] = {
    # PostgreSQL
    "psycopg", "psycopg-binary", "psycopg-pool",
    "psycopg2", "psycopg2-binary",
    "asyncpg",
    # MySQL / MariaDB
    "pymysql", "mysqlclient", "mysql-connector-python",
    "aiomysql", "mariadb",
    # SQLite extras
    "aiosqlite", "sqlite-utils",
    # ORMs and SQL DSLs
    "sqlalchemy", "alembic", "sqlmodel", "peewee", "tortoise-orm",
    "databases", "ormar",
    # MongoDB
    "pymongo", "motor", "beanie", "mongoengine",
    # Redis / KV
    "redis", "hiredis", "aredis", "redis-py-cluster",
    "valkey",
    # Other RDBMS / cloud DBs
    "pyodbc", "cx-oracle", "oracledb", "snowflake-connector-python",
    "google-cloud-bigquery", "google-cloud-spanner",
    # NoSQL / search
    "cassandra-driver", "neo4j", "elasticsearch", "opensearch-py",
    "elasticsearch-dsl",
    "clickhouse-driver", "clickhouse-connect",
    # Message brokers (treated as DB-shaped clients here)
    "pika", "aio-pika", "kafka-python", "aiokafka", "confluent-kafka",
    "pulsar-client", "nats-py", "stomp-py",
}


ML_FRAMEWORK_NAMES: set[str] = {
    "torch", "torchvision", "torchaudio", "torchtext",
    "tensorflow", "tensorflow-cpu", "tensorflow-gpu", "tf-keras", "keras",
    "jax", "jaxlib", "flax", "optax",
    "transformers", "tokenizers", "sentencepiece",
    "diffusers", "datasets", "evaluate", "accelerate", "safetensors",
    "peft", "trl", "optimum", "bitsandbytes",
    "huggingface-hub",
    "lightning", "pytorch-lightning",
    "onnx", "onnxruntime", "onnxruntime-gpu",
}


DATA_SCIENCE_NAMES: set[str] = {
    "numpy", "scipy", "pandas", "polars", "pyarrow",
    "scikit-learn", "scikit-image",
    "matplotlib", "seaborn", "plotly", "bokeh",
    "statsmodels", "sympy", "numba", "numexpr",
    "dask", "xarray", "h5py", "zarr", "tables",
    "joblib",
}


BUILD_TOOL_NAMES: set[str] = {
    "setuptools", "wheel", "build", "pip",
    "hatchling", "hatch", "hatch-vcs", "hatch-fancy-pypi-readme",
    "flit", "flit-core",
    "poetry", "poetry-core",
    "pdm", "pdm-backend",
    "scikit-build", "scikit-build-core", "meson-python", "maturin",
    "setuptools-scm", "setuptools-rust",
}


def detect_profile_from_name(name: str, ecosystem: str) -> tuple[str, str] | None:
    """Apply a role profile based on the canonical package name.

    Conservative on purpose -- prefix matches and tight allowlists only.
    Returns (profile, reason) or None.
    """
    if not name:
        return None
    if ecosystem == "pypi":
        if name.startswith("mcp-server-"):
            return PROFILE_MCP_SERVER, "name-convention: mcp-server-*"
        if name in CLI_FRAMEWORK_NAMES:
            return PROFILE_CLI_FRAMEWORK, f"name-allowlist: {name}"
        if name in NETWORK_LIBRARY_NAMES:
            return PROFILE_NETWORK_LIBRARY, f"name-allowlist: {name}"
        if name in WEB_SERVER_NAMES:
            return PROFILE_WEB_SERVER, f"name-allowlist: {name}"
        if name in BUILD_TOOL_NAMES:
            return PROFILE_BUILD_TOOL, f"name-allowlist: {name}"
        if name in DATA_SCIENCE_NAMES:
            return PROFILE_DATA_SCIENCE, f"name-allowlist: {name}"
        if name in ML_FRAMEWORK_NAMES:
            return PROFILE_ML_FRAMEWORK, f"name-allowlist: {name}"
        if name in DATABASE_DRIVER_NAMES:
            return PROFILE_DATABASE_DRIVER, f"name-allowlist: {name}"
        if name in TEMPLATE_ENGINE_NAMES:
            return PROFILE_TEMPLATE_ENGINE, f"name-allowlist: {name}"
        if name in TEST_FRAMEWORK_NAMES:
            return PROFILE_TEST_FRAMEWORK, f"name-allowlist: {name}"
        if name in CLOUD_SDK_NAMES:
            return PROFILE_CLOUD_SDK, f"name-allowlist: {name}"
        if name in OBSERVABILITY_NAMES:
            return PROFILE_OBSERVABILITY, f"name-allowlist: {name}"
        if name in FORMAT_CODEC_NAMES:
            return PROFILE_FORMAT_CODEC, f"name-allowlist: {name}"
        if name in SCRAPING_NAMES:
            return PROFILE_SCRAPING, f"name-allowlist: {name}"
        if name in WEB_FRAMEWORK_NAMES:
            return PROFILE_WEB_FRAMEWORK, f"name-allowlist: {name}"
        return None
    if ecosystem == "npm":
        if name.startswith("@modelcontextprotocol/server-"):
            return PROFILE_MCP_SERVER, "name-convention: @modelcontextprotocol/server-*"
        if name.startswith("mcp-server-"):
            return PROFILE_MCP_SERVER, "name-convention: mcp-server-*"
        return None
    return None


def detect_profile_from_metadata(audit_root, ecosystem: str) -> tuple[str, str] | None:
    """Apply cli-framework profile when the package declares executable entry points.

    pypi: pyproject.toml [project.scripts] OR [project.entry-points.console_scripts].
    npm: package.json `bin` (string or dict).

    Catches CLI *tools* (ruff, black, mypy) which declare console_scripts. Does NOT
    catch the underlying frameworks like click/typer themselves -- those are handled
    by the name allowlist in detect_profile_from_name.
    """
    from pathlib import Path
    import json
    import tomllib
    root = Path(audit_root)
    if ecosystem == "pypi":
        pyproject = root / "pyproject.toml"
        if not pyproject.exists():
            return None
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            return None
        project = data.get("project") or {}
        scripts = project.get("scripts") or {}
        console = ((project.get("entry-points") or {}).get("console_scripts")) or {}
        if scripts or console:
            n = len(scripts) + len(console)
            return PROFILE_CLI_FRAMEWORK, f"metadata: {n} console-script entry point(s)"
        return None
    if ecosystem == "npm":
        package_json = root / "package.json"
        if not package_json.exists():
            return None
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        bin_field = data.get("bin")
        if bin_field:
            n = len(bin_field) if isinstance(bin_field, dict) else 1
            return PROFILE_CLI_FRAMEWORK, f"metadata: {n} bin entry point(s)"
        return None
    return None


def score(findings: list[Finding], weights: dict[SurfaceKind, Weight] | None = None, *, profile: str = DEFAULT_PROFILE) -> ScoreBreakdown:
    weights = weights or weights_for(profile)
    runtime = [f for f in findings if walker.find_context(f.file) == "runtime"]
    deductions = _build_deductions(runtime, weights)
    _annotate_role_typicality(deductions, weights)
    total_deducted = sum(d["deducted"] for d in deductions)
    typical_deducted = sum(d["deducted"] for d in deductions if d.get("role_typical"))
    share = (typical_deducted / total_deducted) if total_deducted else 0.0
    final = max(0, STARTING_SCORE - total_deducted)
    return ScoreBreakdown(final_score=final, deductions=deductions, role_typical_share=round(share, 3))


def _annotate_role_typicality(deductions: list[dict], weights: dict[SurfaceKind, Weight]) -> None:
    """Mark each deduction as `role_typical` when the active profile relaxes
    that surface vs. plugin baseline.

    A surface is "relaxed" by the profile if either its `per_finding` or
    `cap` is strictly lower than the plugin defaults. This catches the
    common case (cap drop) and the rare per_finding-only drop. Surfaces
    not present in PLUGIN_WEIGHTS (e.g. mcp_tool/mcp_resource) default
    to role-typical when present in the active profile -- the role
    profile explicitly accepts that surface as load-bearing.
    """
    for d in deductions:
        kind_value = d.get("kind")
        try:
            kind = SurfaceKind(kind_value)
        except ValueError:
            d["role_typical"] = False
            continue
        profile_weight = weights.get(kind)
        plugin_weight = PLUGIN_WEIGHTS.get(kind)
        if profile_weight is None or plugin_weight is None:
            d["role_typical"] = False
            continue
        d["role_typical"] = (
            profile_weight.per_finding < plugin_weight.per_finding
            or profile_weight.cap < plugin_weight.cap
        )


def _build_deductions(findings: list[Finding], weights: dict[SurfaceKind, Weight]) -> list[dict]:
    counts: dict[SurfaceKind, int] = defaultdict(int)
    obf_by_shape: dict[str, int] = defaultdict(int)
    for f in findings:
        counts[f.kind] += 1
        if f.kind == SurfaceKind.OBFUSCATION:
            shape = f.extra.get("shape", "dynamic") if f.extra else "dynamic"
            obf_by_shape[shape] += 1
    deductions = []
    for kind, count in counts.items():
        weight = weights.get(kind)
        if not weight or weight.cap == 0:
            continue
        if kind == SurfaceKind.OBFUSCATION:
            deductions.append(_obfuscation_deduction(weight, obf_by_shape))
            continue
        raw = weight.per_finding * count
        deducted = min(raw, weight.cap)
        deductions.append({
            "kind": kind.value,
            "count": count,
            "per_finding": weight.per_finding,
            "cap": weight.cap,
            "deducted": deducted,
        })
    return deductions


def _obfuscation_deduction(weight: Weight, by_shape: dict[str, int]) -> dict:
    enc = by_shape.get("encoded", 0)
    dyn = by_shape.get("dynamic", 0)
    dyn_per = max(1, round(weight.per_finding * OBFUSCATION_DYNAMIC_PER_FINDING_RATIO))
    dyn_cap = round(weight.cap * OBFUSCATION_DYNAMIC_CAP_RATIO)
    enc_deducted = min(weight.per_finding * enc, weight.cap)
    dyn_deducted = min(dyn_per * dyn, dyn_cap)
    total = min(enc_deducted + dyn_deducted, weight.cap)
    return {
        "kind": SurfaceKind.OBFUSCATION.value,
        "count": enc + dyn,
        "encoded_count": enc,
        "dynamic_count": dyn,
        "per_finding": weight.per_finding,
        "cap": weight.cap,
        "dynamic_per_finding": dyn_per,
        "dynamic_cap": dyn_cap,
        "deducted": total,
    }
