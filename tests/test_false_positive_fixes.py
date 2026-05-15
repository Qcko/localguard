"""Targeted regression tests for the false-positives surfaced by the
retroactive GLaDOS web-client audit (vite/typescript/esbuild/rollup).

Four categories:
  1a. `.d.ts` and `.pyi` files classified as `types` (non-runtime).
  1b. mcp_detector's JS prompt-injection scan scoped to MCP-handler files.
  2.  `_is_doc_or_meta_file` recognizes `ThirdPartyNoticeText.txt` style.
  3.  vite/parcel/snowpack/webpack-dev-server resolve to the new
      `dev-server-bundler` profile; pure compilers stay in `build-tool`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from localguard import audit, mcp_detector, rubric
from localguard.report import SurfaceKind
from localguard.walker import SourceFile, find_context


# ---- Issue 1a: type stubs classified as non-runtime ----

@pytest.mark.parametrize("rel,expected", [
    ("lib/lib.es2015.core.d.ts", "types"),
    ("dist/index.d.ts", "types"),
    ("foo/bar.d.ts", "types"),
    ("stubs/numpy.pyi", "types"),
    ("typeshed/os/__init__.pyi", "types"),
    # Generated protobuf stubs keep their stronger `generated` classification
    # (they match _is_autogen_file first).
    ("api/foo_pb2.pyi", "generated"),
    ("api/foo_pb.d.ts", "generated"),
    # Regular .py / .ts files unchanged.
    ("src/main.py", "runtime"),
    ("src/index.ts", "runtime"),
])
def test_find_context_type_stubs(rel: str, expected: str):
    assert find_context(rel) == expected


def test_type_stub_findings_dropped_from_score():
    """A finding in a .d.ts file must not affect the final score, since the
    file's context is `types`, not `runtime`."""
    from localguard.report import Finding, Confidence
    findings = [
        Finding(kind=SurfaceKind.HARDCODED_HOST, file="lib/types.d.ts", line=1, detail="apache.org", confidence=Confidence.LITERAL, extra={"host": "apache.org"}),
        Finding(kind=SurfaceKind.HARDCODED_HOST, file="src/runtime.js", line=1, detail="evil.com", confidence=Confidence.LITERAL, extra={"host": "evil.com"}),
    ]
    score = rubric.score(findings, profile="plugin")
    # Only the runtime finding counts.
    assert any(d["kind"] == "hardcoded_host" and d["count"] == 1 for d in score.deductions)


# ---- Issue 1b: MCP injection scan scoped to files with MCP handlers ----

def _src(text: str, name: str = "module.js") -> SourceFile:
    return SourceFile(path=Path(name), rel=name, language="javascript", text=text)


def test_zero_width_in_non_mcp_js_does_not_fire():
    """A regular JS file with zero-width unicode (e.g. a TypeScript .d.ts
    that happens to have ZWJ in a comment) must NOT trip prompt_injection_hint
    if the file has no MCP handler registrations."""
    code = "// a comment with zero‍width joiner inside\nfunction f() { return 1; }\n"
    findings = mcp_detector.detect_mcp(_src(code, name="lib.es2015.core.d.ts"))
    assert not any(f.kind == SurfaceKind.PROMPT_INJECTION_HINT for f in findings)


def test_zero_width_in_mcp_handler_file_still_fires():
    """If a JS file DOES register an MCP handler, the description scan is
    still active (we want to catch injection attempts on actual tool
    descriptions)."""
    code = """
server.tool('foo', 'desc with zero‍width char');
"""
    findings = mcp_detector.detect_mcp(_src(code))
    # Should detect both the MCP_TOOL registration and the injection hint.
    kinds = {f.kind for f in findings}
    assert SurfaceKind.MCP_TOOL in kinds
    assert SurfaceKind.PROMPT_INJECTION_HINT in kinds


def test_injection_pattern_in_non_mcp_js_does_not_fire():
    """Plain text 'ignore previous instructions' in a non-MCP file is
    almost certainly a doc string about prompt-injection itself, not an
    attack."""
    code = "/* documentation: never write 'ignore previous instructions' in prompts */\n"
    findings = mcp_detector.detect_mcp(_src(code))
    assert not any(f.kind == SurfaceKind.PROMPT_INJECTION_HINT for f in findings)


# ---- Issue 2: third-party-notice metadata files recognized ----

@pytest.mark.parametrize("name,expected", [
    ("ThirdPartyNoticeText.txt", "docs"),
    ("THIRD_PARTY_NOTICES.md", "docs"),
    ("third-party-notices.txt", "docs"),
    ("ThirdPartyNotices.md", "docs"),
    ("LICENSES.txt", "docs"),
    ("Licenses", "docs"),
    # Negative: still don't classify random files as docs.
    ("main.py", "runtime"),
])
def test_third_party_notice_recognized(name: str, expected: str):
    assert find_context(name) == expected


# ---- Issue 3: dev-server-bundler profile + weights ----

def test_dev_server_bundler_profile_registered():
    assert rubric.PROFILE_DEV_SERVER_BUNDLER in rubric.PROFILE_WEIGHTS
    weights = rubric.PROFILE_WEIGHTS[rubric.PROFILE_DEV_SERVER_BUNDLER]
    # listening_port must be fully relaxed (the whole point of the profile).
    assert weights[SurfaceKind.LISTENING_PORT].per_finding == 0
    assert weights[SurfaceKind.LISTENING_PORT].cap == 0
    # outbound_network stays strict-ish (a dev server shouldn't phone home).
    plugin = rubric.PLUGIN_WEIGHTS
    assert weights[SurfaceKind.DATA_EXFIL_HINT].cap == plugin[SurfaceKind.DATA_EXFIL_HINT].cap


def test_dev_server_bundler_role_typical_share_credits_listening_port():
    """A package with listening_port findings under dev-server-bundler should
    have those count as role-typical (relaxed vs plugin), unlike under
    build-tool where listening_port is strict."""
    from localguard.report import Finding, Confidence
    findings = [
        Finding(kind=SurfaceKind.LISTENING_PORT, file="src/dev.js", line=1, detail="server.listen(3000)", confidence=Confidence.LITERAL, extra={"fqn": "server.listen"}),
    ]
    bt = rubric.score(findings, profile=rubric.PROFILE_BUILD_TOOL)
    dsb = rubric.score(findings, profile=rubric.PROFILE_DEV_SERVER_BUNDLER)
    # build-tool: listening_port costs 15 -> score < 100 -> role_share could
    # still be 0 (the finding is role-atypical).
    # dev-server-bundler: listening_port costs 0 -> dropped from deductions
    # entirely -> score 100, role_share 0 (nothing to share).
    assert dsb.final_score == 100
    assert bt.final_score < 100