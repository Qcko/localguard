from pathlib import Path

from localguard import rubric
from localguard.report import Finding, SurfaceKind


def _obf(n: int) -> list[Finding]:
    return [
        Finding(kind=SurfaceKind.OBFUSCATION, file="pkg/runtime.py", line=i + 1, detail="eval(...)", confidence="literal", extra={})
        for i in range(n)
    ]


def test_obfuscation_one_finding_stays_auto_baselineable():
    breakdown = rubric.score(_obf(1))
    assert breakdown.final_score == 92


def test_obfuscation_two_findings_drop_below_auto_threshold():
    breakdown = rubric.score(_obf(2))
    assert 80 <= breakdown.final_score < 90


def test_obfuscation_five_findings_still_acceptable_band():
    breakdown = rubric.score(_obf(5))
    assert 50 <= breakdown.final_score < 90


def test_obfuscation_many_findings_hit_low_score():
    breakdown = rubric.score(_obf(20))
    assert breakdown.final_score < 50


def _surf(kind: SurfaceKind, n: int) -> list[Finding]:
    return [Finding(kind=kind, file="pkg/runtime.py", line=i + 1, detail="", confidence="literal", extra={}) for i in range(n)]


def test_mcp_server_profile_relaxes_listening_port():
    findings = _surf(SurfaceKind.LISTENING_PORT, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    server = rubric.score(findings, profile=rubric.PROFILE_MCP_SERVER)
    assert plugin.final_score < server.final_score
    assert server.final_score == 100  # listening_port is zero-weight under mcp-server


def test_mcp_server_profile_relaxes_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 4)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    server = rubric.score(findings, profile=rubric.PROFILE_MCP_SERVER)
    assert plugin.final_score == 100 - 40  # cap
    assert server.final_score == 100 - 20  # mcp-server cap (5*4=20, under cap 20)


def test_mcp_server_profile_stays_strict_on_obfuscation():
    findings = _surf(SurfaceKind.OBFUSCATION, 10)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    server = rubric.score(findings, profile=rubric.PROFILE_MCP_SERVER)
    assert plugin.final_score == server.final_score


def test_cli_framework_profile_relaxes_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    cli_fw = rubric.score(findings, profile=rubric.PROFILE_CLI_FRAMEWORK)
    assert plugin.final_score == 100 - 40  # cap at 40
    assert cli_fw.final_score == 100 - 10  # cap at 10 under cli-framework (5*2=10)


def test_cli_framework_profile_stays_strict_on_outbound():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 6)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    cli_fw = rubric.score(findings, profile=rubric.PROFILE_CLI_FRAMEWORK)
    assert plugin.final_score == cli_fw.final_score


def test_network_library_profile_relaxes_outbound():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 10)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    netlib = rubric.score(findings, profile=rubric.PROFILE_NETWORK_LIBRARY)
    assert plugin.final_score == 100 - 25  # cap 25
    assert netlib.final_score == 100 - 5   # cap 5 under network-library


def test_network_library_profile_stays_strict_on_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 4)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    netlib = rubric.score(findings, profile=rubric.PROFILE_NETWORK_LIBRARY)
    assert plugin.final_score == netlib.final_score


def test_network_library_profile_stays_strict_on_listening_port():
    findings = _surf(SurfaceKind.LISTENING_PORT, 3)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    netlib = rubric.score(findings, profile=rubric.PROFILE_NETWORK_LIBRARY)
    assert plugin.final_score == netlib.final_score


def test_web_server_profile_relaxes_listening_port():
    findings = _surf(SurfaceKind.LISTENING_PORT, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    web = rubric.score(findings, profile=rubric.PROFILE_WEB_SERVER)
    assert plugin.final_score < web.final_score
    assert web.final_score == 100  # zero-weight under web-server


def test_web_server_profile_stays_strict_on_outbound():
    findings = _surf(SurfaceKind.OUTBOUND_NETWORK, 6)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    web = rubric.score(findings, profile=rubric.PROFILE_WEB_SERVER)
    assert plugin.final_score == web.final_score


def test_web_server_profile_relaxes_fs_write():
    findings = _surf(SurfaceKind.FS_WRITE, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    web = rubric.score(findings, profile=rubric.PROFILE_WEB_SERVER)
    assert web.final_score > plugin.final_score


def test_build_tool_profile_relaxes_subprocess():
    findings = _surf(SurfaceKind.SUBPROCESS, 5)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    bt = rubric.score(findings, profile=rubric.PROFILE_BUILD_TOOL)
    assert plugin.final_score == 100 - 40  # cap 40
    assert bt.final_score == 100 - 20      # cap 20 under build-tool


def test_build_tool_profile_relaxes_fs_write():
    findings = _surf(SurfaceKind.FS_WRITE, 6)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    bt = rubric.score(findings, profile=rubric.PROFILE_BUILD_TOOL)
    assert bt.final_score > plugin.final_score


def test_build_tool_profile_stays_strict_on_obfuscation():
    findings = _surf(SurfaceKind.OBFUSCATION, 10)
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    bt = rubric.score(findings, profile=rubric.PROFILE_BUILD_TOOL)
    assert plugin.final_score == bt.final_score


def test_unknown_profile_falls_back_to_plugin_weights():
    findings = _surf(SurfaceKind.LISTENING_PORT, 5)
    bogus = rubric.score(findings, profile="not-a-real-profile")
    plugin = rubric.score(findings, profile=rubric.PROFILE_PLUGIN)
    assert bogus.final_score == plugin.final_score
