from __future__ import annotations

from localguard import rubric
from localguard.report import Finding, SurfaceKind


def _mcp_tool(file: str) -> Finding:
    return Finding(kind=SurfaceKind.MCP_TOOL, file=file, line=1, detail="", confidence="literal", extra={})


def _mcp_resource(file: str) -> Finding:
    return Finding(kind=SurfaceKind.MCP_RESOURCE, file=file, line=1, detail="", confidence="literal", extra={})


def test_content_detection_fires_on_runtime_mcp_tool():
    result = rubric.detect_profile_from_content([_mcp_tool("server/tools.py")])
    assert result is not None
    assert result[0] == rubric.PROFILE_MCP_SERVER
    assert "mcp_tool/resource" in result[1]


def test_content_detection_ignores_test_dir_findings():
    findings = [_mcp_tool("tests/test_tools.py"), _mcp_resource("examples/demo.py")]
    assert rubric.detect_profile_from_content(findings) is None


def test_content_detection_returns_none_when_no_mcp_findings():
    from localguard.report import Finding, SurfaceKind
    findings = [Finding(kind=SurfaceKind.SUBPROCESS, file="x.py", line=1, detail="", confidence="literal", extra={})]
    assert rubric.detect_profile_from_content(findings) is None


def test_pypi_mcp_server_prefix_detected():
    assert rubric.detect_profile_from_name("mcp-server-filesystem", "pypi") == (
        rubric.PROFILE_MCP_SERVER, "name-convention: mcp-server-*",
    )


def test_pypi_canonical_form_after_pep503_works():
    # The canonical name (post-PEP 503) is what reaches detection.
    assert rubric.detect_profile_from_name("mcp-server-foo", "pypi") is not None


def test_npm_modelcontextprotocol_scope_detected():
    result = rubric.detect_profile_from_name("@modelcontextprotocol/server-filesystem", "npm")
    assert result == (rubric.PROFILE_MCP_SERVER, "name-convention: @modelcontextprotocol/server-*")


def test_npm_bare_mcp_server_prefix_detected():
    assert rubric.detect_profile_from_name("mcp-server-foo", "npm") is not None


def test_click_typer_etc_detect_as_cli_framework():
    assert rubric.detect_profile_from_name("click", "pypi") == (rubric.PROFILE_CLI_FRAMEWORK, "name-allowlist: click")
    assert rubric.detect_profile_from_name("typer", "pypi") == (rubric.PROFILE_CLI_FRAMEWORK, "name-allowlist: typer")
    assert rubric.detect_profile_from_name("fire", "pypi") == (rubric.PROFILE_CLI_FRAMEWORK, "name-allowlist: fire")


def test_metadata_detection_pypi_console_scripts(tmp_path):
    (tmp_path / "pyproject.toml").write_text("""
[project]
name = "demo-cli"
version = "1.0"
[project.scripts]
demo = "demo.main:cli"
""", encoding="utf-8")
    assert rubric.detect_profile_from_metadata(tmp_path, "pypi") == (
        rubric.PROFILE_CLI_FRAMEWORK, "metadata: 1 console-script entry point(s)",
    )


def test_metadata_detection_pypi_no_scripts(tmp_path):
    (tmp_path / "pyproject.toml").write_text("""
[project]
name = "demo"
version = "1.0"
""", encoding="utf-8")
    assert rubric.detect_profile_from_metadata(tmp_path, "pypi") is None


def test_metadata_detection_npm_bin(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"demo","version":"1.0","bin":{"demo":"./cli.js","demo-x":"./xcli.js"}}', encoding="utf-8")
    result = rubric.detect_profile_from_metadata(tmp_path, "npm")
    assert result == (rubric.PROFILE_CLI_FRAMEWORK, "metadata: 2 bin entry point(s)")


def test_metadata_detection_npm_string_bin(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"demo","version":"1.0","bin":"./cli.js"}', encoding="utf-8")
    result = rubric.detect_profile_from_metadata(tmp_path, "npm")
    assert result == (rubric.PROFILE_CLI_FRAMEWORK, "metadata: 1 bin entry point(s)")


def test_requests_httpx_etc_detect_as_network_library():
    assert rubric.detect_profile_from_name("requests", "pypi") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: requests",
    )
    assert rubric.detect_profile_from_name("httpx", "pypi") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: httpx",
    )
    assert rubric.detect_profile_from_name("urllib3", "pypi") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: urllib3",
    )
    assert rubric.detect_profile_from_name("aiohttp", "pypi") == (
        rubric.PROFILE_NETWORK_LIBRARY, "name-allowlist: aiohttp",
    )


def test_normal_libraries_are_not_detected():
    assert rubric.detect_profile_from_name("lodash", "npm") is None
    assert rubric.detect_profile_from_name("mcp", "pypi") is None  # the SDK itself: library, not server
    assert rubric.detect_profile_from_name("@modelcontextprotocol/sdk", "npm") is None
    assert rubric.detect_profile_from_name("numpy", "pypi") is None


def test_empty_or_unknown_ecosystem_returns_none():
    assert rubric.detect_profile_from_name("", "pypi") is None
    assert rubric.detect_profile_from_name("mcp-server-foo", "unknown") is None
