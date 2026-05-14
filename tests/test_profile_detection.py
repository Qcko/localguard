from __future__ import annotations

from localguard import rubric


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


def test_normal_libraries_are_not_detected():
    assert rubric.detect_profile_from_name("requests", "pypi") is None
    assert rubric.detect_profile_from_name("lodash", "npm") is None
    assert rubric.detect_profile_from_name("mcp", "pypi") is None  # the SDK itself: library, not server
    assert rubric.detect_profile_from_name("@modelcontextprotocol/sdk", "npm") is None


def test_empty_or_unknown_ecosystem_returns_none():
    assert rubric.detect_profile_from_name("", "pypi") is None
    assert rubric.detect_profile_from_name("mcp-server-foo", "unknown") is None
