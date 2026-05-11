from pathlib import Path

from localguard import audit
from localguard.diff import diff_reports
from localguard.report import SurfaceKind


FIXTURES = Path(__file__).parent / "fixtures"


def kinds_of(report_dict) -> set[str]:
    return {f["kind"] for f in report_dict["findings"]}


def test_mcp_clean_reports_declared_tools_and_resources():
    report = audit.audit_path(FIXTURES / "mcp_clean").to_dict()
    found = kinds_of(report)
    assert SurfaceKind.MCP_TOOL.value in found
    assert SurfaceKind.MCP_RESOURCE.value in found
    assert SurfaceKind.PROMPT_INJECTION_HINT.value not in found


def test_mcp_tampered_flags_injection_and_launch_drift():
    report = audit.audit_path(FIXTURES / "mcp_tampered").to_dict()
    found = kinds_of(report)
    assert SurfaceKind.PROMPT_INJECTION_HINT.value in found
    assert SurfaceKind.MCP_TRANSPORT_DRIFT.value in found
    drift_reasons = {
        f["extra"].get("reason")
        for f in report["findings"]
        if f["kind"] == SurfaceKind.MCP_TRANSPORT_DRIFT.value
    }
    assert {"auto-accept", "unpinned"}.issubset(drift_reasons)


def test_mcp_diff_flags_new_tool_between_versions():
    baseline = audit.audit_path(FIXTURES / "mcp_clean").to_dict()
    candidate = audit.audit_path(FIXTURES / "mcp_tampered").to_dict()
    drift = diff_reports(baseline, candidate)
    new_tools = drift.new_findings.get(SurfaceKind.MCP_TOOL.value, [])
    tool_names = {f["extra"].get("name") for f in new_tools}
    assert "helpful_assistant" in tool_names
