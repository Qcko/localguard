from pathlib import Path

from localguard import audit, mcp_detector, walker
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


def test_bidi_marks_alone_are_not_flagged():
    # U+200E and U+200F are legitimate Unicode for RTL i18n
    assert mcp_detector.ZERO_WIDTH.search("‎") is None
    assert mcp_detector.ZERO_WIDTH.search("‏") is None
    # ZWSP / ZWNJ / ZWJ still flagged
    assert mcp_detector.ZERO_WIDTH.search("​")
    assert mcp_detector.ZERO_WIDTH.search("‌")
    assert mcp_detector.ZERO_WIDTH.search("‍")
    # Trojan-Source bidi overrides still flagged
    assert mcp_detector.ZERO_WIDTH.search("‮")
    # BOM still flagged
    assert mcp_detector.ZERO_WIDTH.search("﻿")


def test_i18n_directories_classified_as_non_runtime():
    assert walker.find_context("src/locales/fa.ts") == "i18n"
    assert walker.find_context("src/i18n/en.json") == "i18n"
    assert walker.find_context("messages/fr.po") == "i18n"
    assert walker.find_context("lang/de.ts") == "i18n"
    assert walker.find_context("src/runtime.ts") == "runtime"


def test_vendored_directories_classified_as_non_runtime():
    assert walker.find_context("setuptools/_vendor/jaraco/functools/__init__.py") == "vendored"
    assert walker.find_context("setuptools/_distutils/ccompiler.py") == "vendored"
    assert walker.find_context("pip/_vendor/requests/api.py") == "vendored"
    assert walker.find_context("pkg/vendor/lib/x.py") == "vendored"
    assert walker.find_context("pkg/third_party/lib.py") == "vendored"
    assert walker.find_context("pkg/third-party/lib.py") == "vendored"
    assert walker.find_context("pkg/bundled/x.py") == "vendored"
    # Hyphen-suffixed forms (numpy's vendored-meson, etc.)
    assert walker.find_context("numpy/vendored-meson/meson/mesonbuild/mesonmain.py") == "vendored"
    assert walker.find_context("pkg/_vendor-jaraco/x.py") == "vendored"


def test_autogen_files_classified_as_non_runtime():
    # Filename patterns (protobuf / gRPC)
    assert walker.find_context("tensorboard/compat/proto/config_pb2.py") == "generated"
    assert walker.find_context("grpc/health/v1/health_pb2_grpc.py") == "generated"
    assert walker.find_context("foo/bar_pb2.pyi") == "generated"
    assert walker.find_context("foo/bar_grpc_pb.ts") == "generated"
    # Directory patterns
    assert walker.find_context("src/_generated/api.ts") == "generated"
    assert walker.find_context("src/generated/api.py") == "generated"
    assert walker.find_context("src/__generated__/api.py") == "generated"
    # Not autogen
    assert walker.find_context("src/api_pb2_helper.py") == "runtime"  # contains _pb2 but not suffix
    assert walker.find_context("src/runtime.py") == "runtime"
    # Not vendored -- internals, not bundled third-party
    assert walker.find_context("pkg/_internal/x.py") == "runtime"
    assert walker.find_context("pkg/runtime.py") == "runtime"
