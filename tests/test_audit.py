from pathlib import Path

from localguard import audit
from localguard.report import SurfaceKind


FIXTURES = Path(__file__).parent / "fixtures"


def kinds_of(report) -> set[str]:
    return {f.kind.value for f in report.findings}


def test_audit_path_defaults_to_plugin_profile():
    report = audit.audit_path(FIXTURES / "clean_pkg")
    assert report.profile == "plugin"
    assert report.profile_reason is None
    assert report.to_dict()["profile"] == "plugin"


def test_audit_path_stamps_mcp_server_profile():
    report = audit.audit_path(FIXTURES / "clean_pkg", profile="mcp-server", profile_reason="manual: --profile mcp-server")
    assert report.profile == "mcp-server"
    assert report.profile_reason == "manual: --profile mcp-server"
    assert report.to_dict()["profile"] == "mcp-server"


def test_clean_pkg_has_no_dangerous_surface():
    report = audit.audit_path(FIXTURES / "clean_pkg")
    assert report.ecosystem == "pypi"
    assert report.name == "clean-pkg"
    assert report.score.final_score == 100
    forbidden = {
        SurfaceKind.OUTBOUND_NETWORK.value,
        SurfaceKind.SUBPROCESS.value,
        SurfaceKind.LISTENING_PORT.value,
        SurfaceKind.OBFUSCATION.value,
    }
    assert forbidden.isdisjoint(kinds_of(report))


def test_tampered_pkg_detects_network_subprocess_and_exfil():
    report = audit.audit_path(FIXTURES / "tampered_v2")
    found = kinds_of(report)
    assert SurfaceKind.OUTBOUND_NETWORK.value in found
    assert SurfaceKind.SUBPROCESS.value in found
    assert SurfaceKind.ENV_SECRET_READ.value in found
    assert SurfaceKind.DATA_EXFIL_HINT.value in found
    assert report.score.final_score < 100
    hosts = [f.extra.get("host") for f in report.findings if f.kind == SurfaceKind.HARDCODED_HOST or f.kind == SurfaceKind.OUTBOUND_NETWORK]
    assert any("evil.example.com" in (h or "") for h in hosts)


def test_re_compile_does_not_trigger_obfuscation(tmp_path: Path):
    src = tmp_path / "pkg"
    src.mkdir()
    (src / "pyproject.toml").write_text('[project]\nname = "pkg"\nversion = "0.1"\n', encoding="utf-8")
    (src / "mod.py").write_text("import re\npattern = re.compile(some_expr)\n", encoding="utf-8")

    report = audit.audit_path(src)

    assert SurfaceKind.OBFUSCATION.value not in kinds_of(report)


def test_bare_exec_still_triggers_obfuscation(tmp_path: Path):
    src = tmp_path / "pkg"
    src.mkdir()
    (src / "pyproject.toml").write_text('[project]\nname = "pkg"\nversion = "0.1"\n', encoding="utf-8")
    (src / "mod.py").write_text("def run(payload):\n    exec(payload)\n", encoding="utf-8")

    report = audit.audit_path(src)

    assert SurfaceKind.OBFUSCATION.value in kinds_of(report)


def test_test_directory_findings_do_not_deduct_from_score(tmp_path: Path):
    src = tmp_path / "pkg"
    src.mkdir()
    (src / "pyproject.toml").write_text('[project]\nname = "pkg"\nversion = "0.1"\n', encoding="utf-8")
    (src / "pkg.py").write_text("VERSION = '0.1'\n", encoding="utf-8")
    tests = src / "tests"
    tests.mkdir()
    (tests / "test_something.py").write_text(
        "import subprocess\nimport urllib.request\n"
        "subprocess.run(['echo', 'hi'])\n"
        "urllib.request.urlopen('http://example.com')\n",
        encoding="utf-8",
    )

    report = audit.audit_path(src)

    found_kinds = kinds_of(report)
    assert SurfaceKind.SUBPROCESS.value in found_kinds
    assert SurfaceKind.OUTBOUND_NETWORK.value in found_kinds
    assert report.score.final_score == 100


def test_score_includes_visible_rubric_breakdown():
    report = audit.audit_path(FIXTURES / "tampered_v2")
    deductions = report.score.deductions
    assert deductions, "score breakdown must be visible in the report"
    kinds = {d["kind"] for d in deductions}
    assert SurfaceKind.OUTBOUND_NETWORK.value in kinds
    assert SurfaceKind.SUBPROCESS.value in kinds
    for entry in deductions:
        assert "per_finding" in entry and "cap" in entry and "deducted" in entry
