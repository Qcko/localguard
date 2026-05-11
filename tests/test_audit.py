from pathlib import Path

from localguard import audit
from localguard.report import SurfaceKind


FIXTURES = Path(__file__).parent / "fixtures"


def kinds_of(report) -> set[str]:
    return {f.kind.value for f in report.findings}


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


def test_score_includes_visible_rubric_breakdown():
    report = audit.audit_path(FIXTURES / "tampered_v2")
    deductions = report.score.deductions
    assert deductions, "score breakdown must be visible in the report"
    kinds = {d["kind"] for d in deductions}
    assert SurfaceKind.OUTBOUND_NETWORK.value in kinds
    assert SurfaceKind.SUBPROCESS.value in kinds
    for entry in deductions:
        assert "per_finding" in entry and "cap" in entry and "deducted" in entry
