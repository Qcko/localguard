from pathlib import Path

from localguard import audit, manifest
from localguard.diff import diff_reports
from localguard.report import SurfaceKind


FIXTURES = Path(__file__).parent / "fixtures"


def test_diff_catches_new_network_subprocess_and_host(tmp_path: Path):
    library = tmp_path / "library"
    baseline = audit.audit_path(FIXTURES / "tampered_v1").to_dict()
    candidate = audit.audit_path(FIXTURES / "tampered_v2").to_dict()
    manifest.write_library_entry(baseline, library_root=library)

    drift = diff_reports(baseline, candidate)

    assert drift.has_drift
    assert SurfaceKind.OUTBOUND_NETWORK.value in drift.new_findings
    assert SurfaceKind.SUBPROCESS.value in drift.new_findings
    score_delta = drift.to_dict()["score_delta"]
    assert score_delta is not None and score_delta < 0


def test_diff_clean_against_itself_has_no_drift():
    baseline = audit.audit_path(FIXTURES / "clean_pkg").to_dict()
    candidate = audit.audit_path(FIXTURES / "clean_pkg").to_dict()
    drift = diff_reports(baseline, candidate)
    assert not drift.has_drift
    assert drift.new_findings == {}


def test_pin_roundtrip_in_isolated_project(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    report = audit.audit_path(FIXTURES / "clean_pkg").to_dict()
    pin_path = manifest.write_pin(project, report)
    assert pin_path.exists()
    entry = manifest.find_pinned_entry(project, report["name"], report["target_hash"])
    assert entry is not None
    assert entry["target_hash"] == report["target_hash"]
