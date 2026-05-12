import tarfile
from pathlib import Path

from localguard import audit, fetch, manifest, preflight


FIXTURES = Path(__file__).parent / "fixtures"


def _seed_cache(cache_root: Path, fixture: Path, name: str, version: str) -> None:
    archive = cache_root.parent / f"{name}-{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(fixture, arcname=f"{name}-{version}")
    src_dir = cache_root / "pypi" / name / version / "src"
    src_dir.mkdir(parents=True)
    fetch._unpack_into(archive, src_dir)


def test_preflight_first_encounter_blocks_without_accept_new(tmp_path: Path):
    cache_root = tmp_path / "cache"
    library_root = tmp_path / "lib"
    _seed_cache(cache_root, FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")

    verdict = preflight.preflight("clean-pkg==0.1.0", cache_root=cache_root, library_root=library_root, auto_accept_score=101)

    assert not verdict.safe
    assert verdict.status == "first-encounter-needs-accept"


def test_preflight_auto_baselines_high_score_first_encounter(tmp_path: Path):
    cache_root = tmp_path / "cache"
    library_root = tmp_path / "lib"
    _seed_cache(cache_root, FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")

    verdict = preflight.preflight("clean-pkg==0.1.0", cache_root=cache_root, library_root=library_root)

    assert verdict.safe
    assert verdict.status == "first-encounter-accepted"
    assert verdict.score >= 90
    assert manifest.latest_known_good("clean-pkg", "pypi", library_root=library_root) is not None
    assert any("auto-baselined" in r for r in verdict.reasons)


def test_preflight_first_encounter_accepts_and_pins(tmp_path: Path):
    cache_root = tmp_path / "cache"
    library_root = tmp_path / "lib"
    _seed_cache(cache_root, FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")

    verdict = preflight.preflight("clean-pkg==0.1.0", cache_root=cache_root, library_root=library_root, accept_new=True)

    assert verdict.safe
    assert verdict.status == "first-encounter-accepted"
    assert manifest.latest_known_good("clean-pkg", "pypi", library_root=library_root) is not None


def test_preflight_blocks_low_score_first_encounter(tmp_path: Path):
    cache_root = tmp_path / "cache"
    library_root = tmp_path / "lib"
    _seed_cache(cache_root, FIXTURES / "tampered_v2", "drifty-pkg", "0.2.0")

    verdict = preflight.preflight("drifty-pkg==0.2.0", cache_root=cache_root, library_root=library_root, accept_new=True, min_score=80)

    assert not verdict.safe
    assert verdict.status == "low-score"


def test_preflight_detects_drift_against_baseline(tmp_path: Path):
    cache_root = tmp_path / "cache"
    library_root = tmp_path / "lib"
    baseline_report = audit.audit_path(FIXTURES / "tampered_v1").to_dict()
    baseline_report["name"] = "drifty-pkg"
    baseline_report["version"] = "0.1.0"
    manifest.write_library_entry(baseline_report, library_root=library_root)
    _seed_cache(cache_root, FIXTURES / "tampered_v2", "drifty-pkg", "0.2.0")

    verdict = preflight.preflight("drifty-pkg==0.2.0", cache_root=cache_root, library_root=library_root, min_score=0)

    assert not verdict.safe
    assert verdict.status == "drift"
    assert any("novel high-risk" in r for r in verdict.reasons)


def test_preflight_safe_when_baseline_identical(tmp_path: Path):
    cache_root = tmp_path / "cache"
    library_root = tmp_path / "lib"
    baseline_report = audit.audit_path(FIXTURES / "clean_pkg").to_dict()
    baseline_report["name"] = "clean-pkg"
    baseline_report["version"] = "0.1.0"
    manifest.write_library_entry(baseline_report, library_root=library_root)
    _seed_cache(cache_root, FIXTURES / "clean_pkg", "clean-pkg", "0.1.0")

    verdict = preflight.preflight("clean-pkg==0.1.0", cache_root=cache_root, library_root=library_root)

    assert verdict.safe
    assert verdict.status == "safe"
