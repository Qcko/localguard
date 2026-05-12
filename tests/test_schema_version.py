from pathlib import Path

from localguard import manifest


def test_library_entry_stamped_with_schema_version_and_baselined_at(tmp_path):
    report = {
        "name": "demo",
        "version": "1.0",
        "ecosystem": "pypi",
        "target_hash": "abcd",
        "score": {"final_score": 95, "deductions": []},
        "findings": [],
    }
    path = manifest.write_library_entry(report, library_root=tmp_path / "lib")
    stored = manifest._read_json(path)
    assert stored["schema_version"] == manifest.SCHEMA_VERSION
    assert "baselined_at" in stored


def test_write_always_stamps_current_schema_version(tmp_path):
    # schema_version is authoritative on the writer side -- a caller cannot
    # pin it to a stale value. baselined_at IS preserved across writes
    # (we want the original acceptance timestamp to survive refreshes).
    report = {
        "name": "demo",
        "version": "1.0",
        "ecosystem": "pypi",
        "target_hash": "abcd",
        "schema_version": 99,
        "baselined_at": "2024-01-01T00:00:00+00:00",
        "score": {"final_score": 95, "deductions": []},
        "findings": [],
    }
    path = manifest.write_library_entry(report, library_root=tmp_path / "lib")
    stored = manifest._read_json(path)
    assert stored["schema_version"] == manifest.SCHEMA_VERSION
    assert stored["baselined_at"] == "2024-01-01T00:00:00+00:00"
