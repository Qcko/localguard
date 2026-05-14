from __future__ import annotations

import json
from pathlib import Path

import pytest

from localguard import doctor, manifest


@pytest.fixture
def fake_binary(tmp_path, monkeypatch):
    exe = tmp_path / "localguard.exe"
    exe.write_text("", encoding="utf-8")
    monkeypatch.setattr("shutil.which", lambda name: str(exe) if name == "localguard" else None)
    return exe.resolve()


@pytest.fixture
def good_settings(tmp_path, fake_binary):
    settings = tmp_path / "settings.json"
    cmd = f"{fake_binary} hook-bash"
    settings.write_text(json.dumps({
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": cmd}]}]}
    }), encoding="utf-8")
    return settings


def _write_library_entry(library_root: Path, name: str, version: str, *, schema_version=1, target_hash="abc123"):
    bucket = library_root / "pypi" / name / version
    bucket.mkdir(parents=True, exist_ok=True)
    report = {"name": name, "version": version, "ecosystem": "pypi", "target_hash": target_hash, "schema_version": schema_version, "score": {"final_score": 95}}
    (bucket / f"{target_hash}.json").write_text(json.dumps(report), encoding="utf-8")
    index_path = library_root / "pypi" / name / "_index.json"
    index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else {"name": name, "ecosystem": "pypi", "entries": []}
    index["entries"].append({"version": version, "target_hash": target_hash, "audited_at": "2026-05-14T00:00:00+00:00", "score": 95})
    index_path.write_text(json.dumps(index), encoding="utf-8")


def test_doctor_all_green(tmp_path, good_settings):
    library = tmp_path / "library"
    _write_library_entry(library, "six", "1.16.0")
    cache = tmp_path / "cache"
    cache.mkdir()

    report = doctor.run(settings_path=good_settings, library_root=library, cache_root=cache)
    assert report.healthy
    assert report.fail == 0
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["binary"] == "ok"
    assert statuses["hook"] == "ok"
    assert statuses["library-root"] == "ok"
    assert statuses["library-index"] == "ok"
    assert statuses["library-schema"] == "ok"


def test_doctor_fails_when_binary_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    settings = tmp_path / "settings.json"
    library = tmp_path / "library"
    cache = tmp_path / "cache"

    report = doctor.run(settings_path=settings, library_root=library, cache_root=cache)
    assert not report.healthy
    binary_check = next(c for c in report.checks if c.name == "binary")
    assert binary_check.status == "fail"


def test_doctor_fails_when_settings_missing(tmp_path, fake_binary):
    settings = tmp_path / "missing.json"
    library = tmp_path / "library"
    cache = tmp_path / "cache"

    report = doctor.run(settings_path=settings, library_root=library, cache_root=cache)
    hook_check = next(c for c in report.checks if c.name == "hook")
    assert hook_check.status == "fail"
    assert "does not exist" in hook_check.detail


def test_doctor_fails_when_no_bash_matcher(tmp_path, fake_binary):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Read", "hooks": []}]}}), encoding="utf-8")
    library = tmp_path / "library"
    cache = tmp_path / "cache"

    report = doctor.run(settings_path=settings, library_root=library, cache_root=cache)
    hook_check = next(c for c in report.checks if c.name == "hook")
    assert hook_check.status == "fail"


def test_doctor_warns_on_path_mismatch(tmp_path, monkeypatch):
    on_path = tmp_path / "a" / "localguard.exe"
    on_path.parent.mkdir(parents=True)
    on_path.write_text("", encoding="utf-8")
    monkeypatch.setattr("shutil.which", lambda name: str(on_path))

    in_hook = tmp_path / "b" / "localguard.exe"
    in_hook.parent.mkdir(parents=True)
    in_hook.write_text("", encoding="utf-8")
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": f"{in_hook} hook-bash"}]}]}
    }), encoding="utf-8")

    report = doctor.run(settings_path=settings, library_root=tmp_path / "lib", cache_root=tmp_path / "cache")
    hook_check = next(c for c in report.checks if c.name == "hook")
    assert hook_check.status == "warn"
    assert "mismatched" in hook_check.detail


def test_doctor_fails_on_missing_report_file(tmp_path, good_settings):
    library = tmp_path / "library"
    _write_library_entry(library, "six", "1.16.0")
    # Delete the underlying report but keep the index entry.
    (library / "pypi" / "six" / "1.16.0" / "abc123.json").unlink()

    report = doctor.run(settings_path=good_settings, library_root=library, cache_root=tmp_path / "cache")
    idx = next(c for c in report.checks if c.name == "library-index")
    assert idx.status == "fail"
    assert "missing" in idx.detail


def test_doctor_warns_on_orphan_report(tmp_path, good_settings):
    library = tmp_path / "library"
    _write_library_entry(library, "six", "1.16.0", target_hash="indexedhash")
    # Add an orphan file not referenced by the index.
    (library / "pypi" / "six" / "1.16.0" / "orphan.json").write_text(
        json.dumps({"target_hash": "orphan", "schema_version": 1}), encoding="utf-8"
    )

    report = doctor.run(settings_path=good_settings, library_root=library, cache_root=tmp_path / "cache")
    idx = next(c for c in report.checks if c.name == "library-index")
    assert idx.status == "warn"
    assert "orphan" in idx.detail


def test_doctor_warns_on_stale_schema(tmp_path, good_settings):
    library = tmp_path / "library"
    _write_library_entry(library, "six", "1.16.0", schema_version=None)

    report = doctor.run(settings_path=good_settings, library_root=library, cache_root=tmp_path / "cache")
    schema = next(c for c in report.checks if c.name == "library-schema")
    assert schema.status == "warn"
    assert "refresh" in schema.detail


def test_resolve_bash_executable_path_roundtrips_drive(monkeypatch):
    monkeypatch.setattr("os.name", "nt")
    p = doctor._resolve_bash_executable_path("/e/uv/tools/bin/localguard.exe hook-bash")
    assert p == Path("E:/uv/tools/bin/localguard.exe")
