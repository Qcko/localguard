from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_DIR_NAME = ".localguard"
PINNED_FILENAME = "pinned.json"
DEFAULT_LIBRARY_ROOT = Path(os.environ.get("LOCALGUARD_LIBRARY") or r"E:\localguard\library")


def project_pin_path(project_root: Path) -> Path:
    return project_root / PROJECT_DIR_NAME / PINNED_FILENAME


def write_pin(project_root: Path, report: dict[str, Any]) -> Path:
    pin_path = project_pin_path(project_root)
    pin_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_json(pin_path) or {"version": 1, "entries": []}
    existing["entries"] = [e for e in existing["entries"] if not _same_target(e, report)]
    existing["entries"].append(_pin_entry(report))
    _write_json(pin_path, existing)
    return pin_path


def find_pinned_entry(project_root: Path, name: str | None, target_hash: str) -> dict | None:
    pin_path = project_pin_path(project_root)
    data = _read_json(pin_path)
    if not data:
        return None
    for entry in data.get("entries", []):
        if entry.get("target_hash") == target_hash:
            return entry
        if name and entry.get("name") == name:
            return entry
    return None


def write_library_entry(report: dict[str, Any], library_root: Path = DEFAULT_LIBRARY_ROOT) -> Path:
    bucket = _bucket_for(report, library_root)
    bucket.mkdir(parents=True, exist_ok=True)
    report_path = bucket / f"{report['target_hash']}.json"
    _write_json(report_path, report)
    _update_index(report, library_root)
    return report_path


def latest_known_good(name: str, ecosystem: str, library_root: Path = DEFAULT_LIBRARY_ROOT) -> dict | None:
    index_path = library_root / ecosystem / name / "_index.json"
    data = _read_json(index_path)
    if not data:
        return None
    entries = data.get("entries", [])
    if not entries:
        return None
    latest_meta = entries[-1]
    report_path = library_root / ecosystem / name / latest_meta["version"] / f"{latest_meta['target_hash']}.json"
    return _read_json(report_path)


def library_lookup(target_hash: str, name: str | None, ecosystem: str, library_root: Path = DEFAULT_LIBRARY_ROOT) -> dict | None:
    if not name:
        return None
    name_root = library_root / ecosystem / name
    for report_path in name_root.rglob(f"{target_hash}.json"):
        return _read_json(report_path)
    return None


def _bucket_for(report: dict[str, Any], library_root: Path) -> Path:
    ecosystem = report.get("ecosystem") or "unknown"
    name = report.get("name") or "unnamed"
    version = report.get("version") or "unversioned"
    return library_root / ecosystem / name / version


def _update_index(report: dict[str, Any], library_root: Path) -> None:
    index_path = library_root / report["ecosystem"] / report["name"] / "_index.json"
    index = _read_json(index_path) or {"name": report["name"], "ecosystem": report["ecosystem"], "entries": []}
    entry = {
        "version": report.get("version") or "unversioned",
        "target_hash": report["target_hash"],
        "audited_at": _now_iso(),
        "score": (report.get("score") or {}).get("final_score"),
    }
    index["entries"] = [e for e in index["entries"] if e["target_hash"] != entry["target_hash"]]
    index["entries"].append(entry)
    _write_json(index_path, index)


def _pin_entry(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": report.get("name"),
        "version": report.get("version"),
        "ecosystem": report.get("ecosystem"),
        "target_hash": report["target_hash"],
        "pinned_at": _now_iso(),
        "score": (report.get("score") or {}).get("final_score"),
    }


def _same_target(entry: dict, report: dict) -> bool:
    if report.get("name") and entry.get("name") == report["name"]:
        return True
    return entry.get("target_hash") == report.get("target_hash")


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
