from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_DIR_NAME = ".localguard"
PINNED_FILENAME = "pinned.json"
SCHEMA_VERSION = 1
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


def write_library_entry(report: dict[str, Any], library_root: Path | None = None, *, refresh: bool = False) -> Path:
    library_root = library_root or DEFAULT_LIBRARY_ROOT
    bucket = _bucket_for(report, library_root)
    bucket.mkdir(parents=True, exist_ok=True)
    stamped = dict(report)
    stamped["schema_version"] = SCHEMA_VERSION
    stamped.setdefault("baselined_at", _now_iso())
    if refresh:
        stamped["refreshed_at"] = _now_iso()
    report_path = bucket / f"{report['target_hash']}.json"
    _write_json(report_path, stamped)
    _update_index(stamped, library_root)
    return report_path


def latest_known_good(name: str, ecosystem: str, library_root: Path | None = None) -> dict | None:
    library_root = library_root or DEFAULT_LIBRARY_ROOT
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


def library_lookup(target_hash: str, name: str | None, ecosystem: str, library_root: Path | None = None) -> dict | None:
    library_root = library_root or DEFAULT_LIBRARY_ROOT
    if not name:
        return None
    name_root = library_root / ecosystem / name
    for report_path in name_root.rglob(f"{target_hash}.json"):
        return _read_json(report_path)
    return None


def iter_library(library_root: Path | None = None, ecosystem: str | None = None) -> list[dict]:
    library_root = library_root or DEFAULT_LIBRARY_ROOT
    if not library_root.exists():
        return []
    ecosystems = [ecosystem] if ecosystem else [d.name for d in library_root.iterdir() if d.is_dir()]
    rows: list[dict] = []
    for eco in ecosystems:
        eco_root = library_root / eco
        if not eco_root.exists():
            continue
        for name_dir in sorted(eco_root.iterdir()):
            index = _read_json(name_dir / "_index.json")
            if not index:
                continue
            for entry in index.get("entries", []):
                rows.append({
                    "name": index.get("name") or name_dir.name,
                    "ecosystem": eco,
                    "version": entry.get("version"),
                    "target_hash": entry.get("target_hash"),
                    "audited_at": entry.get("audited_at"),
                    "score": entry.get("score"),
                })
    return rows


def library_stats(library_root: Path | None = None) -> dict:
    library_root = library_root or DEFAULT_LIBRARY_ROOT
    rows = iter_library(library_root=library_root)
    by_eco: dict[str, int] = {}
    bands = {"high": 0, "mid": 0, "low": 0, "unscored": 0}
    scores: list[int] = []
    for r in rows:
        by_eco[r["ecosystem"]] = by_eco.get(r["ecosystem"], 0) + 1
        s = r.get("score")
        if s is None:
            bands["unscored"] += 1
        else:
            scores.append(s)
            if s >= 90:
                bands["high"] += 1
            elif s >= 50:
                bands["mid"] += 1
            else:
                bands["low"] += 1
    sorted_by_audited = sorted([r for r in rows if r.get("audited_at")], key=lambda r: r["audited_at"])
    oldest = sorted_by_audited[0] if sorted_by_audited else None
    newest = sorted_by_audited[-1] if sorted_by_audited else None
    size_bytes = _library_size(library_root)
    mean = sum(scores) / len(scores) if scores else None
    median = sorted(scores)[len(scores) // 2] if scores else None
    return {
        "total": len(rows),
        "size_bytes": size_bytes,
        "by_ecosystem": dict(sorted(by_eco.items())),
        "score_bands": bands,
        "mean_score": mean,
        "median_score": median,
        "oldest": oldest,
        "newest": newest,
    }


def _library_size(library_root: Path) -> int:
    if not library_root.exists():
        return 0
    total = 0
    for path in library_root.rglob("*.json"):
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


def find_library_entry(name: str, ecosystem: str, version: str | None = None, library_root: Path | None = None) -> dict | None:
    library_root = library_root or DEFAULT_LIBRARY_ROOT
    name_root = library_root / ecosystem / name
    index = _read_json(name_root / "_index.json")
    if not index:
        return None
    entries = index.get("entries", [])
    if version:
        entries = [e for e in entries if e.get("version") == version]
    if not entries:
        return None
    meta = entries[-1]
    return _read_json(name_root / meta["version"] / f"{meta['target_hash']}.json")


def remove_library_entry(name: str, ecosystem: str, version: str, library_root: Path | None = None) -> bool:
    library_root = library_root or DEFAULT_LIBRARY_ROOT
    name_root = library_root / ecosystem / name
    index_path = name_root / "_index.json"
    index = _read_json(index_path)
    if not index:
        return False
    before = len(index.get("entries", []))
    index["entries"] = [e for e in index.get("entries", []) if e.get("version") != version]
    if len(index["entries"]) == before:
        return False
    version_dir = name_root / version
    if version_dir.exists():
        for report_file in version_dir.glob("*.json"):
            report_file.unlink()
        version_dir.rmdir()
    if index["entries"]:
        _write_json(index_path, index)
    else:
        index_path.unlink()
        if name_root.exists() and not any(name_root.iterdir()):
            name_root.rmdir()
    return True


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
