"""Approved-memory baseline: a store parallel to the package library.

Trusted-content approvals live under `<library-root>/memory/<source>/` so they
never co-mingle with pip/uv/npm baselines in the package views (iter_library
skips the reserved `memory` ecosystem). Layout mirrors the package store so the
mental model carries over:

    <library-root>/memory/<source>/_index.json
    <library-root>/memory/<source>/v<N>/<sha256>.json

`source` is an opaque, stable origin key chosen by the consumer (e.g. an MCP
server id). LocalGuard does content + integrity only; whether the source is
"first-party" is the caller's trust boundary, not ours.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from . import manifest

MEMORY_NAMESPACE = "memory"
APPROVED_STATUS = "approved"


def blob_sha256(blob: str) -> str:
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def memory_root(library_root: Path | None = None) -> Path:
    base = library_root or manifest.DEFAULT_LIBRARY_ROOT
    return base / MEMORY_NAMESPACE


def lookup(source: str, sha: str, library_root: Path | None = None) -> dict | None:
    source_root = memory_root(library_root) / source
    if not source_root.exists():
        return None
    for record_path in source_root.rglob(f"{sha}.json"):
        return manifest._read_json(record_path)
    return None


def lookup_version(source: str, version: str, library_root: Path | None = None) -> dict | None:
    version_dir = memory_root(library_root) / source / version
    if not version_dir.exists():
        return None
    for record_path in version_dir.glob("*.json"):
        return manifest._read_json(record_path)
    return None


def latest_approved(source: str, library_root: Path | None = None) -> dict | None:
    index = _read_index(source, library_root)
    if not index:
        return None
    source_root = memory_root(library_root) / source
    for entry in reversed(index.get("entries", [])):
        record = manifest._read_json(source_root / entry["version"] / f"{entry['sha256']}.json")
        if record and record.get("status") == APPROVED_STATUS:
            return record
    return None


def next_version(source: str, library_root: Path | None = None) -> str:
    index = _read_index(source, library_root)
    if not index:
        return "v1"
    highest = 0
    for entry in index.get("entries", []):
        match = re.fullmatch(r"v(\d+)", entry.get("version", ""))
        if match:
            highest = max(highest, int(match.group(1)))
    return f"v{highest + 1}"


def write_entry(record: dict[str, Any], library_root: Path | None = None) -> Path:
    source = record["source"]
    version = record["version"]
    sha = record["sha256"]
    source_root = memory_root(library_root) / source
    record_path = source_root / version / f"{sha}.json"
    manifest._write_json(record_path, record)
    _update_index(record, library_root)
    return record_path


def iter_memory(library_root: Path | None = None) -> list[dict]:
    root = memory_root(library_root)
    if not root.exists():
        return []
    rows: list[dict] = []
    for index_path in sorted(root.glob("*/_index.json")):
        index = manifest._read_json(index_path)
        if not index:
            continue
        source = index.get("source") or index_path.parent.name
        for entry in index.get("entries", []):
            rows.append({
                "source": source,
                "version": entry.get("version"),
                "sha256": entry.get("sha256"),
                "approved_at": entry.get("approved_at"),
                "status": entry.get("status", APPROVED_STATUS),
                "blob_len": entry.get("blob_len"),
            })
    return rows


def forget(source: str, version: str | None = None, library_root: Path | None = None) -> bool:
    source_root = memory_root(library_root) / source
    index_path = source_root / "_index.json"
    index = manifest._read_json(index_path)
    if not index:
        return False
    entries = index.get("entries", [])
    keep = [e for e in entries if version is not None and e.get("version") != version]
    if version is None:
        removed = bool(entries)
        target_versions = {e.get("version") for e in entries}
    else:
        removed = len(keep) != len(entries)
        target_versions = {version} if removed else set()
    if not removed:
        return False
    for ver in target_versions:
        version_dir = source_root / ver
        if version_dir.exists():
            for record_file in version_dir.glob("*.json"):
                record_file.unlink()
            version_dir.rmdir()
    if keep:
        index["entries"] = keep
        manifest._write_json(index_path, index)
    else:
        index_path.unlink()
        if source_root.exists() and not any(source_root.iterdir()):
            source_root.rmdir()
    return True


def _read_index(source: str, library_root: Path | None) -> dict | None:
    return manifest._read_json(memory_root(library_root) / source / "_index.json")


def _update_index(record: dict[str, Any], library_root: Path | None) -> None:
    source = record["source"]
    index_path = memory_root(library_root) / source / "_index.json"
    index = manifest._read_json(index_path) or {"source": source, "entries": []}
    entry = {
        "version": record["version"],
        "sha256": record["sha256"],
        "approved_at": record.get("approved_at"),
        "status": record.get("status", APPROVED_STATUS),
        "blob_len": record.get("blob_len"),
    }
    index["entries"] = [e for e in index["entries"] if e.get("version") != entry["version"]]
    index["entries"].append(entry)
    manifest._write_json(index_path, index)
