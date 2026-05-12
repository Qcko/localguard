from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from . import fetch


DEFAULT_PRUNE_DAYS = 30


@dataclass
class PruneEntry:
    path: Path
    ecosystem: str
    name: str
    version: str
    size_bytes: int
    age_days: float


@dataclass
class PruneResult:
    candidates: list[PruneEntry]
    removed: list[PruneEntry]
    bytes_freed: int
    dry_run: bool


def prune(*, older_than_days: int = DEFAULT_PRUNE_DAYS, dry_run: bool = False, cache_root: Path | None = None) -> PruneResult:
    cache_root = cache_root or fetch.DEFAULT_CACHE_ROOT
    cutoff_age = older_than_days * 86400.0
    now = time.time()
    candidates: list[PruneEntry] = []
    for entry in _iter_version_dirs(cache_root):
        age_seconds = now - entry["path"].stat().st_mtime
        if age_seconds < cutoff_age:
            continue
        size = _dir_size(entry["path"])
        candidates.append(PruneEntry(
            path=entry["path"],
            ecosystem=entry["ecosystem"],
            name=entry["name"],
            version=entry["version"],
            size_bytes=size,
            age_days=age_seconds / 86400.0,
        ))
    removed: list[PruneEntry] = []
    if not dry_run:
        for cand in candidates:
            shutil.rmtree(cand.path, ignore_errors=True)
            removed.append(cand)
    return PruneResult(
        candidates=candidates,
        removed=removed,
        bytes_freed=sum(c.size_bytes for c in (removed if not dry_run else candidates)),
        dry_run=dry_run,
    )


def touch(path: Path) -> None:
    if path.exists():
        now = time.time()
        os.utime(path, (now, now))


def _iter_version_dirs(cache_root: Path):
    if not cache_root.exists():
        return
    for eco_dir in cache_root.iterdir():
        if not eco_dir.is_dir():
            continue
        for name_dir in eco_dir.iterdir():
            if not name_dir.is_dir():
                continue
            for version_dir in name_dir.iterdir():
                if not version_dir.is_dir():
                    continue
                yield {"path": version_dir, "ecosystem": eco_dir.name, "name": name_dir.name, "version": version_dir.name}


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                continue
    return total
