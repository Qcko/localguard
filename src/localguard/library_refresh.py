from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import inspect as inspect_mod, manifest


@dataclass
class RefreshOutcome:
    name: str
    version: str
    ecosystem: str
    status: str  # "refreshed" | "unchanged" | "error"
    old_score: int | None = None
    new_score: int | None = None
    error: str | None = None


@dataclass
class RefreshSummary:
    outcomes: list[RefreshOutcome]
    dry_run: bool

    @property
    def refreshed(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "refreshed")

    @property
    def errors(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "error")


def refresh(
    *,
    ecosystem: str | None = None,
    name_pattern: str | None = None,
    status: str | None = None,
    dry_run: bool = False,
    redetect_profile: bool = False,
    library_root: Path | None = None,
    on_progress: Callable[[RefreshOutcome], None] | None = None,
) -> RefreshSummary:
    library_root = library_root or manifest.DEFAULT_LIBRARY_ROOT
    rows = manifest.iter_library(library_root=library_root, ecosystem=ecosystem)
    if name_pattern:
        rows = [r for r in rows if name_pattern.lower() in (r.get("name") or "").lower()]
    if status:
        rows = [r for r in rows if r.get("status") == status]
    outcomes: list[RefreshOutcome] = []
    for row in rows:
        outcome = _refresh_one(row, dry_run=dry_run, redetect_profile=redetect_profile, library_root=library_root)
        outcomes.append(outcome)
        if on_progress:
            on_progress(outcome)
    return RefreshSummary(outcomes=outcomes, dry_run=dry_run)


def _refresh_one(row: dict, *, dry_run: bool, redetect_profile: bool, library_root: Path) -> RefreshOutcome:
    name = row["name"]
    version = row["version"]
    eco = row["ecosystem"]
    old_score = row.get("score")
    sep = "@" if eco == "npm" else "=="
    spec = f"{name}{sep}{version}" if version else name
    stored = manifest.find_library_entry(name, eco, version=version, library_root=library_root) or {}
    if redetect_profile:
        stored_profile = None
        stored_reason = None
    else:
        stored_profile = stored.get("profile")
        stored_reason = stored.get("profile_reason")
    try:
        report, _spec, _root = inspect_mod.inspect(spec, ecosystem=eco, profile=stored_profile, profile_reason=stored_reason)
    except Exception as exc:
        return RefreshOutcome(name=name, version=version, ecosystem=eco, status="error", old_score=old_score, error=str(exc))
    new_dict = report.to_dict()
    new_score = (new_dict.get("score") or {}).get("final_score")
    if not dry_run:
        manifest.write_library_entry(new_dict, library_root=library_root, refresh=True)
    return RefreshOutcome(name=name, version=version, ecosystem=eco, status="refreshed", old_score=old_score, new_score=new_score)
