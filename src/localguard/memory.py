"""Public seam for trusted-content vetting.

The contract a consumer (e.g. GLaDOS) integrates against:

    is_approved(source, blob) -> Verdict   # load-time, cheap, deterministic, no model
    approve(source, blob, ...)             # approval-time, records the baseline

Load-time is a pure hash lookup against the approved-memory baseline. Unknown
or changed content fails closed -- LocalGuard never auto-approves. The runtime
guard-wrapping (delimiting the blob as untrusted data) is the consumer's job;
LocalGuard owns the verdict + baseline only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import memory_store
from .report import _finding_to_dict
from .memory_scan import scan_memory, summarize


@dataclass(frozen=True)
class Verdict:
    approved: bool
    reason: str
    source: str
    sha256: str
    version: str | None = None
    reason_code: str = "approved"


def is_approved(source: str, blob: str, library_root: Path | None = None) -> Verdict:
    sha = memory_store.blob_sha256(blob)
    record = memory_store.lookup(source, sha, library_root=library_root)
    if record is None:
        return Verdict(False, "no approved baseline for this content", source, sha, reason_code="unknown_content")
    if record.get("status") != memory_store.APPROVED_STATUS:
        return Verdict(False, f"baseline status is {record.get('status')!r}, not approved", source, sha, reason_code="baseline_not_approved")
    return Verdict(True, "content matches an approved baseline", source, sha, record.get("version"), reason_code="approved")


def approve(
    source: str,
    blob: str,
    *,
    findings: list[Any] | None = None,
    judge: dict | None = None,
    library_root: Path | None = None,
) -> Path:
    sha = memory_store.blob_sha256(blob)
    scan = findings if findings is not None else scan_memory(blob)
    summary = summarize(scan)
    record = {
        "content_kind": "memory",
        "source": source,
        "version": memory_store.next_version(source, library_root=library_root),
        "sha256": sha,
        "blob_len": len(blob),
        "status": memory_store.APPROVED_STATUS,
        "approved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "recommendation": {"level": summary["level"], "message": summary["message"]},
        "findings": [_finding_to_dict(f) for f in scan],
        "content": blob,
        "judge": judge,
    }
    return memory_store.write_entry(record, library_root=library_root)
