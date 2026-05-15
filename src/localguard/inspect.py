from __future__ import annotations

from pathlib import Path

from . import audit, fetch
from .report import AuditReport
from .walker import PACKAGE_AUDIT_SKIP_DIRS


def inspect(raw_spec: str, ecosystem: str | None = None, cache_root: Path | None = None, *, profile: str | None = None, profile_reason: str | None = None) -> tuple[AuditReport, fetch.PackageSpec, Path]:
    from . import rubric
    cache_root = cache_root or fetch.DEFAULT_CACHE_ROOT
    spec = fetch.parse_spec(raw_spec, ecosystem_override=ecosystem)
    unpacked = fetch.fetch_package(spec, cache_root=cache_root)
    audit_root = _pick_audit_root(unpacked, spec.ecosystem)
    if profile is None:
        detected = rubric.detect_profile_from_name(spec.name, spec.ecosystem)
        if detected:
            profile, profile_reason = detected
    report = audit.audit_path(audit_root, profile=profile, profile_reason=profile_reason, skip_dirs=PACKAGE_AUDIT_SKIP_DIRS)
    _override_metadata(report, spec)
    return report, spec, audit_root


def _pick_audit_root(unpacked: Path, ecosystem: str) -> Path:
    if ecosystem == "npm":
        package_dir = unpacked / "package"
        if package_dir.is_dir():
            return package_dir
    entries = [p for p in unpacked.iterdir() if p.is_dir()]
    if len(entries) == 1:
        return entries[0]
    return unpacked


def _override_metadata(report: AuditReport, spec: fetch.PackageSpec) -> None:
    report.ecosystem = spec.ecosystem
    if spec.name:
        report.name = spec.name
    if spec.version and not report.version:
        report.version = spec.version
