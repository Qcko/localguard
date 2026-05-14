from __future__ import annotations

import json
import tomllib
from pathlib import Path

from . import js_ast, mcp_detector, python_ast, rubric, text_sweep
from .report import AuditReport, Finding
from .walker import SourceFile, hash_target, walk_target


def audit_path(target: Path, *, profile: str | None = None, profile_reason: str | None = None) -> AuditReport:
    target = target.resolve()
    sources = list(walk_target(target))
    findings = _collect_findings(target, sources)
    findings = text_sweep.dedupe_hosts(findings)
    metadata = _detect_metadata(target)
    if profile is None:
        detected = rubric.detect_profile_from_content(findings) or rubric.detect_profile_from_metadata(target, metadata.get("ecosystem") or "unknown")
        if detected:
            profile, profile_reason = detected
    effective_profile = profile or rubric.DEFAULT_PROFILE
    report = AuditReport(
        target=str(target),
        target_hash=hash_target(target),
        findings=findings,
        files_audited=len(sources),
        profile=effective_profile,
        profile_reason=profile_reason,
        **metadata,
    )
    report.score = rubric.score(findings, profile=effective_profile)
    return report


def _collect_findings(target: Path, sources: list[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for source in sources:
        findings.extend(_findings_for_source(source))
    findings.extend(_findings_for_mcp_configs(target, sources))
    return findings


def _findings_for_source(source: SourceFile) -> list[Finding]:
    findings: list[Finding] = []
    if source.language == "python":
        findings.extend(python_ast.audit_python(source))
    elif source.language == "javascript":
        findings.extend(js_ast.audit_js(source))
    findings.extend(text_sweep.sweep_text(source))
    findings.extend(mcp_detector.detect_mcp(source))
    return findings


def _findings_for_mcp_configs(target: Path, sources: list[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for source in sources:
        if mcp_detector.is_mcp_config_filename(source.path):
            findings.extend(mcp_detector.detect_mcp_launch_config(source.text, source.rel))
    return findings


def _detect_metadata(target: Path) -> dict:
    pyproject = target / "pyproject.toml"
    if pyproject.exists():
        return _metadata_from_pyproject(pyproject)
    package_json = target / "package.json"
    if package_json.exists():
        return _metadata_from_package_json(package_json)
    return {"ecosystem": "unknown", "name": target.name, "version": None}


def _metadata_from_pyproject(path: Path) -> dict:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {"ecosystem": "pypi", "name": path.parent.name, "version": None}
    project = data.get("project", {})
    return {
        "ecosystem": "pypi",
        "name": project.get("name") or path.parent.name,
        "version": project.get("version"),
    }


def _metadata_from_package_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"ecosystem": "npm", "name": path.parent.name, "version": None}
    return {
        "ecosystem": "npm",
        "name": data.get("name") or path.parent.name,
        "version": data.get("version"),
    }
