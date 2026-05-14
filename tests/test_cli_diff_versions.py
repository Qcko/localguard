from __future__ import annotations

import io
import sys
from types import SimpleNamespace

import pytest

from localguard import cli, fetch, report as report_mod
from localguard.report import AuditReport, Confidence, Finding, ScoreBreakdown, SurfaceKind


def _make_report(name: str, version: str, score: int, findings: list[Finding]) -> AuditReport:
    r = AuditReport(target=name, target_hash=f"{name}-{version}-hash", ecosystem="pypi", name=name, version=version)
    r.findings = findings
    r.score = ScoreBreakdown(final_score=score, deductions=[])
    return r


def _f(kind: SurfaceKind, *, host: str | None = None, file: str = "x.py", line: int = 1) -> Finding:
    extra = {"host": host} if host else {}
    return Finding(kind=kind, file=file, line=line, detail="", confidence=Confidence.LITERAL, extra=extra)


def test_diff_versions_reports_new_surfaces(monkeypatch, capsys):
    a = _make_report("alpha", "1.0", 95, [_f(SurfaceKind.OUTBOUND_NETWORK, host="a.example.com")])
    b = _make_report("alpha", "2.0", 70, [
        _f(SurfaceKind.OUTBOUND_NETWORK, host="a.example.com"),
        _f(SurfaceKind.OUTBOUND_NETWORK, host="evil.example.com"),
        _f(SurfaceKind.SUBPROCESS, file="run.py", line=10),
    ])
    calls = []
    def fake_inspect(spec, ecosystem=None):
        calls.append(spec)
        name, _, ver = spec.partition("==")
        rep = a if ver == "1.0" else b
        pkg = fetch.PackageSpec(name=name, version=ver, ecosystem="pypi")
        return rep, pkg, "."
    monkeypatch.setattr("localguard.cli.inspect_mod.inspect", fake_inspect)

    rc = cli.main(["diff-versions", "alpha", "1.0", "2.0"])
    out = capsys.readouterr().out
    assert rc == 1  # drift present
    assert "alpha (pypi): 1.0 -> 2.0" in out
    assert "95 -> 70" in out
    assert "NEW surfaces" in out
    assert "outbound_network" in out
    assert "subprocess" in out
    assert "evil.example.com" in out


def test_diff_versions_clean_when_no_changes(monkeypatch, capsys):
    findings = [_f(SurfaceKind.OUTBOUND_NETWORK, host="a.example.com")]
    a = _make_report("alpha", "1.0", 95, findings)
    b = _make_report("alpha", "1.1", 95, findings)
    def fake_inspect(spec, ecosystem=None):
        name, _, ver = spec.partition("==")
        rep = a if ver == "1.0" else b
        return rep, fetch.PackageSpec(name=name, version=ver, ecosystem="pypi"), "."
    monkeypatch.setattr("localguard.cli.inspect_mod.inspect", fake_inspect)

    rc = cli.main(["diff-versions", "alpha", "1.0", "1.1"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no surface changes" in out


def test_diff_versions_json_payload(monkeypatch, capsys):
    a = _make_report("alpha", "1.0", 95, [])
    b = _make_report("alpha", "2.0", 80, [_f(SurfaceKind.SUBPROCESS, file="x.py", line=2)])
    def fake_inspect(spec, ecosystem=None):
        name, _, ver = spec.partition("==")
        rep = a if ver == "1.0" else b
        return rep, fetch.PackageSpec(name=name, version=ver, ecosystem="pypi"), "."
    monkeypatch.setattr("localguard.cli.inspect_mod.inspect", fake_inspect)

    rc = cli.main(["diff-versions", "alpha", "1.0", "2.0", "--json"])
    out = capsys.readouterr().out
    assert rc == 1
    import json
    payload = json.loads(out)
    assert payload["name"] == "alpha"
    assert payload["from_version"] == "1.0"
    assert payload["to_version"] == "2.0"
    assert payload["score_delta"] == -15
    assert payload["has_drift"] is True


def test_diff_versions_uses_at_separator_for_scoped_npm(monkeypatch):
    a = _make_report("@scope/pkg", "1.0", 95, [])
    b = _make_report("@scope/pkg", "2.0", 95, [])
    seen = []
    def fake_inspect(spec, ecosystem=None):
        seen.append(spec)
        _, _, ver = spec.rpartition("@")
        rep = a if ver == "1.0" else b
        return rep, fetch.PackageSpec(name="@scope/pkg", version=ver, ecosystem="npm"), "."
    monkeypatch.setattr("localguard.cli.inspect_mod.inspect", fake_inspect)

    cli.main(["diff-versions", "@scope/pkg", "1.0", "2.0"])
    assert seen == ["@scope/pkg@1.0", "@scope/pkg@2.0"]
