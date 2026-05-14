from __future__ import annotations

import json
from pathlib import Path

from localguard import cli


FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_audit_default_profile_is_plugin(capsys):
    cli.main(["audit", str(FIXTURES / "clean_pkg")])
    payload = json.loads(capsys.readouterr().out)
    assert payload["profile"] == "plugin"
    assert payload["profile_reason"] is None


def test_cli_audit_with_profile_flag_stamps_report(capsys):
    cli.main(["audit", str(FIXTURES / "clean_pkg"), "--profile", "mcp-server"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["profile"] == "mcp-server"
    assert payload["profile_reason"] == "manual: --profile mcp-server"


def test_cli_inspect_threads_profile_through(monkeypatch, capsys):
    from localguard import fetch, report as report_mod
    captured: dict = {}

    def fake_inspect(spec, ecosystem=None, profile=None, profile_reason=None, **kw):
        captured["profile"] = profile
        captured["reason"] = profile_reason
        r = report_mod.AuditReport(target=spec, target_hash="t", ecosystem="pypi", name="x", version="1.0")
        r.profile = profile or "plugin"
        r.profile_reason = profile_reason
        r.score = report_mod.ScoreBreakdown(final_score=100)
        return r, fetch.PackageSpec(name="x", version="1.0", ecosystem="pypi"), "."
    monkeypatch.setattr("localguard.cli.inspect_mod.inspect", fake_inspect)

    cli.main(["inspect", "x==1.0", "--profile", "mcp-server"])
    assert captured["profile"] == "mcp-server"
    assert captured["reason"] == "manual: --profile mcp-server"
