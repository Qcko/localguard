import json
import textwrap
from pathlib import Path

from localguard import audit, cli, egress, js_ast, manifest, python_ast
from localguard.report import SurfaceKind
from localguard.walker import SourceFile


def _py(text: str, rel: str = "module.py") -> SourceFile:
    return SourceFile(path=Path(rel), rel=rel, language="python", text=text)


def _js(text: str, rel: str = "module.js") -> SourceFile:
    return SourceFile(path=Path(rel), rel=rel, language="javascript", text=text)


def test_python_literal_host_classified_as_outbound_network():
    findings = python_ast.audit_python(_py("import requests\nrequests.get('https://api.openai.com/v1/chat')"))
    net = [f for f in findings if f.kind == SurfaceKind.OUTBOUND_NETWORK]
    dyn = [f for f in findings if f.kind == SurfaceKind.OUTBOUND_DYNAMIC]
    assert len(net) == 1
    assert net[0].extra["host"] == "api.openai.com"
    assert not dyn


def test_python_dynamic_host_classified_as_outbound_dynamic():
    findings = python_ast.audit_python(_py("import requests\nrequests.get(user_url)"))
    dyn = [f for f in findings if f.kind == SurfaceKind.OUTBOUND_DYNAMIC]
    assert len(dyn) == 1
    assert dyn[0].extra["host"] is None


def test_js_literal_host_classified_as_outbound_network():
    findings = js_ast.audit_js(_js("fetch('https://api.openai.com/v1/chat');"))
    net = [f for f in findings if f.kind == SurfaceKind.OUTBOUND_NETWORK]
    assert len(net) == 1
    assert net[0].extra["host"] == "api.openai.com"


def test_js_dynamic_host_classified_as_outbound_dynamic():
    findings = js_ast.audit_js(_js("fetch(userUrl);"))
    dyn = [f for f in findings if f.kind == SurfaceKind.OUTBOUND_DYNAMIC]
    assert len(dyn) == 1


def test_egress_profile_separates_static_and_dynamic():
    report = {
        "name": "demo", "version": "1.0", "ecosystem": "pypi", "target_hash": "x",
        "findings": [
            {"kind": "outbound_network", "file": "a.py", "line": 1, "detail": "", "confidence": "literal", "extra": {"fqn": "requests.get", "host": "api.openai.com"}},
            {"kind": "outbound_network", "file": "a.py", "line": 2, "detail": "", "confidence": "literal", "extra": {"fqn": "requests.post", "host": "api.openai.com"}},
            {"kind": "outbound_dynamic", "file": "b.py", "line": 5, "detail": "", "confidence": "literal", "extra": {"fqn": "requests.get", "host": None}},
            {"kind": "subprocess", "file": "c.py", "line": 9, "detail": "subprocess.Popen('ls')", "confidence": "literal", "extra": {"fqn": "subprocess.Popen"}},
            {"kind": "listening_port", "file": "d.py", "line": 11, "detail": "", "confidence": "literal", "extra": {"fqn": "app.listen"}},
        ],
    }
    profile = egress.profile_from_report(report)
    assert profile["egress"]["static_hosts"] == ["api.openai.com"]
    assert len(profile["egress"]["dynamic_callsites"]) == 1
    assert profile["egress"]["dynamic_callsites"][0]["file"] == "b.py"
    assert len(profile["egress"]["subprocess_callsites"]) == 1
    assert len(profile["egress"]["listening_ports"]) == 1
    assert profile["policy_hints"]["allowlist_sufficient"] is False  # has dynamic
    assert profile["policy_hints"]["needs_proxy_or_block"] is True


def test_egress_profile_fully_offline_when_empty():
    report = {"name": "clean", "version": "1.0", "ecosystem": "pypi", "findings": []}
    profile = egress.profile_from_report(report)
    assert profile["policy_hints"]["fully_offline_capable"] is True
    assert profile["egress"]["static_hosts"] == []


def test_egress_profile_allowlist_sufficient_when_only_static():
    report = {
        "name": "demo", "version": "1.0", "ecosystem": "pypi",
        "findings": [
            {"kind": "outbound_network", "file": "a.py", "line": 1, "detail": "", "confidence": "literal", "extra": {"fqn": "requests.get", "host": "api.openai.com"}},
        ],
    }
    profile = egress.profile_from_report(report)
    assert profile["policy_hints"]["allowlist_sufficient"] is True
    assert profile["policy_hints"]["needs_proxy_or_block"] is False


def test_cli_egress_reads_library_entry(tmp_path, monkeypatch, capsys):
    report = {
        "name": "demo", "version": "1.0", "ecosystem": "pypi", "target_hash": "hash",
        "score": {"final_score": 95, "deductions": []},
        "findings": [{"kind": "outbound_network", "file": "x.py", "line": 1, "detail": "", "confidence": "literal", "extra": {"host": "api.openai.com"}}],
    }
    manifest.write_library_entry(report, library_root=tmp_path / "lib")
    monkeypatch.setattr(manifest, "DEFAULT_LIBRARY_ROOT", tmp_path / "lib")
    from localguard import cli as cli_mod
    monkeypatch.setattr(cli_mod.manifest, "DEFAULT_LIBRARY_ROOT", tmp_path / "lib")

    rc = cli.main(["egress", "demo==1.0", "--ecosystem", "pypi"])
    out = capsys.readouterr().out

    assert rc == 0
    parsed = json.loads(out)
    assert parsed["egress"]["static_hosts"] == ["api.openai.com"]


def test_cli_egress_missing_entry(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(manifest, "DEFAULT_LIBRARY_ROOT", tmp_path / "lib")
    from localguard import cli as cli_mod
    monkeypatch.setattr(cli_mod.manifest, "DEFAULT_LIBRARY_ROOT", tmp_path / "lib")
    rc = cli.main(["egress", "ghost==9.9", "--ecosystem", "pypi"])
    assert rc == 1
    assert "no library entry" in capsys.readouterr().err
