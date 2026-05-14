from __future__ import annotations

from pathlib import Path

from localguard import text_sweep
from localguard.report import SurfaceKind
from localguard.walker import SourceFile


def _src(text: str, language: str = "python", rel: str = "pkg/x.py") -> SourceFile:
    return SourceFile(path=Path(rel), rel=rel, language=language, text=text)


def _hosts(findings):
    return [f.extra.get("host") for f in findings if f.kind in {SurfaceKind.HARDCODED_HOST, SurfaceKind.TELEMETRY_ENDPOINT}]


def test_rfc_documentation_ipv4_ranges_are_skipped():
    text = "\n".join([
        "a = '192.0.2.1'",      # TEST-NET-1
        "b = '198.51.100.42'",  # TEST-NET-2
        "c = '203.0.113.99'",   # TEST-NET-3
        "d = '255.0.0.0'",      # reserved
        "e = '255.255.255.128'",
        "f = '239.0.0.1'",      # multicast
        "g = '8.8.8.8'",        # real -- should be found
    ])
    findings = text_sweep.sweep_text(_src(text))
    hosts = _hosts(findings)
    assert "8.8.8.8" in hosts
    for noise in ("192.0.2.1", "198.51.100.42", "203.0.113.99", "255.0.0.0", "255.255.255.128", "239.0.0.1"):
        assert noise not in hosts, f"expected {noise} to be filtered"


def test_rfc_documentation_hostnames_are_skipped():
    text = "\n".join([
        "url1 = 'https://example.com/path'",
        "url2 = 'http://example.org'",
        "url3 = 'https://api.example'",
        "url4 = 'http://something.test/x'",
        "url5 = 'https://api.real.com/v1'",  # real -- should be found
    ])
    findings = text_sweep.sweep_text(_src(text))
    hosts = _hosts(findings)
    assert "api.real.com" in hosts
    for noise in ("example.com", "example.org", "api.example", "something.test"):
        assert noise not in hosts


def test_python_comments_skipped_for_urls_and_ips():
    text = "\n".join([
        "# Reference: https://docs.python.org/3 -- comment",
        "# 8.8.8.8 is a doc reference",
        "real = 'https://api.real.com'",
        "real_ip = '54.230.1.1'",
    ])
    findings = text_sweep.sweep_text(_src(text))
    hosts = _hosts(findings)
    assert "api.real.com" in hosts
    assert "54.230.1.1" in hosts
    assert "docs.python.org" not in hosts
    assert "8.8.8.8" not in hosts


def test_python_docstrings_skipped():
    text = '\n'.join([
        'def f():',
        '    """Connect to https://docs.example.com/api.',
        '    ',
        '    Example: 1.2.3.4',
        '    """',
        '    return "https://api.real.com"',
    ])
    findings = text_sweep.sweep_text(_src(text))
    hosts = _hosts(findings)
    assert "api.real.com" in hosts
    assert "docs.example.com" not in hosts
    assert "1.2.3.4" not in hosts


def test_python_single_line_docstring_skipped():
    text = '\n'.join([
        'def f():',
        '    """Calls https://docs.example.com/x and returns it."""',
        '    return "https://api.real.com"',
    ])
    findings = text_sweep.sweep_text(_src(text))
    hosts = _hosts(findings)
    assert "api.real.com" in hosts
    assert "docs.example.com" not in hosts


def test_javascript_line_comments_skipped():
    text = "\n".join([
        "// reference: https://docs.example/x",
        "const real = 'https://api.real.com/v1';",
        "/* block: 8.8.8.8 */",
        "const otherReal = 'http://api.other.com';",
    ])
    findings = text_sweep.sweep_text(_src(text, language="javascript", rel="pkg/x.js"))
    hosts = _hosts(findings)
    assert "api.real.com" in hosts
    assert "api.other.com" in hosts
    assert "docs.example" not in hosts
    assert "8.8.8.8" not in hosts


def test_javascript_block_comment_multiline_skipped():
    text = "\n".join([
        "/*",
        " * see https://docs.example.org/api",
        " * IP: 8.8.8.8",
        " */",
        "const real = 'https://api.real.com';",
    ])
    findings = text_sweep.sweep_text(_src(text, language="javascript", rel="pkg/x.js"))
    hosts = _hosts(findings)
    assert "api.real.com" in hosts
    assert "docs.example.org" not in hosts
    assert "8.8.8.8" not in hosts


def test_real_hosts_still_flagged_when_in_runtime_code():
    text = "url = 'https://api.production.com/v1'"
    findings = text_sweep.sweep_text(_src(text))
    assert any(f.extra.get("host") == "api.production.com" for f in findings)
