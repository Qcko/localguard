"""Edge cases for the file walker and per-language parsers.

Gap 9 of TESTING_PLAN.md. None of these have known regressions, but
graceful handling is part of the contract -- LocalGuard runs against
arbitrary third-party packages, and a single weird file should never
crash the audit.

Covered here:
- UTF-8 BOM at file start (Windows-authored files; should not break parser).
- Python triple-quoted strings with nested triple-quotes via escapes.
- Python syntax errors (the AST parser should fall back gracefully).
- JS syntax errors (tree-sitter is error-recovering by design).
- A "very large" file (cap that's still fast in CI).
- Files we should NOT classify as runtime (already covered elsewhere but
  re-asserted here to make the contract self-evident).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from localguard import audit, js_ast, python_ast
from localguard.walker import SourceFile, walk_target


def _src(text: str, name: str = "module.py", language: str | None = None) -> SourceFile:
    if language is None:
        language = "javascript" if name.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")) else "python"
    return SourceFile(path=Path(name), rel=name, language=language, text=text)


def test_walker_handles_utf8_bom_python(tmp_path):
    """A BOM-prefixed Python file should be readable and parseable -- BOM
    is a common Windows convention and should not change the audit
    outcome."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "mod.py").write_bytes("﻿".encode("utf-8") + b"import os\nos.environ['API_KEY']\n")
    sources = list(walk_target(pkg))
    assert len(sources) == 1
    source = sources[0]
    # BOM is preserved in the text but the parser must still produce findings.
    assert source.text.startswith("﻿") or source.text.startswith("�")
    findings = python_ast.audit_python(source)
    # Either the parser handles BOM transparently and we get a finding, or
    # it errors gracefully and we get no finding. We tolerate either but
    # NEVER a crash.
    for f in findings:
        assert f.kind is not None


def test_walker_handles_utf8_bom_js(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "mod.js").write_bytes("﻿".encode("utf-8") + b"fetch('https://x.com/data');\n")
    sources = list(walk_target(pkg))
    assert len(sources) == 1
    source = sources[0]
    findings = js_ast.audit_js(source)
    # tree-sitter typically tolerates BOM; we don't assert detection,
    # only that the call returns a list (no exception).
    assert isinstance(findings, list)


def test_python_ast_handles_syntax_error_gracefully():
    """A syntactically invalid Python file must not raise during audit."""
    findings = python_ast.audit_python(_src("def broken( :\n    pass\n", name="bad.py"))
    assert isinstance(findings, list)
    # Most likely empty (the AST parser bails), but the contract is just:
    # don't crash.


def test_js_ast_handles_syntax_error_gracefully():
    """tree-sitter is error-recovering -- a malformed JS file should not
    crash and may still produce partial findings from the valid prefix."""
    findings = js_ast.audit_js(_src("function f( { fetch('https://x.com'); }", name="bad.js"))
    assert isinstance(findings, list)


def test_python_ast_handles_nested_triple_quotes():
    """A docstring containing escaped triple-quotes is rare but valid; the
    AST parser must handle it. Single-line `\"\"\"...\"\"\"; real_code`
    is the imprecise case the round-7 handoff documented; we just assert
    no crash here."""
    code = '''
def f():
    """A docstring with \\"\\"\\" inside."""
    import os
    os.environ["API_KEY"]
'''
    findings = python_ast.audit_python(_src(code, name="trick.py"))
    assert isinstance(findings, list)


def test_python_ast_handles_single_line_docstring_followed_by_code():
    '''The known-imprecise case: single-line `"""x"""; real_code` on one
    line. The walker docstring tracker may or may not suppress findings;
    the contract is just no crash.'''
    code = '"""single line doc"""; import os; os.environ["API_TOKEN"]\n'
    findings = python_ast.audit_python(_src(code, name="one.py"))
    assert isinstance(findings, list)


def test_walker_handles_large_file(tmp_path):
    """A 200KB file should walk without issue. We don't pin a perf budget
    here; the assertion is correctness (single file walked, single finding
    found at the bottom)."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    body = ("# " + "x" * 200 + "\n") * 1000  # ~200KB of comments
    body += "fetch('https://x.com');\n"
    (pkg / "big.js").write_text(body, encoding="utf-8")
    sources = list(walk_target(pkg))
    assert len(sources) == 1
    findings = js_ast.audit_js(sources[0])
    # One outbound_network finding from the trailing fetch().
    from localguard.report import SurfaceKind
    assert any(f.kind == SurfaceKind.OUTBOUND_NETWORK for f in findings)


def test_walker_skips_unreadable_binary(tmp_path):
    """A binary file (not in TEXT_SUFFIXES) is silently skipped."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "blob.bin").write_bytes(b"\x00\x01\x02not text\xff")
    (pkg / "mod.py").write_text("x = 1\n", encoding="utf-8")
    sources = list(walk_target(pkg))
    # Only mod.py classified as text/python; blob.bin classified as binary
    # and skipped at the `if language == "binary"` guard.
    rels = {s.rel for s in sources}
    assert "mod.py" in rels
    assert "blob.bin" not in rels


def test_audit_path_survives_one_bad_file_in_tree(tmp_path):
    """A package with one syntax-broken file alongside good files must
    audit cleanly. The bad file contributes nothing; the good files
    contribute their findings."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "good.py").write_text("import os\nos.environ['SECRET_TOKEN']\n", encoding="utf-8")
    (pkg / "bad.py").write_text("def broken( :\n  pass\n", encoding="utf-8")
    report = audit.audit_path(pkg)
    # The good file's env-secret read still surfaces.
    from localguard.report import SurfaceKind
    assert any(f.kind == SurfaceKind.ENV_SECRET_READ for f in report.findings)


def test_walker_handles_invalid_utf8_bytes(tmp_path):
    """A file containing invalid UTF-8 bytes (e.g. a Latin-1 paragraph
    inside) is read with errors=replace; the audit must not crash."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "weird.py").write_bytes(b"x = '\xe9\xe8\xea'\nimport os\nos.environ['API_KEY']\n")
    sources = list(walk_target(pkg))
    assert len(sources) == 1
    findings = python_ast.audit_python(sources[0])
    assert isinstance(findings, list)
