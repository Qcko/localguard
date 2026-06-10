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
from localguard.report import SurfaceKind
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


def test_python_ast_handles_recursion_error_gracefully():
    """Deeply nested machine-generated sources (sympy's expression files)
    exceed the interpreter recursion limit inside ast.parse / the visitor.
    Regression: the RecursionError escaped audit_python and failed the
    whole package audit closed (reproduced with sympy==1.14.0).

    The skip must not be silent: the file runs but cannot be analyzed, so
    padding a payload past the recursion limit would otherwise be an
    audit-evasion channel. The audit reports exactly one unauditable_file
    finding for it.

    Construct notes (CPython 3.12): a long binop chain recurses in the
    C-AST -> Python-AST conversion; deep parens raise SyntaxError ("too
    many nested parentheses") instead, which is the silent-skip path."""
    deep = "x = 1" + "+1" * 30000
    findings = python_ast.audit_python(_src(deep, name="generated.py"))
    assert [f.kind for f in findings] == [SurfaceKind.UNAUDITABLE_FILE]
    assert findings[0].file == "generated.py"
    assert findings[0].extra["stage"] == "parse"


def test_python_ast_visit_stage_recursion_reports_unauditable():
    """A depth that parses fine but blows the visitor's recursion (the
    sympy shape) must surface the same finding. Stage not asserted -- the
    parse/visit boundary shifts with the recursion limit, which is pinned
    here so a host (or pytest plugin) with a raised limit can't make the
    construct pass cleanly and fail the test."""
    import sys

    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(1000)
    try:
        deep = "x = 1" + "+1" * 1000
        findings = python_ast.audit_python(_src(deep, name="generated.py"))
    finally:
        sys.setrecursionlimit(limit)
    assert [f.kind for f in findings] == [SurfaceKind.UNAUDITABLE_FILE]


def test_python_ast_parser_memory_error_reports_unauditable():
    """Deep unary chains exhaust parser memory instead of the recursion
    limit (CPython 3.12: MemoryError from ast.parse). Regression guard:
    this escaped audit_python entirely before being caught alongside
    RecursionError."""
    deep = "x = " + "not " * 30000 + "1"
    findings = python_ast.audit_python(_src(deep, name="generated.py"))
    assert [f.kind for f in findings] == [SurfaceKind.UNAUDITABLE_FILE]


def test_python_ast_syntax_error_stays_silent_skip():
    """A file that cannot parse cannot execute either, so it is not an
    audit-evasion channel -- no synthetic finding, just a clean skip."""
    findings = python_ast.audit_python(_src("def broken( :\n    pass\n", name="bad.py"))
    assert findings == []


def test_unauditable_file_is_scored_but_not_high_risk():
    """The synthetic finding must deduct from the score (a package full of
    unauditable files deserves scrutiny) WITHOUT being a high-risk drift
    surface -- otherwise every already-accepted package containing such
    files (sympy) would re-block on its next same-hash reinstall the
    moment the auditor learned to report them."""
    from localguard import preflight, rubric

    deep = "x = 1" + "+1" * 30000
    findings = python_ast.audit_python(_src(deep, name="pkg/generated.py"))
    breakdown = rubric.score(findings)
    deduction_kinds = {d["kind"] for d in breakdown.deductions}
    assert "unauditable_file" in deduction_kinds
    assert breakdown.final_score < rubric.STARTING_SCORE
    assert "unauditable_file" not in preflight.HIGH_RISK_KINDS


def test_unauditable_file_weighted_in_every_profile():
    """Strict-by-design surface: identical weight in every profile, so it
    is never role-typical and a profile switch can never silence it."""
    from localguard import rubric

    for profile, weights in rubric.PROFILE_WEIGHTS.items():
        assert SurfaceKind.UNAUDITABLE_FILE in weights, profile
        assert weights[SurfaceKind.UNAUDITABLE_FILE] == rubric.Weight(5, 15), profile


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
