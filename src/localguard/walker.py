from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build", ".localguard", ".pytest_cache", ".ruff_cache"}
TEST_DIR_NAMES = {"tests", "test", "testing", "__tests__", "spec", "specs"}
DOC_DIR_NAMES = {"docs", "doc", "examples", "example", "samples"}
I18N_DIR_NAMES = {"locales", "locale", "i18n", "lang", "langs", "translations", "messages"}
# Bundled third-party code that originally lived as its own package. Findings
# inside these directories logically belong to the vendored package (audit it
# under its own name if in doubt), not to the current package being scored.
# Conventions covered: setuptools/pip's `_vendor` and `_distutils`, generic
# `vendor`/`vendored`/`bundled`, the `third_party` variants common in larger
# projects. Tight set on purpose -- this is a context, not an "ignore" knob.
# Auto-generated stub directories. Files matching well-known autogen
# filename patterns (see _is_autogen_file) are also flagged.
GENERATED_DIR_NAMES = {"_generated", "__generated__", "generated"}
VENDORED_DIR_NAMES = {
    "_vendor", "_vendored", "_distutils",
    "vendor", "vendored", "bundled",
    "third_party", "thirdparty", "third-party",
}
PYTHON_SUFFIXES = {".py", ".pyi"}
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
TEXT_SUFFIXES = PYTHON_SUFFIXES | JS_SUFFIXES | {".md", ".txt", ".json", ".toml", ".yaml", ".yml", ".cfg", ".ini"}


@dataclass(frozen=True)
class SourceFile:
    path: Path
    rel: str
    language: str
    text: str


def walk_target(root: Path) -> Iterator[SourceFile]:
    for path in _iter_files(root):
        language = _classify(path)
        if language == "binary":
            continue
        text = _safe_read(path)
        if text is None:
            continue
        yield SourceFile(path=path, rel=str(path.relative_to(root)).replace("\\", "/"), language=language, text=text)


def hash_target(root: Path) -> str:
    digest = hashlib.sha256()
    for source in sorted(walk_target(root), key=lambda s: s.rel):
        digest.update(source.rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(source.text.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()


def _iter_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _is_skipped(path, root):
            continue
        yield path


def _is_skipped(path: Path, root: Path) -> bool:
    rel_parts = path.relative_to(root).parts
    return any(part in SKIP_DIRS for part in rel_parts)


def _classify(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in PYTHON_SUFFIXES:
        return "python"
    if suffix in JS_SUFFIXES:
        return "javascript"
    if suffix in TEXT_SUFFIXES or path.name.lower() in {"readme", "license"}:
        return "text"
    return "binary"


def find_context(rel: str) -> str:
    parts = rel.replace("\\", "/").split("/")
    if any(p.lower() in TEST_DIR_NAMES for p in parts[:-1]):
        return "tests"
    name = parts[-1].lower()
    if name.startswith("test_") or name.endswith("_test.py") or name in {"conftest.py"}:
        return "tests"
    if any(p.lower() in DOC_DIR_NAMES for p in parts[:-1]):
        return "docs"
    if any(p.lower() in I18N_DIR_NAMES for p in parts[:-1]):
        return "i18n"
    if any(_is_vendored_part(p) for p in parts[:-1]):
        return "vendored"
    if any(p.lower() in GENERATED_DIR_NAMES for p in parts[:-1]):
        return "generated"
    if _is_autogen_file(name):
        return "generated"
    if _is_doc_or_meta_file(name) and len(parts) == 1:
        return "docs"
    if name in {"setup.py", "setup.cfg", "pyproject.toml", "package.json", "manifest.in"} and len(parts) == 1:
        return "setup"
    return "runtime"


def _is_autogen_file(name: str) -> bool:
    """Filename-level signals for compiler-emitted stubs.

    Protobuf and gRPC code-gen produce thousands of `*_pb2.py` /
    `*_pb2_grpc.py` files containing dense descriptor strings that read like
    obfuscation / dynamic outbound to the surface walkers. These files are
    not author-written; treat them like vendored code.
    """
    n = name.lower()
    if n.endswith(("_pb2.py", "_pb2_grpc.py", "_pb2.pyi", "_pb2_grpc.pyi")):
        return True
    if n.endswith(("_pb.js", "_pb.ts", "_pb.d.ts", "_grpc_pb.js", "_grpc_pb.ts")):
        return True
    return False


def _is_vendored_part(part: str) -> bool:
    p = part.lower()
    if p in VENDORED_DIR_NAMES:
        return True
    # Hyphen-suffixed forms commonly used by upstreams to keep the bundling
    # explicit: numpy's `vendored-meson`, hypothetical `_vendor-jaraco`, etc.
    return p.startswith(("vendored-", "_vendor-", "_vendored-", "bundled-"))


def _is_doc_or_meta_file(name: str) -> bool:
    stem = name.rsplit(".", 1)[0]
    return stem in {"readme", "changelog", "changes", "history", "license", "licence", "notice", "contributing", "authors", "copying", "security"}


def _safe_read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
