from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build", ".localguard", ".pytest_cache", ".ruff_cache"}
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


def _safe_read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
