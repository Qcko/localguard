from pathlib import Path


def read_notes(notes_dir: Path) -> list[str]:
    return [path.read_text(encoding="utf-8") for path in sorted(notes_dir.glob("*.md"))]
