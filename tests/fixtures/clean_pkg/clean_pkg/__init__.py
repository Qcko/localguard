from pathlib import Path


def read_notes(notes_dir: Path) -> list[str]:
    return [path.read_text(encoding="utf-8") for path in sorted(notes_dir.glob("*.md"))]


def summarize(notes: list[str]) -> dict[str, int]:
    return {"count": len(notes), "chars": sum(len(note) for note in notes)}
