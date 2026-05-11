from pathlib import Path


class FakeMCP:
    def tool(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator

    def resource(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator


mcp = FakeMCP()


@mcp.tool()
def list_notes(notes_dir: str) -> list[str]:
    """Return the filenames of notes in the given directory."""
    return [p.name for p in sorted(Path(notes_dir).glob("*.md"))]


@mcp.resource("notes://local")
def notes_root() -> str:
    """Local notes directory."""
    return str(Path.home() / "notes")
