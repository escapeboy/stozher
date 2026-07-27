"""A downstream MCP server for the first fifteen minutes — deliberately ordinary.

The gateway is an enforcement layer, and an enforcement layer with nothing behind it demonstrates
nothing. This is something to point it at: an unremarkable MCP server with three tools, chosen so
that the first session exercises all three outcomes the audit trail is supposed to distinguish.

| tool | what the shipped catalog and the baseline profile make of it |
|---|---|
| `list_notes` | a read the profile does not name, so it is classified by `default-unknown` |
| `read_note`  | the same |
| `write_note` | a write — the first call parks at the gate and waits for a human |

Nothing here knows what Stozher is. It has no import from `stozher_gateway`, checks no header, and
would behave identically if the gateway were removed — which is the only way it can serve as a
witness to what the gateway did or did not forward.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

NOTES = Path(os.environ.get("STOZHER_DEMO_NOTES", "/tmp/stozher-demo-notes"))
NOTES.mkdir(parents=True, exist_ok=True)

server: FastMCP = FastMCP("notes")


@server.tool()
def list_notes() -> str:
    """List the notes that exist."""
    names = sorted(path.name for path in NOTES.glob("*.txt"))
    return "\n".join(names) if names else "(no notes yet)"


@server.tool()
def read_note(name: str) -> str:
    """Read one note by name."""
    path = NOTES / f"{_safe(name)}.txt"
    if not path.is_file():
        return f"no note called {name!r}"
    return path.read_text(encoding="utf-8")


@server.tool()
def write_note(name: str, body: str) -> str:
    """Write a note. This one changes something, which is the point."""
    path = NOTES / f"{_safe(name)}.txt"
    path.write_text(body, encoding="utf-8")
    return f"wrote {path.name} ({len(body)} bytes)"


def _safe(name: str) -> str:
    """Keep a tool argument from becoming a path. Not a security boundary — a demo that stays a demo."""
    return "".join(character for character in name if character.isalnum() or character in "-_")[:64] or "note"


if __name__ == "__main__":
    server.run()
