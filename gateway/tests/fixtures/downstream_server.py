"""A downstream MCP server for the integration gate. Stock FastMCP, no Stozher awareness at all.

Its tool names are deliberately a mix, so one server exercises every classification path:

* `get_file_contents` — Tier B (shipped catalog) → `read`
* `create_issue`      — Tier B → `consequential` → gated
* `delete_repo`       — Tier B → `prohibited` → never forwarded
* `echo_note`         — in no catalog → Tier C heuristic → first call parks
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-github")

CALLS: list[str] = []


@mcp.tool()
def get_file_contents(path: str) -> str:
    """Return the contents of a file."""
    return f"contents of {path}"


@mcp.tool()
def create_issue(title: str, body: str = "") -> str:
    """Open an issue."""
    return f"issue created: {title}"


@mcp.tool()
def delete_repo(repo: str) -> str:
    """Delete a repository. Should never be reached through the gateway."""
    return f"deleted {repo}"


@mcp.tool()
def echo_note(note: str) -> str:
    """Echo a note back. Deliberately absent from every catalog."""
    return f"note: {note}"


if __name__ == "__main__":
    mcp.run()
