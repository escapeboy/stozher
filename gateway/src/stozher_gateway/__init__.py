"""Stozher enforcement mode for Harbormaster — the MCP gateway.

An organization's existing agents (Claude Code, Cursor, a LangGraph script) point their MCP
configuration at this gateway instead of at their tool servers, and every tool call is classified,
mandated, gated and recorded at the boundary. The calling agent is not modified: zero-touch is the
product, not a convenience.

Nothing in this package runs at import time. There are no module-level singletons that touch the
disk, spawn a thread, or configure logging — Harbormaster's own import-time stores are a known
hazard (`docs/gateway-integration-constraints.md` §7) and adding another would break "a Harbormaster
without a kernel loses nothing" before configuration is even read.
"""

from __future__ import annotations

__all__ = ["Governor", "__version__"]

__version__ = "0.1.0"


def __getattr__(name: str) -> object:
    """Resolve `Governor` on first use, so importing this package still costs nothing.

    PEP 562, and not decoration. A plain `from .governed import Governor` here would pull in
    `runtime`, and through it the emitter, the store and the proxy, at *import* time — which is the
    paragraph above turned into a lie. An integrator who imports this package to read
    `__version__` gets what they asked for and nothing else.
    """
    if name == "Governor":
        from .governed import Governor

        return Governor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

#: The wire version this build speaks. There is no negotiation (spec §01 §1).
PROTOCOL_VERSION = "stozher/0.1"
