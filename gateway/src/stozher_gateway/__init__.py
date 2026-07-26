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

__all__ = ["__version__"]

__version__ = "0.1.0"

#: The wire version this build speaks. There is no negotiation (spec §01 §1).
PROTOCOL_VERSION = "stozher/0.1"
