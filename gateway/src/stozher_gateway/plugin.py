"""The Harbormaster plugin entry point.

```
[project.entry-points."harbormaster.tools"]
stozher-gateway = "stozher_gateway.plugin:register"
```

and, in the operator's `harbormaster.toml`, **only keys Harbormaster already ships**:

```toml
[plugins]
enabled = true
allow = ["stozher-gateway"]
```

That is the whole activation surface (ADR-0005). No section is added to `harbormaster.toml`, no
field to `HarbormasterConfig`, and nothing under `src/harbormaster/` is modified — so a config that
enables the gateway is still valid input to vanilla Harbormaster, and uninstalling the distribution
produces a `WARNING` from `load_plugins`, not a boot failure.

`register()` never raises. `plugins.py:121-145` already wraps it in `try/except` so a raising plugin
cannot break startup, but relying on someone else's `except` to hold your invariant is how the
invariant gets lost in a refactor. When enforcement cannot run, this function refuses to register
proxied tools and says why; Harbormaster's own surface is untouched.
"""

from __future__ import annotations

import atexit
import logging
from typing import Any

from .config import ConfigError, GatewayConfig, load_config
from .runtime import Gateway

__all__ = ["register"]

logger = logging.getLogger(__name__)

#: The live gateway, if one started. A module-level name, not a module-level *side effect*: nothing
#: is constructed until `register()` runs, and `register()` runs from `build_server`, not at import.
_GATEWAY: Gateway | None = None


def register(mcp: Any, config: Any = None) -> None:
    """Register the gateway's proxied tools. `config` is Harbormaster's and is deliberately unused.

    The gateway reads `stozher-gateway.toml` and `STOZHER_*` instead (ADR-0005), so that the two
    products' configuration surfaces do not interleave and neither can break the other's boot.
    """
    global _GATEWAY
    del config  # Harbormaster's configuration is not ours to read.
    try:
        gateway_config = load_config()
    except ConfigError as e:
        logger.error("stozher-gateway: %s", e)
        return
    if not gateway_config.gateway.enabled:
        # The default. A Harbormaster with the distribution installed but enforcement off behaves
        # exactly as it did before, which is the property ADR-0005 exists to make structural.
        logger.info("stozher-gateway: enforcement mode is off")
        return
    try:
        gateway = Gateway(gateway_config)
        registered = gateway.register(mcp)
    except Exception as e:  # noqa: BLE001 - startup must never break the server
        logger.error("stozher-gateway: enforcement mode did not start: %s", e)
        _refuse(mcp, gateway_config, str(e))
        return
    _GATEWAY = gateway
    atexit.register(_shutdown)
    logger.info("stozher-gateway: enforcement mode registered %d tools", registered)


def _refuse(mcp: Any, config: GatewayConfig, detail: str) -> None:
    """Enforcement was asked for and cannot run: proxied tools refuse rather than pass through.

    Failing open here would be the worst outcome available — an operator who configured enforcement
    would get an ungoverned proxy and no signal. Harbormaster's own tools are left alone.
    """
    from .tools import proxy_tool

    for server in config.servers:
        name = f"{server.name}__unavailable"
        mcp._tool_manager._tools[name] = proxy_tool(
            name,
            f"Stozher enforcement is configured for {server.name} but did not start: {detail}",
            {"type": "object", "properties": {}},
            _refusing_handler(detail),
        )


def _refusing_handler(detail: str) -> Any:
    from .runtime import refuse_everything

    return refuse_everything("gateway-enforcement-unavailable", detail)


def _shutdown() -> None:
    global _GATEWAY
    gateway, _GATEWAY = _GATEWAY, None
    if gateway is not None:
        # An open aggregation window is an effect that is not yet in the audit
        # (`gateway-must-flush-on-shutdown`).
        gateway.shutdown()
