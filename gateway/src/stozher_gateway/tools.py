"""Re-exporting a downstream tool with its own schema, as a **sync** FastMCP tool.

Zero-touch means the calling agent sees the upstream tool's real name, description and argument
schema; the only thing that changes is that the call now transits `Enforcer.call`. FastMCP normally
derives a tool's schema from a Python signature, which a proxied tool does not have, so the argument
model is built from the upstream JSON Schema instead.

Two details that would otherwise silently rewrite the caller's request:

* an argument the caller did not supply must not be forwarded as `null`. Optional fields default to
  a sentinel that is dropped before forwarding.
* an argument the schema did not declare must not be dropped. Extras are preserved and passed
  through, because `args-hash` — and the approval signature over it — covers what was actually sent.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp.tools.base import Tool
from mcp.server.fastmcp.utilities.func_metadata import ArgModelBase, FuncMetadata
from pydantic import ConfigDict, Field, create_model

__all__ = ["proxy_tool"]


class _Unset:
    """A value the caller did not send. Never forwarded."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<unset>"


UNSET = _Unset()


class _ProxyArguments(ArgModelBase):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    def model_dump_one_level(self) -> dict[str, Any]:
        dumped = super().model_dump_one_level()
        dumped.update(self.__pydantic_extra__ or {})
        return {name: value for name, value in dumped.items() if not isinstance(value, _Unset)}


def _argument_model(tool: str, schema: dict[str, Any]) -> type[ArgModelBase]:
    properties = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    fields: dict[str, Any] = {}
    for index, name in enumerate(properties):
        field_name = name if name.isidentifier() else f"argument_{index}"
        default: Any = ... if name in required else UNSET
        fields[field_name] = (Any, Field(default, alias=name))
    model = create_model(f"{tool}Arguments", __base__=_ProxyArguments, **fields)
    return model


def proxy_tool(
    name: str,
    description: str,
    schema: dict[str, Any],
    handler: Callable[..., Any],
) -> Tool:
    """Build a sync `Tool` that presents `schema` and calls `handler(**arguments)`.

    The handler is deliberately sync: two dispatch sites call `tool.fn(**arguments)` without
    awaiting (`fleetq/dispatcher.py:626`, `ui/routes.py:2752`), and an async handler returns an
    un-awaited coroutine there.
    """
    return Tool(
        fn=handler,
        name=name,
        title=None,
        description=description,
        parameters=schema or {"type": "object", "properties": {}},
        fn_metadata=FuncMetadata(arg_model=_argument_model(name, schema or {})),
        is_async=False,
        context_kwarg=None,
        annotations=None,
    )
