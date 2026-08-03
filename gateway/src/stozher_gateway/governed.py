"""Governing ordinary Python functions, without MCP and without a subprocess.

An engineer with a working agent system evaluated this product and rejected it. Their tools were
plain Python functions in a registry; the only way in was to re-expose every one of them as an MCP
server and point the gateway at it. The adaptation layer came to 134 lines against a 123-line
application, thirteen concepts had to be learned before the first governed call, and — the part
that decided it — their tool state left their process, so their own driver's assertions read an
empty ledger.

**None of that was buying a security property.** The gateway holds one private key, its own emitter
seed (`identity.seed_file`); `org.roots` holds public key ids and nothing else. The approving key is
on a human's machine either way. And the gateway process is spawned *by the agent's MCP client*, on
the same host as the same user — an evaluator observed that one edit to their own client config
routes around it entirely. So the subprocess boundary was never a boundary against the operator; it
was a transport choice, and it was the whole cost of adoption.

What this module does is expose the wrapping the runtime has always applied to Harbormaster's own
tools (`Gateway.native_handler`) for any callable. Same `Enforcer`, same chokepoint, same eleven
steps, same envelopes — one process instead of two.

    from stozher_gateway import Governor

    with Governor.from_config("stozher-gateway.toml") as governor:

        @governor.governed(server="billing")
        def issue_refund(order_id: str, amount_cents: int) -> str:
            ...

        issue_refund("ORD-88214", 4_999_00)   # classified, mandated, gated, recorded

A refusal is raised as `RefusalError`, exactly as a proxied call's would be, and the wrapped
function is not called. `governed` is not a security boundary against the process it runs in — no
in-process check is — and it never claimed to be: it is the boundary against what the *agent*
decides to do, which is the thing being governed.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from .config import ConfigError, GatewayConfig, load_config, load_config_file
from .enforce import Call, Session
from .runtime import Gateway, StartupRefusedError

F = TypeVar("F", bound=Callable[..., Any])

__all__ = ["Governor"]


class Governor:
    """An open enforcement session, and a decorator that puts calls through it."""

    def __init__(self, config: GatewayConfig) -> None:
        self._gateway = Gateway(config)
        self._session: Session | None = None

    @classmethod
    def from_config(cls, path: str | Path | None = None) -> Governor:
        """Load the same configuration file the MCP gateway reads.

        A path that was named and does not exist is an error here, though `load_config` treats a
        missing file as a disabled gateway. That default is right for the MCP server — a Harbormaster
        with no Stozher configuration loses nothing — and wrong for a caller who typed a filename:
        they got a Governor built from defaults, with no kernel and no identity, and found out at
        the first call. A typo in a path is not a decision to run ungoverned.
        """
        if path is not None:
            named = Path(path)
            if not named.is_file():
                raise ConfigError(f"{named}: no such configuration file")
            return cls(load_config_file(named))
        return cls(load_config(None))

    # -- lifecycle ---------------------------------------------------------------------------

    def open(self) -> Governor:
        """Authenticate, derive the caller key, publish its mandate, record the session open.

        Identical to what the MCP server does on connect, because it is the same method. A session
        that cannot be opened raises rather than degrading: a governed function that silently ran
        ungoverned would be worse than one that could not be called.
        """
        self._gateway.loop.start()
        try:
            self._session = self._gateway.open_session()
        except Exception:
            self._gateway.loop.stop(timeout=1.0)
            raise
        return self

    def close(self, timeout: float = 5.0) -> None:
        """Flush open aggregation windows and drain the push queue.

        Not optional. `read` calls fold into an aggregate that is emitted on a window boundary, so a
        process that exits without this loses the record of every read since the last flush —
        `gateway-must-flush-on-shutdown`. Use the context manager and it is not forgettable.
        """
        self._session = None
        self._gateway.shutdown(timeout=timeout)

    def __enter__(self) -> Governor:
        return self.open()

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- the decorator -----------------------------------------------------------------------

    def governed(
        self, *, server: str, tool: str | None = None, schema: dict[str, Any] | None = None
    ) -> Callable[[F], F]:
        """Wrap a function so every call transits `Enforcer.call` exactly once.

        `server` is the scope the action name is built from, the same way a proxied server's name
        is: it decides whether the call is `billing.issue_refund` or `acme.issue_refund`, and
        therefore whether policy and the shipped catalog have anything to say about it. `tool`
        defaults to the function's name.

        `schema` is the JSON Schema of the arguments, and passing one is worth the trouble: the
        Tier C heuristic reads it to decide whether a call is read-shaped, and without it an
        unknown tool has only its name to go on.
        """

        def decorate(function: F) -> F:
            name = tool or function.__name__
            # Refused at decoration rather than at the call, because the failure it prevents is
            # silent. `Enforcer.call` is synchronous and records `applied` once `forward()` returns
            # — for a coroutine function that is the moment the coroutine object is *constructed*,
            # so the chain would carry an applied effect before the body had run, and carry it still
            # if the caller never awaited or if the await raised. A gate whose record is written
            # before the work is a gate that lies in exactly the direction that matters.
            if inspect.iscoroutinefunction(function) or inspect.isasyncgenfunction(function):
                raise TypeError(
                    f"{name} is async, and `governed` cannot record it honestly: the effect would "
                    "be chained as applied when the coroutine is created, not when it runs. Wrap "
                    "the call in a synchronous function and govern that one."
                )
            signature = inspect.signature(function)

            @functools.wraps(function)
            def governed_call(*args: Any, **kwargs: Any) -> Any:
                if self._session is None:
                    raise StartupRefusedError(
                        f"{name} was called on a Governor that is not open; "
                        "use `with Governor.from_config(...) as governor:`"
                    )
                # Bound to names, because `args-hash` is the hash of the *canonical arguments* and
                # a positional call and a keyword call of the same function must produce the same
                # hash — otherwise one approval would not bind the other, and an approver would be
                # asked twice for what is visibly one action.
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                arguments = dict(bound.arguments)
                call = Call(server, name, arguments, schema)
                # `bound.args`/`bound.kwargs`, not `**arguments`. `BoundArguments.arguments` keys a
                # `**kwargs` parameter under its own name, so `function(**arguments)` handed the
                # function `{'extra': {'cc': ...}}` as one keyword named `extra` — the approver
                # signed `cc`, the function received a dict called `extra` containing it. The same
                # line made a positional-only parameter raise, because there is no keyword spelling
                # for one. The gate recording arguments the function never got is the worst defect
                # this module can have, and it was silent.
                return self._gateway.enforcer.call(
                    self._session, call, lambda: function(*bound.args, **bound.kwargs)
                )

            return governed_call  # type: ignore[return-value]

        return decorate
