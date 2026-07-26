"""Wiring: policy pull, session establishment, tool registration, teardown.

This is where "enforcement mode" becomes a running thing. Everything it builds is built from
configuration the gateway owns (ADR-0005) and nothing here runs at import time — `register()` is
called once from `build_server`, after built-ins, and a gateway that is not enabled does nothing at
all.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import clock as clock_module
from . import crypto
from .background import BackgroundLoop
from .canonical import sha256_hex
from .classify import Classifier
from .config import CallerConfig, GatewayConfig
from .emitter import Emitter
from .enforce import Call, Enforcer, Session
from .kernel_client import KernelClient, KernelUnreachableError
from .policy import Policy, PolicyError
from .proxy import Downstream
from .refusal import refusal
from .signing import SigningKey
from .store import GatewayStore
from .tools import proxy_tool

__all__ = ["Gateway", "PolicyProvider", "StartupRefusedError", "refuse_everything"]

logger = logging.getLogger(__name__)


class StartupRefusedError(RuntimeError):
    """The gateway will not run in this configuration. Failing to start is a way of failing closed."""


class PolicyProvider:
    """Versioned pull with a persistent cache, per `spec/05-policy-distribution.md` §2 and §6."""

    def __init__(
        self,
        kernel: KernelClient,
        store: GatewayStore,
        policy_key: str | None,
        refresh_seconds: int,
        clock: clock_module.Clock | None = None,
    ) -> None:
        self._kernel = kernel
        self._store = store
        self._policy_key = policy_key
        self._refresh_seconds = refresh_seconds
        self._clock = clock or clock_module.Clock()
        self._lock = threading.Lock()
        self._policy: Policy | None = None
        self._verified_at: str | None = None
        self._checked_at: str | None = None

    def current(self) -> tuple[Policy, bool]:
        """The policy in force, and whether it is fresh enough to act on as if online."""
        with self._lock:
            self._refresh_if_due()
            if self._policy is None:
                self._load_cache()
            if self._policy is None:
                raise PolicyError("policy-not-published", "no verified policy is available")
            return self._policy, self._is_fresh()

    def _refresh_if_due(self) -> None:
        now = self._clock.now()
        if self._checked_at is not None:
            due = clock_module.shift(self._checked_at, self._refresh_seconds)
            if now < due:
                return
        try:
            response = self._kernel.current_policy()
        except KernelUnreachableError as e:
            # Degrading to the last verified copy is the offline behaviour maxim 5 requires. It is
            # not a fallback to permissive defaults: the cached document is enforced as written.
            logger.warning("policy pull failed, enforcing the cached copy: %s", e)
            self._checked_at = now
            return
        self._checked_at = now
        if not response.accepted and response.status != 200:
            logger.warning("the kernel did not serve a policy: %s", response.reason_code)
            return
        try:
            policy = Policy.verified(response.body, self._policy_key)
        except PolicyError as e:
            # A document the gateway cannot verify is a document it must not enforce, and refusing
            # to enforce it means keeping the previous one, never relaxing.
            logger.error("refusing an unverifiable policy document: %s", e.code)
            return
        self._policy = policy
        self._verified_at = now
        self._store.cache_policy(policy.version, policy.document, now)

    def _load_cache(self) -> None:
        cached = self._store.cached_policy()
        if cached is None:
            return
        document, verified_at = cached
        try:
            self._policy = Policy.verified(document, self._policy_key)
            self._verified_at = verified_at
        except PolicyError as e:  # pragma: no cover - a cached document was verified when written
            logger.error("the cached policy no longer verifies: %s", e.code)

    def _is_fresh(self) -> bool:
        if self._policy is None or self._verified_at is None:
            return False
        deadline = clock_module.shift(self._verified_at, self._policy.max_staleness_seconds())
        return self._clock.now() <= deadline


class Gateway:
    """Enforcement mode: downstream servers fronted, native tools governed, everything recorded."""

    def __init__(self, config: GatewayConfig, clock: clock_module.Clock | None = None) -> None:
        self.config = config
        self._clock = clock or clock_module.Clock()
        self.store = GatewayStore(config.state_db_path())
        self.kernel = KernelClient(
            config.kernel.url, config.kernel.token(), config.kernel.timeout_seconds
        )
        self.policy_provider = PolicyProvider(
            self.kernel,
            self.store,
            config.org.policy_key,
            config.kernel.policy_refresh_seconds,
            self._clock,
        )
        self.loop = BackgroundLoop()
        self.emitter = Emitter(
            self.store,
            self.kernel,
            config.gateway.component,
            self._clock,
            max_events=config.gateway.aggregate_max_events,
            max_samples=config.gateway.aggregate_max_samples,
        )
        self.classifier = Classifier(
            scopes={server.name: server.scope for server in config.servers},
            org_seeded=self.store.catalog_entry,
        )
        self.enforcer = Enforcer(
            config, self.store, self.classifier, self.emitter, self.policy_provider.current, self._clock
        )
        self.session: Session | None = None
        self._downstream: dict[str, Downstream] = {}

    # -- identity ----------------------------------------------------------------------------

    def _seed(self) -> bytes:
        path = self.config.identity.resolve()
        if path is None:
            raise StartupRefusedError("identity.seed_file (or STOZHER_GATEWAY_SEED) is required")
        if not path.is_file():
            raise StartupRefusedError(f"the identity seed {path} does not exist")
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            # Key material readable by anyone but its owner is key material to treat as compromised.
            raise StartupRefusedError(f"the identity seed {path} is mode {mode:o}; it must be 0600")
        return bytes.fromhex(path.read_text().strip())

    def _selected_caller(self) -> CallerConfig:
        """Which credential this process is serving.

        stdio spawns one process per client connection, so the connection *is* the process and the
        credential is resolved once, at startup, from `STOZHER_GATEWAY_CALLER`. Per-request caller
        resolution on a shared HTTP transport needs middleware Harbormaster owns; until then a
        multi-caller configuration refuses to start rather than guessing whose authority to use.
        """
        name = os.environ.get("STOZHER_GATEWAY_CALLER")
        if name is not None:
            caller = self.config.caller(name)
            if caller is None:
                raise StartupRefusedError(f"STOZHER_GATEWAY_CALLER names no configured caller: {name}")
            return caller
        if len(self.config.callers) == 1:
            return self.config.callers[0]
        if not self.config.callers:
            raise StartupRefusedError("no caller is configured; the gateway has no subject to act as")
        raise StartupRefusedError(
            "several callers are configured; set STOZHER_GATEWAY_CALLER to name this connection's"
        )

    def _authenticate(self, caller: CallerConfig) -> None:
        token = os.environ.get("STOZHER_GATEWAY_CALLER_TOKEN")
        if caller.token_sha256 is None:
            if not self.config.dev.allow_unauthenticated:
                raise StartupRefusedError(
                    f"caller {caller.name!r} has no token_sha256 and unauthenticated passthrough "
                    "is off (gateway-caller-unauthenticated)"
                )
            return
        if token is None or sha256_hex(token.encode("utf-8")) != caller.token_sha256:
            raise StartupRefusedError(f"the credential presented for {caller.name!r} does not resolve")

    def open_session(self) -> Session:
        """Authenticate the caller, derive its key, resolve its mandate, and record the session."""
        crypto.require_crypto()
        caller = self._selected_caller()
        self._authenticate(caller)
        key = SigningKey.derived(
            self._seed(), crypto.ROLE_DEVICE, caller.key_index, caller.subject
        )
        mandate = self._mandate(caller, key)
        stream = f"gw:{self.config.gateway.device}:{caller.name}"
        session = Session(caller.name, caller.subject, key, mandate, stream)
        self.emitter.register_key(key)
        self._publish_mandate(session)
        self._record_session_open(session)
        self.session = session
        # Approvals signed while nothing was connected still classified a tool; putting them in
        # force at connect time is what makes "the next call proceeds" true.
        self.enforcer.apply_pending_seeds(session)
        return session

    def _mandate(self, caller: CallerConfig, key: SigningKey) -> dict[str, Any]:
        assert caller.mandate_file is not None
        try:
            mandate: dict[str, Any] = json.loads(Path(caller.mandate_file).read_text())
        except (OSError, ValueError) as e:
            raise StartupRefusedError(f"mandate-unresolved: {caller.mandate_file}: {e}") from e
        if mandate.get("grantee", {}).get("key") != key.id:
            raise StartupRefusedError(
                f"mandate-grantee-key-mismatch: {caller.mandate_file} was granted to another key"
            )
        if mandate.get("mandate-kind") != caller.mandate_kind:
            raise StartupRefusedError(
                f"the mandate is {mandate.get('mandate-kind')!r}, config says {caller.mandate_kind!r}"
            )
        if self._clock.now() > str(mandate.get("not-after", "")):
            raise StartupRefusedError("mandate-expired: the session mandate has expired")
        return mandate

    def _publish_mandate(self, session: Session) -> None:
        """Make the mandate resolvable at the kernel before anything cites it."""
        mark = f"mandate-published:{session.mandate_ref}"
        if self.store.marked(mark):
            return
        body = {
            "v": "stozher/0.1",
            "kind": "mandate",
            "emitted-at": self._clock.now(),
            "identity": {
                "subject": session.subject,
                "key": session.key.id,
                "component": self.config.gateway.component,
            },
            "mandate": session.mandate,
        }
        self.emitter.append(session.key, session.stream, body)
        self.store.mark(mark, self._clock.now())

    def _record_session_open(self, session: Session) -> None:
        """§10 §1.6: session establishment is itself an envelope.

        The class is the one policy computes for `gateway.session_open`. If policy gates that
        action the gateway refuses to open the session rather than quietly skipping the record —
        an unrecorded session is an unattributable one, and an org that wants session opens gated
        has to say so where a human can read it.
        """
        policy, _ = self.policy_provider.current()
        action = "gateway.session_open"
        classification = policy.classify(session.subject, action, "-", "benign")
        if policy.decision_for(classification).kind != "allow":
            raise StartupRefusedError(
                f"policy classifies {action} as {classification}, which is not allowed without an "
                "approval; classify it as benign to run enforcement mode"
            )
        now = self._clock.now()
        body = {
            "v": "stozher/0.1",
            "kind": "effect",
            "emitted-at": now,
            "identity": {
                "subject": session.subject,
                "key": session.key.id,
                "component": self.config.gateway.component,
            },
            "mandate-ref": session.mandate_ref,
            "policy-version": policy.version,
            "classification": classification,
            "execution": {
                "action": action,
                "target": "-",
                "args-hash": sha256_hex(session.stream.encode("utf-8")),
                "outcome": "applied",
                "started-at": now,
                "finished-at": now,
            },
        }
        self.emitter.append(session.key, session.stream, body)

    # -- registration -------------------------------------------------------------------------

    def register(self, mcp: Any) -> int:
        """Front the configured downstream servers and govern the native tools. Returns the count."""
        session = self.open_session()
        self.emitter.start()
        registered = 0
        for server in self.config.servers:
            downstream = Downstream(
                server,
                self.loop,
                persistent=self.config.gateway.persist_downstream_in_stdio,
            )
            self._downstream[server.name] = downstream
            downstream.start()
            try:
                tools = downstream.list_tools()
            except Exception as e:  # noqa: BLE001 - a dead downstream must not break startup
                logger.error("could not enumerate %s: %s", server.name, e)
                continue
            for tool in tools:
                mcp._tool_manager._tools[f"{server.name}__{tool.name}"] = proxy_tool(
                    f"{server.name}__{tool.name}",
                    tool.description,
                    tool.schema,
                    self._handler(session, server.name, tool.name, tool.schema),
                )
                registered += 1
        if self.config.gateway.govern_native_tools:
            registered += self._govern_native(mcp, session)
        return registered

    def _govern_native(self, mcp: Any, session: Session) -> int:
        """§10 §8: Harbormaster's own tools are actions too when enforcement is on.

        The tool object keeps its name, description and schema — only `fn` is replaced, so the
        calling agent sees no difference and both dispatch paths (`Tool.run` and the two direct
        `tool.fn(**arguments)` sites) go through the chokepoint.
        """
        governed = 0
        for tool in list(mcp._tool_manager._tools.values()):
            if tool.name.startswith(tuple(f"{s.name}__" for s in self.config.servers)):
                continue
            tool.fn = self._native_handler(session, tool.name, tool.fn)
            tool.is_async = False
            governed += 1
        return governed

    def _handler(
        self, session: Session, server: str, tool: str, schema: dict[str, Any]
    ) -> Callable[..., Any]:
        def handler(**arguments: Any) -> Any:
            call = Call(server, tool, arguments, schema)
            return self.enforcer.call(
                session, call, lambda: self._downstream[server].call(tool, arguments)
            )

        return handler

    def _native_handler(
        self, session: Session, tool: str, original: Callable[..., Any]
    ) -> Callable[..., Any]:
        def handler(**arguments: Any) -> Any:
            call = Call("harbormaster", tool, arguments, None)
            return self.enforcer.call(session, call, lambda: original(**arguments))

        return handler

    # -- teardown ------------------------------------------------------------------------------

    def shutdown(self, timeout: float = 5.0) -> None:
        """Flush open aggregation windows, drain the push queue, close everything."""
        try:
            self.emitter.stop(timeout=timeout)
        finally:
            for downstream in self._downstream.values():
                downstream.close()
            self.loop.stop(timeout=timeout)


def refuse_everything(reason_code: str, detail: str) -> Callable[..., Any]:
    """The handler installed when enforcement cannot run: refuse, never proceed unrecorded."""

    def handler(**arguments: Any) -> Any:
        raise refusal("blocked", reason_code, detail, action="gateway.unavailable")

    return handler
