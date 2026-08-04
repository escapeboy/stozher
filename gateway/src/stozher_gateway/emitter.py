"""Envelope emission: local durable chaining, gateway-side read aggregation, async push.

Three properties this module exists to hold:

* **Durable before pushed.** The envelope is chained and written to the local store before it is
  offered to the kernel (§10 §7). A kernel that is briefly unreachable costs latency, not records.
* **The kernel never sees the firehose.** Class `read` folds into an aggregation window here, keyed
  by (stream, subject-key, mandate-ref, policy-version); any change to that tuple closes the window
  (§02 §7.2, §10 §5). A repository scan must not be able to bury the two consequential actions of
  the day under fifty thousand read envelopes.
* **Nothing is lost at shutdown.** An open window is an effect that is not yet in the audit, so
  `stop()` flushes before exit (`gateway-must-flush-on-shutdown`).

The push thread's lifecycle copies `JobWorker` (`jobs/worker.py:115-129`): a `threading.Event`, a
daemon thread, `.stop(timeout=…)`, and teardown from a `finally` block.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, NamedTuple

from . import clock as clock_module
from .canonical import object_hash
from .chain import ChainError
from .envelope import EnvelopeError
from .envelope import validate as validate_shape
from .kernel_client import KernelClient, KernelUnreachableError
from .signing import SigningKey, object_id
from .store import GatewayStore

__all__ = ["Emitter", "WindowKey"]

logger = logging.getLogger(__name__)


class WindowKey(NamedTuple):
    """What an aggregation window is keyed by. Any change closes it (§10 §5.1)."""

    stream: str
    subject_key: str
    mandate_ref: str
    policy_version: str


class _Window:
    def __init__(self, key: WindowKey, opened_at: str, max_samples: int) -> None:
        self.key = key
        self.opened_at = opened_at
        self.last_at = opened_at
        self.counts: dict[str, int] = {}
        self.samples: list[str] = []
        self.max_samples = max_samples

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def add(self, action: str, args_hash: str, at: str) -> None:
        self.counts[action] = self.counts.get(action, 0) + 1
        self.last_at = at
        # Sampling rule `first-and-last`, declared: the opening call is always kept, then the most
        # recent ones, so an auditor can spot-check both ends of the window.
        if len(self.samples) < self.max_samples:
            self.samples.append(args_hash)
        else:
            self.samples[-1] = args_hash


class Emitter:
    """Chains, signs, stores and pushes envelopes; folds reads."""

    def __init__(
        self,
        store: GatewayStore,
        kernel: KernelClient,
        component: str,
        clock: clock_module.Clock | None = None,
        max_window_seconds: float = 300.0,
        max_events: int = 500,
        max_samples: int = 8,
        push_interval: float = 0.25,
    ) -> None:
        self._store = store
        self._kernel = kernel
        self._component = component
        self._clock = clock or clock_module.Clock()
        self._max_window_seconds = max_window_seconds
        self._max_events = max_events
        self._max_samples = max_samples
        self._push_interval = push_interval
        self._chain_lock = threading.Lock()
        self._windows: dict[WindowKey, _Window] = {}
        self._window_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        #: Signing keys by subject key id, so a window can be closed without its caller present.
        self._keys: dict[str, SigningKey] = {}

    # -- lifecycle ---------------------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="stozher-gateway-push", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Flush open windows, drain the push queue, then join."""
        try:
            self.flush_windows()
            self.push_pending()
        finally:
            self._stop.set()
            thread, self._thread = self._thread, None
            if thread is not None:
                thread.join(timeout=timeout)

    def _serve(self) -> None:
        try:
            while not self._stop.wait(self._push_interval):
                self.close_expired_windows()
                self.push_pending()
        finally:
            # A window left open at teardown is an unaudited effect, so the last act is to close it.
            self.flush_windows()
            self.push_pending()

    # -- emission ----------------------------------------------------------------------------

    def register_key(self, key: SigningKey) -> None:
        """Remember a signing key so its windows can be closed after the session ends."""
        self._keys[key.id] = key

    def append(
        self,
        key: SigningKey,
        stream: str,
        body: dict[str, Any],
        payloads: list[dict[str, Any]] | None = None,
        resolve_intent: str | None = None,
    ) -> str:
        """Chain, sign, validate and durably store one envelope. Returns its `id()`.

        Validation runs before the write, with the kernel's own reason codes: emitting an envelope
        the kernel will refuse means an effect happened and never reached the audit, which is the one
        failure this product exists to prevent.
        """
        payloads = payloads or []

        def build(seq: int, prev: str | None) -> tuple[str, dict[str, Any]]:
            envelope = dict(body)
            envelope.update({"stream": stream, "seq": seq, "prev-hash": prev})
            signed = key.sign(envelope)
            try:
                validate_shape(signed)
            except EnvelopeError as e:
                raise ChainError(e.code, e.detail, seq) from e
            return object_id(signed), signed

        # The guarantee that one `seq` is written once lives in `append_next`, which holds the
        # database's writer lock across the read and the insert and so covers the other *processes*
        # a config-derived stream name is shared with. This lock is only to keep this process's own
        # threads off that lock, where they would contend for it and burn the busy timeout.
        with self._chain_lock:
            return self._store.append_next(
                stream, build, payloads, self._clock.now(), resolve_intent=resolve_intent
            )

    def fold_read(
        self,
        key: SigningKey,
        window_key: WindowKey,
        action: str,
        args_hash: str,
    ) -> None:
        """Fold one `read` into its window, closing and emitting when a bound is reached."""
        self.register_key(key)
        closing: _Window | None = None
        with self._window_lock:
            window = self._windows.get(window_key)
            if window is None:
                window = _Window(window_key, self._clock.now(), self._max_samples)
                self._windows[window_key] = window
            window.add(action, args_hash, self._clock.now())
            if window.total >= self._max_events:
                closing = self._windows.pop(window_key)
        if closing is not None:
            self._emit_window(closing)

    def close_expired_windows(self) -> None:
        """Close every window past `policy.aggregate-max-window` (§02 §7.5)."""
        deadline = clock_module.shift(self._clock.now(), -self._max_window_seconds)
        with self._window_lock:
            expired = [
                self._windows.pop(key)
                for key, window in list(self._windows.items())
                if window.opened_at <= deadline
            ]
        for window in expired:
            self._emit_window(window)

    def flush_windows(self) -> None:
        """Close every open window, whatever its age."""
        with self._window_lock:
            windows = list(self._windows.values())
            self._windows.clear()
        for window in windows:
            self._emit_window(window)

    def _emit_window(self, window: _Window) -> None:
        key = self._keys.get(window.key.subject_key)
        if key is None:  # pragma: no cover - a window always has a registered key
            logger.error("no signing key for %s; the window cannot be sealed", window.key.stream)
            return
        subject = key.subject
        body = {
            "v": "stozher/0.1",
            "kind": "aggregate",
            "emitted-at": self._clock.now(),
            "identity": {"subject": subject, "key": key.id, "component": self._component},
            "mandate-ref": window.key.mandate_ref,
            "policy-version": window.key.policy_version,
            "classification": "read",
            "window": {"from": window.opened_at, "to": window.last_at},
            "counts": {"total": window.total, "by-action": dict(window.counts)},
            "sample-hashes": window.samples[:16],
        }
        try:
            self.append(key, window.key.stream, body)
        except ChainError:
            logger.exception("an aggregation record was refused locally; it is not in the audit")

    # -- push --------------------------------------------------------------------------------

    def push_pending(self, limit: int = 64) -> int:
        """Offer locally chained envelopes to the kernel, in order. Returns how many were accepted.

        Push is asynchronous, ordered per stream and retried. A failure leaves the row unpushed and
        the loop tries again — the local chain is the record of truth until the kernel has it.

        **A refusal stops the stream** (§05 §7.1 clause 3). It used to mark the refused row pushed
        and carry straight on to the next envelope, which the kernel then refused `chain-seq-gap`,
        and so on to the end of the queue: every record of that session was marked delivered, none
        of it was, and `pending_push_count()` said zero. Now the position is recorded as a wedge and
        nothing past it is submitted until the wedge is lifted (§04 §7.2), so the rest of the chain
        is still there to submit when it is.
        """
        accepted = 0
        wedged: set[str] = set()
        for envelope_id, envelope, payloads in self._store.unpushed(limit):
            # This envelope is one this component chained and signed itself, and `append_next` wrote
            # the row's `stream` from the same member, so reading the position out of the body here
            # is reading its own record rather than trusting a claim.
            stream = str(envelope.get("stream", ""))
            seq = int(envelope.get("seq", -1))
            if stream in wedged or self._store.wedge(stream) is not None:
                # Submitting past a wedge produces a second rejection record naming the wrong
                # condition, and loses the envelope. Hold it: the local chain keeps it.
                wedged.add(stream)
                continue
            try:
                response = self._kernel.ingest(envelope, payloads)
            except KernelUnreachableError as e:
                self._store.mark_push_error(envelope_id, str(e))
                break
            if response.accepted:
                # An acceptance is the one event that ends a refused state (§05 §7.2 rule 2). It
                # normally clears nothing, because normally there is nothing to clear.
                self._store.mark_pushed(envelope_id, self._clock.now())
                self._store.clear_wedge(stream)
                accepted += 1
                continue
            detail = str(response.body.get("reason") or response.body)
            if not response.refuses_the_object:
                # The kernel answered without judging these bytes — `503 x-store-unavailable`, or a
                # credential the connection could not present. That is §05 §7.1's `unreachable`, and
                # it arrives over HTTP rather than as a dropped socket, which is the only reason it
                # ever looked like a refusal. Retry; wedging here would turn a momentary blip into a
                # hard stop no timer can lift, which is precisely the denial-of-service failure §7.1
                # was written to avoid.
                self._store.mark_push_error(
                    envelope_id, f"{response.reason_code or response.status}: {detail}"
                )
                logger.warning(
                    "the kernel could not answer for envelope %s (%s %s): %s; holding the stream "
                    "and retrying",
                    envelope_id,
                    response.status,
                    response.reason_code or "no reason code",
                    detail,
                )
                break
            # A refusal is permanent for these bytes; retrying identical bytes forever would hide it.
            reason = response.reason_code or "x-kernel-refused"
            self._store.mark_pushed(envelope_id, self._clock.now(), f"{reason}: {detail}")
            self._store.record_wedge(stream, envelope_id, seq, reason, detail, self._clock.now())
            wedged.add(stream)
            # This is an operator-visible failure, not a transient one: the local chain and the
            # kernel's copy of it have diverged, so every later envelope on this stream will be
            # refused `chain-seq-gap`. The local chain still holds the record, the kernel's
            # rejection stream holds the reason, and so now does this component's own state.
            logger.error(
                "the kernel refused envelope %s (%s): %s — %s; stream %s is wedged at seq %s and "
                "this component will not submit past it until an operator resumes the stream",
                envelope_id,
                envelope.get("kind"),
                reason,
                detail,
                stream,
                seq,
            )
        return accepted

    def pending_push_count(self) -> int:
        return self._store.pending_push_count()

    def args_hash(self, arguments: Any) -> str:
        """`object-hash(arguments)` (§01 §3.5), the value an approval signature binds to."""
        return object_hash(arguments)
