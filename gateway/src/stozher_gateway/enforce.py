"""The chokepoint. Every proxied call transits `Enforcer.call` exactly once.

One function, not per-tool logic: ADR-0002 records what happens when authorization lives in many
places — FleetQ re-executed approved proposals by flipping an ambient container binding, and no
amount of care in the individual call sites would have caught it. Here there is exactly one path
from "an agent asked for something" to "the effect happened", and every check is on it.

The order is §10 §2's, and it is not negotiable:

    resolve → normalize → classify → prohibited? → mandate → gate → forward → emit → return

Steps 1-3 and 8 are O(ms) and never block on the kernel. Only a gated call waits, and only for its
own approval.

Between `gate` and `forward` sits one more write that §10 §2 does not name and `spec/09 §4` does:
the record of the effect is persisted *before* the effect is applied, so a crash loses at most the
record of something that did not happen. `forward → emit` is still the order of the envelope; what
precedes it is the write-ahead row that makes the envelope recoverable if `emit` never runs.
"""

from __future__ import annotations

import json
import logging
import secrets
import subprocess
import threading
from collections.abc import Callable
from typing import Any, NamedTuple

from . import budget as budget_module
from . import clock as clock_module
from . import sync as sync_module
from .canonical import CanonicalizationError, canonicalize, object_hash, sha256_hex
from .classify import TIER_MANIFEST, Classification, Classifier
from .config import GatewayConfig
from .emitter import Emitter, WindowKey
from .gate import ActionRequest, Approver, GateRefusedError, action_request, verify_authorization
from .kernel_client import KernelClient, KernelUnreachableError
from .mandate import MandateRefusedError, MandateRequest, verify_mandate_chain
from .policy import Policy
from .refusal import RefusalError, refusal
from .signing import SigningKey, object_id
from .store import GatewayStore

__all__ = ["ARGUMENTS_MAX_BYTES", "Call", "Enforcer", "GateArgumentsError", "Session", "check_arguments"]

logger = logging.getLogger(__name__)

#: How long a parked request may sit in the queue before it must be re-asked.
_REQUEST_LIFETIME_SECONDS = 3600.0

#: §06 §4.4 rule 3 — the cap on the canonical form of the arguments submitted beside a request.
ARGUMENTS_MAX_BYTES = 16384


class GateArgumentsError(ValueError):
    """Argument values that may not be submitted beside a parked request, with its reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def check_arguments(arguments: Any, args_hash: str) -> str:
    """The canonical arguments to submit beside a parked request — §06 §4.4 rules 3 and 4.

    The same predicate the kernel applies on receipt, held on both sides on purpose: a component
    that submitted values the kernel then refused would have parked without them and never learnt
    why, and the approver would see the blank rather than the arguments. The corpus pins the two
    against each other (`spec/vectors/gate-arguments.json`).

    Raises :class:`GateArgumentsError` with `gate-arguments-too-large` or
    `gate-arguments-hash-mismatch`; the caller parks without the values rather than not parking.
    """
    canonical = canonicalize(arguments)
    if len(canonical.encode("utf-8")) > ARGUMENTS_MAX_BYTES:
        raise GateArgumentsError(
            "gate-arguments-too-large",
            f"{len(canonical.encode('utf-8'))} bytes of canonical arguments, above the cap of "
            f"{ARGUMENTS_MAX_BYTES}",
        )
    hashed = sha256_hex(canonical.encode("utf-8"))
    if hashed != args_hash:
        raise GateArgumentsError(
            "gate-arguments-hash-mismatch",
            f"the arguments hash to {hashed}, and the request commits to {args_hash}",
        )
    return canonical


class Session:
    """An authenticated caller: a derived subject key, a mandate, and a stream of its own."""

    def __init__(
        self,
        name: str,
        subject: str,
        key: SigningKey,
        mandate: dict[str, Any],
        stream: str,
    ) -> None:
        self.name = name
        self.subject = subject
        self.key = key
        self.mandate = mandate
        self.mandate_ref = object_id(mandate)
        self.stream = stream


class Call(NamedTuple):
    """What the caller asked for, before anything has been decided about it."""

    server: str
    tool: str
    arguments: dict[str, Any]
    schema: Any


class Enforcer:
    """Classification, mandate verification, gating and emission for every proxied call."""

    def __init__(
        self,
        config: GatewayConfig,
        store: GatewayStore,
        classifier: Classifier,
        emitter: Emitter,
        policy_of: Callable[[], tuple[Policy, bool]],
        clock: clock_module.Clock | None = None,
        revocations_of: Callable[[Policy], tuple[list[dict[str, Any]], bool]] | None = None,
        kernel: KernelClient | None = None,
        budgets: budget_module.BudgetFeed | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._classifier = classifier
        self._emitter = emitter
        #: The kernel-native pending queue (§06 §4.3). Without it a park is visible only to this
        #: process, which is the gap ADR-0008 §A named — so its absence is a warning, never silent.
        self._kernel = kernel
        if kernel is None:
            logger.warning(
                "no kernel queue is wired: a parked request will not reach the console"
            )
        #: Returns the policy in force and whether it is fresh. Raising means no verified policy
        #: exists, which is a refusal to act rather than a permissive default (§05 §2.3).
        self._policy_of = policy_of
        #: Returns the revocations to evaluate and whether the feed is current (ADR-0007 §1).
        self._revocations_of = revocations_of
        if revocations_of is None:
            # Without a feed, revocation reverts to what ADR-0007 §1 called a real security gap:
            # detected by the kernel at ingest, after the effect reached the world. An enforcer
            # built this way still refuses correctly on every *other* ground, so this is a warning
            # rather than a refusal to construct — but it must never be silent.
            logger.warning(
                "no revocation feed is wired: mandate revocation will be detective, not preventive"
            )
        #: The mandate chain's caps and accrued spend (§03 §4.3). Without it a budget is enforced
        #: only at ingest, after the spend — detection rather than prevention. Its absence is a
        #: warning for the same reason the revocation feed's is: the enforcer still refuses
        #: correctly on every other ground, and the gap must not be silent.
        self._budgets = budgets
        if budgets is None:
            logger.warning(
                "no budget feed is wired: mandate budgets will be detective, not preventive"
            )
        self._clock = clock or clock_module.Clock()
        self._component = config.gateway.component
        #: Live park notifiers, so a shutdown can wait for them rather than kill them mid-write.
        self._notifiers: list[threading.Thread] = []
        if not config.gateway.park_notify:
            # Same rule as the three feeds above: a gap that changes what the operator gets is
            # stated once at construction, never left to be discovered. An install with no notifier
            # still gates every call correctly — it just does so where nobody is looking.
            # Scoped to this process on purpose. The kernel has notification channels of its own
            # (Slack, SMTP, webhook), and an evaluation with a working webhook read this line as
            # "nobody was told" while 69 pings were being delivered. The gateway cannot see the
            # kernel's configuration, so it states what it knows and not what it does not.
            logger.info(
                "this gateway has no park_notify argv configured; if the kernel has no "
                "notification channel either, a parked request waits until someone opens the console"
            )

    # -- the one entry point ------------------------------------------------------------------

    def call(self, session: Session, call: Call, forward: Callable[[], Any]) -> Any:
        """Govern one proxied tool call. Raises :class:`RefusalError`; otherwise returns `forward()`."""
        policy, fresh = self._policy(call)
        classification = self._classify(session, call, policy)
        target = self._target(call)
        args_hash = self._args_hash(session, call, classification, target, policy)
        # The revocation set is resolved *here*, before the mandate walk and therefore before
        # anything is forwarded. A feed that could not be re-pulled when `revoke-cached` demanded
        # it makes the gateway not-fresh, which is what turns a stale revocation set into an
        # offline-block for `consequential` rather than a silent proceed (§05 §6, §7).
        revocations, feed_current = self._revocations(policy)
        fresh = fresh and feed_current

        if classification.classification == "prohibited":
            # §05 §3 step 2: nothing permits a prohibited action — not a mandate, not an approval.
            # The attempt is recorded with full evidence, because attempts are the most
            # audit-valuable records in the system.
            envelope_id = self._emit_effect(
                session, call, classification, target, args_hash, "attempted", policy
            )
            raise refusal(
                "prohibited",
                "policy-prohibited",
                "this action is prohibited by organization policy",
                action=classification.action,
                classification=classification.classification,
                classification_tier=classification.tier,
                envelope_id=envelope_id,
            )

        # §05 §7.1, and it comes before the mandate walk on purpose: what the kernel refused may be
        # the very grant this walk would accept. The walk resolves against the roots in this
        # component's own configuration, which is exactly the resolver §10 §1.4 did not name.
        self._require_not_wedged(session, call, classification, target, args_hash, policy)
        self._require_mandate(
            session, call, classification, target, args_hash, policy, revocations
        )
        self._require_online_enough(session, call, classification, target, args_hash, policy, fresh)
        self._require_budget(session, call, classification, target, args_hash, policy)

        decision = policy.decision_for(classification.classification)
        # §10 §4 gates the first call of an *unknown* tool. An action the organization published a
        # class for is not unknown: the kernel evaluates §05 §3 step 1 from the same document, and
        # the catalog entry an approval would seed says nothing policy has not already said. The
        # documented escape from the per-call toll — publish a policy naming your tools — did not
        # work until this line read both.
        first_call = not classification.known and not classification.policy_named
        if decision.kind == "deny":
            envelope_id = self._emit_effect(
                session, call, classification, target, args_hash, "blocked", policy
            )
            raise refusal(
                "denied",
                "policy-denied",
                "organization policy denies this class of action",
                action=classification.action,
                classification=classification.classification,
                classification_tier=classification.tier,
                envelope_id=envelope_id,
            )

        authorization: dict[str, Any] | None = None
        if decision.kind == "gate" or first_call:
            authorization = self._gate(
                session, call, classification, target, args_hash, policy, decision.approvers, first_call
            )

        started_at = self._clock.now()
        # §09 §4 requirement 1 (`emitter-must-persist-before-apply`): the record is persisted before
        # the effect is applied, so a crash loses at most the record of an effect that did not
        # happen. A `read` folding into an aggregation window has no envelope of its own to write
        # ahead of (§10 §5), and an fsync on that path is the firehose aggregation exists to avoid —
        # so the write-ahead covers exactly the calls that produce a per-call envelope.
        folded = classification.classification == "read" and authorization is None
        intent = (
            None
            if folded
            else self._write_ahead(
                session, call, classification, target, args_hash, policy, authorization, started_at
            )
        )
        try:
            result = forward()
        except RefusalError:
            raise
        except Exception:
            # §06 §6: an application that fails is still a record. There is no row in the terminal
            # state table in which an action is silently skipped.
            self._emit_effect(
                session,
                call,
                classification,
                target,
                args_hash,
                "failed",
                policy,
                authorization=authorization,
                started_at=started_at,
                intent=intent,
            )
            raise

        if intent is None:
            self._fold_read(session, classification, args_hash, policy)
            return result
        try:
            self._chain_effect(
                session,
                call,
                classification,
                target,
                args_hash,
                "applied",
                policy,
                authorization=authorization,
                started_at=started_at,
            )
        except Exception as e:  # noqa: BLE001 - a validation refusal or a failing disk, alike
            # §06 §6: a code path that returns success without emitting is non-conformant. The
            # effect did reach the world, so this refusal is not a rollback — it is the caller
            # being told that what it just did is not in the audit. The write-ahead record above
            # is deliberately left open: the next session chains it (`recover_intents`).
            raise refusal(
                "blocked",
                "chain-write-failed",
                "the effect was applied but its record could not be chained locally",
                action=classification.action,
                classification=classification.classification,
                classification_tier=classification.tier,
            ) from e
        self._store.resolve_intent(intent, self._clock.now())
        # Zero-touch: the upstream result is returned unchanged. The gateway may refuse, and a
        # refusal is visible; it never rewrites or summarizes what the agent asked for.
        return result

    def recover_intents(self, session: Session) -> int:
        """Chain every write-ahead record whose call never completed. Returns how many.

        A row survives only when the process died between applying an effect and chaining it, or
        when the chain write itself failed. Either way the honest statement is that the action was
        attempted and this component cannot say whether it applied — which is what `attempted`
        means here, and why these land on the console's attempts page, where a human looks.
        """
        recovered = 0
        now = self._clock.now()
        for intent_id, body, payloads in self._store.open_intents(session.stream, session.key.id):
            record = dict(body)
            record["emitted-at"] = now
            record["execution"] = {**record["execution"], "finished-at": now}
            try:
                self._emitter.append(session.key, session.stream, record, payloads)
            except Exception:  # noqa: BLE001 - one unchainable record must not strand the rest
                logger.exception("a write-ahead record could not be recovered into the chain")
                continue
            self._store.resolve_intent(intent_id, now)
            recovered += 1
        if recovered:
            logger.error(
                "%d effect(s) were applied without their record reaching the chain and have now "
                "been recorded as attempted; the audit cannot say whether they took effect",
                recovered,
            )
        return recovered

    def apply_pending_seeds(self, session: Session) -> int:
        """Put every signed-but-unapplied catalog seed in force. Returns how many were applied.

        Seeding is decoupled from replaying the call that provoked it: the approver's decision does
        two things (§10 §4.2), and the catalog entry is about *future* calls of that tool. Tying it
        to a retry of the original call would mean an approval that classified a tool never took
        effect unless the agent happened to ask for the identical thing again.
        """
        applied = 0
        policy, _ = self._policy_of()
        approvers = self._config.org.root_approvers()
        for parked in self._store.seeded_pending():
            if self._store.catalog_entry(parked.server, parked.tool) is not None:
                continue
            if self._seed_catalog(session, parked, policy, approvers):
                applied += 1
        return applied

    # -- steps --------------------------------------------------------------------------------

    def _policy(self, call: Call) -> tuple[Policy, bool]:
        try:
            return self._policy_of()
        except Exception as e:  # noqa: BLE001 - any failure to hold a verified policy fails closed
            raise refusal(
                "blocked",
                "policy-not-published",
                "the gateway holds no verified policy and will not guess one",
                action=f"{call.server}.{call.tool}",
            ) from e

    def _revocations(self, policy: Policy) -> tuple[list[dict[str, Any]], bool]:
        if self._revocations_of is None:
            return [], True
        try:
            return self._revocations_of(policy)
        except Exception:  # noqa: BLE001 - a feed failure must not become an unchecked mandate
            # Not fresh, and no revocations: the caller then treats `consequential` as
            # offline-blocked, so failing to read the feed cannot become permission to act.
            logger.exception("the revocation feed could not be resolved")
            return [], False

    def _classify(self, session: Session, call: Call, policy: Policy) -> Classification:
        proposed = self._classifier.classify(call.server, call.tool, call.schema)
        # A registered manifest is a proposal the kernel can see and evaluates itself (§05 §3 step
        # 1); every other tier is one it cannot, and §10 §3 says the stronger class is taken there.
        # Passing both through one slot made this build strengthen a *manifest's* class as well,
        # which is a disagreement with the kernel rather than caution.
        from_manifest = proposed.tier == TIER_MANIFEST
        effective = policy.classify(
            session.subject,
            proposed.action,
            self._target(call),
            proposed.classification if from_manifest else None,
            catalog_class=None if from_manifest else proposed.classification,
        )
        return Classification(
            proposed.action,
            effective,
            proposed.tier,
            proposed.classification,
            policy.names(session.subject, proposed.action, self._target(call)),
        )

    def _args_hash(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        policy: Policy,
    ) -> str:
        """`object-hash` of the arguments, or a recorded refusal if they have no canonical form.

        These arguments are foreign-agent input and this is the first thing done with them, so it
        is the first place the gateway can be handed a value the canonicalizer cannot represent —
        an integer outside binary64, a structure nested past what the recursion can carry. That
        fails closed, so it is not a bypass; what it was, before this, was an *unrecorded* refusal.
        The agent got an opaque MCP error, no envelope was emitted, and the attempt was absent from
        the audit — and §06 §6 has no row in which an action is silently skipped.

        The blocked record cannot carry the arguments (hashing them is what failed) nor their
        `args-hash` (they have none). It carries a stand-in naming the reason instead, because
        inventing a digest for a value with no canonical form would put a false statement in the
        chain.
        """
        try:
            return object_hash(call.arguments)
        except (CanonicalizationError, OverflowError, RecursionError, TypeError, ValueError) as e:
            code = e.code if isinstance(e, CanonicalizationError) else "jcs-malformed-json"
            stand_in = call._replace(arguments={"uncanonicalizable-arguments": code})
            envelope_id = self._emit_effect(
                session,
                stand_in,
                classification,
                target,
                object_hash(stand_in.arguments),
                "blocked",
                policy,
            )
            raise refusal(
                "blocked",
                code,
                "the arguments of this call have no canonical form, so no approval could bind them",
                action=classification.action,
                classification=classification.classification,
                classification_tier=classification.tier,
                envelope_id=envelope_id,
            ) from e

    def _target(self, call: Call) -> str:
        """The thing acted upon, in the gateway's namespace.

        The gateway can name the server it is fronting; it cannot in general name the row, repo or
        channel inside it without reading arguments whose meaning only a manifest declares (§08).
        Naming the boundary it actually knows is honest; inferring a finer one would be a guess in
        the field a mandate's `resources` scope is checked against.
        """
        return f"mcp:{call.server}"

    def _require_mandate(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        args_hash: str,
        policy: Policy,
        revocations: list[dict[str, Any]],
    ) -> None:
        request = MandateRequest(
            self._component, classification.action, classification.classification, target
        )
        try:
            verify_mandate_chain(
                {session.mandate_ref: session.mandate},
                session.mandate_ref,
                request,
                at=self._clock.now(),
                subject_key=session.key.id,
                roots=[root.key for root in self._config.org.roots],
                revocations=revocations,
                max_depth=policy.max_delegation_depth(),
            )
        except MandateRefusedError as e:
            envelope_id = self._emit_effect(
                session, call, classification, target, args_hash, "blocked", policy
            )
            raise refusal(
                "blocked",
                e.code,
                e.detail,
                action=classification.action,
                classification=classification.classification,
                classification_tier=classification.tier,
                envelope_id=envelope_id,
            ) from e

    def _require_not_wedged(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        args_hash: str,
        policy: Policy,
    ) -> None:
        """§05 §7.1 — the kernel has answered "no", and the caller is owed that answer.

        This is the step that did not exist. A component whose envelopes the kernel was refusing
        went on serving, went on returning upstream results, and told nobody: to `spec/` a refused
        emitter was merely a late one, so every MUST that fired in the state landed on the kernel,
        which discharged all of them. An evaluation served a week of tool calls into a kernel that
        accepted none of them and was conformant.

        The refusal carries the kernel's reason code **verbatim**. A gateway paraphrase would put
        the component's opinion where the organization's answer belongs, and the operator resuming
        the stream (§04 §7.2) has to cite that code.
        """
        wedge = self._store.wedge(session.stream)
        if wedge is None:
            return
        decision = sync_module.decide(
            outcome=sync_module.REFUSED,
            reason_code=wedge.reason_code,
            classification=classification.classification,
            elapsed_seconds=clock_module.seconds_between(
                wedge.first_refused_at, self._clock.now()
            ),
            offline=policy.offline_for(classification.classification),
            wedge_grace_seconds=policy.wedge_grace_seconds(),
        )
        if decision.action == "serve":
            # Loud, counted, and answerable from this component without reaching the kernel it
            # cannot reach. Silence here is what the grace window would otherwise buy.
            served = self._store.note_grace_use(session.stream)
            logger.error(
                "stream %s is wedged (%s since %s) and this %s call is being served under the "
                "grace window: %d effect(s) so far whose records the kernel has not accepted",
                session.stream,
                wedge.reason_code,
                wedge.first_refused_at,
                classification.classification,
                served,
            )
            return
        envelope_id = self._emit_effect(
            session, call, classification, target, args_hash, "blocked", policy
        )
        assert decision.reason_code is not None
        raise refusal(
            "blocked",
            decision.reason_code,
            f"the kernel refused this stream at seq {wedge.seq} ({wedge.detail}); nothing this "
            "component emits is reaching the audit, so it is not acting",
            action=classification.action,
            classification=classification.classification,
            classification_tier=classification.tier,
            envelope_id=envelope_id,
        )

    def _require_budget(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        args_hash: str,
        policy: Policy,
    ) -> None:
        """§03 §4.3 — an exhausted budget blocks, like an expired mandate.

        This is the *prevention* half. By the time an envelope reaches the kernel the spend has
        already happened and all the kernel can do is flag it, so a budget enforced only there is
        detection — which `docs/product-completion-design.md` §1 names a product defect rather than a
        polish item. The envelope is still emitted, with `outcome: "blocked"`, exactly as §03 §4.3
        says: a refusal is a record, and an action nobody can see refused is not governed.

        The caps come from the whole mandate chain, because a budget bounds "this mandate and
        everything delegated beneath it" — a delegate's own generous cap means nothing when its
        grantor is exhausted.
        """
        if self._budgets is None:
            return
        # One request, decided before it is made. `cost` is not known until after the call, so what
        # is checked here is what this call is *about* to add.
        adding = {"requests": "1"}
        chain = self._budgets.chain(session.mandate_ref)
        if chain is None:
            # Never read. Decide against the mandate the gateway is acting under, which it holds
            # locally: one that declares no budget proceeds, one that does is refused until the
            # figures are readable — acting under a cap whose spend is unknown is how a cap silently
            # stops existing. An *ancestor's* cap is invisible here, which is the same residue every
            # offline decision in this component carries.
            declared = session.mandate.get("budget")
            exceeded = sorted(declared) if isinstance(declared, dict) and declared else []
        else:
            exceeded = budget_module.exceeded_dimensions(chain, adding)
        if not exceeded:
            return
        envelope_id = self._emit_effect(
            session, call, classification, target, args_hash, "blocked", policy
        )
        raise refusal(
            "blocked",
            "mandate-budget-exhausted",
            f"the mandate chain has no remaining budget for: {', '.join(exceeded)}",
            action=classification.action,
            classification=classification.classification,
            classification_tier=classification.tier,
            envelope_id=envelope_id,
        )

    def _require_online_enough(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        args_hash: str,
        policy: Policy,
        fresh: bool,
    ) -> None:
        """While the cached policy is stale, apply `offline` behaviour per class (§05 §6, §7)."""
        if fresh:
            return
        behaviour = policy.offline_for(classification.classification)
        if behaviour == "allow":
            return
        envelope_id = self._emit_effect(
            session, call, classification, target, args_hash, "blocked", policy
        )
        raise refusal(
            "blocked",
            "policy-stale-offline",
            f"the cached policy is stale and this class is {behaviour} while offline",
            action=classification.action,
            classification=classification.classification,
            classification_tier=classification.tier,
            envelope_id=envelope_id,
        )

    def _gate(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        args_hash: str,
        policy: Policy,
        approver_subjects: list[str],
        first_call: bool,
    ) -> dict[str, Any]:
        """Park, or proceed on an approval already signed for exactly this call.

        First-call gating (§10 §4) parks an unknown tool even when the heuristic guessed `read` and
        even when the class would otherwise be allowed: unknown is not ungoverned. The approver's
        decision does two things — it authorizes this call, and it seeds the org catalog entry that
        future calls resolve through — and those are two signatures and two records, never one.
        """
        ask = ActionRequest(
            subject=session.subject,
            key=session.key.id,
            component=self._component,
            mandate_ref=session.mandate_ref,
            policy_version=policy.version,
            classification=classification.classification,
            action=classification.action,
            target=target,
            args_hash=args_hash,
        )
        fields = {
            "subject": ask.subject,
            "key": ask.key,
            "component": ask.component,
            "mandate-ref": ask.mandate_ref,
            "policy-version": ask.policy_version,
            "classification": ask.classification,
            "action": ask.action,
            "target": ask.target,
            "args-hash": ask.args_hash,
        }
        approvers = self._approvers(session, call, classification, target, args_hash, policy, approver_subjects)
        # An answer a human gave in the console lands in the kernel, not here, so the queue is
        # consulted before the local rows: otherwise a call would park a second time against a
        # request that has already been decided.
        self._collect_decisions(fields)
        parked = self._store.decided_for(fields)
        if parked is not None and parked.decision is not None:
            return self._consume(session, call, classification, parked, approvers, policy)

        now = self._clock.now()
        request = action_request(
            ask,
            requested_at=now,
            not_after=clock_module.shift(now, _REQUEST_LIFETIME_SECONDS),
        )
        request_hash = object_hash(request)
        # Local first: §10 §7 forbids keeping the only copy of a record in memory, and a component
        # must go on enforcing while the kernel is unreachable (maxim 5).
        #
        # §06 §4.2: a re-submission of a request nobody has answered resolves to the one already
        # held. The minted request above is discarded when it does — the nonce cost nothing and
        # building it outside the transaction keeps `park_unique`'s writer lock short. What must not
        # happen is the second *park*: the kernel's queue is idempotent by `request-hash` and cannot
        # help, because §06 §1.1 puts the fresh nonce inside the hashed object, so a duplicate
        # reaches it as a genuinely different question and one human is asked twice for one call.
        held = self._store.park_unique(
            request_hash,
            request,
            call.server,
            call.tool,
            classification.classification,
            call.schema,
            first_call,
            now,
            fields,
            now,
        )
        if held is not None:
            request, request_hash, first_call = held.request, held.request_hash, held.first_call
        # §06 §4.4 rule 2. This component holds the values `args-hash` commits to and is the only
        # party that will: it is a stdio process that exits with the session, and an approver
        # reading the queue an hour later cannot ask it anything. So the values go with the request.
        # Rule 3 caps them, and a call over the cap parks *without* them rather than not parking —
        # losing the display costs an approver context, losing the park costs them the gate.
        # `check_arguments` cannot fail on canonicalization here: `_args_hash` canonicalized these
        # same arguments above and refused the call if it could not.
        try:
            check_arguments(call.arguments, args_hash)
            arguments: dict[str, Any] | None = call.arguments
        except GateArgumentsError as e:
            logger.warning(
                "the parked request will carry no arguments for a human to read: %s", e.code
            )
            arguments = None
        # Re-submitted on a reuse as well, and deliberately: the route is idempotent by
        # `request-hash` for this exact object (§06 §4.3 rule 1), so the retry costs one `200` when
        # the request is already queued and *repairs* the case where the first submission never
        # arrived because the kernel was down. A park held locally against an unreachable kernel
        # otherwise stays invisible to every human for as long as the caller keeps retrying.
        not_queued = self._queue_with_kernel(request, arguments)
        if held is None:
            if first_call and classification.proposed:
                self._park_catalog_seed(ask, call, classification, request_hash)
            # Only for a request that is new. The seed request carries a fresh nonce of its own, so
            # re-parking it would duplicate the *second* question §10 §4.3 asks in exactly the way
            # this change stops the first from duplicating. And a notification per retry is the
            # approval fatigue §09 §7 names as an availability attack, delivered by the component
            # that was supposed to be preventing it.
            self._notify_parked(request_hash, ask)
        raise refusal(
            "parked",
            "gate-parked",
            f"awaiting approval from {', '.join(approver_subjects) or 'an enrolled human root'}",
            action=classification.action,
            classification=classification.classification,
            classification_tier=classification.tier,
            request_hash=request_hash,
            # A `parked` refusal is a legitimate terminal response, and the approval binds a *later
            # identical* request — the same call, not a similar one (ADR-0007 §5). The gateway does
            # not block: a sync wait inside a sync MCP handler would stall the whole server
            # (`docs/gateway-integration-constraints.md` §2).
            # No command and no route around the gate: §06 §4.1 forbids a refusal from carrying
            # guidance on obtaining approval by other means, and the first reader of this string is
            # the agent, which would try it. What it may say is what the protocol already promises —
            # that an approval binds a *later identical* request (§4.2), which is why `retryable` is
            # true for a park.
            hint=(
                f"pending request {request_hash}; once approved, the same call may be made again"
                if not_queued is None
                else f"pending request {request_hash} (held locally; {not_queued})"
            )
            # Only on a first call, where it is true: the decision seeds the catalog entry (§10
            # §4.3) and later calls of this tool resolve through it. A tool the catalog already
            # classifies `consequential` parks every time, and saying this there would be the
            # refusal promising something the next call disproves. Two independent evaluators read
            # a first-call park as "this product asks a human to sign every read", concluded it was
            # unusable, and never made the second call — the shape §4.1 calls being refused legibly.
            + (
                ". This tool is not yet classified here, so the first call is gated whatever its "
                "class; the decision also records that classification, and later calls resolve "
                "through it"
                if first_call
                else ""
            ),
        )

    def _park_catalog_seed(
        self, ask: ActionRequest, call: Call, classification: Classification, request_hash: str
    ) -> None:
        """Park the *second* request of §10 §4.3 beside the first: what class this tool is.

        Approving a first call and classifying the tool are two decisions with two signatures, and
        the catalog entry does not come into force without its own — otherwise "deny once" quietly
        becomes "allow forever at the heuristic's class". The gateway's `decide --classify` produced
        both from one invocation, and the console path produced only the first, so on the documented
        route the catalog was never written and every call of the tool parked again forever. Three
        evaluations reported that as "this product wants a human signature for every read".

        The class proposed is the classifier's own, not the escalated one policy gated on: the
        approver is being asked whether this tool is a `read`, which is the question `default-unknown`
        could not answer.
        """
        entry = {"server": call.server, "tool": call.tool, "class": classification.proposed}
        now = self._clock.now()
        seed_request = action_request(
            ActionRequest(
                subject=ask.subject,
                key=ask.key,
                component=ask.component,
                mandate_ref=ask.mandate_ref,
                policy_version=ask.policy_version,
                classification="consequential",
                action="kernel.seed_catalog_entry",
                target=f"tool:{call.server}/{call.tool}",
                args_hash=object_hash(entry),
            ),
            requested_at=now,
            not_after=clock_module.shift(now, _REQUEST_LIFETIME_SECONDS),
        )
        self._store.park_seed(request_hash, seed_request, classification.proposed)
        # The values behind `args-hash` go with it for the same reason the call's do (§06 §4.4
        # rule 2): an approver reading the queue an hour later cannot ask this process anything,
        # and "classify tool:x/y as read" is unanswerable without knowing which class.
        self._queue_with_kernel(seed_request, entry)

    def _notify_parked(self, request_hash: str, ask: ActionRequest) -> None:
        """Tell the operator something is waiting. Never blocks the gate, never fails the call.

        Three properties, each of which could reasonably have gone the other way and did not:

        1. **It cannot fail the call.** A notifier that turns a park into an error makes the gate
           less available than no notifier at all — the agent gets a broken tool because the
           operator's chat server was down, and the gate stops being the thing that decided.
        2. **It carries no argument values.** Those are the sensitive half: they have a retention
           ceiling and an authenticated route, and a notification is delivered to whatever the
           operator wired up, with neither. A pointer, not a copy.
        3. **A failure is logged.** Otherwise "nothing pinged me" and "the ping failed" look
           identical from the console, which is the exact defect class this whole change is about.
        """
        argv = self._config.gateway.park_notify
        if not argv:
            return
        message = json.dumps(
            {
                "stozher": "stozher/0.1",
                "event": "parked",
                "request-hash": request_hash,
                "subject": ask.subject,
                "action": ask.action,
                "target": ask.target,
                "classification": ask.classification,
                "parked-at": self._clock.now(),
            }
        )
        timeout = self._config.gateway.park_notify_timeout_seconds

        def run() -> None:
            try:
                finished = subprocess.run(
                    argv,
                    input=message,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as e:
                logger.warning("the park notifier for %s could not run: %s", request_hash, e)
                return
            if finished.returncode != 0:
                logger.warning(
                    "the park notifier for %s exited %s: %s",
                    request_hash,
                    finished.returncode,
                    finished.stderr.strip()[:200],
                )

        thread = threading.Thread(target=run, name=f"park-notify-{request_hash[:12]}", daemon=True)
        self._notifiers = [t for t in self._notifiers if t.is_alive()]
        self._notifiers.append(thread)
        thread.start()

    def drain_park_notifications(self, timeout: float | None = None) -> None:
        """Wait for in-flight notifiers. For shutdown, so a notifier is not killed mid-write."""
        for thread in list(self._notifiers):
            thread.join(timeout)

    def _approvers(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        args_hash: str,
        policy: Policy,
        approver_subjects: list[str],
    ) -> list[Approver]:
        """The approvers this component can verify a signature against, or a refusal (§06 §5, §6).

        Two cases that look alike and are not. An **empty** `approver_subjects` is first-call gating
        (§10 §4): no rule named anyone, and every enrolled root is a legitimate approver of "what
        class is this tool". A **non-empty** list that resolves to nothing is a rule the gateway
        cannot enforce — §06 §5's other kind of approver is a human holding a mandate, which the
        kernel resolves from its mandate store and this component has no equivalent of.

        Widening the second case to "any root" is the ADR-0008 inversion in miniature: the gateway
        would accept a root's signature, forward the call, the effect would happen, and the kernel
        would then refuse the envelope `gate-approver-not-permitted` — prevention turned into
        detection, and per ADR-0007 §6 the caller's stream wedged as well. A resolution failure
        refuses.
        """
        if not approver_subjects:
            return self._config.org.root_approvers()
        approvers = self._config.org.approvers(approver_subjects)
        if approvers:
            return approvers
        envelope_id = self._emit_effect(
            session, call, classification, target, args_hash, "blocked", policy
        )
        raise refusal(
            "blocked",
            "gate-approver-unresolvable",
            "policy names an approver this component cannot resolve to an enrolled key, so no "
            "signature it could check would satisfy the rule",
            action=classification.action,
            classification=classification.classification,
            classification_tier=classification.tier,
            envelope_id=envelope_id,
        )

    def _queue_with_kernel(
        self, request: dict[str, Any], arguments: dict[str, Any] | None
    ) -> str | None:
        """Put the park where a human can see it (§06 §4.3). Returns why it did not get there.

        `None` means queued. Anything else is the reason, and it is a *string* rather than a flag
        because there are three ways to fail here and they are not the same thing to whoever reads
        the refusal. This returned a bool, and the hint therefore said "the kernel was unreachable"
        for all three — including the one where the kernel answered, was healthy, and refused on
        purpose. A user whose calls had filled the approval queue was told the network was down,
        went to debug the network, and had no way to discover that the request they were told to
        wait for was in no queue at all.

        A kernel that cannot be reached does not turn a park into a proceed — the refusal above is
        raised either way. What it costs is visibility, and that cost is stated rather than leaving
        an operator to wonder why nothing appeared in the console.
        """
        if self._kernel is None:
            return "no kernel is configured, so nothing was queued for a human to see"
        try:
            answer = self._kernel.park_gate_request(request, arguments)
        except KernelUnreachableError:
            logger.exception("the parked request could not be queued with the kernel")
            return "the kernel was unreachable, so nothing was queued for a human to see"
        if answer.status not in (200, 201):
            logger.error(
                "the kernel refused a parked request: %s %s", answer.status, answer.reason_code
            )
            # Raised, not returned. The two remaining paths above are "held locally, and a human
            # will see it when the kernel is back" — `parked` is a true answer there. This one is
            # not: the queue rejected the request on purpose, no notification fires, no console row
            # exists, and no approval will ever arrive. Reported as `parked`, an agent waits for a
            # decision nobody can make, and an operator finds sixty receipts against zero queue
            # entries. `blocked` is the §06 §4.1 word for a call that did not happen and cannot
            # proceed as it stands, and it carries the kernel's own reason code rather than a
            # gateway paraphrase.
            raise refusal(
                "blocked",
                answer.reason_code or "gate-not-queued",
                f"the kernel refused to queue this request ({answer.reason_code or answer.status}), "
                "so it is in no approval queue and no decision can be made about it",
                action=request["action"],
                classification=request["classification"],
                request_hash=object_hash(request),
                hint=(
                    "nothing is pending: the request never entered a queue. Whatever the kernel's "
                    "reason code names has to change before this call can be answered."
                ),
            )
        return None

    def _collect_decisions(self, fields: dict[str, Any]) -> None:
        """Pull answers the kernel holds for this call's still-undecided local parks.

        The decision is copied in as *transport*, exactly as the S2 CLI wrote it: `_consume` runs
        all of §06 §2 over it before anything is forwarded. A row here permits nothing, which is why
        fetching one from the kernel is safe even though the kernel is not the authority — the
        approver's signature is.
        """
        if self._kernel is None:
            return
        for parked in self._store.pending():
            if not all(parked.request.get(name) == value for name, value in fields.items()):
                continue
            try:
                answer = self._kernel.gate_request(parked.request_hash)
            except KernelUnreachableError:
                logger.warning("the kernel could not be asked about %s", parked.request_hash)
                return
            decision = answer.body.get("decision")
            if isinstance(decision, dict):
                self._store.record_gate_decision(parked.request_hash, decision)
            self._collect_seed_decision(parked)

    def _collect_seed_decision(self, parked: Any) -> None:
        """Ask the kernel whether the catalog-seed request parked beside this call was answered.

        Separate from the call's own decision because the two are separately answerable: an
        approver may permit the action once and refuse to classify the tool, which is a coherent
        answer and the reason §10 §4.3 makes them two signatures rather than one.
        """
        if self._kernel is None or parked.seed is None or parked.seed.get("decision") is not None:
            return
        seed_request = parked.seed.get("request")
        if not isinstance(seed_request, dict):
            return
        try:
            answer = self._kernel.gate_request(object_hash(seed_request))
        except (KernelUnreachableError, CanonicalizationError):
            return
        decision = answer.body.get("decision")
        if isinstance(decision, dict):
            self._store.attach_seed_decision(parked.request_hash, decision)

    def _consume(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        parked: Any,
        approvers: list[Approver],
        policy: Policy,
    ) -> dict[str, Any]:
        """Verify a decision through §06 §2 and, if it approves, put its catalog seed in force."""
        authorization = {"request": parked.request, "decision": parked.decision}
        probe = {
            "identity": {
                "subject": parked.request["subject"],
                "key": parked.request["key"],
                "component": parked.request["component"],
            },
            "mandate-ref": parked.request["mandate-ref"],
            "policy-version": parked.request["policy-version"],
            "classification": parked.request["classification"],
            "execution": {
                "action": parked.request["action"],
                "target": parked.request["target"],
                "args-hash": parked.request["args-hash"],
            },
            "emitted-at": self._clock.now(),
            "authorization": authorization,
        }
        try:
            ok = verify_authorization(
                probe, True, approvers, self._seen_hashes(parked.request_hash), self._clock.now()
            )
        except GateRefusedError as e:
            self._store.consume(parked.request_hash, self._clock.now())
            if e.code == "gate-denied":
                # §06 §4.5: a signed denial is as much a record as a signed approval, and the audit
                # must show that a human said no, with the reason.
                envelope_id = self._emit_effect(
                    session,
                    call,
                    classification,
                    parked.request["target"],
                    parked.request["args-hash"],
                    "denied",
                    policy,
                    authorization=authorization,
                )
                raise refusal(
                    "denied",
                    "gate-denied",
                    e.detail,
                    action=classification.action,
                    classification=classification.classification,
                    classification_tier=classification.tier,
                    request_hash=parked.request_hash,
                    envelope_id=envelope_id,
                    decided_by=parked.decision["sig"]["key"],
                    decided_at=parked.decision["decided-at"],
                ) from e
            raise refusal(
                "blocked",
                e.code,
                e.detail,
                action=classification.action,
                classification=classification.classification,
                classification_tier=classification.tier,
                request_hash=parked.request_hash,
            ) from e

        assert ok is not None
        if self._store.catalog_entry(parked.server, parked.tool) is None:
            # Seeding may already have happened at session open. Emitting the seed envelope twice
            # would spend the approver's single-use signature on the second copy and the kernel
            # would refuse it `gate-authorization-replayed` — correctly, which is why the guard is
            # here rather than a hope that it never happens.
            self._seed_catalog(session, parked, policy, approvers)
        self._store.consume(parked.request_hash, self._clock.now())
        self._store.record_gate_use(ok.request_hash, self._clock.now())
        return authorization

    def _seed_catalog(
        self, session: Session, parked: Any, policy: Policy, approvers: list[Approver]
    ) -> bool:
        """Put an org-seeded catalog entry in force — its own gated, chained envelope (§10 §4.3)."""
        if parked.catalog_class is None or parked.seed is None:
            return False
        action = f"{self._classifier.scope(parked.server)}.{parked.tool}"
        entry = {"server": parked.server, "tool": parked.tool, "class": parked.catalog_class}
        seed_request = parked.seed["request"]
        probe = {
            "identity": {
                "subject": seed_request["subject"],
                "key": seed_request["key"],
                "component": seed_request["component"],
            },
            "mandate-ref": seed_request["mandate-ref"],
            "policy-version": seed_request["policy-version"],
            "classification": seed_request["classification"],
            "execution": {
                "action": seed_request["action"],
                "target": seed_request["target"],
                "args-hash": seed_request["args-hash"],
            },
            "emitted-at": self._clock.now(),
            "authorization": parked.seed,
        }
        try:
            verify_authorization(probe, True, approvers, set(), self._clock.now())
        except GateRefusedError as e:
            # The catalog entry must not come into force without its own signature. A seed that
            # does not verify is dropped; the tool stays unclassified and the next call parks again.
            logger.error("the catalog seed for %s was refused: %s", action, e.code)
            return False
        payload_hash = object_hash(entry)
        now = self._clock.now()
        body = {
            "v": "stozher/0.1",
            "kind": "effect",
            "emitted-at": now,
            "identity": {
                "subject": session.subject,
                "key": session.key.id,
                "component": self._component,
            },
            "mandate-ref": session.mandate_ref,
            "policy-version": policy.version,
            "classification": seed_request["classification"],
            "execution": {
                "action": seed_request["action"],
                "target": seed_request["target"],
                "args-hash": seed_request["args-hash"],
                "outcome": "applied",
                "started-at": now,
                "finished-at": now,
            },
            "evidence": {
                "schema": "kernel.seed_catalog_entry.v1",
                "media-type": "application/json",
                "payload-hash": payload_hash,
                "retain-until": self._retain_until(now, seed_request["classification"], policy),
            },
            "authorization": parked.seed,
        }
        payloads = [
            {"payload-hash": payload_hash, "media-type": "application/json", "payload": entry}
        ]
        envelope_id = self._emitter.append(session.key, session.stream, body, payloads)
        self._store.seed_catalog(
            parked.server, parked.tool, action, parked.catalog_class, now, envelope_id
        )
        return True

    def _seen_hashes(self, request_hash: str) -> set[str]:
        return {request_hash} if self._store.gate_seen(request_hash) else set()

    # -- emission -----------------------------------------------------------------------------

    def _fold_read(
        self, session: Session, classification: Classification, args_hash: str, policy: Policy
    ) -> None:
        self._emitter.fold_read(
            session.key,
            WindowKey(session.stream, session.key.id, session.mandate_ref, policy.version),
            classification.action,
            args_hash,
        )

    def _write_ahead(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        args_hash: str,
        policy: Policy,
        authorization: dict[str, Any] | None,
        started_at: str,
    ) -> str:
        """Persist the record of an effect before applying it. Returns the row's id.

        `attempted` is the outcome the record carries if it is ever chained, because it is the only
        one of the five (§02 §4) that does not claim to know how the call ended. It is written here
        and never emitted on the happy path: the row is closed the moment the real envelope lands.
        """
        body, payloads = self._effect_body(
            session,
            call,
            classification,
            target,
            args_hash,
            "attempted",
            policy,
            authorization,
            started_at,
        )
        intent_id = secrets.token_hex(16)
        self._store.record_intent(
            intent_id, session.stream, session.key.id, body, payloads, self._clock.now()
        )
        return intent_id

    def _emit_effect(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        args_hash: str,
        outcome: str,
        policy: Policy,
        authorization: dict[str, Any] | None = None,
        started_at: str | None = None,
        intent: str | None = None,
    ) -> str | None:
        """Chain an effect on a path that is already refusing. A failure here is logged, not raised.

        Every caller of this either raises a refusal of its own or is re-raising the downstream's
        exception, so the call never returns success unrecorded — which is the property §06 §6 is
        about. The applied path uses `_chain_effect` directly and refuses when it cannot write.
        """
        try:
            envelope_id = self._chain_effect(
                session,
                call,
                classification,
                target,
                args_hash,
                outcome,
                policy,
                authorization=authorization,
                started_at=started_at,
            )
        except Exception:  # noqa: BLE001 - a local refusal must be loud, not fatal to the caller
            logger.exception("the gateway could not chain an envelope for %s", classification.action)
            return None
        if intent is not None:
            self._store.resolve_intent(intent, self._clock.now())
        return envelope_id

    def _chain_effect(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        args_hash: str,
        outcome: str,
        policy: Policy,
        authorization: dict[str, Any] | None = None,
        started_at: str | None = None,
    ) -> str:
        body, payloads = self._effect_body(
            session,
            call,
            classification,
            target,
            args_hash,
            outcome,
            policy,
            authorization,
            started_at,
        )
        return self._emitter.append(session.key, session.stream, body, payloads)

    def _effect_body(
        self,
        session: Session,
        call: Call,
        classification: Classification,
        target: str,
        args_hash: str,
        outcome: str,
        policy: Policy,
        authorization: dict[str, Any] | None,
        started_at: str | None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        now = self._clock.now()
        payload = {"server": call.server, "tool": call.tool, "arguments": call.arguments}
        payload_hash = object_hash(payload)
        body: dict[str, Any] = {
            "v": "stozher/0.1",
            "kind": "effect",
            "emitted-at": now,
            "identity": {
                "subject": session.subject,
                "key": session.key.id,
                "component": self._component,
            },
            "mandate-ref": session.mandate_ref,
            "policy-version": policy.version,
            "classification": classification.classification,
            "execution": {
                "action": classification.action,
                "target": target,
                "args-hash": args_hash,
                "outcome": outcome,
                "started-at": started_at or now,
                "finished-at": now,
            },
            "evidence": {
                "schema": f"{classification.action}.v1",
                "media-type": "application/json",
                "payload-hash": payload_hash,
                "retain-until": self._retain_until(now, classification.classification, policy),
            },
        }
        if authorization is not None:
            body["authorization"] = authorization
        payloads = [
            {"payload-hash": payload_hash, "media-type": "application/json", "payload": payload}
        ]
        return body, payloads

    def _retain_until(self, at: str, classification: str, policy: Policy) -> str:
        """`emitted-at + policy TTL` — an emitter cannot buy longer retention, or shorter.

        This used to say `min(our preference, emitted-at + policy TTL)`. There is no "our
        preference" term and there never was: the emitter has no say at all, which is a stronger
        property than the one the docstring claimed and the reason it reads oddly. A `min` would let
        an emitter shorten retention below what policy requires, and evidence an emitter can
        shorten is evidence an emitter can lose (ADR-0030 §6).
        """
        return clock_module.shift(at, clock_module.parse_duration(policy.evidence_ttl(classification)))
