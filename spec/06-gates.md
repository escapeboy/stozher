# 06 — Gates

Normative. A gate is the only mechanism by which a specific action becomes permitted. This section
is the operational form of §00 §4:

> **"Approved" is not a boolean anywhere in this system.** Authorization exists only as an Ed25519
> signature by a named human over a hash of the *specific* action, and it travels inside the
> envelope with the effect.

ADR-0002 records the anti-lesson this design exists to prevent: FleetQ re-executed approved
proposals by flipping an ambient container binding (`app('integration_gate.bypass')`), an
unauditable side channel any code could set. The construction below makes the equivalent mistake
unrepresentable rather than discouraged.

## 1. Objects

Three objects, in this order: an **action request** (what the subject wants to do), a **gate
decision** (a named human's signature over that request's hash), and the **effect envelope** (which
carries both).

### 1.1 Action request

```json
{
  "v": "stozher/0.1",
  "kind": "action-request",
  "requested-at": "2026-07-26T09:14:40.000Z",
  "subject": "agent:claude-code/ivan-mbp",
  "key": "ed25519:<subject key>",
  "component": "gateway",
  "mandate-ref": "<64 hex>",
  "policy-version": "2026.07.1",
  "classification": "consequential",
  "action": "github.create_issue",
  "target": "repo:acme/backend",
  "args-hash": "<64 hex>",
  "nonce": "<32 hex>",
  "not-after": "2026-07-26T10:14:40.000Z"
}
```

- All members are REQUIRED. Unknown members MUST be rejected.
- The action request is **not** signed by the subject in `stozher/0.1`; it is submitted over an
  authenticated channel (§10 §1) and is bound into the effect envelope, which *is* signed by the
  subject. Its integrity as an object comes from `request-hash` being covered by the approver's
  signature.
- `nonce` (32 hex, ≥ 128 bits of entropy) makes two otherwise identical requests distinct objects,
  so an approval of one is not an approval of the other.
- `not-after` bounds how long the request may sit in the queue. The kernel MUST reject a decision
  whose `decided-at` is after the request's `not-after` (`gate-request-expired`).

```
request-hash = object-hash(action-request)
```

`request-hash` therefore binds, cryptographically and inseparably: who (subject + key), under what
authority (mandate-ref), under which policy (policy-version), at what weight (classification), doing
what (action, target), with which arguments (args-hash), which specific occurrence (nonce), and until
when (not-after).

### 1.2 Gate decision

A signed object (§01 §5), signed by the **approver's** key:

```json
{
  "v": "stozher/0.1",
  "kind": "gate-decision",
  "request-hash": "<64 hex>",
  "decision": "approve",
  "decided-at": "2026-07-26T09:14:58.000Z",
  "not-after": "2026-07-26T09:29:58.000Z",
  "single-use": true,
  "reason": null,
  "sig": { "alg": "ed25519", "key": "ed25519:<approver key>", "value": "<128 hex>" }
}
```

- `decision` MUST be `"approve"` or `"deny"` (`gate-decision-unknown`).
- `reason` MUST be a non-empty string when `decision` is `"deny"` (`gate-denial-without-reason`), and
  MUST be `null` or absent for `"approve"`. Denial reasons are the training data for policy tier 3
  (§05 §8) and the explanation the calling agent receives (§4).
- `not-after` (MUST) is when the approval stops being usable. It MUST be after `decided-at` and
  SHOULD be short (default `PT15M`). An approval is a permission to act *now*, not a licence.
- `single-use` (MUST) — see §3. `false` is permitted only where policy explicitly allows it; the
  default profile MUST set it `true`.
- `decision` alone is inert. Note that even the string `"approve"` carries no authority: it is
  meaningless without `sig` verifying and without `request-hash` matching the action actually
  performed. There is no place in this schema where a truthy value grants permission.

### 1.3 `authorization` in the envelope

```json
"authorization": {
  "request":  { …the action-request object, verbatim… },
  "decision": { …the signed gate-decision object, verbatim… }
}
```

Both members are REQUIRED when `authorization` is present. The request is embedded verbatim so that
any verifier — the kernel, the console, an auditor with a JSON parser and an Ed25519 library, three
years later, with the payload long since erased — can recompute `request-hash` and check the
signature with no access to kernel state.

## 2. Verification algorithm

Let `E` be an envelope, `requires-gate` the policy decision for `E` (§05 §3 step 4), and `approvers`
the set of keys permitted to approve that scope.

```
verify_authorization(E, requires-gate, approvers, at = E.emitted-at):

  if requires-gate and E.authorization absent:
      REJECT gate-authorization-missing                     ; (1)

  if E.authorization absent: ACCEPT                          ; nothing to check

  A := E.authorization
  require object-hash(A.request) == A.decision.request-hash
      else REJECT gate-authorization-request-hash-mismatch   ; (2)
  require verify_signed_object(A.decision)
      else REJECT gate-decision-sig-invalid                  ; (3)
  require A.decision.sig.key != A.request.key
      else REJECT gate-self-approval                         ; (4)
  require A.decision.sig.key in approvers
      else REJECT gate-approver-not-permitted                ; (5)
  require A.decision.decision in { "approve", "deny" }
      else REJECT gate-decision-unknown                      ; (6)
  if A.decision.decision == "deny":
      require A.decision.reason is a non-empty string
          else REJECT gate-denial-without-reason             ; (7)
      REJECT gate-denied
  require A.decision.decided-at <= A.request.not-after
      else REJECT gate-request-expired                       ; (8)
  require A.decision.decided-at <= at <= A.decision.not-after
      else REJECT gate-approval-expired                      ; (9)

  ; (10) the effect MUST be the approved effect, field by field
  require A.request.subject          == E.identity.subject
      and A.request.key              == E.identity.key
      and A.request.component        == E.identity.component
      and A.request.mandate-ref      == E.mandate-ref
      and A.request.policy-version   == E.policy-version
      and A.request.classification   == E.classification
      and A.request.action           == E.execution.action
      and A.request.target           == E.execution.target
      and A.request.args-hash        == E.execution.args-hash
      else REJECT gate-authorization-action-mismatch

  ; (11) replay
  if A.decision.single-use and seen(A.decision.request-hash):
      REJECT gate-authorization-replayed
  record_seen(A.decision.request-hash)

  ACCEPT
```

Every step matters, and each closes a specific bypass:

| Step | What it prevents |
|---|---|
| (1) | performing a gated action with no approval at all — the ambient-flag bypass |
| (2) | pairing a real signature with a rewritten request body |
| (3) | forged or corrupted approval |
| (4) | a subject approving its own action (§5) |
| (5) | approval by a subject not permitted to approve this scope |
| (6) | a decision value outside the closed vocabulary being read as permission |
| (7) | treating a *denial* as authorization because a `decision` member was present, and denials recorded without the reason the agent and the audit are owed |
| (8) | approving a request that had already expired in the queue |
| (9) | using an approval before it was granted, or long after |
| (10) | **carrying a valid approval for action A while executing action B** — different target, different arguments, different mandate, or a re-classified action |
| (11) | re-executing an approved action twice off one signature |

An implementation MUST perform all eleven checks at ingest, and a component that enforces locally MUST
perform (2)–(10) before applying the effect. Step (11) requires kernel state and is authoritative at
ingest; a component MAY additionally track it locally.

Note that step (1) is the only step conditioned on `requires-gate`. An `authorization` that is
*present* is always fully verified even when policy did not demand one: an envelope MUST NOT be able
to carry an unverified authorization-shaped object that a later reader might trust.

**There MUST NOT be any other way to satisfy `requires-gate`.** Specifically, an implementation MUST
NOT provide: a bypass flag or environment variable, a "trusted component" list that skips gating, a
request header or gRPC metadata field that marks a call approved, an in-process/DI binding that
suppresses the check, a "re-execution" code path that skips it because approval happened earlier, or
an admin endpoint that appends a gated envelope without `authorization`. Each of these is a
conformance failure, and the conformance harness (§08) MUST test for the last one directly by
attempting it.

## 3. Single use and re-execution

- With `single-use: true` (default), the kernel MUST reject the second envelope carrying the same
  `request-hash` (`gate-authorization-replayed`). The `request-hash` set MUST be retained at least
  until `decision.not-after` of every decision, and SHOULD be retained permanently (it is 32 bytes
  per approval).
- **Re-execution after approval** — the FleetQ pattern harvested in ADR-0002 (approval event →
  queued idempotent execution job) — is supported as follows: the job carries the `authorization`
  object with it, and the effect envelope it eventually emits embeds it. The permission is data that
  travels with the work. If the job is lost, requeued, or retried after `not-after`, it needs a fresh
  approval; it cannot proceed on the strength of a remembered fact.
- A retry of a *failed* application of an approved action MAY reuse the same `authorization` provided
  the previous attempt did not append an accepted envelope with that `request-hash` (that is exactly
  what step (9) tests) and `decision.not-after` has not passed. Idempotency of the effect itself is
  the emitting component's responsibility, declared in its manifest.
- `single-use: false` is a standing permission for a repeated specific action and MUST be used only
  where policy allows it. Anything broader belongs in a standing **mandate** (§03), which has
  mandatory expiry and a scope a human can read — not in a long-lived approval.

## 4. Blocking semantics

1. A `consequential` action under a `gate` rule **parks**: the component MUST NOT apply the effect,
   MUST NOT return a partial result, and MUST NOT perform a "safe subset" of the action unless
   `degrade` is declared for it (§05 §7).
2. Parking is synchronous from the caller's perspective. The kernel is synchronous **only** for
   gates (enforcement-topology doc): everything else is async emission.
3. The kernel MUST record the parked request, notify the approvers (notification adapter — the only
   outbound Stozher owns), and expose it in the console pending queue. A notification that could not
   be delivered MUST be recorded as such (`notify-failed`) rather than silently dropped: an approver
   who was never told is indistinguishable from one who has not answered yet.
4. On approval the component applies the effect and emits the envelope with `authorization`.
5. On denial the component MUST NOT apply the effect and MUST emit an envelope with
   `outcome: "denied"` carrying the *denial* `authorization` — a signed denial is as much a record as
   a signed approval, and the audit must show that a human said no, with the reason.
6. On timeout (`request.not-after` passes with no decision) the component MUST NOT apply the effect
   and MUST emit `outcome: "blocked"`. A timed-out gate is a block, never an allow. An
   implementation MUST NOT provide an "approve on timeout" policy option.

### 4.1 Structured refusal to the calling agent

When a call is denied or blocked, the caller receives a machine-readable refusal (this is also the
gateway's wire format, §10 §6):

```json
{
  "stozher": "stozher/0.1",
  "result": "denied",
  "reason-code": "gate-denied",
  "reason": "we don't file public issues on behalf of customers",
  "action": "github.create_issue",
  "classification": "consequential",
  "request-hash": "<64 hex>",
  "decided-by": "human:ivan",
  "decided-at": "2026-07-26T09:14:58.000Z",
  "envelope-id": "<64 hex>",
  "retryable": false
}
```

- `result` MUST be one of `denied`, `blocked`, `parked`, `prohibited`.
- `retryable` MUST be `false` for `denied` and `prohibited`. A refusal that invites an immediate
  retry teaches agents to loop against a human's decision.
- The refusal MUST NOT contain guidance on how to obtain approval by other means, and MUST NOT
  suggest an alternative unapproved action. Refusals are terminal facts, not negotiations.
- `envelope-id` lets the caller (and its operator) find the record. Being refused legibly is a
  feature: the agent can report accurately to its user instead of retrying blind.

## 5. Approvers

- `approvers` for a scope is determined by the matching `gate-rules` entry (§05 §1). Entries name
  subjects; the permitted keys are those subjects' enrolled keys.
- An approver MUST be a **named human**: an enrolled human root, or a human holding a mandate whose
  scope includes the action being approved. An agent MUST NOT be an approver
  (`gate-approver-not-human`). Escalation always terminates at a named human, and "the team" cannot
  be nudged (maxim 3): `approvers` MUST NOT name a group, a role, or a rotation as the signer of
  record. A rotation MAY determine *whom to notify*; the signature is always one person's.
- **Self-approval is prohibited**: `decision.sig.key` MUST NOT equal `request.key`, and the approver
  subject MUST NOT be the subject that requested the action (`gate-self-approval`). This holds even
  when a human acts directly through a tool — a human's own consequential action under a gate rule
  requires another named human's signature, or the rule should not have been written.
- A request a named human has already answered MUST NOT be answered a second time
  (`gate-decision-already-recorded`): one request, one answer.
- Approval decisions MUST themselves be recorded as envelopes (`kind: "gate-decision"`, member
  `decision-of` = `request-hash`) on `kernel:core`, so the approval history is chained and
  checkpointed independently of the effects that consume it.

## 6. Never silently proceed

The complete set of terminal states for any action under Stozher:

| State | Envelope emitted | `outcome` |
|---|---|---|
| allowed by policy, applied | yes | `applied` |
| allowed, application failed | yes | `failed` |
| gated, approved, applied | yes, with `authorization` | `applied` |
| gated, denied | yes, with denial `authorization` | `denied` |
| gated, timed out or offline-blocked | yes | `blocked` |
| mandate invalid / budget exhausted | yes | `blocked` |
| `prohibited` class attempted | yes, full evidence | `attempted` |

There is no row in which an effect happens without a record, and no row in which an action is
silently skipped. An implementation with a code path that returns success without emitting is
non-conformant, and the conformance harness tests the negative cases specifically (§08 §4).
