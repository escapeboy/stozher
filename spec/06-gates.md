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
- `args-hash` commits to the call's arguments; the request does not carry them and MUST NOT be
  extended to. The values travel beside it in the submission of §4.4, which checks them against this
  digest, and they expire with the request rather than with the envelope that cites it.
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
- All members are REQUIRED and the set is closed: an unknown member MUST be rejected
  (`schema-unknown-member`), exactly as for the action request in §1.1. Stated rather than left to
  symmetry, because asymmetric strictness between the two halves of one signed authorization object
  is a defect waiting to be found, and an implementation accepting unknown decision members would
  not have been violating the text.
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

**`requires-gate` is outcome-conditional.** It is true only when the effect was applied — outcome
`applied` or `failed`. A gated action that was parked, denied or timed out legitimately carries no
approval, and §4 rules 5 and 6 *require* those envelopes to exist. Read without this, step (1) would
refuse the very record of a human saying no.

```
verify_authorization(E, requires-gate, approvers, at = E.emitted-at):

  ; (0) shape, before anything is compared
  if E.authorization present:
      require A.request  conforms to section 1.1's closed member set   ; schema-*
      require A.decision conforms to section 1.2's closed member set   ; schema-*
      require each of A.request.not-after, A.decision.decided-at,
              A.decision.not-after and `at` is a section 01 2.3 timestamp
          else REJECT encoding-bad-timestamp

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
  what step (11) tests) and `decision.not-after` has not passed. Idempotency of the effect itself is
  the emitting component's responsibility, declared in its manifest.
- **A `single-use` that is not a JSON boolean MUST be read as `true`**, and so MUST an absent one on
  a decision that somehow reaches a verifier without it. This is not a rejection: a malformed value
  here is a defect in the approver's tooling, and the restrictive reading of a defect costs an
  approver a second signature while the permissive one costs the organization a second effect. A
  verifier MUST report `single-use: true` to its caller in that case, so the `request-hash` still
  enters the seen-set that step (11) consults.
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

### 4.2 Parking is a terminal answer, not a wait

Parking is synchronous from the caller's perspective in that the caller receives a *terminal answer*
immediately: a `parked` refusal (§4.1) is a legitimate terminal response. The approval binds a
**later identical request** — identical by `request-hash`, therefore the same call and not a similar
one. A component MUST NOT block a request handler waiting for a decision.

An implementation that held the call open would turn every gate into a request-handler leak and an
approver's lunch break into an outage, and it would do so while looking like it worked.

**Re-submission of an identical request MUST be idempotent.** Before building an action request, a
component MUST look for one it already holds for the same call, and where one exists it MUST resolve
to that request — returning the `parked` refusal of §4.1 carrying **that** request's `request-hash` —
rather than enqueue a duplicate.

1. Identity here is **field-wise**: `subject`, `key`, `component`, `mandate-ref`, `policy-version`,
   `classification`, `action`, `target` and `args-hash`, all nine equal. It is deliberately **not**
   `request-hash`. §1.1 puts a fresh `nonce` inside the hashed object, so two submissions of one call
   always hash differently — the same property that keeps an approval of one from being an approval
   of the other makes the hash unusable as the identity of the *call*.
2. A pending request MUST be matched on those fields **before** it is classified as decided or new. A
   lookup that filters on the presence of a decision first has already discarded the row it needed:
   the only question it can answer is "has this been answered?", never "has this been asked?".
3. A held request whose `not-after` has passed MUST NOT be reused. Nobody can answer it any more
   (step 8 of §2 refuses a decision made after that instant, and §4.3 rule 7 has the kernel erase the
   arguments an approver would read), so resolving to it would hand the caller a `request-hash` that
   can never become an approval. That call MUST build a new request.
4. A held request that already carries a decision is governed by §3 and by §2, not by this rule; one
   whose decision has been consumed permits nothing and is not a request to resolve to.

This is a duty of the **component**, and it cannot be delegated to the queue: §4.3 rule 1 makes the
kernel's route idempotent by `request-hash`, which two submissions of one call do not share. Nor may
the kernel collapse them on its own — to the kernel they are two distinct objects, which is precisely
what §1.1 makes them.

It is also not in tension with the paragraph above. That one is about what an *approval* binds —
one signed `request-hash`, the same call and not a similar one. This one is about what a component
may ask *before* anybody has signed anything: asking twice does not produce two permissions, it
produces two questions for one human. Without the rule, every restart multiplies an approver's queue
by the number of times the agent ran — a nightly job that re-runs at 04:00 over its own 03:00 queue
asks for every signature a second time, with nothing in the queue to tell the copies apart — and §09
§7 names approval fatigue as an availability attack. A component that cannot be run twice cannot be
scheduled and cannot hold a standing mandate.

### 4.3 The pending queue

A parked request is **not** an envelope. §02 §2's `kind` vocabulary is closed, and its admission rule
covers what changes what the system will permit; an action request changes nothing. Accordingly:

1. The kernel MUST expose `POST /v1/gate/requests`, taking a **submission** (§4.4) carrying an
   action-request object (§1.1), and it MUST be idempotent by `request-hash`. It MUST validate the
   request against §1.1's closed member set, MUST reject an unknown member
   (`schema-unknown-member`), and MUST reject a request whose `not-after` has already passed
   (`gate-request-expired`).
2. That route MUST NOT append an envelope and MUST NOT be reachable from any code path that can.
3. The kernel MUST record the authenticated caller alongside the request. **The caller need not be
   the subject the request names**: the approval binds `request.key`, so a caller that does not hold
   that key has asked a question it can never act on. An interface MUST show both.
4. The kernel MUST expose the queue for reading, and one request together with its decision when one
   exists. A decision MUST be returned **verbatim**; a component consuming it MUST itself perform §2
   steps (2)–(10) before acting. A queue that pre-digested a decision would be a second verifier, and
   the one that matters is the one at the point of use.
5. The queue MUST be append-only. A request that could be edited after an approver read it is not the
   request they approved, and a decision that could be rewritten is not a decision.
6. The kernel MUST record every approver-notification attempt with its outcome. An interface MUST
   distinguish "no channel is configured" and "no channel delivered" from "an approver was notified"
   (§4 rule 3's `notify-failed`).
7. At most one decision may be recorded per request (`gate-decision-already-recorded`).

### 4.4 The arguments an approver reads

`args-hash` is a commitment to the arguments, not the arguments, and §1.1 carries nothing else. Read
literally, an approver is therefore asked to sign over a call they cannot read: a request that writes
"revenue down 12%" and a request that promotes a build to production differ in the queue by a digest.
The component that holds the preimage is often a process that has already exited by the time a human
looks — a stdio gateway is the ordinary case — so "ask the component" is not an answer, and an
approval given without it is a signature over a hash and nothing more. The values therefore travel
with the request.

1. The body of `POST /v1/gate/requests` is a **submission**:

   ```json
   { "request": { …the action-request object (§1.1)… }, "arguments": { …the argument values… } }
   ```

   Its member set is closed and an unknown member MUST be rejected (`schema-unknown-member`). It
   carries no `v` and no `kind`, exactly as `authorization` (§1.3) — which is the same shape, a
   container for objects that carry their own — does not. A body that is *itself* an action-request
   object MUST also be accepted and is exactly a submission with `arguments` absent. There is one
   hashed object under either spelling and it is the same one: `request-hash` is
   `object-hash(submission.request)`, never of the submission. The older spelling is kept because a
   refused submission is a gate no human can see while the call it belongs to stays blocked, and an
   upgrade in which the kernel moves before its components must not be able to empty the queue.

2. `arguments` is OPTIONAL on the wire and obligatory of a component that can supply it: a component
   that computed `args-hash` from a value it still holds MUST submit that value, unless rule 3
   forbids it. A component that never held the preimage MUST omit the member rather than send a
   stand-in — a plausible-looking argument list nobody executed is worse than none.

3. **Size.** The canonical form (§01 §2) of `arguments` MUST NOT exceed 16384 bytes. A submission
   over that MUST be rejected (`gate-arguments-too-large`), and a component whose values exceed it
   MUST park **without** them rather than not park: losing the display costs an approver context,
   losing the request costs them the gate. The bound is far above what a human reads and what a call
   needs, and the number of requests that can hold one at a time is already bounded by §09 §7.

4. **The commitment is checked, not trusted.** Where `arguments` is present the kernel MUST verify
   `object-hash(arguments) == request["args-hash"]` and MUST reject the submission otherwise
   (`gate-arguments-hash-mismatch`). Without this rule nothing stops a component showing a human one
   call and executing another, and the display would be worth less than the blank it replaced.

5. **An approver MUST be able to repeat that check**, and an interface showing the arguments MUST
   show them in canonical form (§01 §2) and state how — the arguments' `object-hash` is the
   `args-hash` inside the request their signature covers, so the whole chain from what they read to
   what §2 step (10) enforces is recomputable with a JSON canonicalizer and SHA-256. The verifier
   that matters is the one at the point of use, and here that is the human.

6. `arguments` is **not** part of the action request. It is absent from §1.1's member set, it is not
   covered by `request-hash`, and an implementation MUST NOT copy it into `authorization.request`, an
   envelope, or evidence. What a signature binds is `args-hash`; the values are how the signer came
   to know what that digest meant.

7. **Retention falls out of the queue, and adds nothing to it.** The recorded arguments are those of
   the first accepted submission; a later submission of the same `request-hash` MUST NOT replace,
   extend or remove them (rule 5 of §4.3 — the queue is append-only). Once the request's `not-after`
   has passed the kernel MUST NOT serve them and MUST erase them: an expired request can no longer be
   answered (§2 step 8), so values kept past that instant are readable only by someone who cannot act
   on them. Erasing them changes no signed byte — the request object, its `request-hash` and its
   `args-hash` all remain — so this is not §04 §5 decay, requires no checkpoint, and interacts with
   neither.

8. An interface MUST distinguish **arguments that were never supplied** from **arguments that were
   supplied and are empty**, and MUST NOT render the first as the second. "The component did not tell
   us" and "the call took no arguments" are different facts about what is being approved, exactly as
   §4.3 rule 6 separates a notification nobody attempted from one that failed.

9. **A mismatch is a finding, and a durable one.** Rule 4's refusal is a statement about the
   *component*, not about the request: one that submits values its own `args-hash` does not cover is
   broken or lying, and the organization is entitled to see which of its components did it. A refusal
   the submitter alone is told about is visible only to whoever is reading stderr at the time. The
   kernel MUST therefore record it in the rejection stream (§04 §7.1), carrying the authenticated
   caller, the request's `subject` and `action`, the `request-hash`, and the reason code. Two
   boundaries, both deliberate:

   - **Rule 4 only.** A rule 3 refusal (`gate-arguments-too-large`) MUST NOT earn a record. An
     over-sized submission is a component being honest and verbose, and rule 3 already tells it what
     to do instead — park without the values. Recording every §4.4 refusal would fill the chain with
     the events that do not matter and make the one that does harder to find.
   - **Bounded by §09 §7.** A caller that can write to the kernel's chain by submitting garbage is an
     append-only store with a cheap write. The kernel MUST apply §09 §7's per-subject cap to this
     path, counting **the subject's own recorded mismatches** in the window; at or above it the
     submission MUST be refused `gate-rate-limited` and MUST NOT be recorded. The obvious counter is
     the wrong one: a refused submission parks nothing, so a component that only ever lies has a
     parked count of zero forever and would be bounded by nothing at all. The idempotency of §4.3
     rule 1 MUST NOT exempt this path either — a retry of a *queued* request is a component behaving
     correctly, but a retry carrying a mismatch is not the same event and MUST NOT be laundered into
     silence by the request already being on the queue.

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
