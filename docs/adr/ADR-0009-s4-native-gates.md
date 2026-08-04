# ADR-0009: Kernel-native gates — pending queue, key custody, and the spec text

**Status:** Accepted · **Date:** 2026-07-26 · **Arises from** S4 (`feature/s4-native-gates`)
**Closes** ADR-0008 §A and ADR-0007 §5 · **Amends** `spec/02`, `spec/06`

---

## 1. ADR-0008 §A CLOSED — a parked request is not an envelope

`spec/06 §4.3` obliged the kernel to record a parked request and show it in the console, but only
the *emitting component* observes a park, and `spec/02 §2`'s `kind` vocabulary is closed with no
member for one. **Resolution chosen: `spec/06` defines a request-submission route, not a new
envelope kind.** Three reasons, the first two decisive:

1. **`spec/02 §2` states its own admission rule** — "everything that *changes what the system will
   permit* is itself an audited, chained, signed event." An action request changes nothing; it is a
   question. Answering it is what changes something, and the answer already *is* an envelope
   (`gate-decision`).
2. **An envelope takes a `seq` on the emitter's chain.** A request that expired unanswered would
   hold a chain position for something that never happened — and a park the kernel refused would
   **wedge that emitter's effect stream** for every later envelope (ADR-0007 §6). *A question must
   not be able to stall the audit.*
3. `spec/06 §1.1` already said the request "is submitted over an authenticated channel (§10 §1)"
   and that its integrity comes from `request-hash` being covered by the approver's signature. The
   spec had already chosen this shape; only the route was missing.

Nothing is lost from the audit: the decision is chained on `kernel:core`, and the effect embeds the
request verbatim in `authorization.request`.

**Invariants held.** `Store::append` remains `pub(crate)` and `Ingest::submit` remains its only
caller — asserted by `parking_a_request_appends_nothing_to_any_chain`. The three new tables carry no
chain-bearing column and are append-only by trigger. Deny reasons are captured (tier-3 drift
learning data, per `docs/design/policy-model.md`).

### Normative text to add to `spec/`

**(a) `spec/06 §1.1`**, appended to the authenticated-channel sentence:

> The channel is `POST /v1/gate/requests` (§4.3.1). The kernel MUST validate the request against
> this section's closed member set, MUST reject an unknown member (`schema-unknown-member`), and
> MUST reject a request whose `not-after` has already passed (`gate-request-expired`). It MUST
> record the authenticated caller alongside the request. The caller need not be the subject the
> request names: the approval binds `request.key`, so a caller that does not hold that key has
> asked a question it can never act on. The console MUST show both.

**(b) new `spec/06 §4.3.1 — The pending queue`:**

> A parked request is **not** an envelope. §02 §2's `kind` vocabulary is closed and its admission
> rule covers what changes what the system will permit; an action request changes nothing.
> Accordingly:
> 1. The kernel MUST expose `POST /v1/gate/requests`, taking an action-request object (§1.1), and it
>    MUST be idempotent by `request-hash`.
> 2. That route MUST NOT append an envelope and MUST NOT be reachable from any code path that can.
> 3. The kernel MUST expose the queue for reading, and one request together with its decision when
>    one exists. A decision MUST be returned **verbatim**; a component consuming it MUST itself
>    perform §2 steps (2)–(10) before acting.
> 4. The queue MUST be append-only. A request that could be edited after an approver read it is not
>    the request they approved, and a decision that could be rewritten is not a decision.
> 5. The kernel MUST record every approver-notification attempt with its outcome. An interface MUST
>    distinguish "no channel is configured" and "no channel delivered" from "an approver was
>    notified."
> 6. At most one decision may be recorded per request (`gate-decision-already-recorded`).

**(c) `spec/06 §4.2`** — closes ADR-0007 §5:

> Parking is synchronous from the caller's perspective in that the caller receives a *terminal
> answer* immediately: a `parked` refusal (§4.1) is a legitimate terminal response. The approval
> binds a **later identical request** — identical by `request-hash`, therefore the same call and not
> a similar one. A component MUST NOT block a request handler waiting for a decision.

**(d) `spec/06 §5`**, one clause:

> Self-approval is prohibited over the *person*, not the keypair: an implementation MUST refuse a
> decision whose signer resolves to the same **subject** as `request.subject`, not only the same key.

**(e) `spec/02 §9.1`** — adopt or replace `x-gate-decision-already-recorded` and `x-notify-failed`
(the `x-` register grew 8 → 10, still quarantined per ADR-0006 §9).

---

## 2. Key custody — the kernel cannot forge an approval

**The approver's signing key lives nowhere in Stozher.** The kernel holds no approver key material,
has no route that produces an approver's signature, and therefore **cannot manufacture an
approval** — not for an operator with a shell on the box, not for a compromised kernel process, not
for its own maintenance code. *The party that enforces the gate is structurally unable to satisfy
it.*

`POST /console/pending/{hash}/decide` accepts an **already-signed** decision object, verifies it
(shape, hash binding, signature, self-approval by key *and* subject, approver membership resolved
via `Ingest::approvers_for` so the console cannot hold a second opinion, both expiry windows), then
submits it through `Ingest::submit`. The envelope's own signature is the **kernel's** and attests
only receipt and chain position — exactly what it attests on a rejection record. Ingest re-verifies
the inner human signature independently, so a kernel-signed envelope wrapping a forged decision is
refused by the same path that would refuse it from anyone else.

Approvers sign with `stozher-kernel decide --request <hash> --key <seed> --approve`, which does no
network I/O and needs no kernel config: it reads the approver's own owner-only seed file in the
approver's own process and prints the object.

**The trade-off, stated plainly:** the console cannot offer one-click approve to a human with only a
browser. There is a copy-paste step. **That friction is what buys "the kernel cannot forge an
approval" as a structural fact rather than a promise.** The rejected alternative — console holds an
approver seed and signs on a button press — makes the enforcer able to produce the authorization,
which voids `spec/06` entirely. The friction is removed *without* moving the key to the server by
browser-side WebCrypto Ed25519 signing plus a console session scheme; ADR-0008 already places the
session scheme at S5, which is where that pair belongs.

**CSRF:** token = `sha256(per-process nonce ‖ caller ‖ 0x00 ‖ request-hash)`, constant-time
compared, bound to (process, caller, request) — so a page the caller never fetched cannot yield an
accepted token. This specifically defends the header-injecting-reverse-proxy deployment shape
ADR-0008 records. Every other console route stays `GET`-only; the S3 ten-path 405 test passes
unchanged.

---

## 3. The gate was mutation-tested — twice, independently

A gate that has never failed is an untested gate. The ADR-0002 bypass was reintroduced deliberately
and the gate was confirmed to catch it:

- **By the implementing agent**, disabling gating in `enforce.py`: all four S4 gate tests failed,
  and the kernel independently refused the ungated effect with
  `gate-authorization-missing — a gated action carries no approval signature`.
- **By the orchestrator, independently**, replacing the `verify_authorization` call in `_consume`
  with `ok = True` — ambient approval, "the parked row alone permits the call," which is precisely
  the FleetQ failure mode. Result: `test_a_denial_blocks_and_the_downstream_is_never_invoked` and
  the approve-path test **both failed**. Reverted; tree clean; gate green again.

This is the difference between believing the anti-lesson is honoured and knowing it.

## 4. Adversarial coverage (25 kernel tests)

Refused, each with a specific code: rewritten request (`gate-authorization-request-hash-mismatch`);
stranger's signature at console **and** ingest (`gate-approver-not-permitted`); self-approval by key
*and* by subject via a second key (`gate-self-approval`); replay of a single-use approval
(`gate-authorization-replayed`); approval for A authorizing B — `action`, `target`, `args-hash`,
`component`, `mandate-ref` each tested separately (`gate-authorization-action-mismatch`); second
contradicting decision (`x-gate-decision-already-recorded`); forged/empty/wrong-request CSRF (403,
nothing recorded); decision for a never-queued request (404); expired request
(`gate-request-expired`); **a request smuggling an `"approved": true` member**
(`schema-unknown-member`); unauthenticated queue reads (401 on all three paths); denial without a
reason (`gate-denial-without-reason`).

The deny path's witness is the downstream server's own log, written by a different process, asserted
by strict list equality — with the approve-path test as counterfactual, so it cannot pass vacuously.

## 5. Notification adapter

In-kernel, trait-based, exactly three channels (Slack webhook, SMTP, generic webhook) per ADR-0002's
"2–3 channels max." Secrets by `*_env` reference only. Every attempt is recorded with its outcome,
and the console distinguishes "no channel configured" / "no channel delivered" / "an approver was
notified" — a failed ping cannot silently swallow a park.

**SMTP over TLS deferred, deliberately:** the channel speaks plain SMTP to a relay. With no
credential that is the strongest form of "no plaintext secrets" — there is no secret. If
`username`/`password-env` *are* set it sends `AUTH PLAIN` **only to a loopback relay** and refuses
otherwise (`x-notify-failed`) rather than silently downgrading. A second TLS stack inside the binary
is exactly the audit surface ADR-0003 argues against; an on-prem relay is the normal deployment.

## 6. Honest notes carried forward

- **Intermittency, unreproduced.** Twice in ~25 full gateway-suite runs, S2's `test_gateway_e2e.py`
  module fixture errored (3 tests), both immediately after a heavy cargo run in the same shell. 25+
  further attempts, including deliberate concurrent-load runs, **failed to reproduce it or capture a
  traceback**. The suspected path is the pre-existing 20s kernel health-check timeout in
  `tests/support.py::_await_health` racing a cargo relink of the on-disk binary. **This is an
  inference, not an observation**, and is recorded as such. Not S4-specific; every S4 gate run has
  passed. Worth a deterministic fix at S5 (copy the built binary aside per test session).
- **Pre-existing kernel flake, unrelated to S4.** On a baseline run *before* any change,
  `concurrency.rs::s6_one_approval_cannot_be_spent_twice` (named here as
  `one_approval_cannot_be_consumed_twice_however_the_requests_race` until the citation was corrected
  on 2026-08-04) failed once: it
  needs at least one of eight racers to lose on *replay* rather than chain position, and under load
  all seven can lose on position first. Passed 5/5 isolated and every subsequent full run. The
  assertion is inherently timing-dependent — worth tightening, not currently wrong.
- **Approver-flood bound (`spec/09 §7`) not implemented.** No cap on queue depth. The submitter is
  authenticated and only genuine gated calls park, so exposure is bounded by credential possession —
  but a cap deserves an S5 decision.
- **`gateway/uv.lock`** was previously untracked and generated during this session; kept (a lockfile
  belongs in VCS) and isolated in its own commit so it is not mistaken for gate work.
- `_collect_decisions` polls per parked row matching the call; a `since` cursor is wanted before a
  design partner's real log (same note as ADR-0008's pagination item).
