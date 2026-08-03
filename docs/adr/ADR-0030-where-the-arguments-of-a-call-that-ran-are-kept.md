# ADR-0030 — Where the arguments of a call that ran are kept

**Date:** 2026-08-03
**Status:** accepted
**Arises from** `docs/spec-debt.md` §3, second bullet — *"No ADR records that an applied effect
retains its arguments."*

Per ADR-0013's rule, every claim below names the test that fails if it stops being true. Two of the
claims have **no test**, and are listed as such rather than left to look bound.

## 1. Why a fact this ordinary needs a decision record

`grep -rln "v1/payloads\|payload-hash\|payload_hash" docs/adr/` returned nothing before this file.
The fact is in the specification (`spec/04 §5.2`, §5.3), in the code
(`enforce.py`'s `_effect_body`, at the line building
`payload = {"server": call.server, "tool": call.tool, "arguments": call.arguments}`;
`http.rs`'s route table, at the `"/v1/payloads/{payload_hash}"` entry), and in a findings table
(`docs/design-eval-findings.md`, the row beginning *"applied effects retain no arguments"*) — and in
no decision record.

**It has been misread three times in three weeks, twice in opposite directions:**

- Two adoption evaluators concluded that applied effects retain no arguments, only a hash, and filed
  it among the product's worst defects. **False for a call that ran.**
- An incident evaluation exported an applied-looking record, found only a digest, and concluded the
  same — and was **right for its case**: its destructive call was refused four times and never
  executed, and the persona reported all five snapshots present and `purged: []`
  (`docs/validation/persona-program.md`). They went looking for the arguments of a call that never
  happened and correctly found only the commitment.
- A triage agent, correcting the first error, over-corrected to *"the values never reach any
  record."* **False for executed calls**, which is the first error with the sign flipped.

Three readings, two directions, one fact. A findings table is not where a reader following the
decision record forward looks, which is exactly why the error keeps recurring. This ADR states the
boundary in one sentence each way so the fourth misreading has somewhere to be checked against.

## 2. The boundary, stated both ways

> **A call that ran** has its arguments in the effect envelope's evidence payload, served at
> `GET /v1/payloads/{payload-hash}` and retained for the policy's `evidence-ttl` — a year for
> `consequential`, ten for `prohibited`.

> **A request that only parked and was never answered** has its arguments erased when `not-after`
> passes (`spec/06 §4.4` rule 7): nothing was applied, so no effect envelope and no payload ever
> existed, and the only thing that survives the expiry is the commitment.

Neither sentence is a qualification of the other. They describe two disjoint populations, and the
whole of the confusion is that both are true.

## 3. What the code does

**The gateway attaches the payload to every effect body, unconditionally.** `_effect_body` builds
`payload = {"server": call.server, "tool": call.tool, "arguments": call.arguments}`, hashes it, writes
`evidence.payload-hash` into the envelope and returns the payload alongside the body for submission.
There is **no class check and no policy flag** in front of it. Every caller of `_effect_body` —
`_chain_effect` on the applied path, and the write-ahead intent record — gets the same payload, which
is why a `prohibited` action that was never forwarded still carries full evidence.

`_retain_until` is `emitted-at + policy["evidence-ttl"][class]`. In the shipped baseline profile
(`policy.rs`'s `baseline_conservative`, the `"evidence-ttl"` object) those are `P0D` for `read`,
`P30D` for `benign`, **`P365D` for `consequential`, `P3650D` for `prohibited`** — matching
`spec/04 §5.3`'s table, whose note explains the last one: *attempts are the most audit-valuable
records*.

**The kernel serves it, authenticated and inert.** `get_payload` refuses an unauthenticated caller
before touching the store, then returns the bytes as `application/octet-stream` with `nosniff` and a
`Content-Disposition: attachment` — deliberately **not** the emitter-declared media type, because this
origin also serves the console and a payload a browser renders is script running as the console. After
deletion the route answers `410` with `result: "decayed"` and the hash still present, per §04 §5.4.

**Deletion is reference-counted and changes no signed byte.** A payload survives while any referencing
envelope's `retain-until` is unexpired; the sweep runs on a schedule without anyone calling the
endpoint, and checkpoints every affected stream first (§04 §4.6).

**A park is on the other side of the line.** `POST /v1/gate/requests` writes one row to
`gate_requests`, a table `Store::append` never touches, and appends no envelope. A parked call
produces no effect envelope, so it produces no payload; its arguments live only in the queue row and
`erase_expired_gate_arguments` removes them once `not-after` has passed. Erasing them changes no
signed byte either — the request object, its `request-hash` and its `args-hash` all remain — which is
why it is not §04 §5 decay and owes no checkpoint.

## 4. Why it was invisible

Everything above was true before any of the three misreadings, and none of the three readers could
have found it from the surfaces they were using. **The only way to learn the route existed was to
read `enforce.py`.**

That is now partly repaired, and the state as verified on 2026-08-03 is:

- **The console names it.** `console/templates/audit.html` carries the sentence *"the values behind
  `args-hash` — for an executed effect, the arguments the call was made with — are held as the
  envelope's evidence payload and served at `/v1/payloads/<payload-hash>` until its retention
  ceiling"*, and the envelope page renders a preview of the payload itself, truncating with *"the
  whole payload is served by GET /v1/payloads/<hash>"*.
- **The export names it too — in both renderings.** `docs/spec-debt.md` recorded the export as *"a
  separate surface that was not checked here"*; it was checked for this ADR, and it does. The NDJSON
  export carries an `X-Stozher-Payload-Route: /v1/payloads/{payload-hash}` response header, chosen as
  a header and not a body line *because every line of the body is an envelope a verifier re-derives
  `id()` over, and a marker line would break the parser that promise is for*. The HTML rendering
  carries it twice: a `<dt>Argument values</dt>` fact row, and a paragraph saying the payload *"holds
  the call's arguments, and it is served — authenticated — at the route above with that row's payload
  hash."*

So the original complaint is closed on both surfaces. What remains open is that the *record* said
nothing, which is this file.

## 5. What was rejected

- **Putting the argument values in the export.** The export is the record of evidence — every line a
  canonical envelope a regulator re-derives `id()` over. Copying payload contents into it would put
  those bytes in a document with no retention ceiling of its own, defeating §04 §5.4 and GDPR Art. 17
  erasure by duplication. A test asserts the amount is *absent* from the export bytes, alongside the
  header that says where to get it.
- **Reflecting the emitter's declared media type on `GET /v1/payloads/{hash}`.** Ingest allowlists the
  type, but the console proxies browser GETs to this origin with the kernel credential attached, so a
  payload the browser renders is script running as the console. Served as an opaque attachment it
  cannot become a document — including payloads written before the allowlist existed.
- **Making the payload conditional on class or on a policy flag.** Considered and rejected implicitly
  by the code as it stands, and stated here so nobody "optimizes" it later: the `prohibited`
  attempt — the record that was never forwarded — is the one whose arguments matter most, and it is
  exactly the record a class check would strip.
- **Retaining a parked request's arguments past `not-after` so that the two cases would read alike.**
  Rejected in `spec/06 §4.4` rule 7 and not reopened: an expired request can no longer be answered, so
  values kept past that instant are readable only by someone who cannot act on them.

## 6. Residuals

- **The route's authentication is not bound by a test.** `get_payload` refuses an unauthenticated
  caller, and the export document tells a regulator the route is *"authenticated"* — but
  `no_ambient_approval.rs`'s `every_read_route_requires_a_credential_and_none_of_them_writes`
  enumerates its routes explicitly and `/v1/payloads/{hash}` is **not** in the list. Nothing in either
  suite fetches a payload without a credential. This is the highest-value gap this ADR found.
- **Nothing binds the gateway's side of the unconditional attachment.** No test asserts that
  `_effect_body` produces `{server, tool, arguments}`, or that the payload is submitted with the
  envelope. The nearest binding is `test_a_prohibited_action_is_never_forwarded_and_is_recorded_as_attempted`,
  which asserts only that an `evidence` member is present on a never-forwarded attempt. Every test
  that reads a payload's contents builds the payload by hand in the test fixture.
- **The `P365D` / `P3650D` numbers themselves are unasserted.** The tests bind the *mechanism* —
  a payload survives within its `retain-until` and is swept after it — against a `retain-until` the
  test chooses. Changing `baseline_conservative`'s `evidence-ttl` object would break nothing.
- **The audit page's sentence is unasserted.** No test asserts `audit.html` names the route; the
  equivalent sentence in the export *is* asserted. A template edit could silently reopen half of §4.
- **`_effect_body`'s docstring for `_retain_until` says `min(our preference, emitted-at + policy TTL)`
  and the code has no "our preference" term** — it is `emitted-at + policy TTL` outright. The stated
  property (an emitter cannot buy longer retention) holds; the formula is aspirational. Recorded, not
  fixed: this ADR changes no code.

## 7. What now fails if this stops being true

| Claim | Test |
|---|---|
| The export says where the argument values are, the route it advertises serves them, and the values are *not* in the export bytes | `kernel/stozher-kernel/tests/console_evidence_and_approver.rs::the_export_says_where_the_argument_values_are_without_putting_them_in_the_file` |
| A stored payload is served inert — octet-stream, nosniff, attachment — whatever media type was declared | `kernel/stozher-kernel/tests/payload_media_type.rs::a_stored_payload_is_served_inert` |
| Deleting a payload leaves the hash and the chain position intact | `kernel/stozher-kernel/tests/append_only_and_decay.rs::payload_decay_leaves_the_hash_and_the_chain_position_intact` |
| A payload survives while any referencing envelope still needs it | `kernel/stozher-kernel/tests/append_only_and_decay.rs::a_payload_survives_while_any_referencing_envelope_still_needs_it` |
| Retention is enforced on a schedule, not on demand, and a payload inside its window is left alone | `kernel/stozher-kernel/tests/decay_schedule.rs::the_kernel_decays_expired_payloads_without_anyone_calling_the_endpoint` · `kernel/stozher-kernel/tests/decay_schedule.rs::the_sweep_leaves_a_payload_that_is_still_within_its_retention` |
| An action that was never forwarded still carries evidence | `gateway/tests/test_enforcement.py::test_a_prohibited_action_is_never_forwarded_and_is_recorded_as_attempted` |
| The values served back under `args-hash` are the values the approver signed over | `gateway/tests/test_root_change_cli.py::test_two_roots_can_enrol_a_third_and_the_human_is_the_name_recorded` |
| A parked request's arguments are erased once it can no longer be answered, and the digest remains | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::the_arguments_go_when_the_request_can_no_longer_be_answered` |
| Parking appends no envelope, so a park can produce no payload | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::parking_a_request_appends_nothing_to_any_chain` |

**Claims above with no test behind them:**

| Claim | Status |
|---|---|
| `GET /v1/payloads/{hash}` requires a credential | **No test.** Not in `every_read_route_requires_a_credential_and_none_of_them_writes`'s route list; see §6. |
| `_effect_body` attaches `{server, tool, arguments}` to every effect body unconditionally | **No test.** Only the presence of an `evidence` member on an attempt is asserted; see §6. |
| The defaults are `P365D` / `P3650D` | **No test.** The mechanism is bound; the durations are not. |
| `console/templates/audit.html` names the route | **No test.** The export's equivalent sentence is bound; the console's is not. |

## Related

`spec/04-chain-and-checkpoints.md` §5.2, §5.3, §5.4 · `spec/06-gates.md` §4.4 rule 7 ·
`docs/design-eval-findings.md` (the row beginning *"applied effects retain no arguments"*) ·
`docs/validation/persona-program.md` (the incident that was right for its case) ·
`docs/adr/ADR-0029-the-approver-reads-the-arguments.md` (the other half: what an approver sees
*before* the call runs) · `docs/spec-debt.md` §3
