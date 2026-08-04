# ADR-0032 — A component that lies about its own arguments, and who gets to know

**Date:** 2026-08-04
**Status:** accepted
**Arises from** `docs/spec-debt.md` row 8 — the last open row, and the only one that was a judgement
rather than a gap.
**Amends** `spec/06 §4.4` (new rule 9), `spec/04 §7.1` (a third record kind), `spec/09 §7` (the cap
bounds a second thing).

Per ADR-0013's rule, every claim below names the test that fails if it stops being true.

## 1. What was true, and the reason that turned out to be wrong

`spec/06 §4.4` rule 4 checks a submission's argument values against the `args-hash` the approver's
signature will cover. That is the stronger half of ADR-0011 §2 and it shipped. The half that did not
was the ADR's own sentence — the mismatch is *"itself a finding worth surfacing, not an error to
swallow"*. What actually happened was a `422` to the submitter, and from 2026-08-03 a `tracing::warn!`
which is not in the chain, not in the export, and not bound by a test.

The comment in `http.rs` gave a reason:

> A rejection record would be the stronger answer and is not available here: §04 §7's records are
> about *envelopes*, and a gate submission is not one.

**That was wrong about the section it cited.** `spec/04 §7.1` opens by saying the opposite:

> The rejection stream is the kernel's stream of durable records that are **not** envelopes. §02 §2's
> `kind` vocabulary is closed at nine and holds no member for one, so anything the kernel must record
> durably and cannot express as an envelope belongs here … An ingest rejection is the first such
> record; **it is not the only one.**

And by then it demonstrably was not the only one: the ADR-0023 clock declaration is a second, written
through the same `Store::record_rejection`. The premise that made row 8 look like a hard problem was
a misreading of a paragraph that had already answered it. The row stood for a day longer than it
needed to because the reason not to act was never re-checked against the text it named.

## 2. The decision

**A rule 4 mismatch is recorded in the rejection stream, and bounded.** `spec/06 §4.4` gains rule 9.
The record carries the authenticated caller, the request's `subject` and `action`, the
`request-hash`, and the reason code.

The event deserves it on the same grounds the product is sold on: `docs/design/console.md` puts the
attempted-`prohibited` view front and centre because *"attempts are the most valuable records in the
system"*. "A component submitted values its own signature does not cover" is an attempt. It is also
the one class of event where the component is the adversary rather than the victim, which makes the
component's own report of it worth nothing.

**Bound:** `gate_admission_vectors.rs::every_gate_admission_vector_decides_as_the_corpus_says`, over
`spec/vectors/gate-admission.json` (11 vectors).

## 3. Two boundaries, and why each is where it is

### 3.1 Rule 4 only — a size refusal is not a lie

`gate-arguments-too-large` (rule 3) earns **no** record. A component over the 16384-byte cap was
honest and verbose, rule 3 already tells it what to do instead, and it made no claim that turned out
to be false. Recording every §4.4 refusal would fill a hash-chained store with the events that do not
matter and make the one that does harder to find — the same reasoning §09 §7 uses about the approval
queue, applied one surface over.

*Fails if untrue:* the `too-large-is-refused-and-not-recorded` vector. Mutation-tested — widening the
match arm to catch every §4.4 refusal fails that vector by name, and nothing else.

### 3.2 The bound counts records, not parked requests

An unbounded write into an append-only chained store, reachable by anything a caller can send at
will, is a denial-of-service surface with an audit trail attached. So §09 §7's per-subject cap
applies to this path too.

**The obvious way to count does not bind at all.** `gate_requests_since` counts a subject's *parked*
requests, and a refused submission parks nothing — so a component that only ever lies sits at zero
parked forever and would be limited by nothing. The counter is therefore the caller's own recorded
mismatches in the window (`Store::argument_mismatches_since`), which is the quantity actually being
bounded.

This was not caught by reasoning about it. It was caught by asking what number the check would read
for the exact caller the check exists to stop.

*Fails if untrue:* `a-mismatch-at-the-cap-is-rate-limited-and-not-recorded` and its counterfactual
`parked-rows-at-the-cap-do-not-suppress-the-record` — the second exists so that an implementation
wiring the *wrong* counter fails rather than passing on a coincidence. Mutation-tested: substituting
`gate_requests_since` fails the first by name.

### 3.3 Idempotency does not launder the lie

§4.3 rule 1's idempotency skip protects a component retrying after a lost response, which is correct
behaviour. A retry carrying a *mismatch* is not that, and MUST NOT be silenced by the request already
being on the queue.

*Fails if untrue:* `a-mismatch-on-an-already-queued-request-is-still-recorded`.

### 3.4 A store that cannot take the record does not get a verdict

The record is a MUST, so a store that refuses it means the kernel could not complete the admission —
not that it decided against the submission. The route answers `503 x-store-unavailable`, not `422`.
Answering `422` would be DEF-6's mistake a second time: reporting a moment the kernel could not
answer as a verdict about the bytes.

*No test.* Stated here rather than left to look bound: injecting a store failure at that one line is
not something the current harness can do without a fault-injection seam it does not have.

## 4. Alternatives rejected

- **Leave it unrecorded and say so in `spec/`** (close row 8 as a decision). Defensible, and it was
  on the table until §04 §7.1 was actually read. Rejected because the only argument for it was the
  wrong one, and what remained — "a gate submission is not an envelope" — is the *premise* of §7.1
  rather than an objection to it.
- **Dedupe by `request-hash` and skip the ordering change.** Smaller, and it bounds a component
  retrying one lie. It does nothing about a component varying the request each time, which is the
  cheaper attack and the one an adversary picks.
- **Record every §4.4 refusal.** Symmetrical and wrong; see §3.1.
- **Count parked rows.** The bound as it first reads, and it does not bind; see §3.2.

## 5. What this does not settle

The record exists, is chained, is signed, and appears in `/v1/rejections`. **Nothing surfaces it to a
human on its own.** The console has no view that says "these components submitted arguments they had
not committed to this week", and the §09 §7 spike surface covers the approval queue, not this. An
auditor who knows to look will find it; one who does not, will not. That is a smaller gap than the
one this closes and it is not closed here.

The wire contract also changed shape for one caller: a subject at the mismatch cap now receives `429
gate-rate-limited` where it previously received `422 gate-arguments-hash-mismatch`. That is visible
to any component that branches on the code, and it is in the vectors so that both implementations
change together.
