# ADR-0029 — The approver reads the arguments, and the member ADR-0011 asked for was never added

**Date:** 2026-08-03
**Status:** accepted
**Supersedes** ADR-0011 §2 and the non-adoption recorded in ADR-0019 §2 — as the *last word*, not as
history: both were correct decisions when made, and neither describes the product today.
**Arises from** `docs/spec-debt.md` §3, first bullet.

Per ADR-0013's rule, every claim below names the test that fails if it stops being true.

## 1. What the record says, and why following it forward now misleads

ADR-0011 §2 asked for an OPTIONAL `args-preview` member on the action request (`spec/06 §1.1`),
governed by one rule: *"the console MUST render `args-preview` **only** if
`object-hash(args-preview)` equals `args-hash`."* ADR-0019 §2 then recorded its deliberate
non-adoption — a closed, all-REQUIRED member set makes an optional member a versioned wire change —
and said, correctly, that *"recording the non-adoption matters as much as the adoptions."*

Both records still stand, and a reader who follows them forward concludes that an approver sees only
a digest and must obtain the preimage out of band. **That has not been true since `spec/06 §4.4`
shipped.** The obligation ADR-0011 §2 filed was discharged, by a different and better mechanism, and
nobody wrote it down. This is that tombstone.

The failure mode is precisely the one ADR-0019 opened by naming — *"a rule that exists only for
people who have read the ADRs"* — with the sign flipped: a **repair** that exists only for people who
have read `spec/`. The specification moved and the decision record did not follow, so the two now
disagree about the single workflow the product exists for.

## 2. What §06 §4.4 does instead

§4.4 — *"The arguments an approver reads"* — opens by stating the problem in ADR-0011's own terms
(*"an approver is therefore asked to sign over a call they cannot read"*, and *"the component that
holds the preimage is often a process that has already exited by the time a human looks"*) and solves
it **without extending §1.1 by a member**.

**The body of `POST /v1/gate/requests` is a submission, not a request** (rule 1):

```json
{ "request": { …the action-request object (§1.1)… }, "arguments": { …the argument values… } }
```

Its member set is closed and an unknown member is refused (`schema-unknown-member`). It carries no
`v` and no `kind`, exactly as `authorization` (§1.3) — the same shape, a container for objects that
carry their own — does not. **`request-hash` stays `object-hash(submission.request)`, never of the
submission.** A body that is *itself* an action-request object is still accepted and is exactly a
submission with `arguments` absent, so an upgrade in which the kernel moves before its components
cannot empty the queue.

That is the whole of it: §1.1's closed 14-member set is untouched, every existing request object and
every vector is still valid against the schema it was written for, and the values travel *beside* the
hashed object rather than inside it.

## 3. Why the member ADR-0011 asked for was the wrong shape

Not merely expensive — wrong. §4.4 rule 6 says why, and it is the part ADR-0011 could not have
written from where it stood:

> `arguments` is **not** part of the action request. It is absent from §1.1's member set, it is not
> covered by `request-hash`, and an implementation MUST NOT copy it into `authorization.request`, an
> envelope, or evidence. What a signature binds is `args-hash`; the values are how the signer came to
> know what that digest meant.

An `args-preview` member *inside* §1.1 would have been covered by `request-hash` and would therefore
have travelled into `authorization.request` and into every envelope citing that approval — putting
emitter-supplied bytes inside a signed object, with the envelope's retention rather than the
request's, and with no way to erase them later. §4.4's separation is what makes rule 7's erasure
possible at all: the values can be deleted precisely because no signature ever covered them.

`spec/06 §1.1` was amended to say this in one sentence — *"the request does not carry them and MUST
NOT be extended to. The values travel beside it in the submission of §4.4… and they expire with the
request rather than with the envelope that cites it."*

## 4. Rule 4 is ADR-0011 §2's own rule, relocated — and changed in one way worth stating

§4.4 rule 4: where `arguments` is present the kernel MUST verify
`object-hash(arguments) == request["args-hash"]` and MUST reject the submission otherwise
(`gate-arguments-hash-mismatch`). *"Without this rule nothing stops a component showing a human one
call and executing another, and the display would be worth less than the blank it replaced."* That is
ADR-0011 §2's predicate verbatim in intent.

It moved twice over, though, and the second move dropped something:

- **From render-time to admission-time.** ADR-0011 put the check in the console at the moment of
  display. §4.4 puts it at the door: a mismatching submission is refused before anything is recorded,
  so the queue never holds a list that contradicts its own commitment. This is strictly better — a
  console is one interface among several, and a rule enforced only at rendering is a rule the
  `/v1/gate/requests/{hash}` route does not have.
- **The surfacing half was not carried over.** ADR-0011 §2 required the console to *"show that the
  preview contradicts the commitment — which is itself a finding worth surfacing, not an error to
  swallow."* Under §4.4 a mismatch produces a `422` to the submitting component and **nothing else**:
  no queue row, no rejection record, no console surface, not even a log line
  (`post_gate_request`, the `check_arguments` arm returning `refusal(StatusCode::UNPROCESSABLE_ENTITY, …)`).
  A component that lied about its own arguments tells only itself. Recorded as a residual below
  rather than fixed here.

## 5. Four obligations §4.4 added that ADR-0011 did not think to ask for

1. **A bound.** The canonical form of `arguments` MUST NOT exceed 16384 bytes
   (`gate-arguments-too-large`), and a component whose values exceed it MUST park **without** them
   rather than not park — *"losing the display costs an approver context, losing the request costs
   them the gate."* ADR-0011's preview member had no size discipline at all; an unbounded optional
   member on a queue a human reads is the flood §09 §7 exists to bound.
2. **The approver's own recomputation path** (rule 5). An interface showing the arguments MUST show
   them in **canonical form** and state how, so the chain from what the human reads to what §06 §2
   step (10) enforces is recomputable with a JSON canonicalizer and SHA-256. ADR-0011 asked the
   console to check on the approver's behalf; §4.4 asks it to let the approver check for themselves.
   *"The verifier that matters is the one at the point of use, and here that is the human."*
3. **Erasure at `not-after`** (rule 7). Once the request's `not-after` has passed the kernel MUST NOT
   serve the arguments and MUST erase them: an expired request can no longer be answered (§06 §2 step
   8), so values kept past that instant are readable only by someone who cannot act on them. Erasing
   them changes no signed byte, so this is not §04 §5 decay, requires no checkpoint, and interacts
   with neither.
4. **Never supplied ≠ supplied and empty** (rule 8). An interface MUST distinguish the two and MUST
   NOT render the first as the second — *"the component did not tell us"* and *"the call took no
   arguments"* are different facts about what is being approved, exactly as §4.3 rule 6 separates a
   notification nobody attempted from one that failed.

Rules 2 and 7 add two more the ADR did not reach: `arguments` is **obligatory of a component that can
supply it** and a component that never held the preimage MUST omit the member rather than send a
stand-in (*"a plausible-looking argument list nobody executed is worse than none"*); and the recorded
arguments are those of the **first accepted submission**, which a later submission of the same
`request-hash` MUST NOT replace, extend or remove.

## 6. It reaches the vector corpus, which most of ADR-0019's catch-up did not

`spec/vectors/gate-arguments.json` is 11 vectors of kind `gate-arguments`, role `primitive`, listed
in `spec/vectors/index.json`, exercising rules 3 and 4 — including `null` as a value rather than an
absence, an empty object as a value, and a multibyte case whose `canonical-bytes` is given *"so a
harness measuring characters fails visibly"*. Both implementations run it: the kernel through
`gatequeue::check_arguments`, the gateway through its own `check_arguments`, because a component
decides whether to submit the values before the kernel ever sees them and the corpus is what keeps the
two predicates identical.

This is the part that separates §4.4 from most of what ADR-0019 folded in. Of that catch-up's
adopted items, only §03 §6's root-set rule also acquired a vector file (`root-change.json`); the rest
are prose obligations checked, where they are checked, by one implementation's own suite. A rule with
a vector file is a rule a second implementation cannot quietly disagree with.

## 7. What was rejected

- **Amending `spec/06 §1.1` as ADR-0011 §2 asked.** Rejected on the substance, not only the cost: see
  §3. The member would have been covered by `request-hash` and inherited the envelope's retention.
- **Leaving ADR-0011 §2 and ADR-0019 §2 to stand and recording the correction only in
  `docs/spec-debt.md`.** That is where it was recorded, and it is why this ADR exists: a debt table
  is not where a reader following the decision record forward looks. The same reasoning ADR-0019 §2
  gave for recording a non-adoption applies to recording a discharge.
- **Editing ADR-0011 or ADR-0019 in place.** An ADR is a record of what was decided when, and
  rewriting one to agree with the present destroys the only evidence of how the wording came to be.
  They are superseded by this file, not amended.
- **Closing `docs/spec-debt.md` rows 6 and 7 as part of this.** Row 6 (§09 §7 cites the console design
  doc where §06 §4.4 is the normative answer) and row 7 (ADR-0011 §1's amendment to
  `docs/design/console.md`, the line still promising an *"evidence preview"*, was never applied) are
  real and are owned elsewhere. This ADR does not
  touch `spec/` or that design doc. Note only that row 7's amendment is now **obsolete as written**:
  the queue genuinely can show the arguments, so the line wants rewording toward §4.4 rather than
  toward ADR-0011's 2026-07-27 text.

## 8. Residuals

- **A lying component tells only itself.** §4 above: `gate-arguments-hash-mismatch` is a `422` and
  nothing more. The one adversary ADR-0011 §2 designed the rule against — an emitter that displays
  one call and executes another — is refused, correctly, and leaves no trace any human will ever see.
  Whether that should be a rejection record is a live question this ADR does not answer.
- **Rule 6's prohibition is unbound by a test.** Nothing asserts that `arguments` is absent from
  `authorization.request`, from an envelope, or from evidence. It holds today for a structural
  reason — a parked call emits no envelope at all, and `_effect_body` builds `authorization` from the
  request and decision objects — but structure is not a test. The nearest binding is
  `test_a_park_hands_the_notifier_the_request_and_none_of_the_arguments`, which covers the notifier
  and not the envelope.
- **Rule 5's "and state how" is bound only in part.** The test asserts the canonical bytes and the
  full `args-hash` are on the page; nothing asserts the page states the recipe. A console that kept
  the bytes and dropped the sentence would stay green.
- **ADR-0019's own count is off by one, and this ADR inherits the phrasing.** Its §1 table enumerates
  fifteen rules; its prose says *"Sixteen of them are folded in here"* and §2a's arithmetic (nine plus
  seven) agrees with the prose. Not resolved here — recorded so the next reader does not take either
  number as verified.

## 9. What now fails if this stops being true

| Claim | Test |
|---|---|
| The submission wrapper is accepted and the values reach the approver in canonical form, with the full digest they can recompute | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::an_approver_can_read_the_arguments_and_recompute_the_digest_their_signature_binds` |
| A bare action-request object is still accepted, and both spellings hash to the same `request-hash` | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::a_later_submission_cannot_add_arguments_an_approver_never_saw` (parks bare, resubmits as a submission, gets `idempotent: true`) |
| Rule 4 — arguments that are not what the request commits to are refused before anything is recorded | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::arguments_that_are_not_what_the_request_commits_to_never_reach_an_approver` |
| Rule 3 — over the cap costs the display and never the park | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::arguments_over_the_cap_are_refused_rather_than_stored` · `gateway/tests/test_enforcement.py::test_arguments_too_large_to_show_cost_the_display_and_never_the_park` |
| Rule 7 — the values go when the request can no longer be answered, and the digest stays | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::the_arguments_go_when_the_request_can_no_longer_be_answered` |
| Rule 7 — a later submission cannot add arguments an approver never saw | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::a_later_submission_cannot_add_arguments_an_approver_never_saw` |
| Rule 8 — a call that took no arguments is not rendered as one nobody described | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::a_call_that_took_no_arguments_is_not_rendered_as_one_nobody_described` |
| Rule 1 — the submission's member set is closed | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::a_submission_carrying_a_member_nothing_reads_is_refused` |
| The route still appends no envelope, so `arguments` cannot reach a chain through it | `kernel/stozher-kernel/tests/gate_queue_and_console_decisions.rs::parking_a_request_appends_nothing_to_any_chain` |
| Rule 2 — a component that holds the preimage submits it | `gateway/tests/test_enforcement.py::test_the_parked_request_carries_the_arguments_a_human_has_to_read` |
| Rule 4 held on the component side too, so a mismatch is never submitted | `gateway/tests/test_enforcement.py::test_the_component_never_submits_arguments_the_request_does_not_commit_to` |
| Both implementations agree on rules 3 and 4, vector for vector | `kernel/stozher-kernel/tests/kernel_vectors.rs::every_gate_arguments_vector_matches_this_implementation` · `gateway/tests/test_vectors.py::test_vector_file[gate-arguments.json]` |

**Claims above with no test behind them**, stated rather than papered over:

| Claim | Status |
|---|---|
| Rule 6 — `arguments` is never copied into `authorization.request`, an envelope, or evidence | **No test.** Holds structurally; see §8. |
| Rule 5 — the interface *states how* to repeat the check | **Partly.** The canonical bytes and full digest are asserted; the recipe sentence is not. |
| A `gate-arguments-hash-mismatch` is surfaced to anyone but the submitter | **False, and not a test gap** — nothing does this. §8, first bullet. |

## Related

`spec/06-gates.md §1.1`, §4.3, §4.4 · `spec/vectors/gate-arguments.json` ·
`docs/adr/ADR-0011-approver-legibility-and-the-args-commitment.md` §2 (superseded) ·
`docs/adr/ADR-0019-spec-catch-up.md` §2 (superseded) ·
`docs/adr/ADR-0010-s5-packaging-and-rate-limit-home.md` §1 (closed member sets are expensive to open —
still true; §4.4 is what you do instead) · `docs/spec-debt.md` §3 ·
`docs/adr/ADR-0030-where-the-arguments-of-a-call-that-ran-are-kept.md` (the other half: what happens to
the arguments of a call that *did* run)
