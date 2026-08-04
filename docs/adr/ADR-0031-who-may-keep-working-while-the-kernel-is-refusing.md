# ADR-0031 — Who may keep working while the kernel is refusing

**Status:** accepted, 2026-08-03. Implemented in `spec/05 §7.1` and bound by `sync-outcome.json`.
**Supersedes nothing. Corrects nothing.** This records a decision that was made and shipped without
a record, which is the only reason it is being written after the fact rather than before.

## 1. The decision

When a component's submissions are being refused, the reason decides whether a grace window exists
at all, and the class decides who may use it when it does.

- The refusal reason is in the `mandate-*` family, or is `policy-not-published` → **no grace for any
  class.** Every class is refused immediately, `read` and `benign` included, and the component does
  not serve again until a submission is accepted.
- Any other reason → `consequential` and `prohibited` are refused **immediately, with no grace**;
  `read` and `benign` MAY be served until `policy.wedge-grace` (default `PT5M`) has elapsed since the
  **first** refusal, and every effect served in that window is recorded as a finding.
- Grace expiry blocks every class, and an elapsed window is not restarted by a later refusal.

## 2. Why it is written down at all

Because it was a **choice between two coherent proposals**, and the reasoning existed only in a chat
transcript and in the resulting normative text. `spec/05 §7.1` states the rule; nothing stated why
that rule rather than either of the two it was assembled from. A reader of the specification could
implement it correctly and still not know which parts are load-bearing, which is the difference
between a rule you can maintain and a rule you can only obey.

This is the fourth time in three weeks a decision was reachable only through the code or the
specification and not through the decision record. ADR-0029 and ADR-0030 are the other two written on
the same day, for the same reason.

## 3. The two proposals it was assembled from

**By reason** (`docs/proposals/DEF-2-mandate-continuity.md`, the triage run's analysis). A
`mandate-*` reason or `policy-not-published` refuses everything at once, because *authority the
organization cannot resolve is not authority* (ADR-0001) and a `read` without authority is still an
effect. Every other reason gets a bounded window for all classes.

**By class** (the fix run's brief). `read`/`benign` may continue during a bounded window with each
effect flagged; `consequential`/`prohibited` block immediately, because *grace over `consequential`
is exactly the window an auditor asks "what else was still permitted"*.

They cut on different axes and disagreed about one concrete case: a `read` under
`mandate-unresolved`. By-reason refuses it; by-class serves it for up to five minutes.

## 4. Why the intersection, and not either one

**Neither axis is redundant, because they answer different questions.** The reason says whether the
organization still knows who is asking. The class says how much it costs to be wrong. A rule that
used only one of them is wrong in a case the other one catches:

- **By class alone** serves reads under a mandate nobody can resolve. That was the observed incident
  — a gateway served a week of calls under `mandate-unresolved` — and the window would have been
  bounded, but the principle would not: for five minutes the product would do exactly the thing it
  exists to prevent, and say so in a finding nobody reads until later.
- **By reason alone** grants a grace window to `consequential` actions whenever the reason is
  something other than a mandate problem. A malformed envelope on an unrelated stream would buy five
  minutes in which money can move with the record provably not reaching the kernel. That is the
  window an auditor asks about, and there is no good answer to it.

Taking both is not a compromise between them; it is the observation that each rules out a case the
other permits, and neither case is acceptable.

## 5. What was rejected

**Stop on any refusal, immediately, for every class.** The clean answer, and it is a denial-of-service
weapon: one malformed envelope halts a fleet, and anyone able to make a component emit one can do it.
The bounded window exists so that a transient or local fault does not become an outage faster than a
human can read the reason. *(DEF-6 is what happens when this line is drawn one layer too low: an
`x-store-unavailable` was read as a refusal and a single transient error wedged a stream
permanently. The fix was to narrow what counts as a refusal, not to widen the grace.)*

**Unbounded grace, with findings.** Serve indefinitely and record loudly. Rejected because a finding
nobody has to acknowledge is not accountability, and because the whole product claim is that effects
reach an append-only record — a component that serves for a week while provably not reaching it has
falsified that claim regardless of how loudly it says so.

**Operator-configurable per class.** A knob for which classes may use grace. Rejected: the two
classes that must never have it are the two an operator under pressure would most want to grant it
to, and a configuration key that can turn `consequential` back on is a gate you disable by editing a
file. `wedge-grace` bounds the window and cannot widen who may use it.

**Grace measured from the most recent refusal.** Rejected because it never expires: a component
refused every thirty seconds would hold a five-minute window open forever. It runs from the *first*
refusal, and `spec/05 §7.1` says so.

## 6. Residuals

- **The window is a real, bounded hole**, and it is stated as one rather than defended: for up to
  `PT5M` after a non-mandate refusal, `read` and `benign` effects are served and their records
  provably do not reach the kernel. `docs/spec-debt.md`'s DEF-2 row carries it to external review
  under exactly that description.
- **`wedge-grace` is the first OPTIONAL member of `spec/05 §1`'s closed set.** Whether that door
  should have been opened is a wire-contract judgement, also in `spec-debt`.
- **`PT5M` is a default nobody has measured.** It is short enough that an operator reading a page
  notices before it expires and long enough that a restart does not trip it, which is an argument
  from plausibility, not from data.

## 7. What now fails if this stops being true

| Claim | Test |
|---|---|
| A `mandate-*` reason refuses `read` immediately | `spec/vectors/sync-outcome.json`, the mandate-family cases, run by both implementations |
| `consequential` never gets a grace window | `sync-outcome.json`, the consequential cases |
| `read` under a non-mandate reason serves inside the window and is a finding | `sync-outcome.json`, the grace cases; `finding` asserted alongside `action` |
| The window runs from the first refusal and expiry blocks everything | `sync-outcome.json`, the boundary case at exactly `PT5M` and past it |
| An unreachable kernel is not a refusal, so none of this fires | `sync-outcome.json::unreachable-read-under-offline-allow-serves`, and `test_a_kernel_that_could_not_answer_does_not_wedge_the_stream` (DEF-6) |

The last row is the one that keeps the rest honest: without it, "refuse everything" passes every
other case in the file.

## Related

`spec/05 §7.1` (the rule) · `spec/05 §7.2` and `spec/04 §7.2` (the exit, ADR-owed separately) ·
`docs/proposals/DEF-2-mandate-continuity.md` (the by-reason proposal) · `docs/open-defects.md` DEF-2
and DEF-6 · ADR-0001 (authority that cannot be resolved is not authority).
