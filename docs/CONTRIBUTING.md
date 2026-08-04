# Contributing to the documents in `docs/`

Conventions for the prose side of this repository — ADRs, design notes, findings tables, defect
registers, validation reports. Code and `spec/` have their own rules and their own owners.

---

## Cite code by function name plus a line-content fragment, never by a line number alone

**The rule.** Every citation from a `docs/` file into a source file names the **symbol** — function,
method, test, constant, template block — and, where the symbol is large enough that the reader still
has to hunt, a short **fragment of the line itself**. A line number may accompany that. It may never
stand alone.

| Instead of | Write |
|---|---|
| `enforce.py:1224` | `enforce.py`'s `_effect_body`, at the line building `payload = {"server": …, "tool": …, "arguments": …}` |
| `http.rs:69` | `http.rs`'s route table, at the `"/v1/payloads/{payload_hash}"` entry |
| `gate_queue_and_console_decisions.rs:1147-1286` | the named tests, one per claim: `::an_approver_can_read_the_arguments_and_recompute_the_digest_their_signature_binds`, `::a_call_that_took_no_arguments_is_not_rendered_as_one_nobody_described`, … |
| `docs/design-eval-findings.md:56` | `docs/design-eval-findings.md`, the row beginning *"applied effects retain no arguments"* |

The same applies to citations from one `docs/` file into another: name the section or quote the
opening words of the row, not its position in the file.

**Why, from what happened rather than from taste.** Three separate observations, all in the same
fortnight:

1. **`docs/design-eval-findings.md` rotted whole.** Every line number in its findings table had gone
   stale within a week of being written. Two of them — `enforce.py:571` and `:1041` — came to point
   at *unrelated code*, which is worse than pointing at nothing: a reader who follows them lands
   somewhere plausible and draws a conclusion from the wrong function. A third row's verdict, the
   only one marked **Real**, had been closed in the meantime and the table still read as open. The
   file now carries its own note about this and cites by function.

2. **A citation went stale while the document citing it was being written.**
   `docs/validation/persona-program.md` cites the findings-table row *"cited without a line number on
   purpose: that row moved while this document was being written, and its own pointer into
   `enforce.py` had already drifted once."*

3. **The triage run measured the half-life at four minutes.** A citation written by line number was
   invalidated four minutes later by an edit to the file it pointed into. (Reported in the triage
   run's own record; the commit log's granularity is coarser than that, so the figure is not
   re-derivable from git — the two observations above are.)

**What makes this more than a style preference.** These documents exist so that a fact does not have
to be re-derived. A citation whose pointer no longer resolves fails at exactly that: the next reader
re-derives the fact, gets it slightly wrong, and files it as a finding — which is how *"applied
effects retain no arguments"* was concluded twice, in opposite directions, from surfaces that were
each individually true (see `docs/adr/ADR-0030-where-the-arguments-of-a-call-that-ran-are-kept.md`).
A rotted citation is not a cosmetic defect in a document; it is the document's failure mode.

A symbol name also survives the edits a line number does not: reformatting, an import added above, a
neighbouring function growing. When a symbol genuinely is renamed or deleted, a stale citation fails
**loudly** — `grep` returns nothing — instead of silently resolving to different code.

**Where the rule binds hardest:** ADRs (a decision record outlives every line number in it), findings
and defect tables (read months later by someone deciding whether an item is still open), and any
claim→test table, where the test's **full name** is the citation and no line number is wanted at all.

**Where it does not apply.** A citation into `spec/` uses its section numbers (`spec/06 §4.4`) —
those are stable identifiers, not positions. A citation into a frozen artefact — a vector file, a
tagged release, a specific commit named as such — may use whatever locator that artefact guarantees.

**One correction to the sentence above, from 2026-08-04.** *"A stale citation fails loudly — `grep`
returns nothing"* is true only of someone who runs the grep. Two ADRs were found citing a test in
`concurrency.rs` called `one_approval_cannot_be_consumed_twice_however_the_requests_race` — a name no
test has carried for some time; the property was bound throughout by `s6_one_approval_cannot_be_spent_twice`,
and the rot sat in the record unnoticed. It now fails loudly for real:
`gateway/tests/test_doc_citations.py::test_every_test_an_adr_cites_still_exists` resolves every
`file::test_name` citation in `docs/` against the tree, so a rename that leaves a decision record
behind fails the suite rather than waiting for a reader.

---

## Verify a ledger against the artifact, never against the report of work done on it

**The rule.** Any file that tracks outstanding work — `docs/spec-debt.md`, `docs/open-defects.md`, an
ADR's residuals or claim→test table — is reconciled **against the current code and text** at the end
of every run that pays into it. Not against the run's own summary of what it did, and not only when
somebody comes looking for an item.

**Why, from what happened.** Three instances inside three days, and none of them was a careless
entry — every one was true when written:

1. **`docs/spec-debt.md` carried five false claims at once.** A vector recorded as owed had been
   written; two rows shown as outstanding had been paid; both *"an ADR is owed, and this run does not
   write it"* bullets had been discharged the day before by ADR-0029 and ADR-0030.
2. **ADR-0032 §5 overstated its own gap** on the day it was written, claiming nothing surfaced a
   record that `/console/rejections` had been listing all along. The error pointed the other way and
   cost the same.
3. **ADR-0030 §6's first residual — *"the highest-value gap this ADR found"* — was already closed**
   when the file was committed, and stayed listed as open for days afterwards.

**The structural cause, which is why this needs a rule rather than more care.** The artifact and the
record of the artifact are changed by **different acts**, and only the first one has a test. Nothing
in any suite fails when a residuals table goes stale. The party that pays a debt is reliably not the
party that strikes it off, because striking it off is a separate piece of work that nothing forces.

**What this costs when skipped.** `docs/spec-debt.md` row 2 already stated it: *"an inventory that
lists paid debt sends a reviewer hunting for a gap that is not there, which costs the same as missing
one."* The version that flatters — a gap reported as larger than it is — costs the same again, and is
harder to notice because nobody double-checks bad news about their own work.

**Mechanically enforced half.** Citations are checked (see above). A table saying *"No test"* about a
claim that has since been bound is **not** mechanically detectable — nothing distinguishes an honest
gap from a stale one — so that half stays a reading duty, discharged at the end of the run rather
than deferred to the next reader.
