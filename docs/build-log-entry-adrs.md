## Two owed decision records, and a citation convention

`docs/spec-debt.md` §3 listed two findings that were *"ADRs owing a record, not `spec/` owing text"*
and said the run that found them would not write them. This run writes them, and turns the failure
mode that produced both into a rule.

**ADR-0029 — The approver reads the arguments, and the member ADR-0011 asked for was never added.**
ADR-0011 §2 asked for an OPTIONAL `args-preview` member on `spec/06 §1.1`; ADR-0019 §2 recorded its
deliberate non-adoption. Both still stood as the last word, and a reader following them forward
concluded that an approver sees only a digest — untrue since `spec/06 §4.4` shipped. §4.4 discharged
the obligation by making the body of `POST /v1/gate/requests` a **submission**
(`{ "request": {…§1.1 object…}, "arguments": {…} }`) with `request-hash` still
`object-hash(submission.request)`, so §1.1's closed member set was never opened. The ADR records why
that shape is not merely cheaper but *right*: a member inside §1.1 would have been covered by
`request-hash`, would have travelled into `authorization.request` and every citing envelope, and
could never have been erased — which is exactly what rule 7's erasure at `not-after` requires. It
also records the four obligations §4.4 added that ADR-0011 did not reach (the 16 KiB bound, the
approver's own recomputation path, erasure at `not-after`, and *never supplied* ≠ *supplied and
empty*), and that this is one of the few catch-up-era rules to reach the vector corpus
(`spec/vectors/gate-arguments.json`, 11 vectors, run by both implementations).

One correction to the received account, found by reading the code: rule 4's
`gate-arguments-hash-mismatch` is ADR-0011 §2's predicate relocated **and narrowed**. ADR-0011 put
the check at render time and required the console to *show* that the preview contradicted the
commitment — *"itself a finding worth surfacing, not an error to swallow."* §4.4 puts it at the door,
which is stronger, but a mismatch now produces a `422` to the submitting component and nothing else:
no queue row, no rejection record, no console surface, no log line. The component that lied about its
own arguments tells only itself. Recorded as a residual.

**ADR-0030 — Where the arguments of a call that ran are kept.** A fact in the specification, in the
code, and in a findings table, and in no decision record — misread three times in three weeks, twice
in opposite directions. The ADR states the boundary in one sentence each way: a call that **ran** has
its arguments in the effect envelope's evidence payload for the policy's `evidence-ttl`; a request
that only **parked and was never answered** has them erased at `not-after`, with no envelope and no
payload ever created. It records why the fact was invisible — and closes the open half of that
question. `docs/spec-debt.md` had left *"whether the regulator export mentions it"* explicitly
unchecked; **it does**, on both renderings: an `X-Stozher-Payload-Route` response header on the
NDJSON (a header and not a body line, so the per-line `id()` promise survives) and two mentions in
the HTML document.

Both ADRs carry a claim→test table, and both carry a second table naming the claims that have **no
test**. That second table is the point of the exercise. Between them it surfaced four unbound claims,
one of which is worth acting on: **`GET /v1/payloads/{payload-hash}` requires a credential, and no
test says so.** `no_ambient_approval.rs`'s `every_read_route_requires_a_credential_and_none_of_them_writes`
enumerates its routes explicitly and the payload route is not among them, while the export document
tells a regulator in prose that the route is *"authenticated."* The guard is in the code; nothing
would notice if it left.

**The convention: `docs/CONTRIBUTING.md` (new file — no `docs/README.md` exists to extend).** Code
citations in volatile documents anchor by **function name plus a line-content fragment, never by a
line number alone**. Grounded in three observations rather than asserted as taste: every line number
in `docs/design-eval-findings.md`'s table had rotted within a week, two of them coming to point at
unrelated code and a row's *"Real"* verdict having been closed in the meantime;
`docs/validation/persona-program.md` cites that table without a line number *on purpose*, because the
row moved while the document was being written; and the triage run measured the half-life at four
minutes. The rule binds hardest on ADRs, findings tables, and claim→test tables — where the test's
full name is the citation and no line number is wanted at all — and explicitly does not apply to
`spec/` section numbers or frozen artefacts. Both new ADRs are written to it.

No code and no `spec/` was touched. `181 passed, 7 deselected` (gateway) and `349 passed, 2 ignored`
(kernel), unchanged. One flake observed and run down rather than reported as a failure: the kernel
`concurrency` suite failed twice under parallel load with `x-store-unavailable: database is locked`,
on a *different* test each time, and passed 18/18 with `--test-threads=1`. Load-sensitive, not a
regression.
