# Spec debt — what the decision records still owe `spec/`

An ADR that says *"`spec/06 §5` should gain a clause"* and is then filed is a rule that exists only
for people who have read the ADRs. This is the inventory of every such sentence in **ADR-0006
through ADR-0011** that `spec/` still does not say.

**This is an inventory of debt, not a payment.** No file under `spec/` was edited to produce it.

**Method.** Every row was checked against the current `spec/` text at `cf64bf7`, not against the
ADR's own account of itself. Where an ADR asked for text and the text is now present, the row is not
in the table — it is in §2 below, so a reader can tell "paid" from "missed". Blocking status means:
*does this gap stop an external reviewer or an independent implementer working from `spec/` alone.*

---

## 1. Outstanding

| # | Obligation the ADR decided and `spec/` does not state | Deciding ADR | Target `spec/` section | Blocking for external review |
|---|---|---|---|---|
| 1 | ~~A `cognition` envelope MUST cite a mandate but carries no `component`, `action`, `classification` or `resource`.~~ **Paid, and the premise was wrong in the ADR's favour: it does carry `resource`.** `spec/03 §5` now states that a cognition envelope is matched on the one dimension it supplies — `resources`, spelled `<kind>:<name>` as `execution.target` already is — and that the three it cannot supply are unconstrained. A verifier MUST NOT skip `scope_permits` on the grounds that the tuple is incomplete. The kernel's unscoped path is **gone**: it existed for this one record kind, and `walk_mandate_with_depth` now takes a request rather than an `Option`. | ADR-0006 §7 | `spec/03 §5` | **Closed.** It was failing open, not merely undocumented: `resources` bounded every effect and no cognition, so a mandate could not limit what an agent spends on. Bound by `budget_accounting.rs::a_mandate_that_does_not_cover_the_model_refuses_the_spend_on_it` with its paired positive; mutation-tested. **The vector was owed and is now written** (verified 2026-08-04): `mandate-chain.json` carries `cognition-resource-within-scope` and `cognition-resource-outside-scope`. Calling it a gap rather than a decision was right, and understated: while it stood it was not a missing test but a **live divergence**, because the fix had landed in Rust and the gateway kept its own walk. A vector is the only artifact that asks both. |
| 2 | ~~Whether `spec/02 §2`'s closed `kind` vocabulary gains a `rejection` member.~~ **Paid, and by the second of the two options ADR-0006 §8 named.** `spec/04 §7.1` states it outright: *"The rejection stream is the kernel's stream of durable records that are **not** envelopes. §02 §2's `kind` vocabulary is closed at nine and holds no member for one, so anything the kernel must record durably and cannot express as an envelope belongs here."* The deferral is resolved rather than still deferred, and the `kind` table is deliberately unchanged. | ADR-0006 §8 | `spec/04 §7.1` | **Closed.** Found paid on 2026-08-04 while working this inventory: the text had been written and the row not retired. An inventory that lists paid debt sends a reviewer hunting for a gap that is not there, which costs the same as missing one. |
| 3 | ~~A refused envelope wedges its emitter's stream, and `spec/` names **no exit**.~~ **Paid.** `spec/04 §7.2` now specifies the exit ADR-0007 §6 asked for, and it is the second of the two options that ADR named — an **explicit gap record** rather than stream rollover: a root-approved `kernel.resume_stream` envelope on `kernel:core`, binding one `(stream, resume-seq)` and the `object-hash` of the refused bytes that bridges it. §04 §3's no-gap rule gains exactly that one exception and says so. Rollover was rejected in passing rather than silently: it changes stream identity, which is spec-visible (§07) and fragments one emitter's audit trail. | ADR-0007 §6 | `spec/04 §3` (the exception), `spec/04 §7.2` (the act), `spec/05 §5.6` (root-approved), `spec/05 §7.2` (the component's side) | **No longer blocking for the recovery *procedure*.** What remains for external review: the resume is the only act in the system that changes what `Store::append` will accept at a chain position, and its blast radius rests on the root-approval path and one SQLite trigger exemption. Reviewed by nobody outside this repository. Vectors: `spec/vectors/stream-recovery.json`; ingest negatives in `kernel/stozher-kernel/tests/def2_mandate_swap.rs`. **ADR-0031** (2026-08-04) now records the grace rule and the alternatives rejected; the resume act itself is described in `spec/04 §7.2` and `docs/proposals/DEF-2-mandate-continuity.md`, and `resume-request`/`resume-publish` are the commands that mint one. |
| 4 | ~~`execution.target` normalization granularity for proxied calls.~~ **Paid.** `spec/10 §2` step 2 now pins it: the target of a proxied call is `mcp:<server>`, and a gateway MUST NOT infer a finer one from the arguments. Pinned rather than left open because `target` is a scope dimension (§03 §4.2) and a value two gateways spell differently is a mandate that binds under one deployment and not another; and because the proxy is the component least able to do better honestly — which argument names the resource is knowledge the tool has and the proxy does not. A finer target is deferred, not forgotten: `spec/08 §1`'s `target-kind` gives the namespace but no extraction rule, so a manifest cannot yet tell a gateway how to derive one. | ADR-0007 §7 | `spec/10 §2` | **Closed for decidability**, which was the blocking part. Remaining and non-blocking: an organization needing finer than server-level scope over a proxied call must govern the tool directly (§10 §8). The clause states what the gateway's own code already documented. |
| 5 | ~~Which party is **normative** for revocation authorization on the pull path.~~ **Paid.** `spec/03 §7` now says the kernel decides (a)/(b)/(c) and a component pulling the feed does not — the test is stated over a mandate's *chain* and a component holds only its leaf, so it cannot evaluate the ancestor case at all. A consumer MUST verify the revocation object's own signature, MUST honour every entry it can verify, and MUST NOT drop one because it cannot establish the signer's standing. The direction is argued rather than asserted: over-honouring costs availability and is visible; under-honouring costs prevention and is not. | ADR-0008 §C | `spec/03 §7` | **Closed.** The trade is stated in the text rather than left implicit: an attacker who can serve a component's revocation feed can stop it working and cannot make it act. Matches the implementation — the gateway drops entries whose *signature* does not verify, never entries whose signer's standing it cannot resolve. |
| 6 | ~~**`spec/09 §7`'s evidence-preview MUST cites a non-normative design document.**~~ **Paid.** §09 §7 no longer sends a reader outside `spec/`: it requires the queue to show *"the call's arguments as §06 §4.4 supplies them"* and names §06 §4.4 as *"the normative answer to how"* — the values travel beside the request in the submission wrapper, so §06 §1.1's closed member set is untouched, and a queue that cannot show them MUST say so rather than render nothing (§06 §4.4 rule 8). The pointer at `docs/design/console.md` is gone. | ADR-0011 §1 (whose resolution was recorded against the design doc, not against §09 §7) | `spec/09 §7` | **Closed.** Verified against the current text on 2026-08-04, not against a report that it had been done. |
| 7 | ~~**ADR-0011 §1's amendment to `docs/design/console.md:10` was never applied.**~~ **Paid, and by the better wording rather than the ADR's.** The line now reads *"the call's arguments as `spec/06 §4.4` supplies them — with the digest they are checked against, and an explicit statement when the component held none"*. ADR-0011's 2026-07-27 text (*"the args commitment"*) had gone stale in the interval: §06 §4.4 means the queue genuinely shows the values, not merely a commitment to them, so applying the amendment verbatim would have shipped a second wrong sentence. | ADR-0011 §1 | **Not `spec/`** — `docs/design/console.md:10` and its Svod source | **Closed.** Verified on 2026-08-04 by reading the line, not by trusting the row. |
| **DEF-2** | ~~**A refused component is, to `spec/`, merely a late one.**~~ **Paid, and it landed with row 3 as that row required.** `spec/05 §7.1` names the third state and states what the component owes in it: three submission outcomes rather than two, `refused` never treated as `unreachable`, the reason deciding whether a grace window exists at all (`mandate-*` and `policy-not-published`: none, for any class) and the class deciding who may use it (`read`/`benign` only, each served effect a counted finding), expiry blocking everything, and the caller receiving the §06 §4.1 object with the kernel's reason code verbatim. `spec/09 §4.2` gains the third bullet distinguishing *refused* from *quiet*. `spec/10 §1.4` names the resolver. `spec/04 §7.2` gives the state an exit. `spec/03 §7`'s *"and no explanation"* is corrected in place rather than quietly deleted. | **ADR-0031** (2026-08-04) records the grace rule: the two proposals it was assembled from, why the intersection rather than either, and the four alternatives rejected. Written after the fact, and says so. | `spec/05 §7.1`, `§7.2` · `spec/09 §4.2` · `spec/10 §1.4` · `spec/04 §3`, `§7.2` · `spec/05 §1` (`wedge-grace`), `§5.6` | **No longer blocking.** Three vector files bind it across implementations (`sync-outcome` 16, `stream-status` 9, `stream-recovery` 7). **What remains for external review:** (a) the grace window is a deliberate, bounded hole — `read`/`benign` effects are served for up to `PT5M` after a refusal and their records provably do not reach the kernel, which is a trade against unilateral fleet-stop and wants an outside opinion; (b) `wedge-grace` is the first OPTIONAL member of §05 §1's closed set, and whether that door should have been opened at all is a wire-contract judgement; (c) §04 §7.2's bridge is the only mechanism that changes what the store will accept at a chain position. |

| 8 | ~~**A component that submits arguments its own request does not commit to is refused and not recorded.**~~ **Paid, and the reason it had stayed open was wrong.** `spec/06 §4.4` gains **rule 9**: a rule 4 mismatch MUST be recorded in the rejection stream with the caller, `subject`, `action`, `request-hash` and reason; `spec/04 §7.1` names it as a third record kind; `spec/09 §7` records that its cap now bounds two things. The row had been justified by a comment in `http.rs` saying a record was unavailable because *"§04 §7's records are about envelopes"* — but §04 §7.1's **first sentence** says it is the stream for records that are *not* envelopes, *"an ingest rejection is the first such record; it is not the only one"*, and the clock declaration was already a second. Two boundaries are deliberate and both are vector-bound: `gate-arguments-too-large` earns **no** record (a size refusal is a component being honest and verbose, not one making a false claim), and the §09 §7 bound counts **the caller's own recorded mismatches**, because `gate_requests_since` reads zero forever for a component that only ever lies and would bound nothing. **ADR-0032** records the decision and the four alternatives rejected. | ADR-0011 §2 (the surfacing half, dropped when §06 §4.4 relocated the predicate) | `spec/06 §4.4` rule 9 · `spec/04 §7.1` · `spec/09 §7` | **Closed.** Bound by `spec/vectors/gate-admission.json` (11 vectors) through `gate_admission_vectors.rs`; three mutations each fail a different named vector. The surfacing half landed the same day and is bound by two more tests: `/console/rejections` carries a named finding grouping the window's mismatches by caller, and it states that at the cap the count stops growing *because the kernel stops recording*, not because the component stopped. ADR-0032 §5 also records a correction to itself — it had claimed nothing surfaced the record at all, when the page had listed it all along; what was missing was the finding, not the visibility. **What remains for external review:** the threshold and window are inherited from §09 §7's approval-queue cap rather than chosen for this event, which is a defensible default and not a measured one. |

<details><summary>The row as it stood before 2026-08-04</summary>

| 8 (superseded) | **A component that submits arguments its own request does not commit to is refused and not recorded.** §06 §4.4 rule 4 checks the values against `args-hash` at admission — the stronger half of ADR-0011 §2, and it shipped. The half that did not is the ADR's *"itself a finding worth surfacing, not an error to swallow"*: the submitter gets a `422` with `gate-arguments-hash-mismatch`, and nothing else happens. No queue row, by design; no rejection record, because §04 §7's records are about **envelopes** and a gate submission is not one; and until 2026-08-03 not even a log line. The kernel now warns with the subject, action, request hash and reason, which is an operational improvement and **not** a durable record: it is not in the chain, not in the export, and not bound by a test. A broken or lying component is visible only to whoever is reading stderr at the time. | ADR-0011 §2 (the surfacing half, dropped when §06 §4.4 relocated the predicate) | `spec/04 §7` (whether a submission refused at admission earns a record of its own), or `spec/06 §4.4` (stating that it deliberately does not) | **Non-blocking** — nothing is ambiguous for an implementer: the refusal and its code are specified and tested. What is missing is a decision about whether the organization gets to see it, and that is a judgement rather than a gap. Flagged for external review because "a component lied about its arguments" is exactly the event an auditor would expect to survive. |

Kept because the reason it gives — *"no rejection record, because §04 §7's records are about
envelopes"* — is the thing that turned out to be false, and a row that is silently rewritten hides
the more useful lesson: the debt stayed open on a justification nobody re-read against the section it
cited.

</details>

## 1a. Found by a blind reader — four rows, opened 2026-08-04

The nine rows above were found from inside. **These were not, and that is the point of them.** They
come from `FINDINGS.md`, written by an agent given `spec/*.md` and the corpus and nothing else — no
`kernel/`, no `gateway/`, no `generate_vectors.py` (ADR-0033). Its verdict: *"yes, but for four
things — and one of them is fatal on its own."*

**Every row below was verified against this repository before being written here**, because an
outside report is a claim like any other.

| # | The gap | Verified how | Blocking |
|---|---|---|---|
| B1 | ~~**`policy-stale-offline` is a required wire value that the specification never defines.**~~ **Paid 2026-08-04.** `spec/05 §7.1` gains a second table — what the *caller* is told in each of the three outcomes — naming `policy-stale-offline` for an `unreachable` submission whose `offline[class]` is not `allow`, and stating that it is the component's own code and never the kernel's, since by construction the kernel said nothing. Written to match what was already there rather than to introduce anything: the corpus regenerates byte-identical and both suites are green, so no behaviour moved. The original text: An implementation built from the text emits a different reason code for the same refusal, and §05 §7.1 rule 5 puts that code in front of the calling agent. | `grep` over all 11 spec files: **zero hits**. Present in `spec/vectors/sync-outcome.json` and in **both** implementations (`kernel/stozher-core/src/sync.rs`, `gateway/src/stozher_gateway/sync.py`). A string both halves know and the text does not contain. | **Yes.** Not inferable, not a judgement — a missing value. |
| B2 | **§06 §2 declares its eleven steps complete and they are not.** Nothing validates the *shape* of `not-after` / `decided-at` before steps (8) and (9) compare them as strings, so a verifier built exactly to the algorithm accepts an approval whose `not-after` is `"z"` and never expires. | `grep -n "encoding-bad-timestamp" spec/06-gates.md`: **zero hits**. The steps do compare timestamps as strings. | **Yes** — an approval that never expires is a security property, not a formatting one. |
| B3 | **No error-code precedence rule exists**, over roughly ninety normative codes. §02 §2.1 and §02 §9.1 give different codes for the same input and the text never says which wins. Two implementations that disagree here disagree *on the wire*, since §00 §1 makes codes part of the contract. | The auditor lost four vectors to it. The collision is in the text as described. | **Yes** for interoperability, no for safety. |
| B4 | **Monetary comparison has three incompatible spellings of its own outcome** — `spec/03 §4.3` (`schema-type-mismatch`), `vectors/README.md` §3 (`-1\|0\|1`), and `money-compare.json` (`less\|equal\|greater\|refused`). A harness written from either document fails all 31 vectors. | `money-compare.json` carries `less/equal/greater/refused`; §03 §4.3 names `schema-type-mismatch`. Confirmed. | **No**, but cheap, and it costs a newcomer a whole file. |

**The auditor's own summary of the shape**, which is worth more than the rows: *"every area where the
specification records its own past failure is excellent (§02 §2.1, §05 §3.1, §04 §7.2, §10 §2). The
gaps are all in places nobody has yet been bitten — which is precisely what a blind reader is for."*

That sentence is the argument for having done this at all. §01 and §04 passed 65/65 and 15/15 with no
corrections — the parts that were fought over are sound. What the insiders could not see is the
places nothing had gone wrong yet, because a specification is proof-read by its author against
memories of what went wrong.

**Proposed text for each row is in `FINDINGS.md` §"The three worst gaps"** and was written by the
reader who needed it, which is the right author for it. None of it is applied here: a spec change
lands with its vectors (this file's own rule), and B1–B4 have not been through that.

---

**Nine rows, and as of 2026-08-04 none outstanding.** Paid rows are struck through rather than
deleted, so a reader can tell "paid" from "never asked". Rows 1, 3, 4, 5 and DEF-2 were paid on
2026-08-03/04; row 2 was found to have been paid earlier and never retired; rows 6, 7 and 8 were
closed on 2026-08-04. Previously five of eight were blocking.

**An empty table is not a complete specification, and this file must not be read as claiming one.**
What it tracked was one bounded thing: sentences an ADR decided and `spec/` did not say. Three of the
closed rows record a **stated trade** rather than the removal of one — the §7.1 grace window, the
`wedge-grace` member, and §04 §7.2's bridge — and every one of them, plus the two closed here, has
been reviewed by nobody outside this repository. The external-review targets are listed per row and
they did not go away when the rows did.

**Every row is now paid.** Rows 6 and 7 were verified against the current text on 2026-08-04 — §09 §7
cites §06 §4.4 and no longer points outside `spec/`; `docs/design/console.md:10` is rewritten. Row 8,
the last one and the only one that was ever a judgement rather than a gap, was closed the same day by
`spec/06 §4.4` rule 9 and ADR-0032.

**Row 8 is worth reading twice, because it did not close on new information.** It closed because the
reason it had stayed open was checked against the text it cited and did not survive: the comment said
§04 §7's records are about envelopes, and §04 §7.1's opening sentence says it is the stream for
records that are *not* envelopes. Everything needed to close it had been in the specification for
days, including a second record kind already using the mechanism. A justification that is never
re-read is indistinguishable from a correct one, and this file is where the difference shows up.

**The ledger had itself gone stale, and that is the finding worth carrying out of this run.** On
2026-08-04 five claims in this file were false in the same direction — rows 6 and 7 shown as
outstanding when both were paid, row 1's *"a vector is owed"* when both vectors were written, and
both §3 bullets saying *"an ADR is owed, and this run does not write it"* when ADR-0029 and ADR-0030
had been written the day before. Not one of them was wrong when it was written. They went wrong
because the debts were paid faster than the ledger recording them, and **the party paying a debt is
not reliably the party who strikes it**. Row 2 named this exact cost — *"an inventory that lists paid
debt sends a reviewer hunting for a gap that is not there, which costs the same as missing one"* —
and then the file accrued five more instances of it. The rule the next run should apply: **an
inventory of debt is verified against the artifacts, never against the reports of work done on it**,
and it is verified at the end of every run that pays anything, not only when someone comes looking.

Rows 3 and DEF-2 were paid together because they had to be: §7.1 makes a wedge loud and safe, and a
component that refuses everything until a submission is accepted needs a conformant way to get one.
Landing the first without the second would have made the second urgent the moment it shipped, which
is what the DEF-2 proposal said and is why this change is one change.

Row 7's target is a design document rather than a `spec/` section, and it is in this table by
decision rather than by the table's own rule: it is an ADR obligation that was recorded and not
carried out, and splitting it out of the inventory would make it easier to lose than the debts that
do land on `spec/`.

---

## 2. What the ADRs asked for and `spec/` now says — verified, not assumed

The brief that commissioned this inventory named seven items as known debt. **Six of the seven are
already paid**, by ADR-0018 (the `x-` register) and ADR-0019 (the spec catch-up). Verified against
the current text rather than against ADR-0019's own table:

- **Genesis is two envelopes and neither is exempt** — `spec/05 §5` rule 2: *"The ceremony is two
  envelopes and neither is exempt … `seq` 0 of `kernel:core` is an **interactive mandate**"*.
  (ADR-0006 §2.) **Paid.**
- **The ≥2-root requirement** — `spec/03 §6`: *"the root set requires at least two enrolled roots"*.
  (ADR-0006 §3.) **Paid.**
- **`gate-denied` conditionality** — `spec/06 §2`: *"**`requires-gate` is outcome-conditional.** It
  is true only when the effect was applied"*, with step (1) named as the only step conditioned on it.
  (ADR-0006 §5.) **Paid.**
- **The pending-queue route** — `spec/06 §4.3` rule 1: `POST /v1/gate/requests`, idempotent by
  `request-hash`, appending no envelope; rule 5 makes the queue append-only. (ADR-0009 §1(a),(b).)
  **Paid.**
- **The revocation feed** — `spec/03 §7`: *"An implementation MUST expose the revocation feed for
  reading, with a **monotonic `revocation-epoch`** as its entity tag"*. (ADR-0008 §E.) **Paid.**
- **Where the rate limit lives** — `spec/09 §7`: *"**The cap lives in the kernel's own
  configuration, not in policy.**"* (ADR-0010 §1.) **Paid**, and the deviation is now the rule.

Three further asks that the brief did not name are also paid, and are listed so a later reader does
not re-open them: the catalog "stronger-of" rule (`spec/10 §3`, ADR-0007 §2), org-catalog seeding as
its own gated policy change (`spec/10 §4` rule 3, ADR-0007 §3), and self-approval prohibited over
the **subject** and not only the key (`spec/06 §5`, ADR-0009 §1(d) — note ADR-0019's header claims
to close only §1(a)–(c), but the clause is in the text).

### The approver-legibility obligation was discharged by a different mechanism

ADR-0011 §2 asked for an OPTIONAL `args-preview` member on `spec/06 §1.1`, and ADR-0019 §2 recorded
its deliberate non-adoption. **The obligation behind it is nonetheless met, and by a better design
than the one requested.** `spec/06 §4.4` — *"The arguments an approver reads"* — opens by stating the
problem in ADR-0011's own terms (*"an approver is therefore asked to sign over a call they cannot
read"*) and solves it **without** extending §1.1 by a member:

- The body of `POST /v1/gate/requests` is a **submission**, `{ "request": {…§1.1 object…},
  "arguments": {…values…} }`, and `request-hash` stays `object-hash(submission.request)` — never of
  the submission (rule 1). A bare action-request object is still accepted, so an upgrade cannot empty
  the queue.
- `arguments` is OPTIONAL on the wire and **obligatory of a component that can supply it**; a
  component that never held the preimage MUST omit it rather than send a stand-in (rule 2).
- **The commitment is checked, not trusted**: where `arguments` is present the kernel MUST verify
  `object-hash(arguments) == request["args-hash"]` and MUST reject otherwise
  (`gate-arguments-hash-mismatch`, rule 4) — the identical rule ADR-0011 §2 wrote, relocated.
- Rule 6 states why the member ADR-0011 asked for would have been the wrong shape: `arguments` is
  **not** part of the action request, is not covered by `request-hash`, and MUST NOT be copied into
  `authorization.request`, an envelope, or evidence.
- Rules 3, 5, 7 and 8 add what the ADR did not think to ask for: a 16 KiB bound with
  `gate-arguments-too-large`, an approver's own recomputation path, erasure at `not-after`, and an
  interface obligation to distinguish *never supplied* from *supplied and empty*.

Unlike most of ADR-0019's sixteen, this one **reaches the vector corpus** —
`spec/vectors/gate-arguments.json` exercises rules 3 and 4 — and it is implemented and tested
(`gatequeue.rs:135-153`, `http.rs:646`, `console.rs:301-306`,
`gate_queue_and_console_decisions.rs:1147-1286`, which asserts `arguments-supplied` both true and
false). Nothing is owed to `spec/` here.

### The eleven `x-` conditions — the count in the brief is stale

The brief asked for an enumeration of *"the eleven `x-`prefixed conditions."* **There are six**, and
the eleven were correct only up to v0.9.

- ADR-0006 §9 quarantined **eight** unnamed MUST conditions behind an `x-` prefix. ADR-0009 §1(e)
  took the register 8 → 10; ADR-0010 §1 took it 10 → 11 with `x-gate-rate-limited`.
- **ADR-0018 adopted sixteen of them into `spec/`, dropping the prefix.** `spec/00 §1` states the
  transition rule and the count: *"Sixteen `x-` codes were adopted in the `stozher/0.1` revision
  that added this paragraph"*, with the MUSTs that a reader of a historical rejection record must
  treat `x-<name>` and `<name>` as the same condition and MUST NOT rewrite the chained past. All
  sixteen were confirmed present in `spec/` (`budget-exceeded-applied`, `policy-offline-allows-gated`,
  `policy-change-target-mismatch`, `policy-change-document-unbound`, `aggregate-window-too-long`,
  `aggregate-window-inverted`, `checkpoint-stream-unknown`, `manifest-malformed`,
  `root-enrollment-malformed`, `gate-decision-already-recorded`, `gate-rate-limited`,
  `aggregate-cardinality`, `aggregate-count-negative`, `checkpoint-range-mismatch`,
  `media-type-not-allowed`, `notify-failed`).
- **The six that survive are not debt.** `kernel/stozher-kernel/src/codes.rs::REGISTER` is
  `[&str; 6]`: `x-store-unavailable`, `x-caller-unauthenticated`, `x-schema-version-ahead`,
  `x-schema-migration-failed`, `x-conformance-driver-failed`, `x-conformance-harness-failed`. None
  of them refuses an object — each reports a condition of the *kernel* (store unreachable, no
  credential presented, store schema newer than the build, component would not speak the conformance
  protocol). Putting them in a wire contract about objects would be wrong, so the prefix is the
  correct permanent state, and a test asserts the set cannot grow without a visible diff.

One observed inconsistency, recorded rather than resolved: `codes.rs`'s module documentation says
*"**Fifteen** of them were adopted"*, while `ADOPTED` is declared `[&str; 16]` and `spec/00 §1` says
sixteen. Two of the three agree; the doc comment is the outlier. Not a spec hole — a stale comment
in one file — and out of scope for this run to change.

### DEF-1's hole is paid: `spec/06 §4.2` now states re-submission idempotence

The 2026-08-03 triage classified DEF-1 as a **spec hole** and did not open a row for it here, because
the hole was found and closed in the same pass. Recorded so a later reader can tell it from the debt
that is still outstanding:

- **What was missing.** §06 §4.3 rule 1 put idempotency on the kernel and it was discharged; §06 §1.1
  made the fresh `nonce` normative, which forecloses deriving it from the call's fields; §06 §4.2
  said what an approval covers and **nothing about a component holding an unanswered request**. No
  clause required reuse and none forbade it, so a gateway that parked a second request for a call a
  human was already being asked about was conformant.
- **What `spec/` now says.** §06 §4.2, *"Re-submission of an identical request MUST be idempotent"*,
  in four numbered clauses: identity is **field-wise** over §1.1's nine members and expressly not
  `request-hash`; the match happens *before* a row is classified as decided or new; a request past
  its `not-after` MUST NOT be reused; decided and consumed rows belong to §3. The closing paragraph
  states why the queue cannot discharge it for the component, and why this does not contradict the
  section's existing sentence about what an approval binds.
- **Bound by vectors, not only by prose.** `spec/vectors/gate-resubmission.json` (12 vectors,
  `role: "primitive"`), run by the gateway against its real store and by the kernel against its real
  `gatequeue::validate`. **Paid**, and `docs/open-defects.md` records DEF-1 as closed.

---

## 3. Two findings outside `spec/` and outside the table

Both are ADRs owing a record, not `spec/` owing text. The other design-doc item is row 7 above; the
file it names is owned elsewhere and was not edited here.

~~**No ADR records that `spec/06 §4.4` discharged ADR-0011 §2.**~~ **Written.** `ADR-0029 — The
approver reads the arguments, and the member ADR-0011 asked for was never added` (2026-08-03)
supersedes ADR-0011 §2 and ADR-0019 §2 *as the last word rather than as history*: both were correct
when made, and neither describes the product today. The tombstone exists, so a reader following the
decision record forward no longer concludes the approver sees only a digest.

~~**No ADR records that an applied effect retains its arguments.**~~ **Written.** The same `grep`
now returns `ADR-0030 — Where the arguments of a call that ran are kept` (2026-08-03), which records
the payload route, why it exists, and its boundaries — and, per ADR-0013's rule, marks the two of its
claims that have **no test** as such rather than letting them look bound. The fact had been got wrong
three times in three weeks, twice by evaluators and once in a draft of
`docs/validation/persona-program.md`, in both directions. A findings table is not where a reader
following the decision record forward looks, which is exactly why the error kept recurring; an ADR
was cheaper than a fourth misreading.

Part of the original complaint has since been repaired and part is unverified: `console/templates/audit.html:79`
now states the route in prose — *"held as the envelope's evidence payload and served at
`/v1/payloads/<payload-hash>` until its retention ceiling"* — so the console no longer hides it.
Whether the regulator export mentions it is a **separate surface that was not checked here**, and
nothing in either document asserts anything about it.
