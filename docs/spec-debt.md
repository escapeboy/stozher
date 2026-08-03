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
| 1 | A `cognition` envelope MUST cite a mandate but carries no `component`, `action`, `classification` or `resource` (§02 §6), so §03 §5's `require scope_permits(m.scope, request)` cannot be evaluated for it. The implementation resolves this with a separately-named unscoped entry point that runs every §03 §5 check *except* `scope_permits`. `spec/` names no such path and its verification pseudocode is unconditional. | ADR-0006 §7 | `spec/03 §5` (verification algorithm); cross-reference from `spec/02 §6` | **Blocking** — an implementer reading §03 §5 literally either cannot verify a cognition envelope at all or invents its own scope semantics, and the two implementations silently disagree on every cognition record. |
| 2 | Whether `spec/02 §2`'s closed `kind` vocabulary gains a `rejection` member. Rejections are chained and checkpointed (§04 §7) but are not envelopes, so the audit's most security-relevant records sit outside the one vocabulary the spec closes. ADR-0006 called this an *"open decision for the spec … deferred, not forgotten"*. | ADR-0006 §8 | `spec/02 §2` (the `kind` table), or an explicit statement in `spec/04 §7` that rejection records are deliberately not envelopes | **Non-blocking** — §04 §7 already defines the record's shape and chaining, so an implementer can build it; what is missing is the *rationale*, not the requirement. |
| 3 | A refused envelope wedges its emitter's stream, and `spec/` names **no exit**. ADR-0019 folded the *fact* into §03 §7 (*"the emitter's stream is wedged at that position until an operator intervenes — §04 §3 admits no gap"*), but ADR-0007 §6 asked §04 for a recovery procedure — stream rollover **or** an explicit gap record — and §04 still contains neither. | ADR-0007 §6 (fact partly paid via ADR-0019 → §03 §7) | `spec/04 §3` / `spec/04 §7` | **Blocking** — the spec documents a permanent stuck state with no conformant way out, so two implementations will invent two different recoveries and at least one of them will violate §04 §3's no-gap rule. |
| 4 | `execution.target` normalization granularity for proxied calls. `spec/10 §2` step 2 says only *"normalize to an `action` identifier and a `target`"*. The gateway can honestly name no more than `mcp:<server>`; a finer target needs a manifest-declared `target-kind` extraction rule, and `spec/08 §4` requires `target-kind` on Tier A manifests without saying how a proxied Tier B/B′/C call derives its target. | ADR-0007 §7 | `spec/10 §2` (with a cross-reference to `spec/08 §4`'s `target-kind`) | **Blocking** — two conforming gateways can emit different `execution.target` for the identical proxied call, so a resource-scoped mandate is not portable and `scope_permits` is not decidable across implementations. |
| 5 | Which party is **normative** for revocation authorization on the pull path. §03 §7 makes a revocation valid iff signed by the mandate's grantor, **an ancestor's** grantor, or an enrolled root — but a component holding only its leaf mandate cannot decide the ancestor case. The implementation accepts any signature-valid object from the authenticated feed (deliberately the safe direction: over-accepting costs availability, under-accepting costs prevention). `spec/` does not say this is permitted, or that feed integrity rests on the kernel's channel. | ADR-0008 §C | `spec/03 §7` | **Blocking** — a security property is left to implementer choice, and the unsafe reading (verify the ancestor case yourself, reject what you cannot resolve) turns revocation from preventive back into detective. |
| 6 | **`spec/09 §7`'s evidence-preview MUST cites a non-normative design document.** It requires that *"the pending queue MUST show the mandate chain to the human root, the classification, and an evidence preview **(console doc)**"* — pointing at `docs/design/console.md` when the normative answer is one file away in `spec/06 §4.4`, which supplies the preview through the submission wrapper rather than through §1.1. A reader who follows the only pointer given lands outside `spec/`. | ADR-0011 §1 (whose resolution was recorded against the design doc, not against §09 §7) | `spec/09 §7` | **Non-blocking** — a cross-reference fix; the requirement is satisfiable as written and §06 §4.4 says how, so no implementer is left without an answer, only without a signpost. See also §3 below. |
| 7 | **ADR-0011 §1's amendment to `docs/design/console.md:10` was never applied.** The ADR decided that *"evidence preview"* becomes *"the args commitment, and an explicit statement of what the kernel does not hold"*. Both the repo mirror (`docs/design/console.md:10`) and its Svod source (`projects/stozher/docs/design/console.md`) still read "evidence preview". This is the design-doc side of row 6's dangling pointer: §09 §7 cites a document that was supposed to have been rewritten and was not. | ADR-0011 §1 | **Not `spec/`** — `docs/design/console.md:10` and its Svod source | **Non-blocking** — debt against the design docs rather than the specification; no implementer reads `spec/` and is misled. Note the amendment is now *obsolete as written*: `spec/06 §4.4` means the queue genuinely can show the arguments, so the line wants rewording toward §4.4 rather than toward ADR-0011's 2026-07-27 text. |
| **DEF-2** | **A refused component is, to `spec/`, merely a late one.** The specification models an emitter in two states — chained locally, and synced — and treats the distance as latency (§04 §3). A permanent refusal is a third state the text never names, so every MUST that fires in it lands on the kernel, which discharges all of them (§04 §7 rejection records, §09 §4.2 quiet streams). Nothing is required of the component: not to stop serving, not to tell its caller, not even to keep the reason code. §03 §7 describes the state exactly, in a rationale bullet with no RFC 2119 keyword, and concedes the cost in five words — *"and no explanation"*. §10 §1.4's "resolvable" names no resolver, so a mandate the organization's kernel would never accept satisfies it. **No vector covers a mid-stream mandate change** (twenty files; none). | *No deciding ADR yet — this run recorded the hole and proposed the text; the ADR is owed.* | `spec/05 §7.1` (new, "Refused is not offline") · `spec/09 §4.2` (third bullet) · `spec/10 §1.4` (name the resolver). Draft text and three new vector files in `docs/proposals/DEF-2-mandate-continuity.md`. | **Blocking** — a component can serve a week of tool calls into a kernel that accepted none of them and be conformant. ADR-0001's *traceable* mandate is void for the window while both ends report health; observed detection latency seven days. Lands with row 3: §7.1 makes the wedge loud and safe without making it recoverable. |

**Eight rows, all substantive — DEF-2's placeholder was filled by the triage run of 2026-08-03 and
it is blocking, which makes five.** Previously: four of the seven.

**Four of the seven pre-existing rows are blocking**
(rows 1, 3, 4, 5); three are non-blocking (rows 2, 6, 7).

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

---

## 3. Two findings outside `spec/` and outside the table

Both are ADRs owing a record, not `spec/` owing text. The other design-doc item is row 7 above; the
file it names is owned elsewhere and was not edited here.

**No ADR records that `spec/06 §4.4` discharged ADR-0011 §2.** ADR-0011 §2 and ADR-0019 §2 both
still stand as the last word, and both say `args-preview` is deferred to a future versioned wire
change. A reader following the decision record forward concludes the approver still sees only a
digest, which has not been true since §4.4 shipped. This is ADR bookkeeping, not spec debt: the
correct repair is a short record pointing ADR-0011 §2 at §06 §4.4 and saying why the submission
wrapper was the better shape.

**No ADR records that an applied effect retains its arguments.** `grep -rln "v1/payloads\|payload-hash\|payload_hash" docs/adr/`
returns **nothing**: the payload route is in `spec/04 §5.2`, in the code (`enforce.py:1224`,
`http.rs:69`), and in a findings table (`docs/design-eval-findings.md`, the row beginning *"applied
effects retain no arguments"*) — but in no decision record. The fact has now been got wrong three times in three weeks, twice by evaluators and once in
a draft of `docs/validation/persona-program.md`, in both directions. A findings table is not where a
reader following the decision record forward looks, which is precisely why the error keeps
recurring. This is the same shape as the item above: an ADR is owed, and this run does not write it.

Part of the original complaint has since been repaired and part is unverified: `console/templates/audit.html:79`
now states the route in prose — *"held as the envelope's evidence payload and served at
`/v1/payloads/<payload-hash>` until its retention ceiling"* — so the console no longer hides it.
Whether the regulator export mentions it is a **separate surface that was not checked here**, and
nothing in either document asserts anything about it.
