# ADR-0015: v0.4 — money stops being a float, tier A stops being unreachable, and a budget becomes a figure

**Status:** Accepted · **Date:** 2026-07-31 · **Arises from** `docs/product-completion-design.md`
§3 (v0.4) and §4.2 · **Follows** ADR-0014 · **Deviates from** the design note's §4.2 enforcement
proposal · **Extends** ADR-0010 (where a knob lives)

Three of v0.4's four items are in. Each of them turned out to be worse than the design note recorded,
in a way that only showed up on reading the code rather than the note. Per ADR-0013's rule, every
claim below about behaviour names the test that fails if it stops being true.

---

## 1. The design note's "open decision" was not open

§4.2 presents "whether exhausting a budget **blocks** or **gates**" as a product decision for the
owner. It is not: `spec/03 §4.3` already says, normatively,

> Exhausted budget blocks like an expired mandate: `outcome: "blocked"`, envelope still emitted.

So `block` is the specified behaviour, and choosing `gate` would be a wire change to a frozen
specification, with everything that implies — not a free choice between two equal options. The
implementation follows the spec. If the organisation-facing argument for gating is persuasive, that
is a spec revision with its own ADR, and this note is where the question was answered rather than
re-opened.

## 2. Enforcement flags; it does not refuse — against the design note

§4.2 proposed that "an effect whose accrual would exceed any budget in its chain is **refused** with
a named code", on the grounds that a refusal is chained and therefore auditable. That is true about
refusals and wrong here, and `ingest` already contains the reasoning, written for `prohibited`:

> An envelope reporting one as *applied* is a component confessing a violation. It is appended and
> flagged rather than refused: refusing would delete the only record that the violation happened,
> which is the opposite of an audit.

Budget is the same shape. The effect has already happened by the time the envelope arrives; the spend
is real whether or not the kernel keeps the record. Refusing would make the store's account of the
world quieter than the world — the one failure this product cannot have. So an over-budget `applied`
effect is appended with `policy_violation = x-budget-exceeded-applied`, exactly as a prohibited one
is, and the *blocking* stays where §03 §4.3 puts it: with the emitter.
→ `an_over_budget_applied_effect_is_flagged_and_kept_rather_than_refused`, paired with
`an_effect_within_budget_carries_no_violation` — without the second, "flag everything" would pass.

## 3. Money was compared through a float, in both implementations

`spec/01 §2.5` puts monetary quantities out of the reach of binary64 by requiring them to be decimal
**strings**. Both implementations then parsed them back into a float to compare them — Rust
`s.parse::<f64>()`, Python `float(s)` — at the one place that decides whether delegated authority
narrows. Two failure modes, both reachable and neither covered by the 177 vectors that preceded this:

* **Precision.** `9007199254740993` and `9007199254740992` are one apart and the same binary64, so a
  child budget one unit over its parent's compared *equal* and the grant was accepted.
* **Divergence.** The two parsers do not accept the same strings. `float(" 25 ")` is 25.0 and
  `" 25 ".parse::<f64>()` is an error; both accept `"1e5"` and `"infinity"`. The same mandate was
  therefore valid through one implementation and refused by the other — a live parity divergence in
  a place no vector reached.

Fixed in both (`stozher_core::decimal`, `stozher_gateway.money`) with a deliberately narrow grammar:
`digits [ "." digits ]`, at most 32 characters, no sign, exponent, whitespace or separators. Every
omitted form is one two languages read differently, and none is a way anybody writes money. A budget
is a cap on spend, so a negative one is refused rather than given a meaning.

**A second defect, adjacent and unrecorded anywhere:** the *integer* branch compared through
`as_f64` / `int()` without checking the type at all, so a fractional budget silently became a float
comparison after everything above. It is now a type error.

The comparison semantics are now normative in `spec/03 §4.3`, which previously defined none — the
one spec edit §4.2 explicitly authorised.
→ 31 `money-compare` vectors, whose expected values are computed in `generate_vectors.py` by a
**third** technique (integer tuples, no `Decimal`, no float), so agreement is three implementations
agreeing rather than one checking itself. Mutation-tested: reverting Rust to `f64` fails 12 of 428
assertions, reverting Python to `float()` fails the same boundary vector.

## 4. Tier A existed and was unreachable

`Classifier.classify` has consulted a component's own manifest since S2 — it is the *first* thing it
checks — and **nothing ever populated the map**. So a component we did not write always fell through
to the shipped table, the org's seeded catalogue, or the shape heuristic: the tier the four-class
taxonomy is least confident about, and precisely the one registering a manifest exists to leave.
Registration worked, the manifest was retained forever, and no route ever handed it back.

`GET /v1/manifests` now serves each component's current manifest, and a `ManifestFeed` supplies the
classifier. Two decisions worth recording:

**The classifier reads a callable, not a snapshot.** `kernel.register_component` is a gated action a
human signs *while the gateway is running*, so a classifier that read the map once at construction
would keep classifying a freshly registered component by the heuristic until someone restarted it.
→ `test_the_classifier_reads_the_feed_on_every_call_so_a_registration_lands_mid_session`

**An unreadable answer is not an empty one.** A 200 whose body is not the promised shape, a 503, or
an unreachable kernel all keep the cached map. Replacing it would silently demote every governed
component to the shape heuristic while every call kept succeeding — quieter than a refusal, and
worse. The first implementation of this got it wrong and a test caught it.
→ `test_a_refusal_or_a_malformed_answer_is_not_read_as_an_empty_set`,
`test_the_feed_keeps_what_it_has_when_the_kernel_is_unreachable`

## 5. Accrual reaches every ancestor, and the projection is a fold

A budget caps "this mandate and everything delegated beneath it" (§03 §4.3), so a cost is charged to
the citing mandate **and every ancestor**. Without that, a delegation chain is a way to multiply an
organisation's limit by its own depth: each hop carrying an untouched cap, the root that authorised
everything reading zero.

The `spend` table is in `REBUILDABLE_TABLES` and that is executable, not a comment: `rebuild_spend`
drops it and recomputes from the envelope stream, and a test asserts the figures come back identical.
That is what keeps a budget an answer *about* the chain rather than a second place the truth lives
(maxim 9) — and it gives an operator who suspects the totals a way to settle it that does not involve
trusting them.
→ `the_projection_is_a_fold_and_recomputes_to_the_same_figures`,
`the_charge_walks_from_the_cited_mandate_to_every_ancestor`

**A defect found while writing this, worth recording because the fix was structural:** the budget
step was first written inside `validate_effect_kind`. Cognition envelopes take a *different* ingest
path — they carry no action to match a scope against — and `cost` lives on cognition (§02 §6). So
money would never have accrued at all. The step is now a method both paths call.

## 6. Stated gaps, rather than assumptions

**Dimension names do not line up, and nothing here invents a mapping.** `cost` reports
`wall-clock-ms`; §03 §4.3 caps `wall-clock-seconds`. `cost` reports `tokens-in` and `tokens-out`;
§03 §4.3 also names a combined `tokens`. Converting the first or summing the second would be
inventing normative meaning the specification does not state, and a budget enforced by an invented
rule is worse than one not enforced. Unmatched dimensions accrue nothing. Closing this is a spec
question for v0.9's catch-up, not an implementation choice.
→ `cognition_cost_accrues_money_and_the_dimensions_the_spec_shares` pins the current set.

**The ancestry charge is asserted at the walk, not end to end.** §03 §1 forbids a self-grant, so a
delegated mandate necessarily has a second grantee, and acting under this fixture's one needs a gated
action and an approval — machinery that would make the test about the gate. The walk that produces
the charge list is asserted directly; the two-level end-to-end spend is not.

**No gateway-side pre-spend check yet.** §03 §4.3's blocking belongs to the emitter, and the kernel
now exposes the figures it would need. The gateway does not yet consult them before acting, so today
an over-budget action is *recorded* as a violation rather than *prevented*. That is the difference
between detection and prevention, which `docs/product-completion-design.md` §1 names as a product
defect — it is stated here rather than left to be discovered.

## 7. What v0.4 has not closed

| Item | State |
|---|---|
| Conformance harness | **Open.** `spec/08 §3.3`'s "no green conformance run, no registration" is enforced — `store.rs` checks for an applied `kernel.conformance_run` committing to the manifest hash — and the harness that would *produce* such a run does not exist. So the gate is real and the evidence behind it is currently whatever an operator asserts. §4.3 specifies the shape, including that it must attempt the negative cases and be mutation-tested against a deliberately non-conformant component |
| Gateway pre-spend budget check | **Open**, see §6 |

v0.4's gate — "a component not written by us registers through the documented path, its manifest
governs its classification, and its budget is enforced at spend time" — has its second clause and
most of its third. The first stands on a harness that has not been built.

## Related

`docs/product-completion-design.md` §3, §4.2 · `spec/03 §4.3` (which answers §1, and which this
release extended with comparison semantics) · ADR-0010 (a knob that authorizes nothing lives in
kernel config) · ADR-0013 (an ADR points at a test) · ADR-0014 (the v0.3 items)
