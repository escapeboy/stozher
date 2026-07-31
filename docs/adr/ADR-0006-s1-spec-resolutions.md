# ADR-0006: Spec resolutions surfaced by the S1 implementation

**Status:** Accepted · **Date:** 2026-07-26 · **Arises from** S1 (`feature/s1-event-store`)
**Amends** `spec/02`, `spec/03`, `spec/04`, `spec/05`, `spec/06`

Implementing the kernel against the S0 normative text surfaced eight places where the spec is
circular, silent, or under-specified. None is a design-doc deviation; each is a gap that had to be
resolved to produce working code. Recorded here rather than absorbed silently, and the spec text
should be amended to match before S2 consumes it.

---

## 1. Validation order: signature before schema — the spec wins

The S1 brief said "shape → signature." `spec/02 §9.2` says **signature → schema**, reasoning that
"a schema check that runs before signature verification lets an attacker probe schemas with
unsigned objects."

**Resolution: the spec is correct and the brief was wrong.** Verifying the signature over the
received bytes first means an unauthenticated caller learns nothing about schema internals, and
cannot use the kernel as a schema oracle.

> **CORRECTION (2026-07-31, v0.2).** This section originally ended "Implementation follows the
> spec. No change." **The second sentence was false, and stayed false for the whole of v0.1.**
>
> The *ingest* path did follow the spec. But `stozher-core::chain::verify_chain` — the library
> function an external auditor calls to check a range — validated **schema before signature**
> (`chain.rs:52-57`). So on an envelope that was both malformed and badly signed it answered with a
> structural code, which is exactly the schema-oracle behaviour §02 §9.2 forbids. Fixed in v0.2
> (`f77b85d`) and now pinned by the `parity` vector
> `unsigned-object-must-not-probe-the-schema`, which both implementations consume.
>
> Recorded rather than silently amended because the failure mode is the point: **this ADR was
> accurate about the decision and wrong about the fact, and nobody re-checked the fact for a full
> release.** A reader following the reasoning would have concluded the code was conformant. That is
> the documentation equivalent of a guard no test binds — and it was found by writing a vector, not
> by reading the ADR again.
>
> Rule adopted from it: an ADR may record what was **decided** on its own authority, but a claim
> about what the code **does** belongs in a test, with the ADR pointing at it.

## 2. Bootstrap is circular — resolved with exactly two validated envelopes

`spec/05 §5.2` wants the first policy at `seq` 1 of `kernel:core`, gated. But a gated effect needs
a mandate *and* a policy to evaluate against; `spec/02 §2` makes `authorization` a **required**
member of `policy-change`, so it cannot be omitted; and `spec/03 §6` wants the first root
self-asserted as an `effect` at `seq` 0, which itself needs `mandate-ref` and a policy.

**Resolution: genesis is two fully-validated envelopes, not a bypass.**
- `seq` 0 — an *interactive* root mandate.
- `seq` 1 — the first policy change, approved by a root's signature over the document hash.

No pre-installed policy row, no privileged append path. Every other envelope is refused with
`policy-not-published` until genesis completes, and genesis can fire at most twice per deployment.
This preserves the ADR-0002 anti-lesson: even the bootstrap carries real signatures. **`spec/05 §5`
needs text describing this sequence.**

## 3. A named human acting directly cannot satisfy `mandate-ref`

Effect kinds require `mandate-ref`; `spec/03 §1` forbids self-grant. A human therefore acts only
under a mandate **another** human granted.

**Consequence, accepted deliberately: changing the root set requires ≥2 enrolled roots.** This is
defensible — it makes root-set changes a two-person operation, which is the right posture for the
most privileged action in the system — but it is currently accidental rather than stated.
`spec/05 §5`'s example shows `human:ivan` citing a `mandate-ref` without saying who granted it.
**Spec text needed**, and the ≥2-root requirement belongs in the S5 bootstrap docs as an operator
prerequisite, not a surprise.

## 4. A `prohibited` action reported as applied is ACCEPTED and flagged, not rejected

`spec/05 §3` step 2 hard-blocks `prohibited` but names no ingest refusal code for an emitter that
reports having *already applied* such an action.

**Resolution: accept the envelope and flag it as `policy_violation`, queryable via
`?violations-only=true`.** Signed off deliberately.

Rationale: **the kernel records effects; it does not apply them.** By the time such an envelope
arrives, the act already happened in the world. Rejecting it would delete the only record that the
violation occurred — precisely inverting the design intent. `docs/design/policy-model.md` states
it directly: *"prohibited (attempted) | full envelope | long TTL — attempts are the most
audit-valuable records in the system"*, and `docs/design/console.md` puts the attempted-`prohibited`
view "front and center."

Rejecting here would have been the security-theatre choice: it looks strict and destroys evidence.
**`spec/05 §3` needs text making this explicit**, because the naive reading points the other way.

## 5. `gate-denied` — the gate requirement is outcome-conditional

`spec/06 §2` step (5) rejects `gate-denied`, yet `spec/06 §4.5` requires the denial envelope to
exist. Taken literally, a denial can never be recorded.

**Resolution:** `requires_gate` is true only for outcomes `applied` / `failed`. A `gate-denied`
result is accepted only when **nothing was applied**. A denial therefore can never accompany an
applied effect, and the denial record survives for the audit (and for future drift learning, which
`docs/design/policy-model.md` tier 3 depends on). **Spec text needed.**

## 6. Aggregation records carry no resource

`spec/03 §4.2`'s scope tuple cannot be formed for `aggregate` records, which have no `resource`
member. Each folded action is checked with the `"-"` sentinel of `spec/02 §4`.

**Consequence:** a mandate whose `resources` scope is narrower than `["-"]` / `["*"]` cannot cover
aggregated reads. Either `aggregate` gains a resource member or **`spec/02 §7` must state this
limitation.** Left as-is for now; flagged because it will bite the first org that writes a
narrowly-scoped read mandate.

## 7. Cognition cites a mandate but has no action/class/resource

`spec/02 §6` gives cognition envelopes no action, classification, or resource, yet they MUST cite a
mandate. Resolved with `verify_mandate_chain_unscoped` — a **separately named entry point** that
runs every `spec/03 §5` check except `scope_permits`. Naming it separately is deliberate: the
scope skip is visible at the call site rather than hidden behind a flag on the main verifier.

## 8. Rejections are chained but have no envelope `kind`

`spec/04 §7` says rejections are "appended to the kernel's own rejection stream," but `spec/02 §2`'s
`kind` vocabulary is closed and has no rejection member.

**Resolution:** implemented as a chained, signed record in its own table — satisfying "chained and
checkpointed" without inventing an envelope kind. **Open decision for the spec:** whether `spec/02`
should gain a `rejection` kind. Deferred, not forgotten.

## 9. Eight unnamed MUST conditions, quarantined behind an `x-` prefix

The spec states eight conditions as MUST without naming a reason code: offline-allows-gated
(`05 §7`), policy-change target mismatch / document unbound (`05 §5.1, §5.3`), aggregate window too
long / inverted (`02 §7.5`), checkpoint stream unknown (`04 §4`), manifest malformed (`08 §1`), root
enrollment malformed (`03 §6`).

**Resolution:** all live in `kernel/stozher-kernel/src/codes.rs` prefixed `x-`, with a test
asserting the prefix so no reader mistakes one for wire contract. Every code the spec **does** name
is used verbatim. When the spec names these, drop the prefix.

---

## Security-relevant dependency change (recorded for the pre-v1 review)

`cargo audit` initially failed on `time 0.3.45` — **RUSTSEC-2026-0009**, stack-exhaustion DoS in
date parsing. The upstream fix requires Rust 1.88, past this workspace's 1.85 MSRV.

**Resolution: the dependency was removed rather than the MSRV bumped.** The vulnerable code path is
timestamp parsing, and the kernel parses timestamps from untrusted emitter input, so this removed a
vulnerability *class* on a hostile input path rather than one advisory. The wire format is a fixed
24 bytes, so `clock.rs` does fixed-width field extraction plus Hinnant calendar arithmetic,
round-tripped exhaustively over every day from 1900 to 2200
(`the_calendar_round_trips_over_three_centuries`). Removed 4 crates. `cargo audit` is clean over 171
dependencies.

**Flagged for the external security review** that `docs/build-plan.md` already requires before
anything is called v1: hand-rolled calendar arithmetic is a classic defect site, and exhaustive
round-tripping over a date range does not prove correct rejection of *malformed* input. This is the
highest-value thing in the kernel for a reviewer to attack.

## Repo fix (not spec)

`.gitignore` had an unanchored `store/` pattern which silently excluded
`kernel/stozher-kernel/src/store/` — source that built locally but was **missing from a clean
clone**. Anchored to `/store/`, `/data/`, `/var/`; `keys/` and `secrets/` deliberately remain
unanchored so key material is ignored at any depth. Verified with `git check-ignore` and a scan for
ignored source files.
