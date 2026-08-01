# ADR-0020: an internal security review, what it found, and what it does not close

**Status:** Accepted · **Date:** 2026-08-01 · **Arises from** `SECURITY.md`'s reviewer map ·
**Follows** ADR-0019 · **Does not close** v0.9's external review

`SECURITY.md` names six surfaces a reviewer should attack first, and `docs/build-plan.md` requires an
external cryptographic and security review before anything is called v1. This is **not** that review,
and nothing here should be read as if it were: it was performed by the same agent that wrote much of
the code, which is the one property an independent review has and this does not. What it is worth is
what it found.

Per ADR-0013's rule, every claim below names the test that fails if it stops being true.

---

## 1. The finding: one instant had two spellings, and only one of them round-tripped

`SECURITY.md` calls `clock.rs` "the single highest-value target in the codebase" and says exactly why:
it is round-tripped exhaustively over every date from 1900 to 2200, and **exhaustive round-tripping
over valid dates proves nothing about the rejection of malformed input.** Attacking the rejection
side found it.

**`2026-07-26T23:59:60.000Z` was accepted by the kernel and refused by the gateway.** A leap second is
a real UTC second and not a value of §01 §2.3's form: it has no distinct millisecond representation,
so the instant it denotes renders back as `23:59:60` → `00:00:00` of the following minute. The same
held for year `0000`, which the proleptic Gregorian calendar has and `datetime.strptime` does not.

Why it matters in a product whose output is an audit record:

- **An emitter chose which verifiers agreed with it.** A component stamping `:60` produced an
  envelope the kernel appended and the gateway's validator refused. A chain that verifies for one
  party and not another is the one thing an audit may not be — and the choice belonged to the party
  with the most reason to want it.
- **It broke the property rule 3 exists for.** §01 §2.3's stated rationale is that timestamps are
  compared as strings. Two spellings of one instant makes string comparison stop being instant
  comparison: `before < leap` and `leap == after` while the strings say otherwise.
- **It was decided, not overlooked.** A unit test asserted the acceptance, on the reasoning that *"the
  specification's own validator accepts `:60`"* — which cited `stozher_core::envelope::is_timestamp`,
  this project's own code, as if it were the specification. §01 §2.3 said nothing about it. This is
  ADR-0017 §1's lesson arriving a third time: a clause the specification does not decide, decided
  differently by two implementations, with the reasoning citing an implementation as the authority.

**Resolution.** §01 §2.3 now states the rule as a rule — *one instant, one spelling*: a string of
this shape MUST render back to itself from the instant it denotes — with the leap second and year
zero as its two consequences. Stating the property rather than the two cases is deliberate; it
decides the next one too.
→ `a_leap_second_is_refused_because_the_other_implementation_refuses_it`,
`year_zero_is_refused_at_both_implementations`, and the corpus vectors
`emitted-at-leap-second` / `emitted-at-year-zero`, which ask both implementations.

The general invariant is now a test in its own right: every byte position of a valid timestamp is
corrupted with every ASCII byte, and **anything accepted must render as itself**
(`no_single_byte_corruption_is_accepted_unless_it_is_still_a_real_instant`). That is what caught the
leap second, and it is the shape of assertion the exhaustive valid-date round-trip could never make.

## 2. Two smaller ones

**`shift` could emit a string its own parser refused.** Its lower bound was year `0000`, so a
negative shift near the epoch's far end produced a timestamp `parse_timestamp` would then reject. The
bound is now `0001-01-01T00:00:00.000Z`.
→ `the_representable_range_is_closed_at_both_ends`.

**`canonical.parse` let `RecursionError` escape.** `RecursionError` is not a `ValueError`, so the
handler three lines below it — which `canonicalize` has had since v0.1 — did not apply. The
docstring promises a reason code a caller can put in a record; an interpreter exception is not one.
**Not reachable from foreign input today**: the proxy path canonicalizes rather than parses, and that
path was verified to bound nesting and return `jcs-malformed-json` in both languages. It is recorded
at its real severity — an unmet promise in a helper — rather than inflated.

## 3. What was attacked and held

Stated because a review that reports only findings tells you nothing about coverage:

- **The single append path.** `Store::append` is `pub(crate)` with exactly one caller,
  `Ingest::submit`. Verified by grep over the crate, not by trusting the comment.
- **The conformance harness.** It holds a root key and drives a foreign process, which is why
  `SECURITY.md` lists it. It is referenced only from `main.rs`'s `conformance` subcommand — never
  from `serve`, never from `http.rs` — it hard-codes `":memory:"` and accepts no `--config`, so it
  cannot be pointed at a real store, and it prints its result rather than submitting it.
- **Signature before schema.** `verify_chain` verifies the signature first, with the reasoning
  stated where it is done: a schema check that ran first would answer an *unsigned* object with a
  structural code and turn the verifier into an oracle. ADR-0006 §1 records that this was wrong for
  the whole of v0.1 and was corrected in v0.2; it is right now.
- **Replay consumption is atomic with the append.** The `gate_use` row is written inside the same
  `BEGIN IMMEDIATE` transaction, and `one_approval_cannot_be_consumed_twice_however_the_requests_race`
  races it.
- **Ed25519.** Only `verify_strict` is exposed — no lenient path exists to reach — so small-order
  keys and non-canonical signatures are refused.
- **Arithmetic.** Every timestamp and duration operation is checked and range-bounded; nothing
  attacker-influenced reaches an unchecked `*` or `+`. This matters more here than usual: the release
  profile sets `overflow-checks = true`, so an overflow is a panic, and a panic on the ingest path is
  an availability failure with no envelope to show for it.
- **Nesting.** `serde_json`'s 128-frame limit is in force (no `disable_recursion_limit`, no
  `unbounded_depth`), and the Python canonicalizer converts `RecursionError` into a reason code.
- **Key material.** Generated from the OS CSPRNG, written `0600`, refused on load if not owner-only,
  backed up under `umask 077`, and zeroed on drop.

## 4. One observation, not a finding

`Seed` and `SigningKey` zero their bytes in `Drop` with `fill(0)`, and the comment calls it
"best-effort hygiene", which is honest. A plain `fill` may be elided by the optimizer where a
volatile write would not; `zeroize` is already in the dependency graph via `ed25519-dalek`, so using
it would cost nothing. Left as it is because changing key-handling code on the strength of an
internal review is the wrong order of operations — it is exactly the kind of thing to hand to the
external reviewer with the observation attached.

## 5. What this does not close

v0.9's gate is an **independent** implementation, written from `spec/` alone by someone who has not
read this code, passing the corpus. The external cryptographic and security review is the same shape
of requirement: its value is in the reviewer's independence, and an internal pass has none of it. Six
surfaces were attacked here; a reviewer will bring assumptions this codebase does not know it has.

What this review does buy is a better starting point for that one. The map in `SECURITY.md` is now
accurate, the timestamp parser has an adversarial suite rather than only a valid-input one, and the
one clause that had two readings has one.

## Related

`SECURITY.md` · `spec/01 §2.3` · `docs/build-plan.md` (which requires the external review) ·
ADR-0006 §1 (signature before schema, corrected) · ADR-0013 (an ADR points at a test) ·
ADR-0017 (the same lesson, twice before)
