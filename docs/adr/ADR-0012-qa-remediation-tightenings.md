# ADR-0012: Three tightenings from the QA remediation that go beyond the spec's letter

**Status:** Accepted · **Date:** 2026-07-28 · **Arises from** the QA remediation (`17da8c2`)
**Tightens** `spec/06 §1.2`, `spec/08 §3.3` · **Names a bound in** the console export

The remediation closed every confirmed QA finding. Three of its decisions are **not** direct
readings of the spec — two tighten behaviour beyond what the text requires, and one accepts a limit
worth naming. Recorded per ground rule 8: deviation is allowed, silence is not.

---

## 1. `kernel.conformance_run` is now a root-approved action (a real tightening)

**What the spec says.** `spec/08 §3.3` requires "no green conformance run, no registration"
(`manifest-conformance-not-green`), and `spec/08 §177` requires the harness to emit its result as an
envelope with `action: "kernel.conformance_run"`. **Nowhere does the spec say that envelope must
itself be root-approved.**

**What was found (SEC-6).** `store.rs`'s `conformance_run_is_green` checked only that an *applied*
envelope existed with that action and a matching `args_hash`. Since `kernel.conformance_run` was not
in `ROOT_APPROVED_ACTIONS`, an org whose policy classified it below `gate` let any subject with a
covering mandate emit the green claim for an arbitrary manifest hash. Registration itself still
required a root signature — so this was never a bypass — but the root was approving **on the
strength of a claim the kernel had verified only for existence.** As the implementation's own
comment puts it: *"Whoever could emit the run decided what the root was agreeing to."*

**Decision.** `kernel.conformance_run` joins `ROOT_APPROVED_ACTIONS` (now 5:
`publish_policy`, `register_component`, `enroll_root`, `retire_root`, `conformance_run`), and
`conformance_run_is_green` binds `target` as well as `args_hash`. The claim now costs what the
registration it unlocks costs.

**Reasoning, stated as reasoning rather than as a quote.** This applies `spec/05 §5.2`'s principle —
policy cannot lower the bar on the mechanism that enforces policy — to `spec/08 §3.3`'s registration
precondition. A conformance run is not an ordinary effect; it is the evidence a root relies on when
signing a registration. Evidence that the policy under audit can cheapen is not evidence.

**Consequence an operator must know:** this **changes what an existing deployment has to sign.** A
component registration flow that previously emitted a conformance run under an ordinary mandate now
needs a root's approval for that run too. That is a deliberate cost, not an oversight — but it is a
breaking operational change, which is exactly why it is in an ADR rather than only in a commit
message. `spec/08 §3.3` should gain a sentence saying so.

## 2. The embedded gate decision is held to a closed member set (a reading, not the letter)

`spec/06 §1.1` states plainly, for the action **request**: *"All members are REQUIRED. Unknown
members MUST be rejected."* `spec/06 §1.2` lists the **decision's** nine members but never states the
closed-set MUST in words.

`gatequeue::validate_embedded` enforces a closed 9-member set on the decision **by symmetry with
§1.1**. This is the right default — an unknown member on a signed authorization object is exactly
the shape SEC-4 was about, and asymmetric strictness between two halves of the same object is a
defect waiting to be found — but it is an inference. **`spec/06 §1.2` should say it explicitly.**
Until it does, an independent implementation that accepts unknown decision members is not violating
the text, and our test vectors would not catch the divergence.

## 3. The regulator export is assembled in memory (a named bound)

UX-1 was fixed by having the export ignore `limit` entirely and page the filtered set to exhaustion.
The store is paged in 10,000-row batches, so **no single query is unbounded** — but the response body
is assembled as one `String` before it is sent.

Streaming would require a `Stream` implementation and therefore a new dependency, which ADR-0003's
"every dependency is a security-questionnaire line" argues against for a file a human downloads once.
Accepted as the right trade at this scale, and **named here rather than left to be discovered** at a
design partner with a large log. Revisit trigger: the first export that exhausts memory, or the first
partner whose audit log makes a single-file download impractical.

Related, and deliberately not done: no manifest or count line is prepended to the body. Every line
must remain exactly one canonical envelope or the parser the completeness promise exists for breaks.
The record count travels in the `X-Stozher-Export-Records` header instead, and a test asserts every
line still parses with a signature on it.

---

## Also recorded: the one assertion that legitimately inverted

`gateway/tests/test_s4_native_gates.py` asserted the full 72-character `ed25519:` key appeared on
the answered-queue row. The console now truncates identifiers to 12 characters like every other
identifier (QA finding M3 — a full key in a `nowrap` cell pushed the `reason` and `record` columns
off-screen at laptop width). The assertion was updated to the rendered form.

**The property under test is unchanged** — the human who answered is named against the request — and
the full key is still asserted a few lines above on the decision record, which is where a verifier
needs it. This was a cross-agent interaction: two fix agents working in isolated directories were
each green alone and only the combined gate caught it.

## Related

`docs/adr/ADR-0011-approver-legibility-and-the-args-commitment.md` ·
`docs/adr/ADR-0010-s5-packaging-and-rate-limit-home.md` (the precedent for keeping a change out of a
closed member set) · `docs/build-log.md` (QA pass and remediation entries)
