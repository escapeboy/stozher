# ADR-0016: the component drives its own refusals, and the harness never holds a component key

**Status:** Accepted · **Date:** 2026-07-31 · **Arises from** `spec/08 §4` and
`docs/product-completion-design.md` §4.3 · **Follows** ADR-0015 (which left four groups unrun) ·
**Adds** `spec/08 §4.8`

ADR-0015 §8 recorded three of `spec/08 §4`'s seven groups as implemented and four as blocked on the
same missing piece: a way to make a live component *act*. This closes them. Per ADR-0013's rule,
every claim about behaviour below names the test that fails if it stops being true.

---

## 1. The open question was not open either

ADR-0015 §8 left a decision to the owner: §4.4 requires eight refusals of envelopes the component
signed, and the harness cannot build seven of them without the component's signing key. The two ways
out looked like a product choice — either the component exposes a conformance mode, which reads as a
change to the component contract, or the harness receives a temporary signing key.

It is not a choice. `spec/08 §1.1` has required `conformance` as a MUST member of every manifest
since the specification was written, its example is `{ "self-test": "…", "vectors-version": "…" }`,
and `manifest.rs` has always refused a manifest that omits it
(`manifest/conformance-self-test-missing` in the reject/accept matrix, added here because the clause
this whole decision rests on had no row of its own).
The contract already said the component exposes a self-test. What was missing was not permission —
it was a protocol.

This is the second time in two releases that an "open decision" turned out to be already settled
normatively and nobody had read the clause (ADR-0015 §1 was the first, over §03 §4.3). The lesson is
cheap and worth writing down: **before recording a decision as open, grep the specification for the
member it would add.** A decision framed as a product question, taken by a team that has forgotten
its own normative text, is how a specification stops being the source of truth.

## 2. Why a temporary signing key was refused anyway

Even had the contract been silent, the alternative was the wrong one. A harness holding a
component's key can emit envelopes indistinguishable from that component's own. Certification would
then be performed by a program able to forge the exact attribution it certifies — and the product's
whole claim is that an envelope's signature says who acted.

The lifetime of such a key is also not a detail that stays small. It would need issuing, scoping,
revoking and auditing, and none of that appears anywhere in `spec/`, so it would be a second
authorization mechanism living outside the one the specification describes. §06 §2's claim is that
no path satisfies a gate without a signature over the exact action; a key handed out for testing is
exactly the kind of thing that erodes such a claim by degrees.

So the division is: **the harness decides what the attempt is, the component signs it, and the
kernel decides what happens to it.** The harness holds the run's root key and the component holds
neither it nor any approver's; nothing the component does can produce an approval, and nothing the
harness does can produce the component's signature.
→ `a_conforming_component_produces_a_green_run` drives the whole protocol; the harness refuses a run
where the key saying hello is not the key the manifest was signed with
(`test_hello_names_the_key_the_manifest_was_signed_with` is the component's half of that pair).

## 3. The protocol: line-delimited JSON over a subprocess

`spec/08 §4.8` is new normative text. A subprocess, one JSON object per line each way, five cases
(`hello`, `vectors`, `emit`, `negative`, `offline`).

- **A fresh process per run** is what makes §4's "no component-side state" structural rather than
  promised. There is no session to resume and nothing to clear between runs.
- **Every request carries its context** — `{ at, mandate-ref, policy-version }`, minted by the
  harness. `at` is the instant the component stamps its envelopes with, because §4 requires a
  deterministic run and a component reading its own clock would produce different bytes and
  different signatures every time.
- **The harness mandates the key the component reports**, so a run needs no prior relationship
  between the two. That is what makes it re-runnable by an operator who has just received a manifest
  from a stranger.
- **Requests carry inputs only.** For §4.1 every expected value is stripped before the vector is
  sent. This is the single load-bearing rule of that group: a component that saw the answers could
  pass by echoing them, having implemented no canonicalizer, no hash and no signature at all.
  → `a_component_that_echoes_the_request_fails_because_the_answers_were_stripped`.
- **`expect` tells the component what becomes of its last submission.** A refused envelope never
  occupied a chain position, so a component that counted its seven §4.4 refusals would come out
  seven positions ahead of the kernel and every later envelope — the whole offline queue — would be
  refused for a chain gap that has nothing to do with what it was being tested on. Telling it here
  keeps the self-test a mode that emits what it is told, rather than one that has to know which of
  §4.4's cases the kernel records.
  → `test_a_refused_attempt_does_not_take_a_chain_position` and `test_an_accepted_attempt_does_take_one`.

One member is an answer in some vectors and an input in others: an `ed25519` vector carrying a
secret key asks the component to *produce* a signature, and one without asks it to verify a
signature it must therefore be given. Stripping it from both would ask a component to verify
nothing.

## 4. §4.4's fifth case is refused earlier than the specification describes

§4.4 asks for "an envelope under a delegated chain not terminating at a human root → rejected
`mandate-root-grantor-not-human` or `mandate-delegation-depth-exceeded`". In this implementation
that refusal cannot happen at *use* time, because such a chain can never be stored: the grant is
refused when it is introduced.

So the case is driven as the component attempting to introduce it — a standing mandate whose grantor
is an agent — and the kernel refuses with the code §4.4 names. The refusal arrives one step earlier
than the text describes, which is stronger: the chain never exists to be cited.

This is recorded rather than quietly reinterpreted, because a reader comparing the harness against
§4.4 will otherwise find them describing different moments.

## 5. The run happens against a kernel that is built and thrown away

A run performed against the organization's live kernel would leave the component's samples, its eight
deliberate refusals and a payload decay in the production audit log, and the second run would start
from a different store than the first — so it would be neither re-runnable nor deterministic, the
two properties §4 opens by requiring. §4.7 also requires *deleting* payloads, which is not something
a certification exercise may do to a real deployment.

So `harness.rs` builds its own store in memory, performs its own root ceremony, mints its own
mandate for the component's key, moves its own clock, and discards all of it. Nothing about the
organization is read and nothing about it is touched.

The clock moves exactly once, and only because §4.4 needs a mandate that has run out. Expiry is
judged against an envelope's `emitted-at`, so nothing but a clock move produces one honestly — a
mandate expired at the moment it was granted would never have been appendable to cite. The move is
two days: past the brief mandate minted for that case, well short of the grant the rest of the run
acts under and the approvals the harness signed.

## 6. The harness produces evidence and stops

`stozher-kernel conformance` prints the result document and exits non-zero when the run is red. It
does not submit anything to a live kernel. `spec/08 §3.1` wants a human signature over the exact
manifest hash and ADR-0012 makes `kernel.conformance_run` root-approved; a harness that submitted its
own green result would be a program deciding that a third party's code may run in the organization,
which is the decision this product exists to keep with a person.

Red is also the exit code, not merely the text: a harness whose failure an operator has to notice by
reading is a harness that will pass in a script.

## 7. Every group is still run against a component built to fail it

The discipline ADR-0015 §8 set for the first three groups holds for the four added here. A group only
ever exercised against a conformant component would certify a state machine that accepts everything
and would look identical to one that worked. So `conformance_driven_groups.rs` runs each against a
scripted component built to fail exactly the property under test:

| Group | The failure it is proved to catch |
|---|---|
| §4.1 vectors | a component that echoes its input; one wrong digest; a corpus shipped missing a kind; a component that will not answer |
| §4.3 aggregation | a component that itemized every call; sampling past the *manifest's* declared `max-samples`, which the kernel has never read; counts that do not describe the calls driven |
| §4.4 negative cases | an attempt the kernel accepted; a refusal for the wrong reason; a case declined; a prohibited action reported as applied |
| §4.5 offline | a gated action applied while nobody could approve it; a queue that does not chain; a component that blocked nothing; a component that queued nothing |

Two of those deserve naming because the kernel cannot make them for itself. §4.3's sample bound is
the *manifest's*, not §02 §7.4's sixteen — a component that declared eight and sampled twelve broke
the promise an auditor was told to expect, and only something holding both documents notices. And
§4.5's "without renumbering" is read back out of the store rather than off the request the harness
still holds; comparing a local document with itself would pass for a kernel that renumbered
everything it was sent.

## 8. What this leaves

v0.4's gate is met: a component registers through the documented path, its manifest governs its
classification, its budget is enforced at spend time, and a green conformance run is now something
that can actually be produced. `deploy/gate/conformance.sh` performs one — the Rust harness
certifying the Python component, cross-language, seven groups, 131 assertions.

It is deliberately not folded into `clean-install.sh`. That gate lives entirely in Docker and the
harness spawns its component as a local subprocess; wiring them together would produce a step whose
failures are about container plumbing rather than about conformance. It is documented alongside it in
`deploy/README` §7 instead.

The honest residue: **we wrote both halves.** A green run proves the path works and proves the
harness catches the failures enumerated above. It does not answer empirical question #2 — whether the
four-class taxonomy survives a foreign domain — which only a component we did not write can answer.

## Related

`spec/08 §4`, `§4.8` (new) · `docs/product-completion-design.md` §4.3 · ADR-0012 (a conformance run
is root-approved) · ADR-0013 (an ADR points at a test) · ADR-0015 §8 (which this closes)
