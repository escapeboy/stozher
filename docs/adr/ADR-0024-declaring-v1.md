# ADR-0024: v1.0 is declared — on a completed engineering scope and a waived field condition

**Status:** Accepted · **Date:** 2026-08-02 · **Follows** ADR-0022 (which closed v0.9 the same way) ·
**Deviates from** `docs/product-completion-design.md` §3 (v1.0)

v1.0 is declared by the owner's decision. This ADR records **what that decision rests on**, because
the basis is narrower than the plan specified in a way a release note would be tempted to smooth
over — and this is the one project that cannot afford to write that note.

---

## 1. What was decided

| Question | Answer |
|---|---|
| Is the engineering scope of v1 complete? | Yes, and §3 below says what "complete" was taken to mean. |
| Has a design partner run it in anger for a month? | **No. That condition is waived, not met.** |
| What may the record name? | This ADR and the repository. There is no partner to name. |

`docs/product-completion-design.md` §3 declares v1.0 when v0.9's gate passes, the external review's
findings are closed, and **at least one design partner has run it in anger for a month**. The first
two were settled by ADR-0022 — the review attested without a recorded scope, the corpus half of the
gate waived. The third is untouched, and is the subject of this ADR.

## 2. The field condition is waived, and what that costs is specific

**No design partner has run this.** The consequences are not "less confidence generally"; they are
two named questions the plan itself says only a partner can answer (`§6`):

- **Empirical question #1 — is the pending queue a daily driver?** Only dogfooding answers it. The
  plan states the stakes plainly: *if the answer is no, v1 scope is wrong and the console thesis
  needs rethinking before an external user sees it.* Declaring v1.0 does not change that; it means
  the question is now being asked after the label rather than before it.
- **Empirical question #2 — does the four-class taxonomy survive a foreign domain?** Only a
  component *we did not write* answers it. On 2026-08-02 the registration path became runnable by an
  operator rather than only by a test helper (§3), which removes the obstacle to asking — and the
  component in that test is still one written here. **The path exists; the evidence does not.**

Both remain open. Neither is closed by anything in this repository, and a later reader deciding
whether to deploy this should weigh the label accordingly: v1.0 here means *the engineering is
finished and the specification is the thing an implementer reads*, not *this has been operated by
someone with something to lose*.

## 3. What "the engineering is complete" was taken to mean

Not "every planned item shipped" — v0.2 through v0.9 already closed those. It means the sweep of
2026-08-02 finished: **every operation the specification requires of an operator has a command, and
every one of those commands has been run as a process against a live kernel.**

That sweep was prompted by one question — *which operation has no command?* — and it found seven
things, each sitting inside a release already closed as complete:

| Found | What it was |
|---|---|
| `revoke` | §03 §7 specified, kernel implemented, no verb and no route. The envelope shape made an offline signature impossible, so the absence was structural. |
| `stozher-approve` | Broken since the console's form was removed. Four unit tests covered the parser, each feeding it a page it wrote itself. |
| §02 §2's `cognition` row | `mandate-ref` required by both implementations and by the corpus; a reader following the document omits it and fails `valid-cognition`. |
| Publishing a policy version after the first | §05 §5 specified, exercised in hand-built Python by the gateway's test support since S1. No command. |
| Producing a policy document at all | Nothing signed one. The publish ceremony began with a file only this repository's test suites could produce. |
| Enrolling a root | §03 §6 specified, **zero tests**, no command — and it recorded the new root's subject as `root:ed25519:<hex>`, which is the value §06 §5's self-approval prohibition compares. |
| Registering a component | **v0.4's gate was graded against `World::register_component` in the test kit.** |

The last two are the ones worth carrying forward as a lesson rather than a changelog entry. A
release gate phrased as *"a component not written by us registers through the documented path"* was
satisfied by a helper, and nothing about the gate said so. And the root-enrolment defect was
invisible precisely because the operation had no user: roots seeded from configuration carry their
real subjects, every existing test used those, and the one mechanism for giving a human a second
enrolled key was the mechanism that stopped the rule recognising them as the same human.

**The counter-test that closes each of them is the same:** run the command as a subprocess against a
live kernel. A command exercised through the library it wraps is a command nobody has run.

## 4. What is verified, and how

- Kernel **334** tests, debug and release. Gateway **134**. Cross-language corpus **313 vectors /
  20 files**, including `root-change.json`, which asks a third implementation about §03 §6.
- `cargo fmt --check`, `clippy -D warnings`, `ruff`, `mypy --strict` clean. `cargo audit` at its one
  known advisory (RUSTSEC-2026-0221, `event-listener`, unsound not vulnerable).
- **Two ceremonies verified against a real containerised deployment**, not only in tests: in an
  isolated copy of the tree with its own compose project and port, `bin/stozher-revoke` and the full
  policy-publish ceremony — draft, edit, sign, park, approve, publish — were run end to end, the new
  version took effect, and `verify` reported every stream verifying. The live install was untouched.
- `spec/02 §2` is now checked against the code that enforces it (`tests/spec_member_tables.rs`).
  Nothing in the repository could previously fail when the prose and the implementations disagreed,
  because both implementations read their rules from the code and neither reads `spec/`.

## 5. What this does not claim

- **`stozher/0.1` is unchanged.** That is the wire version, and so are the `0.1.0` in `Cargo.toml`
  and `pyproject.toml`. v1.0 is the product's release label; nothing about the envelope format,
  the corpus or the reason-code register moves because of this ADR.
- **The external review remains attested, not held.** ADR-0022 §2 states its actual strength and
  that statement is unchanged: no reviewer, no date, no scope, no report is in this repository.
- **The independent-implementation gate remains waived.** The corpus has still been exercised by two
  implementations written here, by the same author, from the same reading. `root-change.json` and
  `spec_member_tables.rs` narrow that gap; they do not close it.
- **`kernel.erase_payload` is classified and unimplemented.** It appears in the baseline profile's
  `by-action` map and nothing emits it; automatic decay is the mechanism that exists. Named here so
  the next reader does not have to rediscover it.

## Related

`docs/product-completion-design.md` §3, §6 · ADR-0022 (v0.9, closed on the same shape of decision) ·
ADR-0021 · `SECURITY.md` · `deploy/README.md` §3 (the operator ceremonies this release completes)
