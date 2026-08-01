# Security policy

## Status: no external security review has been performed

**Do not deploy this to protect anything you cannot afford to have wrong.**

Stozher's own build plan makes an external cryptographic and security review mandatory before
anything is called v1. That review has **not** happened. What exists instead is documented,
adversarially-tested engineering — which is not the same thing, and is not offered as if it were.

If you are evaluating this, the honest summary is: the enforcement properties are structural and
tested, the gaps are named rather than hidden, and an independent reviewer has not yet tried to break
it.

## Where a reviewer should look first

These are the places the project itself considers highest-risk. They are named here because a review
that starts from a map is worth more than one that starts from a README.

1. **`kernel/stozher-kernel/src/clock.rs` — hand-written timestamp parsing and calendar arithmetic.**
   Adopted deliberately to remove a dependency carrying a stack-exhaustion advisory
   (RUSTSEC-2026-0009) on a path that parses attacker-controlled input, rather than raising the
   minimum toolchain for one advisory. It is round-tripped exhaustively over every date from 1900 to
   2200 — but exhaustive round-tripping over *valid* dates proves nothing about the rejection of
   malformed input. **This is the single highest-value target in the codebase**, and an internal
   review of exactly that gap found one (ADR-0020): a leap second was accepted here and refused by
   the other implementation, giving one instant two spellings and letting an emitter choose which
   verifiers agreed with it. `tests/timestamp_adversarial.rs` now attacks the rejection side; a
   reviewer should assume it is not exhaustive.
2. **`kernel/stozher-core/src/gate.rs` — the eleven-step authorization algorithm.** Everything the
   product claims rests on it. In particular: the binding of an approval to a specific effect, replay
   handling, and the self-approval check that compares *subjects* and not only keys.
3. **`kernel/stozher-core/src/jcs.rs` — RFC 8785 canonicalization.** A canonicalization disagreement
   between implementations is a signature-validity disagreement. Number serialization
   (ECMAScript `Number::toString` semantics) and UTF-16 key ordering are the classic traps.
4. **`kernel/stozher-kernel/src/ingest.rs` — validation order and the single append path.**
   `Store::append` is crate-private with `Ingest::submit` as its only caller; that claim is worth
   re-verifying mechanically rather than trusting.
5. **`gateway/src/stozher_gateway/enforce.py` — the proxy chokepoint.** Whether any call can reach a
   downstream tool without transiting it.
6. **`deploy/` — the key ceremony and file modes.** Keys are generated on the operator's machine,
   never on the server.
7. **`kernel/stozher-kernel/src/harness.rs` and `driver.rs` — the conformance harness.** It builds a
   throwaway kernel, performs a root ceremony with a generated seed, mints mandates and signs
   approvals. It is the one place in the codebase that legitimately holds a root key and drives a
   foreign process, so it is the one place where "this is only for testing" would be the most
   dangerous sentence in the repository. The harness must not be reachable from the service, and it
   must not be able to submit its own result (`spec/08 §3.1` requires a human signature).

## Known limitations, stated rather than discovered

- **No independent implementation has been written from `spec/` alone.** That is the project's own
  definition of done for a protocol product and the one gate it cannot grade itself. The corpus
  (`spec/vectors/`, 293 vectors) is what such an implementation would be measured against, and the
  three most recent releases were largely spent making it able to catch things: eleven concrete
  disagreements between this repository's own two implementations were found in v0.9 by reading
  clauses rather than by running tests, each one a place the specification decided nothing and two
  authors decided differently (ADR-0017). It is reasonable to assume more remain.
- **Six rules are checkable only against a running kernel.** The pending queue's append-only
  property, the root-approved floor over policy amendment, the idempotence of
  `POST /v1/gate/requests` — these are covered by this repository's tests, not by the corpus, so an
  independent implementation could pass every vector and still get them wrong (ADR-0019 §3).
- **TLS is terminated externally.** The containers publish on loopback and expect a terminator; they
  do not speak TLS themselves.
- **The regulator export is assembled in memory** (the store is paged in 10,000-row batches, so no
  single query is unbounded).
- **Revocation on the gateway hot path** is enforced from a cached feed. A revocation is preventive
  once the feed is pulled; between pulls the window is bounded by the poll interval and visible in
  the audit.
- The four-class action taxonomy has been exercised only through the gateway's boundary
  classification, never by a component that classifies natively. The conformance harness
  (`spec/08 §4`) now exists and produces a green cross-language run, but **both halves of that run
  were written here**: it proves the registration path works and that the harness catches the
  failures it enumerates. It does not answer whether the taxonomy survives a foreign domain.
- **The only review performed has been internal.** ADR-0020 records one: six surfaces attacked, one
  real cross-implementation defect found and fixed, two smaller ones, and a list of what held. It was
  performed by the same party that wrote the code, which is the one property the required review has
  and it does not. Read it as a map of what has been looked at, not as assurance.
- **Payload decay has no second custodian.** Deleting a payload is the one destructive operation the
  kernel performs, and the property that makes it safe — chain verification never reads a payload —
  is enforced by the schema (no chain-bearing column in `payloads`) rather than by a separate
  authority. A reviewer should try to make verification depend on payload presence.

## Reporting a vulnerability

Please report privately rather than opening a public issue:

- GitHub **Security Advisories** on this repository (preferred): *Security → Report a vulnerability*
- Or contact PRICEX LTD directly.

Please include what you did, what you expected, and what happened. A proof of concept is welcome but
not required — a precise description of the property you believe is violated is enough to start.

There is no bug bounty. This is a portfolio and design-partner-stage project; reports are handled
because the correctness matters, not because there is a payout.

## What is in scope

The kernel, the gateway, the console, and the deployment scripts in this repository.

**Out of scope:** Harbormaster itself (a separate MIT project this integrates with — report there),
and any deployment's own operational key handling.

## A note on the test vectors

`spec/vectors/` contains fields named `secret-key` and `private-key`. These are **public test data** —
the SLIP-0010 specification's own published seeds, plus keys derived deterministically from a public
label so any implementation can regenerate them. Signature conformance is not testable without known
keypairs. No committed key is ever operational; see `spec/vectors/README.md` §0.
