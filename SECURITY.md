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
   malformed input. **This is the single highest-value target in the codebase.**
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

## Known limitations, stated rather than discovered

- The specification **lags the implementation**: ADRs 0006–0012 hold normative text not yet folded
  into `spec/`, and 11 conditions live in a quarantined `x-` reason-code register standing in for
  missing spec language. An independent implementation could legally diverge today.
- **Budget enforcement is not implemented.** Mandates carry budget dimensions and cognition envelopes
  carry cost, but nothing accumulates spend.
- **TLS is terminated externally.** The containers publish on loopback and expect a terminator; they
  do not speak TLS themselves.
- **The regulator export is assembled in memory** (the store is paged in 10,000-row batches, so no
  single query is unbounded).
- **Revocation on the gateway hot path** is enforced from a cached feed. A revocation is preventive
  once the feed is pulled; between pulls the window is bounded by the poll interval and visible in
  the audit.
- The four-class action taxonomy has been exercised only through the gateway's boundary
  classification, never by a component that classifies natively.

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
