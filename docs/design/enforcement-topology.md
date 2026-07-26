<!-- MIRROR of Svod note `projects/stozher/docs/design/enforcement-topology.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# Enforcement topology — hybrid with local enforcement

## The dilemma

- **Inline kernel** (every action passes through it): single point of failure, added latency on every effect, kills offline (maxim: everything works on a laptop).
- **Pure observer**: enforcement is fiction; the audit describes violations instead of preventing them.

## Decision: hybrid

1. **Components enforce locally.** Lattice and Boruna already gate their own actions — nothing is torn out. Each component holds a cached copy of applicable policy and evaluates it in-process.
2. **Kernel is the source of truth for policy.** Components pull policy (versioned; policy version stamped into every envelope so the audit shows *which* policy governed each effect). Envelopes push async — batched, retried, ordered per subject.
3. **Kernel is synchronous ONLY for gates.** Approval is blocking by nature, not by architectural whim. A `consequential` action under a gate rule parks until a named human signs. Gates are kernel-native (pattern borrowed from FleetQ approvals; no FleetQ runtime in the stack — build plan S4).

## Offline (maxim 5 preserved)

A component with cached policy operates alone: local enforcement continues, envelopes queue locally (hash-chained locally too), sync on reconnect. Gate-requiring actions offline: block or degrade per policy — never silently proceed.

## Failure modes, named honestly

- **Stale policy window**: component acts on policy version N while N+1 exists. Mitigation: short pull intervals, policy version in envelope makes the window visible and auditable, and policy *tightening* can carry a "revoke-cached" flag forcing re-pull before next consequential action.
- **Envelope loss before sync**: local chain + sync ack protocol; gaps are detectable (chain), not silent.
- **Component lies** (emits false envelopes / skips emission): not solvable by topology — solvable by the conformance harness (extension contract) + the fact that gated actions physically require kernel signatures to proceed. A component can hide benign effects; it cannot fake an approval. Stated plainly in the threat model rather than hand-waved.
