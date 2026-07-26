<!-- MIRROR of Svod note `projects/stozher/docs/design/policy-model.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# Policy model — three tiers, approvals as training data

Answers the residual tension of ADR-0001: who authors granularity policy without dying of configuration fatigue.

## Tier 1 — Shipped baseline profiles

- Universal action taxonomy at kernel level: `read | benign | consequential | prohibited` (lifted from Lattice `policy_classify`).
- Every component's manifest declares the map `my action type → class` (see [[projects/stozher/docs/design/extension-contract]]).
- Day-1 org writes nothing: starts on a conservative shipped profile (e.g. all `consequential` actions gated, `prohibited` hard-blocked, mass reads aggregated).

## Tier 2 — Org overrides as policy-as-code

- Overrides live in git (Svod space), reviewable, diffable, revertable.
- **Changing policy is itself a consequential effect in an envelope**: passes a gate, signed by a named human. Policy is audited by the same mechanism it enforces — no privileged side channel.
- Override forms: reclassify an action type per subject/scope; add standing rules (which are mandates, see identity doc); set evidence TTLs per class; set budget dimensions.

## Tier 3 — Drift learning (deferred; trigger: ~1000 approval events)

- Kernel observes gate history: "action class X approved 47/47 by the same human → propose standing rule."
- The proposal passes the **same gate** as any policy change. Nothing self-activates.
- This is the FleetQ `evolution_manage` pattern applied to policy instead of agents. Nobody ever writes policy from scratch — it precipitates from approvals and vetoes.
- Hard limit: learning proposes; humans dispose. No learned rule without a signature.

## Evidence retention by class (feeds event-store design)

| Class | Envelope | Evidence payload |
|---|---|---|
| read (mass) | aggregated record | none (counts + sample hashes) |
| benign | full envelope | short TTL |
| consequential | full envelope | long TTL, org-configurable |
| prohibited (attempted) | full envelope | long TTL — attempts are the most audit-valuable records |

## Open risk

The four-class taxonomy is validated only against components I wrote. Empirical question #2 in [[projects/stozher/docs/open-questions]]: does it survive the first foreign domain?
