<!-- MIRROR of Svod note `projects/stozher/docs/design/console.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# Console — the product surface (v1, nothing else)

One console, two reasons it gets opened:

## 1. Pending approvals — the daily driver

Why they open it every day. Queue of gate-parked actions: subject, mandate chain (one click to human root), action class, the call's arguments as `spec/06 §4.4` supplies them — with the digest they are checked against, and an explicit statement when the component held none — approve/deny with signature. Deny reasons feed drift learning (tier 3). Gates are kernel-native — the approval-gate pattern is borrowed from FleetQ, the FleetQ app is not a dependency (build plan S4).

## 2. Audit explorer — the reason they buy it

The CISO/auditor view. Filter by subject / mandate / class / component / window / durable object. Chain verification button ("prove nothing was tampered with in this range"). Walk any envelope to its human root. Export for regulators. Attempted-`prohibited` view front and center — attempts are the most valuable records in the system.

## Also in v1 (small, necessary)

- **Mandate registry**: who delegated what to whom; expiring standing rules surfaced up front (expiry is mandatory, so this list is the heartbeat of org autonomy).
- **Servanda view**: what's pending between people — commitments folded from transition envelopes ("what am I owed / what do I owe").
- **Budgets**: spend by subject/mandate/dimension against caps.
- **Notification adapter (approver ping)**: the only outbound Stozher owns — "something parked, come sign" via Slack/email/webhook, 2–3 channels max (ADR-0002). Everything else outbound is the client's own tools through the gateway, governed as effects.

## Explicitly NOT in v1

Dashboards-for-dashboards, agent chat UIs, workflow editors (FleetQ has one), knowledge browsing (Svod UI exists), theming, marketplace. Triggers for each live in [[projects/stozher/docs/build-plan]].

## Empirical bet, stated honestly

That "pending approvals" is genuinely a daily driver is **empirical question #1** ([[projects/stozher/docs/open-questions]]). Dogfood from day 1 on my own fleet answers it before any external user exists.
