<!-- MIRROR of Svod note `projects/stozher/docs/open-questions.md` — build artifact. Svod is the source of truth; edit there, not here. -->
<!-- Mirrored at S0, 2026-07-26. -->

# Open questions

## Empirical (cannot be closed by design; only by contact with reality)

1. **Is "pending approvals" a daily driver?** The console thesis rests on it. Test: dogfood on my own fleet from day 1 (Lattice + FleetQ gates through the kernel). If I don't open it daily within two weeks of S4, the surface thesis is wrong and v1 scope must be rethought — before any external user sees it.
2. **Does the four-class taxonomy (read/benign/consequential/prohibited) survive a foreign domain?** Validated only against components I wrote. Test: first component not written by me (or first genuinely alien domain — e.g. a finance connector). If the manifest requires contortions, the taxonomy needs revision at manifest time, not production time.

## Administrative

3. **Name — candidate "Stozher"** (стожер: the central threshing-floor pole everything is tethered to; tethering = mandate). Wire string candidate `stozher/0.1`. Pending the Servanda ritual before it takes root: web collision check, EUIPO/USPTO Nice 9/42, domains (stozher.dev/.org), GitHub org, npm/crates scope. Fallback candidates: Главина (hub of a wheel — where the spokes meet), Ос (axis). Latinization check needed (zh digraph readability for non-Slavic markets).

## Design-level questions deliberately NOT open (closed by decision, recorded for honesty)

- Multi-tenancy: closed — single-tenant per org, by maxim.
- Inline vs observer: closed — hybrid, local enforcement + sync gates ([[projects/stozher/docs/design/enforcement-topology]]).
- Svod as event log: closed — no; separate chained store ([[projects/stozher/docs/design/event-store]]).
- Cognition auditing: closed — out of scope by design; effects only (ADR-0001 case 2).
- Fifth weight class: not open until question #2 forces it.
