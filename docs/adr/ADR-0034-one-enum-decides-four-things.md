# ADR-0034: One enum decides four unrelated things, and four design partners all said so

**Status:** Accepted (as a problem statement; the change is deferred with its conditions named) ·
**Date:** 2026-08-05 · **Follows** the design-partner program of 2026-08-04
(`docs/validation/design-partners/`) · **Records** DEF-14

## 1. What was observed

Four agents were each given a foreign domain, this repository, and the documented install path, and
told to get work done. They did not talk to each other. All four arrived at the same structural
complaint from four different directions, and **none of them asked for a fifth class**. All four
asked for a **second dimension**.

`classification` — `read` / `benign` / `consequential` / `prohibited` — currently decides, at once:

1. **the gate** — whether a human must approve (§05 §3 step 4);
2. **retention** — `retain-until`, via the policy's per-class ceilings;
3. **offline behaviour** — what `offline[class]` permits when the kernel is unreachable (§05 §7.1);
4. **record granularity** — `read` folds into a counted aggregate with sample hashes and no payload;
   everything else keeps a per-event envelope.

Those four are independent questions about an action. The taxonomy answers them with one answer.

## 2. The evidence, per partner

| Domain | What they hit |
|---|---|
| Clinical research | `read_chart` is honestly `read`, which folds it into an aggregate — **the trail cannot say whose chart was read**. The only class that keeps a per-disclosure record is `benign`, and "chart access is benign" cannot be written in a regulatory submission. They also reversed 2 of 3 sample hashes by guessing subject IDs. |
| Litigation | The same trade, reached independently: `fetch_privileged_material` classifies as `read`, gets a `P0D` ceiling and a resource-less aggregate, so they **published it as `benign` to keep evidence** and said so — their chain now asserts that reading privileged material is benign. |
| SRE | "Restart a service" is `benign` on a stateless worker and `consequential` on a primary database — *the same action name*. `execution.target` can only ever be `mcp:<server>` (`enforce.py`), so a policy rule keyed on `svc:db-primary` matched nothing, silently, and **"RESTART PRIMARY DATABASE" applied ungated as `benign`**, indistinguishable in the trail from the worker restart beside it. |
| Commerce | Money is invisible: classification matches on (subject, action, resource), `resource` is `mcp:commerce` for every tool, and the amount lives inside `args-hash` — a digest a policy cannot read by design. **"This agent may refund at most €5,000/day" cannot be written anywhere in this system.** |

The clinical and litigation rows are the same defect twice: an organization that needs a per-event
record for a read action must lie about its class, and the lie is signed and permanent.

## 3. Why this is a decision record and not a fix

**Because every repair changes the wire contract**, and this repository's own rule is that a spec
change lands with its vectors in the same change. Three candidate shapes, none costed:

- **A second scope dimension** (a real `resource` an implementation can supply, rather than
  `mcp:<server>`). Addresses SRE and commerce. `spec/08 §1`'s `target-kind` gives the namespace and
  no extraction rule, which ADR-0007 §7 already deferred once — so this is the second time the same
  gap has been named, and that is worth recording on its own.
- **Splitting record granularity out of `classification`.** Addresses clinical and litigation. The
  cheapest of the three and the one with the clearest shape: a per-action *record* mode, defaulting
  to today's behaviour, so a `read` action can keep per-event records without being reclassified.
- **An amount-aware gate rule** bound to a declared value rather than to the args digest.
  Addresses commerce. The largest: it needs a value that travels beside the request (§06 §4.4
  already carries the arguments, so the mechanism exists) and a comparison the policy language does
  not have.

**What is decided here is the diagnosis, not the cure**: the axis is right and the resolution is
wrong, four independent evaluations agree, and none of the three shapes above may ship as a same-day
fix to a report that landed the day before.

## 4. What would make this urgent rather than owed

Two of the four consequences are *silent*, and that is the part that should decide the schedule:

- the SRE case applied a consequential action ungated **and left a trail that cannot distinguish it**
  from a benign one;
- the clinical and litigation cases produce a signed record asserting a classification the
  organization does not believe.

Neither is a refusal an operator can see. Everything else this system gets wrong, it gets wrong
loudly.

## 5. What may be said, and what may not

**May be said:** four independent evaluations in four foreign domains found the four-class taxonomy
sufficient as a gate vocabulary and insufficient as a description of an action, and named the same
missing dimension.

**May not be said:** that the taxonomy is wrong — none of the four proposed replacing it; that the
fix is known — three shapes are sketched here and none is costed; or that agents evaluating a
product is the same evidence as customers using one. `docs/product-completion-design.md` §6's
question #4 — whether anyone wants this — is untouched by all four reports together, and this ADR
does not touch it either.

## Related

`docs/validation/design-partners/README.md` · `docs/open-defects.md` DEF-14 ·
ADR-0007 §7 (which deferred the target-granularity question the first time) ·
`docs/product-completion-design.md` §6
