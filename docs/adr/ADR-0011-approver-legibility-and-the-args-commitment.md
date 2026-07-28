# ADR-0011: Approver legibility — the args commitment, and where "evidence preview" goes

**Status:** Accepted · **Date:** 2026-07-27 · **Arises from** the post-build QA pass
**Resolves** the conflict between `docs/design/console.md:10` and `spec/06 §1.1`
**Amends** `docs/design/console.md`; schedules a versioned amendment to `spec/06`

---

## The conflict

`docs/design/console.md:10` promises the pending queue will show an **"evidence preview"** so an
approver can see what they are being asked to authorize.

The gate-request object cannot carry one. `spec/06 §1.1` defines a **closed 14-member set** and the
implementation (`kernel/stozher-kernel/src/gatequeue.rs:60,93,166,237`) carries `args-hash` only —
a 32-byte commitment, no preimage. There is no evidence member to preview.

The QA review put the consequence plainly: for `notes.write_note` the approver is asked to sign
"write a note" without being able to learn *which note, with what content*. **That is the
difference between an approval and a rubber stamp** — and it lands on the one workflow the product
exists for.

Either the design doc or the protocol has to move. Both, as it turns out, in different directions.

## Decision

### 1. Now (this fix pass): the console states the commitment honestly. No invented preimage.

The console **must not** fabricate or infer arguments it does not hold. It currently renders
`args-hash` with the same typographic weight as `policy-version`, so a careful approver has no way
to know they are being asked to sign something they cannot inspect. That is the actual defect:
not the missing data, but the **silence about its absence**.

The page must say that the hash is a commitment whose preimage this kernel does not hold, and name
where the approver can obtain and check it. This is the same discipline already applied elsewhere in
the console — the pending page's "no notification channel is configured … stated rather than left to
look like silence", and the 404's "an audit citation that does not resolve is itself worth
investigating". An interface that declares its blind spot is trustworthy; one that hides it is not.

`docs/design/console.md:10` is amended: **"evidence preview"** becomes **"the args commitment, and
an explicit statement of what the kernel does not hold"** for as long as the protocol carries no
preimage.

### 2. Later (versioned protocol amendment): an *optional, verified* preview member.

`spec/06 §1.1` should gain an OPTIONAL `args-preview` member, governed by one rule that is the whole
point of the design:

> The console MUST render `args-preview` **only** if `object-hash(args-preview)` equals `args-hash`.
> If it is present and does not match, the console MUST refuse to render it and MUST show that the
> preview contradicts the commitment — which is itself a finding worth surfacing, not an error to
> swallow.

This buys legibility **without buying trust**. The approver reads the arguments, and the arguments
are cryptographically bound to the thing the signature will cover. An emitter that lies about its
own preview produces a mismatch the console reports rather than a lie the approver acts on.

### Rejected: put the arguments in the request unconditionally, rendered as-is.

This was the obvious fix and it is wrong on two counts.

1. **It creates an attacker-controlled channel into the approver's eyes.** The gateway proxies
   foreign agents; `args` is whatever a third-party tool call contained. Rendering it unverified
   invites an emitter to write persuasive text — "routine cleanup, pre-approved by security" — next
   to the approve control. The console escapes HTML correctly (verified in QA, asserted by a live
   test), so this is not an XSS concern; it is a **social-engineering** one, and escaping does not
   help against it.
2. **It weakens the commitment.** If the preview is authoritative, the approver is trusting emitter
   data. If it is checked against `args-hash`, the hash stays the source of truth and the preview is
   merely a convenience. Only the second survives an adversarial emitter, which is the threat model
   `spec/09` already assumes ("a component can hide benign effects; it cannot fake an approval").

### Also rejected: have the kernel fetch the preimage from the emitter at approval time.

It makes the kernel depend on the emitter being reachable and honest at the moment of decision,
inverts the trust direction, and adds a synchronous network call to the gate path that
`docs/design/enforcement-topology.md` deliberately keeps free of them.

## Why the amendment is not made in this pass

`spec/` is frozen for this build: the S0 gate validates 161 language-neutral vectors against two
independent implementations, and `spec/06 §1.1`'s member set is closed. Adding a member is a
versioned wire change that must be made **with** new vectors and both implementations updated
together — the same reasoning that kept the rate limit out of the closed policy member set
(ADR-0010 §1). Doing it inside a fix pass would break the gate everything else is verified against.

## Consequences

- The approver's legibility problem is **acknowledged in the interface now** and **solved in the
  protocol later**. Neither half is silent.
- Until the amendment ships, an org whose approvers need argument-level detail must obtain the
  preimage out of band and check it against `args-hash` themselves. The console must tell them that
  is what they are doing — hence item 1.
- The verified-preview rule should be written alongside the S2b/Tier-A manifest work, since a
  manifest-declared `evidence-schema` (`spec/08 §4.2`) is the natural place to say what a preview
  for a given action type may contain.

## Related

`docs/design/console.md` · `spec/06-gates.md §1.1` · `spec/08-extension-manifest.md §4.2` ·
`docs/adr/ADR-0009-s4-native-gates.md` (key custody — the approver signs off-box) ·
`docs/adr/ADR-0010-s5-packaging-and-rate-limit-home.md §1` (closed member sets are expensive to open)
