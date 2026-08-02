# ADR-0025 — Configuration seeds the root set once, and never again

**Date:** 2026-08-02
**Status:** accepted
**Supersedes nothing. Amends the behaviour ADR-0006 §3 assumed.**

## What was true

`Kernel::assemble` replayed `config.roots[]` into the `roots` projection on **every boot**, with
`ON CONFLICT DO NOTHING` and `envelope_id = 'configuration'`. A root that appeared in the file
appeared in the projection, and `Ingest::root_approvers` — which feeds `gate::verify_authorization`
for both policy amendment and every gated effect — reads that projection.

So: append one entry to `config.json`, restart, and the deployment has a new trusted approver.
No envelope, no signature, and the chain's head hash unchanged. A security reviewer did exactly
that during an adoption evaluation on 2026-08-02, then re-ran `verify` and got `anchored: true`
with a byte-identical head.

Two things made it worse than it first looks:

1. **The product's headline control is that the key which can approve never touches the server.**
   This reached the same end without needing that key at all. `SECURITY.md` named `config.json` as
   "the file through which root trust already enters" and disclosed only the *evidence-decay*
   consequence via `clock-advance`. The larger one was not written down.
2. **`roots` is in `REBUILDABLE_TABLES`** — the class of tables `migrate.rs` declares "may be
   dropped and recomputed from the envelope stream" — while holding rows the envelope stream does
   not contain. The invariant contradicted itself, and a rebuild would have silently dropped the
   genesis root.

The code said why it was like that, in `Store::seed_configured_root`: *"The bootstrap ceremony is
S5. Until it exists the root set has to enter the store somehow."* The ceremony shipped in S5. The
scaffolding outlived the reason for it by four releases.

## Decision

**Configuration seeds the root set only into an empty one.** That case is genesis, where the
circularity is unavoidable and §05 §5.2 licenses it: the first root cannot be enrolled by an
envelope that nobody yet has the authority to approve.

On every later boot, `roots[]` is read and ignored. A key in the file that is not in the projection
is **logged as ignored**, naming the subject and pointing at `kernel.enroll_root`.

## Why ignored rather than refused

Refusing to start on any mismatch is the stronger-looking option and is wrong here. A root
legitimately retired through `kernel.retire_root` stays listed in an operator's `config.json` —
nothing removes it, and nothing should, since the file is the operator's. Making that fatal turns a
stale line in a config file into an outage on the next restart, which is a worse failure than the
one being fixed and would be discovered at the least convenient moment.

Ignoring silently would be this repository's own recurring defect wearing the opposite sign, so it
is ignored **loudly**.

## What this does not fix

- **Someone who can write `config.json` still controls the deployment in other ways.** The policy
  key id, the caller tokens and `clock-advance` all enter through the same file, and ADR-0023 §4
  already states what the last of those costs. This closes the path to *becoming an approver*; it
  does not make the file untrusted.
- **`roots` still carries no append-only triggers**, because it is a projection. A direct
  `INSERT` on the database file by someone with write access to it still works. That is the same
  class as root on the host (`deploy/README.md` §6), and the answer is the same: an off-box anchor
  makes it non-silent, and `bin/stozher-anchor` is what takes one.
- **The genesis root is still `envelope_id = 'configuration'`.** An auditor reading the projection
  cannot distinguish it from a pre-fix injection in a store created before this change. Nothing here
  is retroactive.

## Consequences

An operator adding a root now has exactly one path, and it is the specified one: `root-request` →
`park` → a second root approves → `root-publish`. That path required `submit-mandate`, which did
not exist until the same day (see `deploy/README.md`, "Changing the root set") — enrolment was
specified, implemented, and unreachable, which is very likely why the configuration path was never
questioned.

`the_configuration_never_enrols_a_root_after_genesis` and its paired positive
(`configuration_still_seeds_the_first_root_of_an_empty_store`) are in
`kernel/stozher-kernel/tests/root_enrollment.rs`. Reverting the guard makes the first fail with
`human:mallory` in the root set, which is the reviewer's finding reproduced as a test.
