# DEF-4 — the policy bundle: normative text for the bootstrap that was built

**Status:** applied 2026-08-04 as `spec/05 §7.3`. Kept rather than deleted: the argument in §4 for why
this is not a privileged path around §05 §5 is the reasoning behind the applied clauses, and it does
not fit in the specification.
**Classification:** **SPEC HOLE** (tooling/documentation), closed in the implementation; the wire
object it introduces has no normative description yet.
**Evidence:** `gateway/tests/test_policy_bundle.py` (16, default suite),
`kernel/stozher-kernel/tests/policy_bundle_cli.rs` (5, against the real binary).

---

## 1. The finding, in one paragraph

`spec/05 §7` describes what a component does with a **cached** policy while the kernel is
unreachable, and this build implements it exactly: `{read: allow, benign: allow, consequential:
block}`, verified from a warm cache against a dead port. What no clause describes is the call before
that one — **how a component that has never reached a kernel obtains its first verified policy.**
§05 §2 makes the pull the only distribution mechanism, so the cache had exactly one writer; a fresh
container therefore had no policy at all and `PolicyProvider.current` raised `policy-not-published`
inside `Governor.__enter__`, before a single call was classified. Enforcement that cannot start in CI
is enforcement an integrator comments out, which is why this is filed as high-for-adoption and
none-for-security: nothing was permitted that should not have been.

## 2. What the normative text says, and where it stops

**§05 §2 — components pull; the kernel does not push.** The mechanism is complete for a component
that can reach a kernel and silent about one that cannot yet. It is not *wrong*: a pull is the right
steady-state mechanism, and nothing here proposes replacing it.

**§05 §7 — offline behaviour.** Every clause is conditioned on a cached policy existing. *"proceed
under cached policy"*, *"refuse the action, emit an envelope"* — the profile governs a document the
component already holds. The document's arrival is out of scope by construction.

**§00 maxim 5 — "everything works offline."** The maxim is the reason a reader expects the
first run on a never-online machine to be covered, and the reason its absence reads as a bug rather
than as a boundary. `docs/design/enforcement-topology.md` §Offline says the same thing in the same
shape: *"A component with cached policy operates alone."* Both start from the cache.

**§05 §5 — publishing a policy version.** This is the clause that makes a bootstrap non-trivial to
add casually: publishing is a `consequential` effect judged by the policy already in force and
approved by a named human, precisely so that no privileged path can install policy. Any bootstrap
must not become one. The bundle does not, and §4 below is the argument.

## 3. What was built

`stozher-kernel policy export-bundle` (`main.rs::policy_export_bundle`, *"Assemble the root-signed
bundle a component bootstraps from"*) writes one signed object:

```json
{
  "v": "stozher/0.1",
  "kind": "policy-bundle",
  "bundle-version": 1,
  "exported-at": "2026-08-03T09:14:22.100Z",
  "max-age": "P7D",
  "policy":      { "…the policy document, signature intact…" },
  "revocations": [ "…signed revocation objects, possibly empty…" ],
  "anchor":      { "…what `anchor` printed, or null…" },
  "sig":         { "alg": "ed25519", "key": "ed25519:…", "value": "…" }
}
```

The reader is `stozher_gateway.bundle.load_policy_bundle`, called from `Gateway.__init__` before the
policy provider exists (`runtime.py::_bootstrap_from_bundle`, *"Seed the policy and revocation caches
from a root-signed bundle, or refuse to start"*). Its order is the security property: nothing is
written to the store until every check has passed.

## 4. Why this is not a privileged path around §05 §5

Three separations, and each of them is load-bearing:

1. **The root signature does not make policy.** The document inside is re-verified against the
   organization's `policy-key` on its own terms (`bundle.py`, *"the root's signature says 'this is
   the set I exported'; it does not stand in for the policy key"*). A root cannot mint a policy by
   wrapping one, and the test that binds it is
   `test_a_policy_signed_by_the_wrong_key_is_refused_even_inside_a_valid_bundle`.
2. **The bundle carries no authority its contents do not already have.** Every document in it was
   signed by the key that was always going to sign it. What the root's signature adds is *this set,
   at this instant, for this long* — a freshness statement, which is the one thing that cannot be
   derived from the parts.
3. **The command opens no socket.** That is why: a server able to manufacture the freshness statement
   could pin a component to a genuine but superseded policy and an empty revocation set for the whole
   of `max-age`, which is exactly what versioning exists to stop. So `policy export-bundle` sits with
   `decide`, `revoke` and `policy-sign` — the commands that hold a key and never talk to the network.

## 5. The proposed normative text

**Applied 2026-08-04 as `spec/05 §7.3`, not §7.1.** The number this proposal asked for was taken by
the mandate-continuity change ("Refused is not offline") between this being written and being
applied, and §7.2 by the component's side of recovery — a collision worth naming, because a proposal
that names a section number is a proposal with a fact in it that can go stale. The clauses below are
the applied text; two sentences were added at rules 3 and 7 giving the reason each is stricter than
the neighbouring rule it could be mistaken for, and a closing paragraph states that the producing
side is not normative.

> ### 7.1 Bootstrap (the first policy on a component that has never pulled)
>
> A component MAY be configured with a **policy bundle**: a single signed object carrying the policy
> document, the revocation set, and a checkpoint anchor, from which it seeds the caches §7 governs.
>
> 1. A bundle MUST carry `v`, `kind: "policy-bundle"`, `bundle-version`, `exported-at`, `max-age`,
>    `policy`, `revocations` and `anchor`. A component MUST refuse a bundle missing any of them
>    (`bundle-missing-member`) and MUST refuse a `bundle-version` it does not implement
>    (`bundle-version-unsupported`). `anchor` MUST be present and MAY be `null`: "nothing was
>    anchored" and "this producer did not say" are different facts.
> 2. A component MUST verify the bundle's signature and MUST refuse it unless the signer is one of
>    the human roots that component has enrolled (`bundle-sig-invalid`, `bundle-signer-not-a-root`).
>    A bundle that is refused MUST NOT be cached, in whole or in part.
> 3. A component MUST verify `policy` against the organization's policy key **independently** of the
>    bundle's signature (`policy-sig-invalid`). The bundle's signer MUST NOT be accepted in place of
>    the policy key.
> 4. `max-age` MUST be a member of the signed body. A component MUST refuse to start when
>    `exported-at + max-age` is earlier than its own clock (`bundle-expired`). It MUST NOT warn and
>    continue: a component enforcing a policy no enrolled root still vouches for is the state this
>    clause exists to prevent.
> 5. A component MUST record the bundle's `exported-at` as the policy's verification time, not the
>    moment of the load. A bundle-seeded component has not contacted the kernel, so §6's staleness
>    and §7's `offline` profile MUST govern it from its first call rather than after a grace period
>    no kernel granted.
> 6. A bundle MUST NOT permit anything §7 does not. In particular it MUST NOT make a class whose gate
>    rule requires a human signature succeed offline (`policy-offline-allows-gated` continues to
>    apply): an action that needs a signature cannot acquire one from a document.
> 7. Every revocation in a bundle MUST verify. A component MUST refuse the whole bundle over one that
>    does not (`bundle-revocation-sig-invalid`) — unlike the live feed of §03 §7, where dropping an
>    unverifiable entry can only cause a refusal to be missed. A bundle's entries arrive inside a set
>    a root signed **as a set**.

## 6. What this does not fix, stated plainly

**No offline mode can make a `consequential` call succeed**, and no clause above tries. §05 §7 means
an action under a gate rule cannot acquire a human signature while offline, so an agent test suite
that needs one to pass needs a **fixture-signed approval**, not a bundle. The recipe is
`gateway/README.md` §"Running an agent suite in CI", and it is two passes rather than one because the
approval names a request hash carrying a fresh `nonce` (§06 §1.1) and therefore cannot be signed
before the call exists. That is friction the design chose deliberately; it is not something a
bootstrap is entitled to remove.

**A second implementation has nothing to read yet.** The five vector files under `spec/vectors/`
describe every other signed object in the system and none describes this one. Until §7.1 or something
like it lands, `kernel/stozher-kernel/tests/policy_bundle_cli.rs` asserts the member set against a
list written down in the test — which is a contract between two files in one repository, not a
contract between two implementations. A `policy-bundle.json` vector is the right follow-up and is
deliberately not smuggled in with this change.

## 7. Alongside, and settled here: `[gateway] enabled`

Not a spec matter — the flag is the gateway's own configuration (ADR-0005) and `spec/10` says nothing
about it — but recorded because DEF-4 named it. It was read by `plugin.register` and by a `config
check` finding, and by nothing else, so a `Governor` built from `enabled = false` opened a session
and gated every call. The ruling is that it governs both paths, and that the two honour it
differently: the MCP plugin registers nothing, because "off" there means *this Harbormaster is
vanilla Harbormaster*; a `Governor` **refuses to be built**, because there "off" could only mean
*call the decorated functions ungoverned*, and a gate you disable by editing a config key is not a
gate. Bound by `test_enabled_false_refuses_to_build_a_governor` and its paired positive.
