## DEF-4 closed — a component can now obtain a verified policy with no kernel

The reported symptom was "no offline mode", and it was wrong. The offline profile is implemented and
works: with one cached policy and the kernel on a dead port, a `read` proceeds and folds and a
`consequential` is refused, `{read: allow, benign: allow, consequential: block}` exactly as §05 §7
requires. That was the triage run's one deliberately *passing* quarantined test, kept as a control so
the false framing could not survive contact with the code, and it is still here — unquarantined now,
still using no bundle, so if the bootstrap ever became the only way the offline profile works it is
the test that notices.

What was missing was the call *before* that one. §05 §2 makes the pull the only distribution
mechanism, so the policy cache had exactly one writer, a successful pull. A container that had never
reached a kernel therefore had nothing to enforce and `PolicyProvider.current` raised
`policy-not-published` inside `Governor.__enter__`, before a single call was classified. The only
offline seeding anywhere in the repository was tests calling `store.cache_policy(...)` directly,
which is why the in-process path always *looked* testable while no integrator could reproduce it.
Enforcement that cannot start in CI is enforcement an integrator comments out.

**`stozher-kernel policy export-bundle`** is the second writer. It assembles one signed object —
`kind: "policy-bundle"`, `bundle-version`, `exported-at`, `max-age`, the policy document with its
signature intact, the revocation set, and the checkpoint anchor the two were exported against — and
signs it with a human root's key at role `0'`. It opens no socket and reads no configuration, which
puts it with `decide`, `revoke` and `policy-sign` rather than with `policy-publish`, and here that
split is load-bearing rather than tidy. The bundle grants no authority its contents do not already
carry: the policy was signed by the organization's policy key and each revocation by its revoker.
What the root's signature adds is *this set, at this instant, for this long* — and a server able to
manufacture that could pin a component to a genuine but superseded policy and an empty revocation set
for the whole of `max-age`, which is precisely the attack versioning exists to stop. So the freshness
authority must not live where the network does.

The gateway reads it in `Gateway.__init__`, before the policy provider that would go looking in the
cache. Four things are checked and every one of them is a refusal to start rather than a degraded
start: the bundle's signature must verify and its signer must be a root **this deployment enrolled**;
the policy inside must verify against the organization's policy key **independently**, so a root
cannot mint policy by wrapping it; every revocation must verify; and `exported-at + max-age` must not
have passed. Nothing is written to the store until all of them pass, which is why the two
`cache_*` calls are the last two statements in `load_policy_bundle` — "an unverified bundle is
refused, never cached" is an ordering property, not a comment.

`max-age` is a member of the **signed body**, so how long a bundle may be enforced is the root's
declaration and not the file-holder's. An expired one refuses to start. Not a warning: a component
enforcing a policy nobody can vouch for any more is the thing this product exists to prevent, and a
warning in a CI log is a line nobody reads.

One decision worth stating because it is easy to get backwards. The seeded verification time is the
bundle's own `exported-at`, not the moment of the load. Stamping the load time would have made a
machine that has never seen a kernel report itself as freshly online for `max-staleness-seconds`;
stamping `exported-at` means §05 §7's `offline` profile governs from the first call, which is the
truth. A bundle older than five minutes therefore blocks `consequential` with `policy-stale-offline`
instead of parking it — refused either way, and both are asserted.

**The counterfactual.** Deleting the signature check (`signer = verify_signed_object(document)` →
read the key out of the `sig` member and trust it) and re-running:

```
FAILED test_a_flipped_byte_in_the_signature_is_refused
    E   Failed: DID NOT RAISE StartupRefusedError
FAILED test_an_edited_max_age_is_refused_because_it_is_inside_the_signature
    E   Failed: DID NOT RAISE StartupRefusedError
FAILED test_a_flipped_byte_in_the_policy_is_refused_rather_than_started_on
    E   AssertionError: assert 'bundle-sig-invalid' in 'the policy bundle was refused —
        policy-sig-invalid: … the policy signature does not verify'
```

Two of the three would have *started* on the tampered file. The third still refused, but for the
wrong reason — the policy's own signature caught it, which is defence in depth working and is exactly
the kind of accident that makes a missing check look tested. Deleting the bootstrap call instead
turns **thirteen of the sixteen** red, the first with `policy-not-published: no verified policy is
available`, which is the defect stating itself. Both mutations were reverted and the suite re-run
green.

Both were run twice, and the second time is the one to trust. The worktree had no `gateway/.venv`, so
the first pass used the main checkout's interpreter with `PYTHONPATH` shadowing its editable install
— which did resolve to this worktree's sources (`stozher_gateway.bundle` does not exist in `main`, so
it could not have imported otherwise), but it depends on `sys.path` ordering and is not a thing to
rest a security claim on. The rerun used a venv copied into the worktree with its `.pth` re-pointed,
verified by printing `stozher_gateway.__file__`. Every number in this entry is from that rerun. One
changed: the bootstrap mutation is thirteen red, not ten — the first count was read off a `head`-
truncated grep, which is its own small lesson about counting failures from a filtered pipe.

**`[gateway] enabled = false` is ruled on rather than documented around.** It was read by
`plugin.register` and by a `config check` finding and by nothing else, so a `Governor` built from a
configuration that said enforcement was off opened a session and gated every call anyway. It now
governs both paths, and the two honour it differently on purpose. For the MCP server "off" has a safe
meaning — register nothing, and a Harbormaster with the distribution installed is exactly vanilla
Harbormaster. For a `Governor` there is no such meaning: the caller has already wrapped functions
that apply effects, so "off" could only mean *call them ungoverned*, and a gate you disable by
editing a config key is not a gate. So it refuses to be built, loudly, at construction rather than at
the first call.

**What no offline mode can fix, said in the documentation rather than discovered in a sprint.** §05
§7 means a `consequential` call can never acquire a human signature offline, so an agent suite that
needs one to succeed needs a **fixture-signed approval**, not a bundle. `gateway/README.md`
§"Running an agent suite in CI" is the recipe: export the bundle, point `STOZHER_GATEWAY_BUNDLE` at
it, and for a gated call run twice — the call parks, a fixture root enrolled in that deployment only
signs the park by its request hash, the re-run finds the decision and forwards. Two passes and not
one because the request hash carries a fresh `nonce` per park (§06 §1.1), so the approval cannot be
signed before the call exists, and the decision is single-use so each gated call under test needs its
own. That friction is the design; a bootstrap is not entitled to remove it. `deploy/README.md`
carries the operator half.

**No `spec/` text was edited.** The bundle is an implementation of §05 §7's bootstrap and needs no
new clause to be correct, but the wire object deserves one before a second implementation reads it —
`docs/proposals/DEF-4-policy-bundle.md` carries proposed §7.1 text, the argument that it is not a
privileged path around §05 §5, and the honest note that `spec/vectors/` still has nothing describing
this object, so the Rust test asserts its member set against a list written in the test: a contract
between two files in one repository, not between two implementations.

Measured: `pytest gateway/tests` **197 passed, 4 deselected** (from 181/7 — sixteen new, three moved
out of quarantine); `-m open_defect` **4 failed**, all DEF-1 and DEF-2, red by design.
`cargo test` **354 passed, 2 ignored** (from 349/2). `cargo clippy --all-targets -- -D warnings`,
`ruff check`, `mypy --strict` clean; `type: ignore` still 2, and `#[allow]` unchanged at the one
pre-existing `dead_code` in `tests/concurrency.rs` — none added.

`cargo fmt --all --check` is **not** clean on this branch and was not clean at `47fc577` either:
`kernel/stozher-kernel/tests/open_defects.rs` carries two pre-existing diffs, untouched here.
`rustfmt --check` on the two files this entry changed exits 0.
