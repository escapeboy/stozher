# ADR-0010: Packaging decisions, and where the gate rate limit lives

**Status:** Accepted · **Date:** 2026-07-27 · **Arises from** S5 (`feature/s5-packaging`)
**Closes** ADR-0007 §4, ADR-0009 §6 · **Deviates from** `spec/09 §7` · **Defers** ADR-0008's console session scheme

---

## 1. DEVIATION — the gate rate limit lives in kernel config, not in policy

`spec/09 §7` states the approver-flood bound is **"policy-configured."** It is implemented in the
kernel's own configuration (`gate-rate-limit`) instead. Recorded per ground rule 8.

**Why, in the order that decided it:**

1. **`spec/05 §1`'s policy member set is closed *and every member is required*** — `policy.rs` loops
   `for required in MEMBERS`. Adding a 17th member is therefore a breaking wire change that
   invalidates **every existing policy document and every S0 test vector simultaneously**. That is
   not a change to make inside a packaging stage, and doing it quietly would have broken the S0 gate
   that everything else is verified against.
2. **It is the wrong home regardless.** Every other policy member authorizes something or changes
   somebody's rights, and components pull and evaluate policy. A queue-depth bound authorizes
   nothing, changes nobody's rights, and no component pulls it. It is an operational property of the
   kernel process, like a port or a timeout.

**Suggested resolution for the spec:** either `spec/09 §7` drops "policy-configured" and names the
kernel configuration, or a future *versioned* policy amendment adds it as an **optional** member —
which also requires `spec/05 §1` to stop requiring every member.

**What was implemented:** default 30 requests per subject per `PT5M`, and it **cannot be disabled** —
`per-subject: 0` and a non-positive window are startup failures. (A cap an operator can zero out on
a busy afternoon is a cap that is off in every deployment that ever needed one.) Refusal is HTTP 429
with `x-gate-rate-limited` (the `x-` register grows 10 → 11, still quarantined per ADR-0006 §9,
because `spec/09 §7` names no reason code either). Per `spec/09 §7`'s second MUST, a spike is
surfaced **as a finding** on the console pending page at half the cap — not as a longer queue.
Three tests: the cap holds *and the window releases*; an identical retry is never counted (a
component retrying after a lost response is behaving correctly, not attacking); an ordinary queue is
not reported as a spike.

## 2. The three ADR-0009 §6 carried-forward items — all closed

**(a) Test intermittency — deterministic fix implemented.** `build_kernel` now copies the binary to
`$TMPDIR/stozher-kernel-<pid>` once per session. `cargo build` replaces
`target/debug/stozher-kernel` **in place**, so a concurrent build in the same tree can swap the file
out from under a kernel the suite is starting — exactly the shape ADR-0009 suspected. **The claim is
correctly bounded: this cannot be said to fix the flake, because the flake was never reproduced and
so there is nothing to re-fail.** It removes the race whether or not that was the cause, and suite
independence from whatever else is compiling is worth having on its own terms. (I hit this same
class of staleness myself during verification — a missing `.rlib` doctest error that vanished on
re-run.)

**(b) `concurrency.rs` — tightened, strictly strengthened, not deleted or ignored.** Previously all
eight racers contended for one chain position, so a loser could lose on position *or* on replay, and
under load all seven could lose on position first — making the replay assertion true only when the
scheduler cooperated. Each racer now sits at seq 0 of **its own stream**, so with no position to
contend for, the only thing that can refuse the other seven is the replay set. The assertion is now
`assert_eq!(reasons.len(), 7)` and **every** loser must be `gate-authorization-replayed`; the
`|| chain-seq-duplicate` escape hatch is gone. Single-position contention is still proven separately
by `only_one_writer_can_take_a_chain_position`, so no coverage was lost. 5/5 consecutive runs.

**(c) Approver-flood cap — implemented**, see §1.

## 3. Console session scheme — deliberately NOT in S5

**Decision: console stays Bearer-only; ship `bin/stozher-console`, a localhost-only, GET-only
header-injecting proxy that runs on the operator's machine; revisit the session scheme together with
browser-side signing.**

1. **A session alone buys the wrong thing** — browser access to a *read-only* view, while adding a
   second credential path into the kernel. The friction worth removing is one-click approve, and
   ADR-0009 §2 is right that this needs browser-side WebCrypto Ed25519 **plus** a session. Shipping
   half the pair leaves the friction and pays the whole cost.
2. **The signing half is a key-lifecycle decision, not a packaging one.** WebCrypto cannot derive a
   SLIP-0010 child of the operator's seed, so browser signing means a **per-device approver key
   enrolled in the root set** — with enrolment, revocation, and ADR-0006 §3's ≥2-root rule applying
   to every such change. That deserves its own stage and its own review.
3. **Shipping it would have required editing an S4 gate assertion.** A `POST /console/login` breaks
   `the_console_still_has_exactly_one_write_verb`. Renegotiating a gate inside a packaging change is
   exactly what ground rule 1 forbids — *"I had to loosen the write-verb test to install the
   product"* is the wrong sentence to write.
4. **The packaging problem is solved without it.** `bin/stozher-console` is operator-side tooling,
   not a third service: it does not touch the two-service constraint, binds `127.0.0.1` only,
   forwards `GET` only (the mutating route needs a signed decision, which belongs in
   `stozher-approve` where key and network stay in separate processes), never logs the token, and
   closing the window closes the access.

## 4. ADR-0007 §4 closed

The shipped baseline profile now classifies the gateway's own bookkeeping actions —
`gateway.session_open` as `benign`, `kernel.seed_catalog_entry` as `consequential` — so the gateway
no longer refuses to start against a default install.

## 5. ADR-0006 §3's ≥2-root prerequisite is now surfaced three times

`genesis` prints a warning naming the consequence, `stozher-bootstrap` repeats it at the end, and
`deploy/README.md` §0 places it **before** the install command with the exact commands the second
root runs on their own machine. A one-root install is **supported and warns** rather than being
refused — maxim 5 (solo is not a mode) requires that it work on a laptop.

## 6. Deferred, with reasons

- **`mypy --strict tests/`** — 3 pre-existing `import-untyped` errors on `harbormaster.*`; neither
  the PyPI wheel nor the local checkout ships `py.typed`. Fixing needs either a per-module override
  (forbidden — no suppression baselines) or upstream shipping `py.typed` (read-only to us per
  ADR-0005). **Left visible rather than papered over.** `src/` alone is clean.
- **Every proxied tool parks on first call, including reads** — the documented cost of ADR-0007 §2's
  stronger-of-(catalog, `default-unknown`) rule. The operator publishes
  `stozher-gateway catalog policy-fragment` to make reads flow. The demo server's tools were
  deliberately **not** pre-classified: Variant B is more honest when the partner's own tools park.
- **TLS** — the images terminate none; compose publishes `127.0.0.1` only and the README states the
  expectation per `spec/09 §8` rather than implying protection.
- **`govern_native_tools = false`** in the generated gateway config, with the reason in the file:
  `true` classifies Harbormaster's own tools by `default-unknown` and parks all of them — a terrible
  first fifteen minutes. Flagged as an operator choice, not hidden.
- **Gateway image ships no `npx`/node** — a partner's npm-based MCP servers need either a line in
  `Dockerfile.gateway` or the documented host-run form. Both are in the README.

## 7. Incidental bug found and fixed

`gateway/tests/test_cli.py::test_config_check_names_every_missing_prerequisite` asserted "the kernel
is unreachable" against the **default** URL `127.0.0.1:8787` — which is the port
`deploy/docker-compose.yml` publishes. **The test failed for anyone who had actually installed the
product.** Now points at `http://127.0.0.1:1`; the assertion is unchanged, only its independence
from the developer's machine.
