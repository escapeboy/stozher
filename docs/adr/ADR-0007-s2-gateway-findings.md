# ADR-0007: Findings from the S2 gateway implementation

**Status:** Accepted · **Date:** 2026-07-26 · **Arises from** S2 (`feature/s2-gateway`)
**Amends** `spec/04`, `spec/05`, `spec/08`, `spec/10` · **Builds on** ADR-0004, ADR-0005, ADR-0006

Building the gateway against the S0 spec and the S1 kernel surfaced one **open security gap** and
six spec under-specifications. Recorded per ground rule 8 — deviations and gaps are never silent.

---

## 1. OPEN SECURITY GAP — revocation is not checked on the hot path

**This is the most important item in this ADR and it is not closed.**

The gateway calls `verify_mandate_chain` with an **empty revocation set**. It holds one session
mandate, and there is no kernel endpoint that lists revocations (`GET /v1/envelopes` has no `kind`
filter).

**Consequence:** a revoked mandate is caught by the kernel at ingest — that is, **after the effect
has already been applied to the world.** Revocation is therefore detective, not preventive, on the
gateway path. For a product whose pitch is preventive control, that is a real gap, not a nit.

It does not make the audit wrong: the envelope is refused, the rejection is recorded, and the chain
shows exactly what happened. But "we noticed after the fact" is not what an operator revoking a
mandate expects.

**Required fix (S3/S4):** a kernel revocation feed the gateway can pull and cache, evaluated on the
hot path before forwarding. Until it exists, revocation latency equals the policy pull interval at
best and "never, until ingest" at worst. **Must not ship to a design partner unfixed.**

## 2. The shipped catalog is invisible to the kernel — resolved by taking the stronger class

`spec/10 §3` makes the Tier B shipped catalog a classification tier. But `spec/05 §3` step 1 orders
reclassify → `by-action` → the **emitting component's manifest** → `default-unknown`. The kernel
evaluates the *gateway's manifest*, not the gateway's catalog.

**Observed live before it was fixed:** a catalog `read` on an action the org policy does not list is
computed `consequential` by the kernel, so the envelope is refused
`policy-component-override-attempt`. The gateway and kernel disagreed about the class of the same
call.

**Resolution implemented:** where policy has no explicit opinion, the gateway takes the **stronger**
of (tier class, `default-unknown`). The two evaluations now agree by construction and the gateway
can never under-declare a class. Cost: an uncatalogued-by-policy `read` is gated.
`stozher-gateway catalog policy-fragment` prints the `by-action` map for the operator to publish,
which closes the loop.

**Spec decision needed:** either `spec/05 §3` gains a catalog tier, or `spec/10 §3` states that a
catalog class is **advisory until published as policy**. The second is likely correct — it keeps
the kernel the single source of policy truth, which is the whole enforcement-topology argument.

## 3. Org-seeded catalog entries have no path into force at the kernel

Same root cause. `spec/10 §4.3` calls first-call seeding "a policy change … §05 §5", but the emitted
`kernel.seed_catalog_entry` action is stored by the kernel as an **ordinary effect, not as policy**.
Today the seed is authoritative for the gateway only; the e2e test shows the operator subsequently
publishing the class as a real gated policy version.

**Open for S4/S5:** whether seeding should *publish* a policy version directly. Note the tension —
auto-publishing policy from a single approval is exactly the kind of thing
`docs/design/policy-model.md` tier 3 says must pass the same gate as any policy change.

## 4. `gateway.session_open` cannot be `benign` on its own

`spec/10 §1.6` requires class `benign`, but `default-unknown` is `consequential`. An org that does
not classify it would gate its own session opens, and the kernel would then refuse the envelope as
an override attempt.

**Resolution:** the gateway refuses to start and names the exact policy entry to add — fail loud at
startup rather than fail confusing at first call. **The shipped baseline profile must classify the
gateway's own bookkeeping actions** (S5 bootstrap).

## 5. "Parking is synchronous" vs "never block inside a sync handler"

`spec/06 §4.2` says parking is synchronous from the caller's perspective. The integration brief
(correctly, from observation) forbids a blocking wait inside a sync tool handler — it would stall
the entire MCP server, including concurrent `await_inbox` calls.

**Resolution:** park returns the `parked` structured refusal **immediately**; the approval then
covers a subsequent identical call (bound by request-hash, so it is the *same* call, not a similar
one). **Spec text needed** stating that a `parked` refusal is a legitimate terminal response and
that an approval binds a later identical request.

## 6. A refused envelope wedges its stream

A locally-chained envelope that the kernel refuses means every later envelope on that stream is
refused `chain-seq-gap`. `spec/04` defines no recovery procedure.

Current behaviour: the gateway logs an ERROR naming the stream, the rejection lands in the kernel's
rejection stream, and the local chain keeps the record — so nothing is lost or hidden. But the
stream is stuck until an operator intervenes. **Open decision:** stream rollover vs. an explicit gap
record. `spec/04` needs one or the other.

## 7. `execution.target` granularity for proxied calls

The gateway can honestly name only `mcp:<server>`. A finer target needs a manifest-declared
`target-kind` extraction rule (`spec/08`).

**Consequence:** resource-scoped mandates are writable only at server granularity today. This is the
right call — inferring a finer target from arguments would be a *guess* in the field that mandates
are checked against, and a wrong guess there silently widens or narrows authority.

## 8. ADR-0006 §6 confirmed empirically

Aggregates carry no resource, so a mandate whose `resources` scope is narrower than `["-"]`/`["*"]`
cannot cover aggregated reads. Predicted at S1, observed at S2.

---

## Deferred, with reasons (all recorded, none forgotten)

| Item | Why deferred |
|---|---|
| Per-request caller resolution on shared HTTP transports | One caller per process today (`STOZHER_GATEWAY_CALLER`, authenticated against `token_sha256`); a multi-caller config **refuses to start rather than guess whose authority to use** — the right failure. Matches stdio's one-process-per-connection model; HTTP needs middleware Harbormaster owns |
| Tier A manifest loading; `kernel.register_component` + conformance run | Classifier supports Tier A, nothing loads one yet. `spec/08` harness is its own body of work |
| Shipped catalog is unsigned (`spec/08 §5` wants the release key) | Signing belongs with S5 packaging |
| `offline: degrade` | Gateway blocks instead. `degrade` needs manifest-declared reduced forms — cannot be invented per-tool |
| `revoke-cached` parsed but not acted on | No forced re-pull before next consequential action. Related to finding #1; fix together |
| Notification adapter, kernel-native pending queue | S4 by design |

## What is real vs. stubbed in the S2 gate

**Real:** compiled `stozher-kernel` serving HTTP over SQLite, bootstrapped through the real
two-envelope genesis ceremony (ADR-0006 §2); a real `python -m harbormaster --transport stdio`
process loading the gateway through Harbormaster's own `load_plugins`; a **stock
`mcp.ClientSession`** over stdio whose agent side imports nothing from `stozher_gateway` (asserted
by AST parse); a real unmodified downstream FastMCP server; real Ed25519 throughout; real chain
verification via `/v1/streams/{stream}/verify`.

**Stubbed pending S4:** only the *transport and notification* of the approval — the parked request
and signed decision travel through the gateway's local SQLite rather than a kernel-native pending
queue. **This is not a bypass.** There is no ambient flag and no boolean: a row in that table
permits nothing until `verify_authorization` passes request-hash binding, signature validity,
self-approval rejection, approver membership, request and approval expiry, field-by-field action
match, and replay. Two negative tests prove it, including one that tampers a field the row lookup
does *not* key on — so the hash binding, not the lookup, is what refuses.
