# ADR-0019: the normative text that had been living in ADRs

**Status:** Accepted · **Date:** 2026-07-31 · **Arises from** `docs/product-completion-design.md`
§3 (v0.9) · **Follows** ADR-0018 · **Closes** asks recorded in ADR-0006 §§4–6, ADR-0009 §1(a)–(c),
ADR-0012 §§1–2

An ADR that says "`spec/06 §5` should gain a clause" and is then filed is a rule that exists only for
people who have read the ADRs. v0.9's gate is an implementation written **from `spec/` alone**, so
every such sentence is a way for that implementation to be correct and fail anyway — or worse, to be
wrong in a way the corpus does not catch. Nine of them are folded in here.

---

## 1. What moved into `spec/`

| Rule | Now in | Asked for by |
|---|---|---|
| The pending queue: `POST /v1/gate/requests`, idempotent by `request-hash`, appends no envelope, append-only, records the authenticated caller separately from the subject, returns decisions verbatim | §06 §4.3 | ADR-0009 (a), (b) |
| Parking is a *terminal answer*; a component MUST NOT block a request handler waiting for a decision | §06 §4.2 | ADR-0009 (c) |
| The gate decision's member set is closed, exactly as the request's is | §06 §1.2 | ADR-0012 §2 |
| `requires-gate` is outcome-conditional — true only for `applied`/`failed`, so a denial record can exist at all | §06 §2 | ADR-0006 §5 |
| A `prohibited` action reported as applied is **accepted and flagged**, never refused | §05 §3 step 2 | ADR-0006 §4 |
| The same for an effect applied past an exhausted budget | §05 §3 step 2 | ADR-0015 §2 |
| Policy cannot lower the bar on the mechanism that enforces policy: five actions are root-approved whatever class policy assigns them | §05 §5 rule 6 | ADR-0012 §1 |
| A conformance run is itself root-approved and commits to the manifest in `target` as well as `args-hash` — with the operational cost stated | §08 §3.3 | ADR-0012 §1 |
| An aggregation record carries no `resource`, so a narrowly-scoped read mandate cannot cover aggregated reads | §02 §7 rule 7 | ADR-0006 §6 |

Two of them deserve their reasoning repeated here, because the naive reading points the other way in
both cases.

**Accepted and flagged.** Refusing an envelope that reports a prohibited action as applied looks
strict and destroys evidence. The kernel records effects; it does not apply them, and by the time
that envelope arrives the act has happened in the world. The only thing refusing it removes is the
record that it happened. `docs/design/policy-model.md` had this right from the beginning —
"attempts are the most audit-valuable records in the system" — and the specification now says it
where an implementer will read it.

**Outcome-conditional gating.** §06 §2 step (1) rejects a gated envelope with no `authorization`,
and §06 §4 rules 5 and 6 *require* denial and timeout envelopes to exist. Read literally, together,
a denial can never be recorded. The resolution has been in the implementation since v0.1 and in
ADR-0006 §5 since then; it is now in the text that step (1) is read against.

## 2. What was deliberately not folded in

**`args-preview` (ADR-0011 §2).** §06 §1.1's member set is closed and every member is REQUIRED, so
an OPTIONAL member is a wire change: every existing request object and every vector would have to be
re-examined against a schema that is no longer the one they were written for. ADR-0011 filed it as a
*versioned protocol amendment* rather than a v0.9 item, and that judgement stands. What ships instead
is what ADR-0011 §1 decided: the console shows the args commitment and states plainly what the
kernel does not hold.

Recording the non-adoption matters as much as the adoptions. A catch-up that silently skipped it
would leave the next reader unable to tell "considered and deferred" from "missed".

## 3. What this does not close

`spec/` is not now the complete record of every decision — ADRs still hold reasoning, alternatives
rejected, and the history of how a rule came to be worded. That is what an ADR is for. What has
changed is that they no longer hold rules an implementer needs and cannot find.

The standing test is the one ADR-0017 §5 states: a clause no vector exercises is a clause two
implementations will disagree about. Six of the nine rules above are checkable only against a running
kernel — the queue's append-only property, the root-approved floor, the idempotence of
`POST /v1/gate/requests` — and are covered by `reject_accept_matrix` and the gate-queue tests rather
than by the corpus. The three that are corpus-checkable (the closed decision set, accept-and-flag,
the aggregate's missing resource) reach it through `envelope-shape` and the matrix's replay.

## Related

`spec/02 §7` · `spec/05 §3`, `§5` · `spec/06 §1.2`, `§2`, `§4.2`, `§4.3` · `spec/08 §3.3` ·
ADR-0006 §§4–6 · ADR-0009 §1 · ADR-0011 §2 (deferred, deliberately) · ADR-0012 · ADR-0017 (the
clauses that were under-specified rather than absent) · ADR-0018 (the reason codes)
