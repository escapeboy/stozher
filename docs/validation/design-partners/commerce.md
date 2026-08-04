# Stozher — design-partner evaluation, revenue operations

**Domain.** Mid-size e-commerce, ~200k orders/month (~6,700/day). Agents change prices, apply and
expire promo codes, issue refunds, cancel and reship orders, send transactional and marketing email,
adjust inventory, and set ad budgets on three platforms.

**What I ran.** `deploy/gate/clean-install.sh --port 8834` on commit `96b9811`, isolated compose
project `stozher-commerce`, own image tags. Then my own downstream MCP server
(`deploy/demo/commerce_server.py`, 16 tools), my own signed policy
(`2026.08.commerce.1`), ~280 governed tool calls, 41 human signatures, a 30-day clock advance,
a kernel outage, and an auditor export.

**Verdict up front: no. I would not put this in front of real money today** — not because the idea
is wrong, but because the shipped release gate is red, the queue caps out at 8% of my daily volume
and discards the overflow without a record, and the one dimension my domain is actually about — the
amount — is invisible to every control the system has.

---

## 0. The install is broken at HEAD

`./deploy/gate/clean-install.sh` **failed**, exit 1, at step 5:

```
GATE FAILED: the approved call did not reach the downstream server — the approval bought nothing
{"event":"call","tool":"notes__write_note","is_error":true,
 "text":"Error executing tool notes__write_note: 'NoneType' object is not subscriptable"}
```

I reproduced it by hand, single run, no concurrency: park → `bin/stozher-approve` → identical call
again → same Python `TypeError`. After the whole exercise the audit trail held **zero** applied
`notes.*` effects.

**Root cause** (`gateway/src/stozher_gateway/enforce.py:1159`):

```python
seed_hash = str(parked.seed["decision"]["request-hash"])
```

The first call to an unknown tool parks **two** requests: the call itself, and a separate
`kernel.seed_catalog_entry` request that classifies the tool. `bin/stozher-approve` answers exactly
one hash. On the retry, `_consume` sees the tool still uncatalogued, calls `_seed_catalog`, whose
guard checks `parked.seed is None` but never `parked.seed["decision"] is None` — and that member is
literally `None` for an unanswered seed. The sibling call site (`seeded_pending()`) filters this in
SQL; the `_consume` path bypasses that filter. The exception is swallowed upstream into a tool-error
string, so there is no traceback anywhere — I had to read the source to find it.

The code around it is dated today (`6422e4d`, `d30a4f0`, "fix(DEF-7)"), which is the same day v1.0
was declared. **The executable definition of done was not re-run before the label went on.**

Blast radius: it hits only the *unknown-tool* path — precisely the path `README.md` sells as "the
first fifteen minutes" and the one the gate measures. Once I published a policy naming my tools by
action, park → approve → retry worked perfectly. So the fix for an operator is "never let a tool be
unknown", which is the opposite of the shipped first-call-gate story.

**The README's headline "169 seconds to first audited envelope" is not reproducible at HEAD.**

Other install friction, in order of how much time it cost me:

- Adding my own downstream MCP server required a **gateway image rebuild** (`COPY deploy/demo/`).
  `deploy/README.md` says this, fairly. It still means every tool addition is a rebuild plus a
  restart of every employee's MCP client.
- `bin/stozher-approve` runs `docker run -i` and **drains its caller's stdin**. My first batch loop
  approved exactly one request out of 26 and reported success. Anyone who writes the obvious
  `while read h; do stozher-approve "$h"; done < hashes` gets a silent one-of-N. Needs `</dev/null`.
- The pending queue is **HTML only**. There is no JSON route for it (`/v1/gate/requests/{hash}`
  fetches one you already know). To wire approvals into Slack/PagerDuty with context you scrape
  `/console/pending`. The kernel's notification channels give you a ping per park but no way to
  enumerate or triage the queue.
- Mandate ids render truncated to 12 hex on `/console/mandates`; the full 64 is in the HTML but not
  selectable as such. `--mandate <64 hex>` wants the full one.

---

## 1. Is the pending queue a daily driver?

**No. It is a rubber stamp, and it became one for me in under an hour — not three days. And before
it became a rubber stamp it had already stopped being a queue at all, because 71% of my day's
consequential work was refused outright rather than queued.**

### The numbers

One simulated morning (`deploy/gate/make_day.py`), 233 calls in a single session:

| outcome | count |
|---|---|
| reads allowed (`query_analytics`, `get_order`, `get_product`) | 80 |
| benign applied (`add_internal_note`, `send_transactional_email`) | 60 |
| **consequential → parked** | **27** |
| **consequential → `gate-rate-limited`, `retryable: false`** | **66** |
| prohibited hard-blocked (`purge_customer`) | 1 |

The cap is `per_subject: 30`, `window_seconds: 300`
(`kernel/stozher-kernel/src/config.rs:113-124`). Its own comment reads:

> *"Ordinary work does not come close: a gated action is one a human is about to be asked about, not
> one an agent performs in a loop."*

That is a stated assumption about volume, and my domain violates it on day one. My real daily
consequential load is roughly **360 actions** — ~300 refunds (4.5% of 6,700 orders) plus ~60 price
changes, cancels, reships, promos, inventory corrections, ad-budget moves and blasts. Refund sweeps
arrive in bursts after the morning support queue, which is exactly the shape the limiter punishes.

The failure mode is the problem, not the cap. `retryable: false`, and the hint says
*"nothing is pending: the request never entered a queue."* The refund does not happen. The customer
does not get their money. Nobody is paged. And — see §3 — there is no record of it anywhere.

### Where I stopped reading

I approved the first request honestly, the way `/console/pending` instructs: I took the canonical
arguments block, ran SHA-256 over it, and confirmed it equalled the `args-hash` inside the request
object my key would sign.

```
args  : {"amount_cents":526,"order_id":"d1-ORD-26","reason":"shipping delay"}
sha256: c7e7d43360b02cbccc38aff2167a1b96692133b150ed07e124a52c99ecbf57ba   ✓ matches
```

That worked, and it is a genuinely good property.

Then I looked at the other 26 entries. They were `amount_cents` 526, 525, 524, 523, 522, 521, 520…
`order_id` `d1-ORD-26`, `d1-ORD-25`, `d1-ORD-24… `reason` identical on all of them. The page renders
**2,162 lines of text for 32 entries** — about 67 lines each, most of it the same explanatory copy
repeated verbatim per request.

**At entry two I wrote `deploy/gate/approve_all.sh`.** That was roughly 35 minutes after my first
contact with the system. I did not read entries 2 through 27; I fed a file of hashes to a loop.
26 approvals, **18 seconds** of machine time, 0.69 s each. That is the honest answer to the question:
the queue did not survive one morning.

### The demonstration

I then built a batch of ten refunds, nine at €5.00 and one at **€50,000.00**, deliberately placed
sixth:

```
     BATCH-0       500c  parked          BATCH-5       500c  parked
     BATCH-1       500c  parked          BATCH-6       500c  parked
     BATCH-2       500c  parked          BATCH-7       500c  parked
     BATCH-3       500c  parked          BATCH-8       500c  parked
     BATCH-4       500c  parked
   BATCH-BIG   5000000c  parked
```

`approve_all.sh` → `approved=10 failed=0 seconds=7`. Retry → all ten `APPLIED`, including
`BATCH-BIG`. The €50,000 refund now carries a named human's Ed25519 signature over its exact
`args-hash`, in a hash-chained envelope that verifies. **That human read nothing.** The audit is
perfect and the control was zero.

### The other half nobody counts

I produced **41 `gate-decision` envelopes** and only **11 refunds applied**. An approval does not
execute anything — the *agent must call again*. Most of my approvals bought nothing because the
agent had already received a terminal `parked` refusal and moved on. In production this means the
human does the work and the effect still does not happen unless the orchestrator is written to
re-drive approved intents. Nothing in the docs warns that "approved" and "done" are different states
with no bridge.

### What it would actually cost

At 360 gated actions/day, at a generous 20 seconds each (glance, run the command), that is
**2 hours/day**. At the verification the console itself prescribes — copy the arguments to a file,
shasum, compare 64 hex characters, then run the approve command — it is 60–90 seconds each, i.e.
**6–9 hours/day**. It is a full-time job, and the job is one whose entire content is comparing
hex strings, which is the job humans are worst at.

Splitting agents into separate subjects (`agent:refunds`, `agent:pricing`, …) would multiply the
rate-limit headroom. It would not change the 360 signatures. And the rate limiter exists
*specifically* to bound approval fatigue (`spec/09 §7`), so evading it by sharding subjects defeats
the control on purpose.

---

## 2. Does the four-class taxonomy survive my domain?

**Three of the four classes survive cleanly. `consequential` collapses, because it is asked to carry
the entire range from a €5 goodwill credit to a €50,000 wire, and it has no dimension to tell them
apart. Class-plus-budget is not enough. The taxonomy needs an amount-aware dimension it does not
have, and cannot easily be given, because classification never sees argument values.**

### My mapping

| Class | My actions | Verdict |
|---|---|---|
| `read` | `get_product`, `get_order`, `query_analytics` | fits perfectly; 80 reads folded into 4 `aggregate` envelopes |
| `benign` | `add_internal_note` | fits |
| `benign` (forced) | `send_transactional_email` | **does not fit.** ~6,700/day, irreversible (you cannot unsend), and expected by the customer. Gating is arithmetically impossible; so I classified it `benign` and accepted that an agent can email every customer "your order is cancelled" with no gate. There is no class for *irreversible but routine*. |
| `consequential` | `set_price`, `bulk_reprice`, `issue_refund`, `cancel_order`, `reship_order`, `create_promo`, `expire_promo`, `adjust_inventory`, `set_ad_budget`, `send_marketing_blast` | **the class does too much** — see below |
| `prohibited` | `purge_customer` | fits, and works: refused instantly, recorded `outcome: "attempted"`, visible on `/console/attempts` |

`prohibited` is the best-designed part of the taxonomy. It is evaluated *before* mandates
(`spec/05 §3`), so no grant can widen it, and the attempt is still recorded. I would use it.

### Where `consequential` breaks

Two calls that differ by four orders of magnitude in money:

```
issue_refund(order_id="BATCH-4",   amount_cents=500)      → consequential, gated
issue_refund(order_id="BATCH-BIG", amount_cents=5000000)  → consequential, gated
```

They differ in exactly one field of the whole governed record: `args-hash`. Same action, same class,
same target, same gate rule, same approver, same everything an approver's eye is drawn to.

`bulk_reprice(collection="winter-clearance", multiplier="0.80", sku_count=41200)` — one call, 41,200
SKUs — is the same class as `set_price` on one SKU. `send_marketing_blast(recipient_count=203441)` is
the same class as `create_promo`. **The unit of governance is the verb; my risk is in the noun.**

### Why policy cannot fix it

Classification matches on three dimensions only — `subject`, `action`, `resource`
(`spec/05 §3.1`). I checked what `resource` actually is for a proxied call: it is the *server*.

```
"target": "mcp:commerce"
```

Every commerce tool shares it. So `reclassify` cannot even discriminate between `issue_refund` and
`get_product` by resource, let alone by amount. I wrote the entry I wanted to write and left it in my
published policy with the reason recorded, because it is the honest artifact:

```json
{ "subject": "agent:refunds-small", "action": "commerce.issue_refund", "class": "consequential",
  "reason": "we want small refunds allowed and large refunds gated; there is no dimension here for
             the amount, so every refund gets the strict answer" }
```

The amount lives inside `args-hash`, which is a SHA-256 digest by construction — policy cannot read
it, and `spec/06 §1.1` is explicit that the request "does not carry" the arguments and MUST NOT.
That is a good security property and it is the same property that makes amount-aware policy
impossible in the current shape.

### The budget does not help — I measured it

The comparison logic is *excellent*. I ran the full corpus against the shipped implementation:

```
money-compare: 31 passed, 0 failed, 31 vectors
```

Exact decimal comparison, `9007199254740993 > 9007199254740992` correct, refusals for signs,
exponents, whitespace, `.5`, `5.`. Someone thought hard about this and got it right.

**But it is measuring the wrong money.** `spec/03 §4.3`: *"accounting inputs are `cost` in cognition
envelopes and the emitter's declared budget dimensions"* — i.e. inference cost. And the gateway only
ever accrues one dimension (`enforce.py:598`):

```python
adding = {"requests": "1"}
```

Live proof, after 76 refund attempts moving real money through my mandate:

```json
GET /v1/mandates/e434a940…/budget
{"budget": null, "spent": {"requests": "73"}}
```

`money-eur` never moved once. A `money-eur` budget on a mandate caps **what the agent costs to run**,
not **what the agent can spend**. So the sentence a CFO wants — *"this agent may refund at most
€5,000 per day"* — cannot be written anywhere in this system: not as a class, not as a mandate scope,
not as a budget.

The nearest available approximation is a `requests` cap, which bounds the *number* of refunds and
says nothing about their size. 300 × €5 and 300 × €50,000 are the same budget.

### What is missing, concretely

An **amount-aware dimension** with three parts:

1. A declared, typed quantity on the action — the emitter states `value: {"money-eur": "500.00"}`
   the way it already states `cost`, committed to by `args-hash` so it cannot be lied about without
   breaking the approval binding.
2. A **threshold in `gate-rules`** — `{"classes":["consequential"], "when":{"money-eur":{"above":"1000"}},
   "decision":"gate", "approvers":["human:cfo"]}` — so €5 is `allow`, €1,000 is one approver,
   €50,000 is two.
3. A **spend budget** separate from the cost budget, so the €5,000/day sentence exists.

Without (1) none of this is safe, because the amount would be self-reported by the very agent being
governed. With (1) it is exactly as safe as the rest of the system: the approver's signature already
binds `args-hash`, so a declared value that contradicts the arguments fails step (10) of
`spec/06 §2`. The hook is already there; nothing uses it.

Until then, the only real control I have is *"is this agent allowed to touch refunds at all"* — a
boolean — and my actual policy is a curve.

---

## 3. Findings I did not go looking for

### 3a. Offline, the refusal lies

`deploy/README.md` and my policy both say `offline.consequential = block`. With the kernel genuinely
stopped (`docker compose run --no-deps`, because the documented command auto-starts the kernel via
`depends_on`), a refund came back:

```json
{"result": "parked", "reason-code": "gate-parked", "classification": "consequential",
 "classification-tier": "heuristic", "retryable": false,
 "hint": "pending request 4d3d8e055542730dc591d1e464c3621055a8675f2971…"}
```

I restarted the kernel and looked for it:

```
OFFLINE-UNIQUE-7788 in pending queue: 0
GET /v1/gate/requests/4d3d8e05… → 404 {"reason":"no such parked request"}
```

**The agent is told a human was asked. No human was asked, no request exists, and none ever will.**
In my shop that reads back to a support rep as "refund pending approval" and the customer waits
forever. It should say `blocked`, with an offline reason code — the spec even has
`policy-stale-offline`. This is the single most dangerous thing I found, because it is silent and it
is on the availability path where nobody is watching.

Related: `classification-tier` came back `heuristic` **even when online and even for actions my
signed policy names explicitly by `by-action`**. The code has a separate `policy_named` flag
(`classify.py:88-93`) that would disambiguate; the refusal document does not expose it. For an
auditor asking "how was this classified?", the answer shown is wrong.

### 3b. Refused work leaves no audit trail

66 consequential money actions were refused `gate-rate-limited`. I searched everywhere:

```
rate-limited request hash anywhere in /v1/envelopes : False
any envelope with outcome "blocked"                 : False
GET /v1/rejections                                  : {"count": 0}
/console/attempts                                   : 1 entry (the prohibited purge_customer)
issue_refund envelopes of any outcome               : 1   (at that point)
```

`spec/05 §3` promises `outcome: "blocked"` with an envelope for mandate and budget failures, and the
prohibited path does record an `attempted`. But a request the *kernel refuses to queue* produces
nothing at all. For a product whose entire pitch is "who did what, under whose authority", **76
attempted refunds and one record** is the wrong answer. The only trace was my agent's stdout, which
is exactly the ungoverned surface this exists to replace.

### 3c. A month later, the agent says "Unknown tool"

I advanced the clock 30 days (ADR-0023, declared in both components). Everything behaved as
documented — and one thing did not.

Stale approvals refused precisely, which is right:

```
gate-request-expired: decided at 2026-09-03T17:11:42Z, the request expired at 2026-08-04T18:10:49Z
```

But the standing mandate (`P30D` out) had expired, and what the agent saw was:

```
Error: Unknown tool: commerce__issue_refund
```

The reason is in gateway stderr, which an MCP client discards:

```
ERROR stozher_gateway.plugin — enforcement mode did not start: mandate-expired
```

It **fails closed** — the governed tools are not proxied at all, no ungoverned passthrough — and I
want to credit that, it is the right direction. But `delegation.max-standing-lifetime` is `P90D`, so
every agent in the fleet stops dead at most every 90 days, and the message that reaches the on-call
engineer at 3am is "Unknown tool". They will look for a deployment bug for an hour.

Combined with §3a: the two states an operator most needs to tell apart — *waiting on a human* and
*not working at all* — are the two the agent-facing surface reports most misleadingly.

### 3d. Parked work dies quietly

Parked requests expire after an hour. The agent already got `retryable: false`, so it never retries.
An ad-budget change that had to land at 09:00 and was not signed by 10:00 is simply gone, and the
only trace is a queue entry nobody re-reads. There is no dead-letter, no re-drive, no escalation.

---

## 4. What genuinely worked

Credit where it is due, and this list is not short:

- **The gate property is real.** I tried to make the kernel sign for me and there is no route that
  does it. `approved: true` is rejected as `schema-unknown-member`. Signing happens in my process
  with my seed; the network path holds no key. The copy-paste friction is the price and it is
  honestly priced.
- **The policy publication flow is excellent** — `policy-draft` from the document actually in force,
  sign offline under `--network none`, park, a *different* command for the human to approve, then
  `--resume`. Five steps, a real human in the middle, and the script deliberately refuses to sign
  its own approval even though it holds the seed. This is how the whole product should feel.
- **`prohibited` works exactly as advertised.** Hard-blocked before mandate evaluation, recorded as
  `attempted` with full evidence.
- **Read aggregation is right.** 80 reads collapsed into 4 `aggregate` envelopes. The audit does not
  drown in `get_order`.
- **Retention and decay work, and the chain survives them.** A forced sweep decayed a large batch of
  payload hashes, checkpointed first, and afterwards `verify` reported *all 3 streams verify*,
  anchored. The second sweep was idempotent (`payloads-deleted: 0`). The claim "closed loops decay to
  signed hashes" is one the system actually delivers.
- **Evidence payloads carry the amount and are retained by class.** The €5 refund's payload was
  still fetchable with `retain-until 2027-08-04`, holding
  `{"amount_cents":500,"order_id":"BATCH-8","reason":"shipping delay"}`. So *post-hoc* I can
  reconstruct exactly how much money moved. That is a real capability and it is what makes me say
  "not yet" rather than "no".
- **The auditor export is a genuine deliverable** — 146 self-contained signed NDJSON records,
  including checkpoints, in one authenticated GET.
- **The `args-hash` verification the console prescribes actually checks out.** I did it by hand and
  it matched. The chain from what an approver reads to what their key signs is closed.
- **The clock override did exactly what ADR-0023 says**, including the warning line on startup, and
  it refuses to go backwards.
- **`clean-install.sh` fails loudly and correctly.** It caught its own product's regression and said
  so in one red line. I would rather have a gate that fails than one that does not exist.

---

## 5. Ranked adoption blockers

1. **`clean-install.sh` is red at HEAD** (`enforce.py:1159`). The first-call gate — the flagship
   demo — crashes after approval and the effect never happens. Ship nothing until the release gate
   is green, and add a regression test for *approve the call but not its catalog seed*.
2. **Volume.** 30 parks/subject/5 min, and the overflow is `retryable: false` **lost work**, not
   deferred work. At 360 gated actions/day this discards ~92% of my refunds. Needs a real queue with
   backpressure, or the cap needs to be a documented deployment decision with a dead-letter.
3. **No amount dimension.** €5 and €50,000 are the same class, and the `money-eur` budget counts
   inference cost, not transacted value. Until a declared value can reach `gate-rules`, this system
   cannot express any policy my finance team would recognise.
4. **Refused work leaves no audit trail.** 66 attempted money actions, zero envelopes, zero
   rejections, zero attempts entries. This contradicts the product's core claim.
5. **Offline reports `parked` for requests that were never queued.** Silent, on the availability
   path, and it makes "waiting on a human" indistinguishable from "gone".
6. **Approval ≠ effect.** 41 signatures produced 11 effects. There is no re-drive path and no
   documentation of the gap.
7. **Approval ergonomics guarantee rubber-stamping.** 67 lines of near-identical text per entry, a
   64-hex hash to copy, one CLI invocation each. Needs: per-entry diffing against a baseline, a JSON
   queue endpoint, grouping of identical-shaped requests, and — most of all — something that makes
   the €50,000 row *look different from* the €5 row.
8. **Mandate expiry surfaces as "Unknown tool."** Fails closed, which is right, but undiagnosable.
   The MCP error should carry the reason code.
9. **`classification-tier` says `heuristic` for policy-named actions.** Exposes the wrong field to
   the one person who needs the right one.
10. **`bin/stozher-approve` eats its caller's stdin**, so the obvious batch loop silently approves
    one of N and reports success. Small bug, ugly failure.
11. **Operational surface gaps**: HTML-only pending queue, image rebuild per downstream server,
    truncated mandate ids.

---

## 6. Would I keep it after a month, and what would make me turn it off

**I would keep it running in shadow mode over `read` and `benign` traffic, and I would not route a
single refund through it.**

What I would keep it for is not the gate — it is the **record**. The append-only chain, the
per-class retention, the auditor export, and the fact that `verify` still returned *all 3 streams
verify* after a decay sweep are things I cannot buy elsewhere and cannot build in a quarter. If the
EU AI Act conversation lands on my desk, this is the artifact I want to hand over.

What would make me turn it off, in the order I expect it to happen:

1. **The first lost refund that becomes a chargeback.** `gate-rate-limited`, `retryable: false`, no
   audit record. When finance asks "what happened to these 66 refunds" and the answer is "the
   governance system dropped them and did not write it down", the system is off that afternoon.
2. **The first €50,000 mistake approved by a batch loop.** It will happen, because I wrote that loop
   on day one and so will everyone else. When the post-mortem says "the control produced a signature
   and no scrutiny", the control is worse than nothing — it moves liability onto a named human who
   genuinely did not look.
3. **An agent stuck reporting "Unknown tool" at 3am** because a 90-day mandate lapsed, and an hour
   of on-call spent looking in the wrong place.
4. **A support queue full of "refund pending approval"** for requests that were never queued because
   the kernel was down for six minutes.

None of those are the *idea* failing. The primitive is good, the gate property is real and
structurally enforced, and the design record is the most honest engineering documentation I have read
in a long time — the README's *"What this is not"* section told me the truth about half of what I
then found. The problem is that this v1.0 is scoped for a domain where consequential actions are
rare and roughly interchangeable. Mine is a domain where they are constant and differ by four orders
of magnitude in blast radius, and the taxonomy has no place to put that number.

**Plain sentence: no — I would not put this in front of real money today, because the one thing my
domain is about, the amount, is the one thing the system cannot see, and because the release gate
that is supposed to prove the basics is failing at HEAD.** Give me a declared, `args-hash`-bound
value in `gate-rules`, a real queue instead of a rate limiter that drops money on the floor, and a
green `clean-install.sh`, and I will run the refund agent through it and mean it.

---

### Reproduction notes

Everything above was run in `deploy/` of this worktree, compose project `stozher-commerce`, kernel on
`127.0.0.1:8834`, images `stozher-commerce-{kernel,gateway}:0.1.0`. Files I added:
`deploy/demo/commerce_server.py`, `deploy/gate/agent_drive.py`, `deploy/gate/make_day.py`,
`deploy/gate/approve_all.sh`, `deploy/gate/q.py`, `deploy/gate/pending.py`,
`deploy/config/policy-2026.08.commerce.1.json`. Nothing in the repository's own code was modified and
nothing was committed. The live `stozher` deployment on 8787 was not touched.

The clock on this deployment is advanced 30 days and cannot be moved back; its records are not
evidence of when anything happened.
