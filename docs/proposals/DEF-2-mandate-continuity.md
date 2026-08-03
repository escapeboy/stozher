# DEF-2 — mandate continuity: the normative text permits the silence

**Status:** proposal. Nothing under `spec/` was edited to produce this document.
**Classification:** **SPEC HOLE**, with one implementation defect found alongside it (§5).
**Evidence:** `gateway/tests/test_def2_mandate_swap.py`, `kernel/stozher-kernel/tests/def2_mandate_swap.rs`.

---

## 1. The finding, in one paragraph

A component whose envelopes the kernel is **refusing** is, to `spec/`, a component that is merely
**behind**. The specification's model of an emitter has two states — chained locally, and synced —
and treats the distance between them as latency (maxim 5; §04 §3: *"Offline emitters chain locally
with the same rule and sync later"*). A permanent refusal is a third state, and the normative text
names it exactly once, descriptively, in a rationale bullet about revocation (§03 §7). Every MUST
that fires in that state lands on the **kernel**, and the kernel discharges all of them. Nothing is
required of the component: not to stop serving, not to tell the caller, not even to keep the reason
code it was given. So the gateway serving a week of tool calls into a kernel that accepted none of
them is, as `spec/` stands, conformant behaviour.

## 2. What the normative text actually says

**§03 §7 — the closest the spec comes, and it is descriptive.** The spec has already contemplated
this exact state, for revocation:

> *"Between the revocation and the emitter's next feed pull, the emitter keeps building its local
> chain under a mandate the kernel will refuse. Every one of those envelopes is rejected, the only
> kernel-side record is the rejection record of §04 §7, and **the emitter's stream is wedged at that
> position until an operator intervenes** — §04 §3 admits no gap, so it cannot simply skip past them.
> Nothing is lost and nothing is silently accepted; but an operator who expects revocation to be free
> will find a stopped component and no explanation, and that is worth one sentence here rather than
> one incident."* (`spec/03-mandate.md` §7)

This is the strongest text for the opposite reading, so state its limits precisely: it is a
rationale bullet, it carries no RFC 2119 keyword, its subject is the revocation feed, and *"a stopped
component"* names the **stream** being wedged, not a requirement that the component stop serving. It
also concedes the whole defect in five words — *"and no explanation"* — as an accepted cost.

**§09 §4.2 — the kernel's obligation, and it is discharged.**

> *"the kernel MUST track the last accepted `seq` per stream and MUST surface streams that have gone
> quiet beyond a policy-configured interval — an absent emitter is a finding, not a null result"*

That is the `7d — quiet` row the evaluation eventually saw. It fired as specified. The interval is
`checkpoint-interval` (`console.rs::quiet_after_seconds`); until it elapses, the row of a stream
being actively refused is byte-identical to the row of a stream with nothing to say. Asserted in
`def2_mandate_swap.rs`.

**§04 §7 — the kernel's other obligation, also discharged.**

> *"An ingest rejection MUST be recorded with: the reason code, `object-hash` of the rejected bytes
> as received, the submitting connection's authenticated subject (if any), and the timestamp …
> MUST be visible in the console."*

All four refusals were recorded with their reason codes. Asserted in `def2_mandate_swap.rs`.

**§06 §6 — "Never silently proceed" — is satisfied.** Its table is over *terminal states of an
action*, and its non-conformance test is *"a code path that returns success without emitting"*. The
gateway emitted: durably, chained, signed, before applying (§09 §4.1). The envelope exists. It simply
never reaches the audit anyone queries. §06 §6 does not reach the difference.

**§05 §7 — "Silently proceeding is never permitted for any class"** — same answer, and worse: its
`allow` row explicitly blesses the behaviour (*"proceed under cached policy, queue envelopes
locally"*). The clause distinguishes proceeding-without-a-record from proceeding-with-one; it does
not distinguish a queue that will drain from a queue that never will.

**§10 §1.4 — the session mandate.**

> *"A session without a resolvable, unexpired mandate MUST be refused at connect time with
> `mandate-unresolved` or `mandate-expired`."*

`resolvable` names no resolver. The gateway resolved it — it read the file, checked the grantee key,
the kind and the expiry (`runtime.py::_mandate`), and its per-call §03 §5 walk then accepted it
against the roots in its own configuration. Under the only reading the text supports, §10 §1.4 was
satisfied at connect time by a mandate the organization's kernel would never accept. This is the
single sentence most in need of a resolver.

**Is there a vector for a mid-stream mandate change?** **No.**

```
$ grep -rn "mandate-unresolved\|swap\|rotat\|mid-stream\|replace" spec/vectors/*.json
spec/vectors/mandate-chain.json:1342:        "error": "mandate-unresolved"

$ grep -o "wedge\|quiet\|push\|sync\|rejection\|refused\|last-accepted" spec/vectors/*.json | sort | uniq -c
   1 spec/vectors/index.json:refused        # the word, in money-compare's description
  21 spec/vectors/money-compare.json:refused
   1 spec/vectors/parity.json:quiet         # "cannot quietly lose the key check", unrelated
```

The one hit is `mandate-chain.json`'s `unresolved-mandate` vector: a pure-function case where
`leaf-ref` is absent from the supplied `mandates` map. It binds the *walk*. Nothing in the corpus
covers a mandate changing under a live stream, a component's sync state, or what either
implementation owes anyone when submissions are being refused. Twenty vector files, and the state
this defect lives in is not among them.

## 3. Proposed normative fix

Three clauses. The first is the load-bearing one; the second makes the state visible where a human
already looks; the third closes §10 §1.4's missing resolver.

### 3.1 New — `spec/05 §7.1`, "Refused is not offline"

Placed in §05 §7 because that is where a component's behaviour when it cannot reach the kernel is
specified, and this is the state §05 §7 currently mis-files as `offline`.

> **7.1 Refused is not offline.** A component's submission has exactly three outcomes, and an
> implementation MUST distinguish them:
>
> | Outcome | What happened | What the component does |
> |---|---|---|
> | `accepted` | the kernel appended it | continue |
> | `unreachable` | no answer: transport failure, timeout, no route | retry; §7's `offline` map governs |
> | `refused` | the kernel answered with a rejection (§04 §7) | this subsection governs |
>
> 1. A component MUST NOT treat a `refused` submission as `unreachable`. The `offline` map governs
>    a kernel that cannot answer, never one that has answered "no": retrying identical bytes is
>    futile (§04 §3 makes the outcome deterministic in the bytes) and the `allow` row would
>    otherwise licence unbounded unaudited operation.
> 2. A component MUST record the rejection's reason code durably against the local envelope, and
>    MUST NOT erase it on any later transition of that row. An operator asked to intervene (§03 §7)
>    can only do so from the reason.
> 3. The component's stream is **wedged** at that position (§03 §7, §04 §3). A component MUST NOT
>    submit past a wedge, and MUST NOT renumber, skip or rewrite the refused position.
> 4. **While wedged**, and for each class, the component MUST apply the `offline` map *and*, in
>    addition:
>    - if the reason code is one of the `mandate-*` family, or `policy-not-published`, the component
>      MUST refuse **every** class, including `read` and `benign`, and MUST NOT serve again until a
>      submission is accepted. Authority that the organization cannot resolve is not authority
>      (ADR-0001), and a `read` performed without authority is still an effect (§10 §1.4);
>    - for any other reason code, the component MUST refuse every class once
>      `policy.wedge-grace` (default `PT5M`) has elapsed since the first refusal. The grace exists so
>      that one malformed envelope cannot stop an organization's tooling faster than a human can
>      read the reason; it is bounded so that the stopped state cannot be waited out.
> 5. A refusal issued under this subsection MUST be the §06 §4.1 refusal object with
>    `result: "blocked"` and `reason-code` set to the kernel's reason code verbatim. The calling
>    agent is told that its effects are not being recorded, in the same shape as every other
>    refusal, and stops (§10 §6).
> 6. Recovery is an operator action and is out of scope here; see the open question in §6 below.

### 3.2 New — `spec/09 §4.2`, third bullet, extending the quiet-stream requirement

> the kernel MUST surface a stream whose most recent submission was **refused** immediately and
> distinguishably from one that has merely gone quiet. Quiet is the absence of evidence; refused is
> evidence. Waiting out the quiet interval before reporting a stream the kernel is actively
> rejecting reports the weaker fact, later.

### 3.3 Amended — `spec/10 §1.4`, naming the resolver

Current text, with the addition in bold:

> A session without a resolvable, unexpired mandate MUST be refused at connect time with
> `mandate-unresolved` or `mandate-expired`. **"Resolvable" means resolvable by the kernel: the
> gateway MUST publish the session mandate and observe its acceptance before serving any call under
> it. If the kernel is `unreachable` (§05 §7.1) at connect time the gateway MAY serve under §7's
> `offline` map with the mandate chained locally, and MUST re-attempt on every reconnect; if the
> publication is `refused`, §05 §7.1 clause 4 governs and the gateway MUST NOT serve.** The gateway
> MUST NOT accept calls and defer the mandate question until the first consequential one: a `read`
> performed without authority is still an effect (exfiltration is a read).

## 4. Vectors that would have to exist

None of these can be met by an existing file; each is a pure function of stated inputs, which is what
makes it vector-able rather than prose. Both implementations must read the expected values from here
(`index.json`: *"consuming test suites MUST read expected values from here and MUST NOT hardcode
them"*).

| New file | `kind` | Binds | Shape |
|---|---|---|---|
| `sync-outcome.json` | `sync-outcome` | §05 §7.1 clauses 1–4 | input: `{ submission-outcome, reason-code, class, elapsed-since-first-refusal, policy: { offline, wedge-grace } }` → expected: `serve` \| `refuse`, plus the `reason-code` the refusal carries. Must include: `mandate-unresolved` + class `read` → `refuse` (the DEF-2 case); `unreachable` + class `read` + `offline.read: allow` → `serve` (the counterfactual that stops "refuse everything" from passing); a non-mandate reason inside and outside the grace. |
| `stream-status.json` | `stream-status` | §09 §4.2 | input: `{ last-accepted-at, last-refused-at, last-refusal-reason, now, quiet-after-seconds }` → expected: `healthy` \| `quiet` \| `refused`. The row the console renders is an implementation's business; the predicate behind it must not be. |
| `mandate-continuity.json` | `mandate-continuity` | §10 §1.4 as amended | a session-lifecycle sequence: mandate M1 published and accepted → effect accepted → mandate file replaced with M2 → publication of M2 refused with a given reason → expected: the next call is refused, with this reason code, and the stream head is unchanged. This is the mid-stream mandate change the corpus has no vector for. |

`envelope-shape.json` and `mandate-chain.json` need no change: nothing here alters an envelope's
shape or the §03 §5 walk. That is deliberate — the fix is entirely in what a component does with an
answer it already receives.

## 5. Found alongside: one implementation defect, not the cause

Independent of the spec hole, and already true under §04 §7's spirit if not its letter:
`emitter.py::push_pending` writes the kernel's reason code into `envelopes.push_error`
(`emitter.py:253`) and then calls `store.mark_pushed`, whose UPDATE is
`SET pushed_at = ?, push_error = NULL` (`store.py:236`). The reason survives one statement. Afterwards
the row is indistinguishable from an accepted one and `pending_push_count()` reports zero, so the
gateway's own state says the push queue is healthy while every envelope in it was rejected. The only
surviving trace is a line on stderr. This is what makes the silence total rather than merely
unhelpful, and it is what §3.1 clause 2 would forbid. Reproduced by
`test_the_kernels_refusal_survives_somewhere_the_gateway_can_be_asked`.

Related but distinct: the gateway does not enforce §03 §3's `delegation.max-standing-lifetime`
ceiling, because the §03 §5 algorithm it implements does not contain that check — the ceiling is
stated in §03 §3 and enforced at ingest (`ingest.rs::validate_mandate_grant`). That asymmetry is the
trigger the reproduction uses; it is not the defect. Any kernel-side refusal of the grant reaches the
same state.

## 6. Open question this proposal does not close

**How a wedged stream is un-wedged.** `docs/spec-debt.md` row 3 already carries it (ADR-0007 §6 asked
§04 for stream rollover or an explicit gap record; §04 still has neither) and marks it blocking. §3.1
above makes the wedge *loud* and *safe*; it does not make it recoverable, and a component that
refuses everything until a submission is accepted needs a conformant way to get one. The two
proposals should land together or the second becomes urgent the moment the first does.
