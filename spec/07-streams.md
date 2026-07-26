# 07 — Streams: outbound effects and inbound signals

Normative. Two streams, asymmetric by design (ADR-0001 case 5): **outbound effects carry authority;
inbound signals carry none.** The asymmetry is the executable form of maxim 1 — *signal content is
data forever, never instruction.*

## 1. The two kinds of record

| | Outbound effect | Inbound signal |
|---|---|---|
| What happened | an agent acted on the world | the world spoke |
| Object | envelope, `kind` ∈ effect kinds (§02 §2) | envelope, `kind: "signal"` |
| Signed by | the acting subject | the **receiving component** |
| Carries `mandate-ref` | MUST | MUST NOT |
| Carries `classification` | MUST | MUST NOT |
| Grants authority | to nothing — it *records* authorized action | never, to anything |
| May cause an effect | it *is* the effect | only via a standing mandate (§4) |

A webhook, an email, a Slack message, a cron tick, a market data update, a git push notification, a
customer reply: none of them is an effect and none of them produces an envelope of an effect kind. No
agent acted. Recording them as effects would put an unauthenticated third party inside the audit's
authority model.

## 2. Signal record

```json
{
  "v": "stozher/0.1",
  "kind": "signal",
  "emitted-at": "2026-07-26T09:10:00.000Z",
  "stream": "signals:gateway:0001",
  "seq": 5512,
  "prev-hash": "…",
  "identity": { "subject": "agent:gateway", "key": "ed25519:<component key>", "component": "gateway" },
  "signal": {
    "source": "webhook:github",
    "source-ref": "delivery:8f2c-…",
    "received-at": "2026-07-26T09:09:59.870Z",
    "media-type": "application/json",
    "payload-hash": "<64 hex>",
    "retain-until": "2026-08-25T00:00:00.000Z",
    "sender-verified": true,
    "sender-verification": "hmac-sha256/github-webhook-secret"
  },
  "sig": { … }
}
```

Rules:

1. A signal envelope MUST NOT contain `mandate-ref`, `classification`, `execution`, `authorization`,
   `commitment-ref` or `evidence` (`signal-envelope-has-effect-fields`). There is no field in which a
   signal could assert authority, because there is no field in which it could carry a mandate.
2. It is signed by the **receiving component's** key. That signature attests *receipt* — "this
   component received these bytes at this time" — and nothing about the content's truth or the
   sender's authority. Implementations MUST NOT present it as anything else in the console.
3. Signal content lives in the payload store like evidence (§04 §5), with its own `retain-until`. It
   decays the same way and the chain is likewise independent of its presence.
4. `sender-verified` records whether transport-level sender authentication succeeded (webhook HMAC,
   DKIM, mTLS), with `sender-verification` naming the mechanism. `sender-verified: true` means the
   bytes came from the claimed sender. It does **not** upgrade the signal to an instruction. A signed
   email from the CEO saying "wire the money" is a verified signal and still carries no authority
   whatsoever.
5. Signals live in their own streams, chained and checkpointed identically (§04). Signal streams MUST
   be separate from effect streams (`stream-kind-mixed`) so that an audit query over effects is never
   diluted by inbound volume, and so that a flood of inbound traffic cannot advance an effect
   stream's `seq`.
6. Signal volume MAY be aggregated by the receiving component using the same aggregation record
   shape (§02 §7) with `kind: "signal-aggregate"`; the per-signal payloads are then not stored.
   Aggregation of signals is a storage decision and never changes their (nil) authority.

## 3. Prompt injection is a signal problem, and this is the answer to it

Any content reaching an agent from outside — a web page Lattice perceives, an issue body, an email,
a tool result, another agent's message — is signal content. Normatively:

1. Signal content MUST NOT be treated as instruction by any component. An implementation MUST NOT
   derive a mandate, a classification, an approval, a policy change, a scope, an approver, or a
   `correlation-ref` interpretation from signal content.
2. If content that arrived as a signal appears to request an action, the *only* path to that action
   is: the agent forms an intent, the intent is classified, a mandate is verified, and a gate (if
   applicable) is passed by a named human. That path is identical to the path for an intent the agent
   formed by itself. Content-derived intent gets no shortcut and no discount.
3. Therefore the worst outcome of a successful injection is an action **within the standing mandate's
   scope and weight class**, recorded in the audit under a named human's authority — never an
   escalation of that scope. This bound is the whole reason the mandate is on the envelope rather
   than in the agent's head. §09 §6 states what remains unmitigated.
4. Components MUST NOT implement "trusted sources" whose content is exempt from (1). A trusted source
   is a source whose compromise is unrecorded.

## 4. Triggers: a trigger is a standing mandate reference

The only way a signal leads to an effect:

```json
"trigger": {
  "signal-ref": "<64 hex — id() of the signal envelope>",
  "standing-mandate-ref": "<64 hex — id() of the standing mandate>",
  "rule": "github.issue_opened → triage"
}
```

Rules:

1. An effect emitted because of a signal MUST carry `trigger`, and `trigger.standing-mandate-ref`
   MUST equal the envelope's `mandate-ref` (`trigger-mandate-mismatch`). The authority for a
   triggered action is a human's standing rule, cited explicitly, and it is the same mandate the
   effect is otherwise judged against.
2. `trigger.signal-ref` MUST resolve to an appended signal envelope (`trigger-signal-unresolved`).
   The audit can therefore answer "why did this happen at 03:00 with nobody awake" with: this signal,
   under this human's standing rule, which expires on this date.
3. The mandate MUST be of kind `standing` (`trigger-mandate-not-standing`). An `interactive` mandate
   cannot authorize a triggered action — by definition nobody was watching.
4. A trigger rule (the `rule` string) is descriptive. Scope enforcement comes from the mandate's
   `scope`, never from the rule text. Matching more signals than intended cannot widen what the
   effect may do.
5. Scheduled work (cron, a timer, a queue tick) is the same shape: the tick is a signal, the schedule
   is a standing mandate. "The scheduler did it" is not an author (ADR-0001 case 4).

## 5. Ordering and causality — stated honestly

- There is no global order across streams. Cross-stream sequencing is displayed by `emitted-at` and
  MUST NOT be relied on for causality (clocks drift; §09 §5).
- Causality is expressed only by explicit references: `prev-hash` within a stream, `trigger.signal-ref`,
  `authorization.request`, `commitment-ref`, `mandate-ref`. If a link matters, an emitter MUST record
  it; the kernel MUST NOT infer it.
- `correlation-ref` groups records for display and query only, and is never interpreted (§02 §10).

## 6. Outbound messaging is an effect, not a stream feature

Sending a message (Slack, email, webhook, SMS) is a governed `consequential` effect performed through
the organization's own tools via the gateway (ADR-0002: outbound inverted). Stozher owns exactly one
outbound path of its own — the approver ping ("something parked, come sign") — and that adapter MUST
be limited to notification delivery, MUST NOT accept arbitrary content from agents, and MUST NOT be
reachable as a tool. Otherwise it becomes an ungoverned message channel wearing the kernel's badge.
