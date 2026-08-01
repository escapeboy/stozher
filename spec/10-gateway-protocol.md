# 10 — Gateway protocol

Normative. The gateway is the universal day-1 entry point: an organization's existing agents (Claude
Code, Cursor, Copilot, LangGraph scripts) point their MCP configuration at the gateway instead of
directly at their tool servers, and every tool call is classified, mandated, gated and recorded at the
boundary — **zero-touch for the calling agent.**

Per ADR-0004 the gateway's MCP proxy path is **built, not extended**: Harbormaster has no client-side
proxy path to wrap. This section specifies the protocol that path must implement; everything else in
the gateway design doc (three classification tiers, zero-touch, gateway-side read aggregation,
structured refusal, O(ms) hot path) remains binding.

## 1. Caller authentication and session mandate

1. Every connection MUST be authenticated. Unauthenticated passthrough MAY exist for local
   development only, MUST be off by default, and MUST be impossible to enable in a deployment where
   any human root is enrolled (`gateway-passthrough-in-org-deployment`).
2. A caller presents a **caller credential** (bearer token, mTLS client certificate, or an OS-local
   socket peer credential). The gateway MUST map it to:
   - a **derived subject key** at SLIP-0010 role `2'` (§01 §6): one key per (caller, device). The
     gateway holds the key material; the calling agent never sees it and needs no changes.
   - a **subject identifier** of the form `agent:<tool>/<device>` (for example
     `agent:claude-code/ivan-mbp`).
3. Each session MUST carry a `mandate-ref`:
   - **interactive** by default — a human is at the keyboard; the mandate is issued when the human
     starts the session and expires with it (`not-after` REQUIRED, §03 §3);
   - **standing** for headless or scheduled callers (CI, cron, a service) — a human signed a rule with
     mandatory expiry.
4. A session without a resolvable, unexpired mandate MUST be refused at connect time with
   `mandate-unresolved` or `mandate-expired`. The gateway MUST NOT accept calls and defer the mandate
   question until the first consequential one: a `read` performed without authority is still an
   effect (exfiltration is a read).
5. The gateway MUST NOT allow a caller to choose its own subject, key, mandate, or classification
   through any request field. Everything identity-bearing is derived from the authenticated
   credential (`gateway-caller-asserted-identity`).
6. Session establishment MUST be recorded: an envelope (`action: "gateway.session_open"`, class
   `benign`) naming the credential's subject, the derived key, and the mandate.

## 2. Call flow

For each proxied MCP tool call, in this order:

1. **Resolve** the target server and tool from the gateway's routing table.
2. **Normalize** to an `action` identifier and a `target`, and compute
   `args-hash = object-hash(arguments)` (§01 §3.5).
3. **Classify** (§3). Produces `classification` and the catalog tier used.
4. **Prohibited?** → refuse immediately (§6), emit `outcome: "attempted"` with full evidence, do not
   forward.
5. **Verify the mandate** for (component, action, class, target) (§03 §5). Failure → refuse with
   `outcome: "blocked"`.
6. **Gate rule?** → build the action request (§06 §1.1), submit it with the arguments it commits to
   (§06 §4.4 — a component that still holds the values MUST send them, or the approver signs a
   digest with nothing behind it), park the call, notify approvers, wait.
   - approved → continue with the `authorization` object in hand;
   - denied → refuse with the denial `authorization`, `outcome: "denied"`;
   - request expiry or kernel unreachable → refuse, `outcome: "blocked"` (§05 §7). Never forward.
7. **Forward** the call to the upstream server.
8. **Emit** the envelope: `read` class → into an open aggregation window (§4); everything else → one
   envelope per call, with `authorization` when gated, `policy-version` stamped, `evidence.payload-hash`
   over the declared evidence for that action, payload submitted alongside (§04 §5.2).
9. **Return** the upstream result unchanged to the caller (zero-touch), or the structured refusal (§6).

Latency requirement: steps 1–3 and 8 MUST be O(ms) and MUST NOT block on the kernel. Only step 6
blocks, and only for gated calls. Envelope push is asynchronous, batched, ordered per stream, and
retried; a kernel that is briefly unreachable MUST NOT stall `read` and `benign` traffic (§05 §7).

## 3. Classification order

Exactly this order, first match wins:

1. **Tier A — manifest.** The upstream server is registered with a Stozher manifest (§08): use its
   declared `action → class`, then apply org policy reclassification (§05 §3). Full fidelity.
2. **Tier B — shipped catalog.** A curated `server + tool → action + class` catalog versioned with the
   product (§08 §5), signed by the release key. Covers the popular MCP servers.
3. **Tier B′ — org-seeded catalog.** Entries created by first-call gating (§4 below), marked
   `origin: "org-seeded"`.
4. **Tier C — conservative heuristic.** For an unknown tool:
   - `read` only if the tool's name and schema are read-shaped **and** the schema declares no
     mutation: name matches `^(get|list|read|search|find|query|describe|fetch|show|count)(_|$)` and no
     argument is a body/content/patch-shaped field;
   - `consequential` for everything else, including anything mutating, anything with an opaque or
     absent schema, and anything whose name is ambiguous;
   - the heuristic MUST NOT ever produce `benign` or `prohibited`. Those require a human's judgement,
     shipped curation, or a manifest.
5. Policy reclassification (§05 §3) applies on top of every tier, in both directions.

Normative constraints:

- The classification and the tier used MUST be recorded in the envelope's evidence
  (`classification-tier`: `manifest` | `shipped` | `org-seeded` | `heuristic`). An auditor must be able
  to ask "how confident was this label?" — and a fleet where most traffic is `heuristic` is a finding.
- **Unknown ≠ ungoverned. Unknown = expensive until classified** (gateway design doc). An
  unclassifiable tool is `consequential` and therefore gated under the default profile; it is never
  forwarded silently.
- The heuristic MUST be a pure function of tool name and declared schema. It MUST NOT read tool
  descriptions, documentation, or any other model-authored text to make its decision: those are
  attacker-controllable in a hostile MCP server (§07 §3), and a classifier that reads them is a
  classifier an adversary configures.
- A tool's class MUST NOT be downgraded by anything the upstream server says at call time.
- **A tier the kernel cannot see MUST NOT come out weaker than the kernel's own answer.** Tier A is a
  registered manifest, so the kernel evaluates §05 §3 step 1 with the same input the gateway has and
  the two agree by construction. Tiers B, B′ and C are invisible to it: the kernel reaches
  `classification.default-unknown` where the gateway reached its catalog. So when org policy has said
  nothing — no `reclassify` entry, no `by-action` entry — the gateway MUST take the **stronger** of
  its own tier's class and `default-unknown`.

  Without this, a catalog entry weaker than `default-unknown` produces an effect the gateway applies
  believing it `read` and the kernel refuses to record
  (`policy-component-override-attempt`): the action happens and the audit does not have it. The rule
  is deliberately confined to the tiers the kernel cannot see — applying it to Tier A would
  strengthen a class the kernel evaluated as declared, which is a disagreement with §05 §3 rather
  than caution. To realize a catalog downgrade, the organization publishes it as a `by-action` entry.

## 4. First-call gating and org-catalog seeding

The first invocation of a tool with no Tier A/B/B′ entry MUST park at a gate, regardless of the
heuristic's result.

1. The gate request (§06 §1.1) carries the heuristic's proposed class, the tool name, and the argument
   schema, so the approver decides with the same information the gateway had.
2. The approver's decision does two things at once: it authorizes (or refuses) **this call**, and it
   seeds an org-local catalog entry for **future** calls of that tool. The approver MUST be able to
   choose the class assigned to the entry independently of approving the call.
3. Seeding a catalog entry is a policy change and therefore its own gated, chained envelope
   (`action: "kernel.seed_catalog_entry"`, class `consequential`, §05 §5). One human interaction MAY
   produce both signatures, but there MUST be two records, and the catalog entry MUST NOT come into
   force without its own signature.
4. Org-seeded entries MUST be marked `origin: "org-seeded"` (§08 §5) and MUST be reviewable and
   revisable in the console. A shipped catalog entry MUST NOT be silently replaced by an org-seeded
   one: a conflict MUST be surfaced.
5. If the approver denies, the tool MUST remain unclassified — a denial is not a classification. The
   next call parks again. (Otherwise "deny once" would quietly become "allow forever at the heuristic's
   class".)

## 5. Gateway-side aggregation

Read aggregation happens at the gateway; the kernel never sees the firehose (§02 §7, event-store doc).

1. An open window is keyed by (stream, subject-key, mandate-ref, policy-version). Any change closes
   the window and starts a new one.
2. A window MUST be closed and emitted when any of: `policy.aggregate-max-window` elapses (default
   `PT5M`), the count reaches the configured maximum, the session ends, the policy version changes, or
   the process is shutting down. On shutdown the gateway MUST flush open windows before exit
   (`gateway-must-flush-on-shutdown`); an unflushed window is an unaudited effect.
3. Only class `read` may be aggregated. A call reclassified to `consequential` by policy — bulk export,
   credential read — MUST be emitted individually even if its verb looks read-shaped (§02 §7.6).
4. `sample-hashes` MUST be produced by the declared sampling rule (§08 §1.2) with at most 16 entries.
5. Aggregation MUST NOT delay refusal: a `read` that fails the mandate check is refused and emitted
   individually with `outcome: "blocked"`, not folded into a count.

## 6. Structured refusal

On any refusal the gateway MUST return the §06 §4.1 refusal object to the caller as the MCP tool
result, marked as an error result, and MUST NOT return a fabricated success, an empty success, or a
partial result.

```json
{
  "stozher": "stozher/0.1",
  "result": "parked",
  "reason-code": "gate-parked",
  "reason": "awaiting approval from human:ivan",
  "action": "github.create_issue",
  "classification": "consequential",
  "classification-tier": "shipped",
  "request-hash": "<64 hex>",
  "envelope-id": null,
  "retryable": false,
  "hint": "approve at https://stozher.acme.internal/pending/<request-hash>"
}
```

- `result` ∈ `denied` | `blocked` | `parked` | `prohibited`; `reason-code` is a normative code from
  this specification (§00 §1).
- `hint` MAY carry an operator-facing URL. It MUST NOT describe a workaround, an alternative tool, or a
  way to proceed without approval.
- The refusal MUST be legible enough for the calling agent to tell its human what happened and stop.
  An agent that receives a clear terminal refusal reports it; an agent that receives a vague error
  retries — which is a load-generating attack on the approver (§09 §7).
- The gateway MUST NOT include the approver's key material, other pending requests, or any policy
  document content in a refusal.

## 7. What the gateway MUST NOT do

- MUST NOT let a caller assert identity, mandate, classification, policy version, or approval through
  any request field, header, or tool argument (§1.5).
- MUST NOT accept an "approved" marker from anywhere other than a verified §06 `authorization` object
  it obtained itself (`gateway-external-approval-marker`).
- MUST NOT forward a call whose class is `prohibited`, whatever the caller's mandate says.
- MUST NOT rewrite or summarize upstream results for callers (zero-touch means the agent's behaviour is
  unchanged); it MAY refuse, and refusal is visible.
- MUST NOT interpret `correlation-ref` supplied by a caller beyond storing it (§02 §10). A caller MAY
  supply one — that is its purpose — and it MUST NOT influence any decision.
- MUST NOT keep the only copy of an emitted envelope in memory: local durable chaining before applying
  the effect is required (§09 §4).

## 8. Harbormaster boundary

- The Stozher enforcement layer ships as Harbormaster's **enforcement mode**. With no kernel
  configured, Harbormaster MUST behave exactly as before (`harbormaster-parity-without-kernel`), and
  this MUST be covered by an automated test (ADR-0004).
- Harbormaster's own native tool surface (`ask_project`, `delegate_task`, …) is subject to the same
  rules when enforcement mode is on: those are actions too, they get classified, and delegation to a
  sub-agent is a **delegated mandate** (§03), not an internal implementation detail.
