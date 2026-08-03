# 05 — Policy distribution

Normative. The kernel is the source of truth for policy; components enforce it locally from a cached
copy (enforcement-topology design doc). Policy is versioned, signed, pulled, and stamped into every
envelope so the audit shows *which* policy governed each effect.

## 1. Policy document

A policy document is a signed object (§01 §5), signed by the organization's policy key (role `4'`,
§01 §6).

```json
{
  "v": "stozher/0.1",
  "kind": "policy",
  "policy-version": "2026.07.1",
  "issued-at": "2026-07-26T08:00:00.000Z",
  "profile": "baseline-conservative",
  "revoke-cached": false,
  "max-staleness-seconds": 300,
  "checkpoint-interval": "PT1H",
  "aggregate-max-window": "PT5M",
  "classification": {
    "default-unknown": "consequential",
    "by-action": {
      "github.get_file":       "read",
      "github.create_issue":   "consequential",
      "github.delete_repo":    "prohibited",
      "slack.post_message":    "consequential",
      "fs.read_file":          "read"
    },
    "reclassify": [
      { "subject": "agent:reporting", "action": "github.export_all", "class": "consequential",
        "reason": "bulk export is exfiltration-shaped regardless of verb" }
    ]
  },
  "gate-rules": [
    { "classes": ["consequential"], "decision": "gate", "approvers": ["human:ivan"] },
    { "classes": ["prohibited"],    "decision": "deny" },
    { "classes": ["read", "benign"], "decision": "allow" }
  ],
  "evidence-ttl": { "read": "P0D", "benign": "P30D", "consequential": "P365D", "prohibited": "P3650D" },
  "budgets": { "defaults": { "requests": 10000, "money-eur": "50.00" } },
  "delegation": { "max-depth": 3, "max-standing-lifetime": "P90D" },
  "offline": { "consequential": "block", "benign": "allow", "read": "allow" },
  "sig": { "alg": "ed25519", "key": "ed25519:<policy key>", "value": "…" }
}
```

- `policy-version` (MUST): an opaque, **monotonic** version string. Implementations MUST NOT parse
  it for meaning; ordering is established by the publication chain (§5), not by string comparison.
  It MUST be unique forever within an organization (`policy-version-reused`).
- `profile` (MUST): the shipped baseline this document derives from (Tier 1, policy-model doc).
- All duration members follow §01 §2.4; all monetary values are decimal strings.
- Unknown members MUST be rejected (`schema-unknown-member`). A policy document an implementation
  does not fully understand is a policy document it MUST NOT enforce; failing closed here means
  failing to start, not failing open.
- **Every member above is REQUIRED. There is exactly one OPTIONAL member**, `wedge-grace` (§7.1),
  a duration of §01 §2.4 whose default when absent is `PT5M`. An implementation MUST accept a
  document that omits it, MUST accept one that carries it, and MUST NOT treat it as unknown.

  The asymmetry is deliberate and is the smallest one available. Making it REQUIRED would
  invalidate every document and every vector already signed, for a member that bounds how long a
  component may keep serving `read` traffic after the kernel started refusing it — a *bound on a
  degraded state*, not a grant of authority. A deployment that says nothing gets the bound anyway;
  that is what a default is for, and it is why this member may be absent while none of the others
  may.

## 2. Distribution — versioned pull

1. Components **pull**; the kernel does not push. Rationale: a push channel is a second control path
   that must be authenticated, ordered, and available; a pull loop degrades to "keep using the cached
   copy", which is exactly the offline behaviour maxim 5 requires.
2. Endpoints (binding for S1):
   - `GET /v1/policy/current` → the signed policy document, with `ETag: "<policy-version>"`.
   - `GET /v1/policy/{policy-version}` → that exact document, forever (the kernel MUST retain every
     version it has ever published, so an envelope's `policy-version` always resolves).
   - Both MUST require caller authentication (§10 §1) and MUST be readable by any authenticated
     component.
3. A component MUST verify the policy document's signature against the enrolled policy key before
   applying it (`policy-sig-invalid`), and MUST refuse to run with an unverifiable policy rather
   than falling back to permissive defaults.
4. Pull interval SHOULD be ≤ 60 s, MUST be ≤ `max-staleness-seconds`.
5. A component MUST stamp the `policy-version` it actually applied into every envelope it emits. It
   MUST NOT stamp a version it has not itself verified.

## 3. Evaluation order

For a request tuple (§03 §4.2), the effective decision is computed in this order, and only this
order:

1. **Classification.** `classification.reclassify` entries matching (subject, action, resource) win,
   most specific first; then `classification.by-action`; then the component manifest's declared class
   (§08); then `classification.default-unknown`. A component's manifest MAY be overridden by org
   policy in either direction; a component MUST NOT silently override org policy
   (`policy-component-override-attempt`).
2. **Prohibition.** If the resulting class is `prohibited`, the action is hard-blocked. No mandate,
   no approval, and no gate decision can permit it. The attempt MUST be emitted with
   `outcome: "attempted"` and full evidence.

   An envelope that reports a `prohibited` action as `applied` or `failed` MUST be **accepted and
   flagged** (`prohibited-applied`), never refused. The kernel records effects; it does not apply
   them, and by the time such an envelope arrives the act has already happened in the world.
   Refusing it would delete the only record that the violation occurred — the strict-looking choice
   that destroys evidence. The same holds for an effect reported as applied past an exhausted budget
   (`budget-exceeded-applied`, §03 §4.3): a component confessing that it acted anyway is the most
   audit-valuable record the system holds, and an implementation MUST make such envelopes
   queryable as violations.
3. **Mandate.** Verify the chain (§03 §5). Failure blocks (`outcome: "blocked"`).
4. **Gate rule.** The first matching `gate-rules` entry decides `allow` | `gate` | `deny`. `gate`
   requires an approval signature per §06 before the effect may be applied.
5. **Budget.** Exhausted budget blocks (§03 §4.3).

`prohibited` before mandate is deliberate: an organization must be able to state "nobody, under any
authority, does this", and that statement must not be defeatable by issuing a broader mandate.

### 3.1 How a `reclassify` entry matches, and which one wins

An entry has three dimensions — `subject`, `action`, `resource` — and a `class`. Each is a **pattern
in the vocabulary of §03 §4.1**: an exact string, `*`, or a `<prefix>.*` segment prefix.

`subject` and `action` MUST be present; write `*` for "any"
(`schema-missing-member`). `resource` MAY be absent, and an absent dimension is `*`. The asymmetry is
deliberate: those two decide *who* and *what*, and a reclassification silent about either is more
often a mistake than an intention, so an author has to say `*` and mean it. A rule that applies to
every resource is ordinary, which is why the third may be left out — and why §1's worked entry does.

§03 §4.1's segment separator is `.`, so a `<prefix>.*` pattern is only useful on `action`. `agent:*`
is **not** a prefix pattern and matches nothing but a subject literally named `agent:*`; write `*`
or omit the dimension. This is stated because it reads like it should work, and a reclassification
rule that silently matches nothing is worse than one that is refused.

An entry matches only if every dimension it states matches. Among matching entries, the **most
specific** wins, and specificity is a number:

| Dimension match | Score |
|---|---|
| exact | 2 |
| `<prefix>.*` segment prefix | 1 |
| `*`, or the dimension is absent | 0 |

The entry's specificity is the sum over the three dimensions; the highest total wins, and **among
equal totals the earliest entry in the document wins.** Naming two dimensions therefore beats naming
one, which is what "more specific" means to the person writing the policy; nothing about the *kind*
of dimension breaks the tie, because there is no deployment-independent sense in which naming a
resource is narrower than naming an action.

Both are stated because they were not. For the whole of v0.1 this clause said "most specific first"
and defined neither the patterns nor the ordering: one implementation scored the dimensions
unequally, the other supported no patterns at all — it matched `subject`, `action` and `resource`
by string equality, so a policy reclassifying `github.*` was silently ignored by the emitter and
honoured by the kernel. That combination is the worst one available: the emitter applies an effect
believing it is `read`, and the kernel refuses the record of it
(`policy-component-override-attempt`). The action happens and the audit does not have it.

## 4. Retention and TTL

`evidence-ttl` maps each class to the **maximum** payload lifetime. An emitter computes
`evidence.retain-until = min(its own preference, emitted-at + evidence-ttl[class])`. The kernel
re-derives the ceiling and rejects excess (`evidence-retention-too-long`). `P0D` means no payload is
stored at all; the kernel MUST discard any payload submitted for such an envelope and MUST NOT treat
its submission as an error (the emitter may be running older policy).

## 5. Changing policy is itself a gated envelope

There is no privileged path by which policy changes. Publishing a policy version is an effect:

```json
{
  "v": "stozher/0.1", "kind": "policy-change",
  "stream": "kernel:core", "seq": 88, "prev-hash": "…",
  "identity": { "subject": "human:ivan", "key": "ed25519:<root>", "component": "kernel" },
  "mandate-ref": "<64 hex>",
  "policy-version": "2026.07.0",
  "classification": "consequential",
  "execution": {
    "action": "kernel.publish_policy", "target": "policy:2026.07.1",
    "args-hash": "<object-hash of the new policy document>",
    "outcome": "applied", "started-at": "…", "finished-at": "…"
  },
  "evidence": { "schema": "kernel.publish_policy.v1", "media-type": "application/json",
                "payload-hash": "<object-hash of the new policy document>",
                "retain-until": "2036-07-26T00:00:00.000Z" },
  "authorization": { "request": { … }, "decision": { … } },
  "sig": { … }
}
```

Normative:

1. `policy-version` on a `policy-change` envelope is the version **in force while the change was
   made** (the outgoing one). The new version is identified by `execution.target`, which MUST be
   `policy:<policy-version>` of the document `execution.args-hash` commits to
   (`policy-change-target-mismatch`).
2. `classification` MUST be `consequential` and `authorization` MUST be present and valid (§06),
   signed by an enrolled human root. A policy change without an approval signature is rejected
   `gate-authorization-missing` like any other gated effect. Policy is audited by the mechanism it
   enforces — there is no bootstrap exception except the ceremony's first policy, which MUST be
   `seq` 1 of `kernel:core`, signed by the first root, and MUST be recorded as such.

   **The ceremony is two envelopes and neither is exempt.** A gated effect needs a mandate to be
   judged against, and §03 §1 forbids self-grant, so the mandate cannot come from the subject
   publishing the policy. Therefore:

   - `seq` 0 of `kernel:core` is an **interactive mandate**: a named human root grants a bootstrap
     subject authority over `kernel.*` for the length of the ceremony and no longer.
   - `seq` 1 is the **first policy change**, carrying an approval that root signed over the exact
     `object-hash` of the policy document.

   Both are fully validated by the same ingest path as everything after them. Nothing is
   pre-installed, and no code path writes either of them without the checks. A bootstrap that
   skipped validation would make the first two records the only two nobody verified — which is the
   pair an attacker would most want to choose.
3. `execution.args-hash` MUST equal `object-hash` of the new policy document
   (`policy-change-document-unbound`), so the approval
   signature binds the exact bytes of the policy that took effect. Approving "a policy change" in the
   abstract is not representable.
4. A policy version becomes effective only once its `policy-change` envelope is appended. A document
   served by `/v1/policy/current` MUST have a corresponding appended envelope
   (`policy-not-published`).
5. Org overrides live in git and are reviewable (policy-model Tier 2); the git commit is *not* the
   authority — the envelope is. Reviewability and enforceability are separate properties and this
   spec provides the second one.
6. **Policy cannot lower the bar on the mechanism that enforces policy.** The actions that change
   what the system will permit — `kernel.publish_policy`, `kernel.register_component`,
   `kernel.enroll_root`, `kernel.retire_root`, `kernel.conformance_run`, `kernel.resume_stream`
   (§04 §7.2) — MUST be approved by an
   enrolled human root, whatever class the policy in force assigns them. An organization may
   classify them *higher*; it MUST NOT classify them lower, and a `gate-rules` entry that would
   allow one of them without a root's signature has no effect on them.

   A policy that could downgrade its own amendment path is a policy that can be amended into
   permitting anything, in one step, by whoever holds the weakest mandate that step then requires.

## 6. Cache, staleness, and `revoke-cached`

- A component MUST cache the last verified policy document persistently and MUST enforce it while
  offline (maxim 5).
- `max-staleness-seconds` is the age after which the cached policy is *stale*. While stale, the
  component MUST apply `offline` behaviour (§7) for each class rather than continuing as if fresh.
- **`revoke-cached: true`** on a newly published policy means: every component MUST re-pull before
  performing its next `consequential` action, regardless of pull interval and regardless of
  staleness. A component that cannot re-pull MUST treat `consequential` as offline-blocked. It is set
  when policy **tightens** (a class raised, a gate added, a mandate scope narrowed, a root retired).
- **The duty ends when it has been discharged for that version.** A component has satisfied
  `revoke-cached` once it has successfully re-pulled while that policy version is the one in force;
  it does not re-pull before every subsequent action under the same version. Stated because the
  obligation had a beginning and no end, and an obligation with no end is one every implementation
  terminates differently — before every action, once per process, or never again after the first.
- The flag lives in the *new* document, so a component learns of it only by pulling; therefore
  tightening is not instantaneous, and the residual window is real. It is bounded by
  `max-staleness-seconds` and is visible in the audit because every envelope carries the version it
  applied. Named honestly in §09 §2 rather than described as solved.
- Loosening policy MUST NOT set `revoke-cached`: an old, stricter cached copy is always a safe state
  to be in.

## 7. Offline behaviour

`offline` maps each class to `allow` | `block` | `degrade`.

- `allow`: proceed under cached policy, queue envelopes locally (§04 §3).
- `block`: refuse the action, emit an envelope with `outcome: "blocked"` into the local chain.
- `degrade`: perform a policy-declared reduced form of the action (declared per action type in the
  manifest, §08) and record the reduced form as the effect.
- The default profile MUST set `consequential: "block"` and MUST NOT allow `consequential` while a
  gate rule applies to it (`policy-offline-allows-gated`): an action requiring a human signature
  cannot acquire one offline.
- **Silently proceeding is never permitted** for any class. Every path terminates in either an
  applied effect with an envelope, or a refusal with an envelope (§06 §6).

### 7.1 Refused is not offline

This subsection is here because §7 above is where a component's behaviour when it cannot reach the
kernel is specified, and *refused* is the state §7 currently mis-files as `offline`. Everything §7
says about `offline` continues to apply to `unreachable` and to nothing else.

A component's submission has exactly **three** outcomes, and an implementation MUST distinguish
them:

| Outcome | What happened | What governs the component |
|---|---|---|
| `accepted` | the kernel appended it | continue |
| `unreachable` | no answer: transport failure, timeout, no route | retry; §7's `offline` map |
| `refused` | the kernel answered with a rejection (§04 §7) | this subsection |

1. A component MUST NOT treat a `refused` submission as `unreachable`. The `offline` map governs a
   kernel that cannot answer, never one that has answered "no": retrying identical bytes is futile
   (§04 §3 makes the outcome deterministic in the bytes), and the `allow` row would otherwise
   licence unbounded unaudited operation.
2. A component MUST record the rejection's reason code durably against the local envelope, and MUST
   NOT erase it on any later transition of that row. An operator asked to intervene (§03 §7) can act
   only from the reason, and the recovery act of §04 §7.2 cites it.
3. The component's stream is **wedged** at that position (§03 §7, §04 §3). A component MUST NOT
   submit past a wedge, and MUST NOT renumber, skip or rewrite the refused position. It MUST go on
   chaining locally: the local chain is the record of truth until the kernel has it, and a component
   that stopped writing would lose the evidence of what it did while wedged.
4. **While wedged, the reason decides whether a grace window exists at all, and the class decides
   who may use it.** For every call, in this order:
   - if the reason code is one of the `mandate-*` family, or `policy-not-published`, the component
     MUST refuse **every** class immediately, `read` and `benign` included, and MUST NOT serve again
     until a submission is accepted. Authority the organization cannot resolve is not authority
     (ADR-0001), and a `read` performed without authority is still an effect (§10 §1.4). There is no
     grace here for any class;
   - otherwise, `consequential` and `prohibited` MUST be refused immediately, with no grace. Grace
     over `consequential` is exactly the window an auditor asks *"what else was still permitted"*
     about;
   - otherwise, for `read` and `benign`, a bounded grace window applies: the component MAY serve
     until `policy.wedge-grace` (default `PT5M`, §1) has elapsed since the **first** refusal on that
     stream. Each effect served under grace MUST be recorded as a finding — counted against the
     wedged stream and answerable from the component itself, without reference to the kernel it
     cannot reach. Serving under grace is loud or it is not permitted;
   - once `policy.wedge-grace` has elapsed, every class MUST be refused. The window is measured from
     the first refusal and MUST NOT be restarted by a later one: a wedge that could be re-graced by
     re-offering the same bytes is not bounded.
5. **Silent degradation MUST NOT exist.** A refusal issued under this subsection MUST be the §06
   §4.1 refusal object with `result: "blocked"` and `reason-code` set to the kernel's reason code
   **verbatim** — not a paraphrase, not a gateway code of the component's own. The calling agent is
   told that its effects are not being recorded, in the same shape as every other refusal, and stops
   (§10 §6).
6. Recovery is §04 §7.2 and §7.2 below. A wedge ends when a submission on that stream is accepted,
   and by no other event: neither the passage of time, nor a restart of the component, nor a new
   session under a new mandate clears it.

**Why the shape is this shape, and not either of the two obvious ones.** Stopping unilaterally on
any refusal is a denial-of-service weapon: one malformed envelope, emitted by one component, halts
an organization's tooling faster than a human can read the reason, and an adversary who can provoke
a rejection can therefore provoke an outage. Unbounded grace is the opposite failure and the one
this specification was written against: a component that serves indefinitely while nothing it does
reaches the audit. The class-bound, reason-gated window is the narrow bridge between them — long
enough to read a reason code, short enough that no `consequential` effect ever crosses it, and
closed entirely when what the kernel refused was the authority itself.

### 7.2 Resuming, from the component's side

1. A component MUST NOT resume submitting past a wedge on its own initiative, on any timer, or on
   any signal from the caller. The exit is the operator act of §04 §7.2 and nothing else.
2. Once the kernel accepts a submission on that stream again, the component MUST clear the wedge and
   MUST resume serving under the ordinary rules. It MUST NOT re-submit the refused bytes: they were
   refused, they stay refused (§04 §7.2 rule 4), and the position they occupy is bridged rather than
   filled.
3. A component MUST NOT report, to a caller or in its own surfaces, that the effects served under
   grace were recorded at the kernel. They were not, and a recovery that quietly relabels them
   converts a bounded gap in the audit into a false statement about it.

## 8. Tier 3 — drift learning (deferred, constrained here)

Deferred until ~1000 approval events (build plan). The constraint is normative now so the deferral
cannot become a loophole later:

- The kernel MAY analyse gate history and **propose** policy changes.
- A proposal MUST be represented as a policy-change envelope in `proposed` state that has no
  `authorization` and therefore has no effect. It MUST pass the same gate as any policy change.
- No learned rule may take effect without a human signature over its exact document hash
  (`policy-learned-rule-unsigned`). Learning proposes; humans dispose.
