# 09 — Threat model

Normative where it states requirements; otherwise an honest statement of what this architecture does
and does not solve. External security and cryptographic review is REQUIRED before anything in this
repository is called v1 (inherited Servanda rule, build plan).

Scope: a single-tenant Stozher deployment for one organization (maxim 4). Out of scope for 0.1:
inter-org federation, multi-tenant isolation, confidentiality of envelopes at rest.

## 1. Adversaries

| # | Adversary | Capability assumed |
|---|---|---|
| A1 | Compromised or malicious **agent** | holds an agent key, can call tools, can lie about what it is doing |
| A2 | Compromised or malicious **component** (emitter) | holds a component key, sits between the agent and the world, controls what it emits |
| A3 | **Insider with an agent key** | as A1, plus knowledge of the org's policy |
| A4 | **Insider who is an approver** | can sign approvals within their scope |
| A5 | **External content author** | controls text an agent reads (web page, issue, email) |
| A6 | **Operator of the host** | root on the box the kernel runs on |
| A7 | **Network attacker** | sees and can modify traffic between components and kernel |

## 2. What the architecture stops, and by what mechanism

| Attack | Mechanism | Section |
|---|---|---|
| Acting with no authority | envelope requires `mandate-ref`; chain must reach an enrolled human root | §03 §5 |
| Self-issued authority | `grantor.key != grantee.key`; roots must be enrolled | §03 §1, §6 |
| Agent granting itself more scope | delegated scope may only narrow; hop budget decreases | §03 §5 |
| Autonomy that outlives its grant | `not-after` mandatory on every mandate, incl. standing | §03 §3 |
| Performing a gated action without approval | `gate-authorization-missing`; no ambient bypass exists | §06 §2 |
| Reusing an approval for a different action | approval signs `request-hash` binding subject/mandate/policy/action/target/args | §06 §2 (8) |
| Re-executing an approved action twice | `single-use` + `request-hash` seen-set | §06 §3 |
| Approving one's own action | `gate-self-approval` | §06 §5 |
| Rewriting history in the store | append-only + hash chain + signed checkpoints exported off-box | §04 §2, §4 |
| Hiding a record by deleting it | envelopes are never deletable; only payloads decay | §04 §5.4 |
| Retention laundering (long TTL by an emitter) | kernel re-derives the TTL ceiling from policy | §05 §4 |
| Injected instruction escalating privilege | signal content grants nothing; effects still need mandate + gate | §07 §3 |
| Policy changed quietly | policy change is a gated, chained envelope binding the new document hash | §05 §5 |
| Learned rule activating itself | tier 3 proposals have no `authorization` and no effect | §05 §8 |
| Unknown foreign tool used freely | conservative default + first-call gating | §10 §3–4 |
| Registering a capability without review | manifest registration is gated; no green conformance, no registration | §08 §3 |

## 3. Lying emitters (A2) — bounded, not solved

A component that holds a valid key can:

- **omit** envelopes for effects it performs (silently do work and not report it);
- **misreport** evidence content (emit a `payload-hash` of a sanitized version of what it did);
- **misclassify** its own actions downward *in its manifest proposal* (but not below effective policy).

Not solvable by topology. What bounds it:

1. **A component cannot fake an approval.** Gated actions physically require a human's Ed25519
   signature over the exact `request-hash` (§06). A lying component can hide a `benign` effect; it
   cannot manufacture authority for a `consequential` one, because it does not hold the approver's
   key. This is the single most important property in this document.
2. **The conformance harness** (§08 §4) tests emission per declared action type, including the negative
   cases, before registration. It proves the component *can* behave, not that it always does.
3. **Chain gaps are detectable** (§4 below): a component cannot skip a `seq` without the gap showing.
   It can, however, simply not emit at all — an idle-looking component is indistinguishable from an
   honest quiet one, and no signature scheme fixes that.
4. **Classification is the org's, not the component's** (§05 §3): the manifest is a proposal.

**Stated plainly:** Stozher's audit is trustworthy about *authority* and about *what was reported*. It
is not a proof of *completeness* against a compromised emitter. Anyone selling the second property is
lying. Mitigations belong outside the kernel (host attestation, egress monitoring, code review of
components, least-privilege credentials at the boundary) and are explicitly not claimed here.

## 4. Envelope loss and gap detection

- Within a stream, loss is detectable: `seq` gaps and `prev-hash` breaks are mechanical
  (`chain-seq-gap`, `chain-prev-hash-mismatch`).
- **Truncation of the tail** — an offline emitter losing its last N envelopes before sync — is
  detectable only if something else attests to the head. Requirements:
  1. an emitter MUST persist its local chain durably (fsync) before applying an effect, not after
     (`emitter-must-persist-before-apply`), so a crash loses at most the record of an effect that did
     not happen;
  2. the kernel MUST track the last accepted `seq` per stream and MUST surface streams that have gone
     quiet beyond a policy-configured interval — an absent emitter is a finding, not a null result;
  3. the kernel MUST checkpoint per stream (§04 §4.6), so a later attempt to replace the tail with a
     different tail contradicts a published head hash.
- A stream that is deleted wholesale from a compromised emitter's disk before ever syncing leaves only
  the quiet-stream signal. Named, not solved.

## 5. Replay, freshness, and clocks

- **Approval replay:** blocked by `single-use` + seen-set on `request-hash` (§06 §3).
- **Envelope replay:** re-submitting a byte-identical envelope is idempotent by `id()` (§04 §3);
  submitting it under a different `(stream, seq)` fails because `stream`/`seq` are signed members —
  the envelope cannot be moved.
- **Cross-organization replay:** out of scope for 0.1 (single-tenant). A future federation profile
  MUST bind an organization identifier into the signed body; without it, envelopes are portable
  between deployments that share a key, and no deployment should share a key.
- **Clock manipulation:** an emitter controls its own `emitted-at`, and mandate validity is evaluated
  at that instant. A compromised emitter can therefore backdate an effect into a window when a
  mandate was valid. Bounds: the kernel MUST reject `emitted-at` more than `PT5M` in the future
  (`envelope-emitted-in-future`) and MUST record the ingest arrival time separately from
  `emitted-at`. Backdating beyond the last checkpoint of that stream contradicts the checkpoint. A
  gap of drift between `emitted-at` and arrival remains, is recorded, and is queryable — the honest
  answer is "visible, not prevented".
- **Timestamps are never used for chain order** (§04 §2). Ordering is `prev-hash`.

## 6. Prompt injection (A5) — the residual is scope-shaped

The architecture removes the *escalation* path (§07 §3): injected content cannot obtain a mandate,
cannot forge an approval, cannot reclassify an action, cannot change policy.

What remains: an injection can cause an agent to perform actions **inside the scope and weight class
that a human already granted it**, and those actions will be correctly attributed to that human's
standing mandate. If a standing mandate permits `slack.post_message` to any channel, an injection can
post an embarrassing message, legitimately, under that mandate. The mitigation is scope discipline
(narrow `resources`, short `not-after`) and gating of the classes that matter — i.e. it is a policy
question, and the system's job is to make the blast radius **exactly** the granted scope and to make
it visible afterwards. That is an improvement over an unbounded blast radius and an invisible one; it
is not immunity, and §07 says so in the same words.

## 7. Approver-side risks (A4)

- A hurried approver is the system's weakest link and the console's main design problem: the pending
  queue MUST show the mandate chain to the human root, the classification, and an evidence preview
  (console doc) so a decision is possible in seconds without being blind.
- Approval fatigue is an availability attack: an adversary that generates many gate-worthy actions can
  train an approver to click through. Requirements: the kernel MUST rate-limit gate requests per
  subject per interval (`gate-rate-limited`) and MUST surface a spike as a finding rather than as a
  longer queue. Refusing a *request* is not refusing an *action*: the call is still gated and still
  blocked, and what the flooding subject loses is the ability to keep growing the queue a human has
  to read.
- A malicious approver acting within scope is not an attack the audit prevents — it is an attack the
  audit *records*, with a name, a timestamp, and a signature over the exact action. That is the
  designed outcome, and it is also why `single-use` and short `not-after` matter: the blast radius of
  one signature is one action.
- Approvers MUST be humans (§06 §5). An agent that can approve is a system with no gates.

## 8. Host and infrastructure (A6, A7)

- **Root on the host (A6)** can read keys held in that host's memory, forge anything those keys can
  sign, and delete data. Requirements: private keys MUST be stored with owner-only permissions
  (`0600`) and MUST NOT be world-readable or group-readable; the kernel MUST refuse to start if its
  key material is more permissive (`key-file-permissions`); checkpoints SHOULD be exported off-box
  (§04 §4.7) so post-hoc rebuilds are detectable. Root compromise is not defended against — it is
  made non-silent.
- **Network (A7):** all component↔kernel traffic MUST be TLS. This is transport security only: the
  audit's integrity does not depend on it (every object is independently signed), but caller
  authentication (§10 §1) and policy freshness do.
- **Denial of service:** the kernel is on the hot path only for gates. A kernel outage MUST NOT
  silently permit gated actions — offline behaviour is `block` for `consequential` by default (§05 §7).
  So an outage degrades availability of gated work, deliberately, rather than availability of
  enforcement.

## 9. Cryptographic assumptions

- Ed25519 (RFC 8032) unforgeability, SHA-256 collision resistance, HMAC-SHA-512 as a PRF for
  SLIP-0010. A SHA-256 collision would break chain immutability and payload binding; a
  migration path (a `stozher/0.2` suite plus re-checkpointing under the new digest) is future work,
  explicitly not designed here.
- Strict Ed25519 verification is REQUIRED (§01 §4) to avoid signature malleability and small-order-key
  repudiation.
- Deterministic signatures mean `id()` is stable, and also mean a subject cannot produce two different
  valid signatures over one body to create ambiguity.
- **Not reviewed yet:** this document is one person's threat model. Items requiring external review
  before v1: the JCS-plus-Ed25519 signing construction, the mandate-chain algorithm, the gate binding,
  and (when it exists) the X25519-from-Ed25519 mapping for encryption at rest.

## 10. What this system is not

- Not a capability sandbox: it does not prevent an agent from having credentials it should not have.
  Boruna sandboxes execution; the kernel governs whether the effect was authorized and records it.
- Not a DLP product: it records that a read happened and (per class) what was read; it does not
  inspect content for sensitivity.
- Not an authentication system for humans: SSO/2FA for console login is a deployment concern. The
  approval *signature* is the security boundary, not the session cookie.
- Not a guarantee that an organization's policy is sensible. It guarantees the policy was authored by a
  named human, enforced as written, and recorded — nothing about whether it was wise.
