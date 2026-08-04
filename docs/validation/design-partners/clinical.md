# Stozher — design-partner evaluation, clinical research coordination

**Evaluator's position:** research coordination office at a hospital running 30 concurrent trials.
HIPAA/GDPR-shaped. Two properties dominate: a subject withdrawing consent must stop processing
everywhere, fast; and I must be able to hand an auditor a record they can verify without trusting me.

**What I actually ran:** `deploy/gate/clean-install.sh` on a fresh worktree (compose project
`stozher-clinical`, port 8839), then a real downstream MCP server with nine clinical tools
(`deploy/var/notes/trials_server.py`), the documented policy-change ceremony, a real revocation
against a live agent session, the resume ceremony, the audit export verified with my own code, and a
60-day clock advance with a forced retention sweep.

Every claim below is marked `[observed]` (I ran it and read the output) or `[inferred]`.

---

## 0. The first thing that happened was damage to a deployment that was not mine

`deploy/README.md` §1 "Two installs on one host" says, in bold:

> **One thing is not namespaced: the image tags.** … If the two installs are not the same commit,
> give each its own tags … Both default to the plain names and every script here reads them, so
> **put them in `.env`** … Exporting them in your own shell is *not* enough.

I did exactly that — `STOZHER_KERNEL_IMAGE=stozher-kernel-clinical:0.1.0` and the gateway equivalent
in `deploy/.env`, before the ceremony. The gate then deleted and rebuilt the host's **production**
`stozher-kernel:0.1.0` and `stozher-gateway:0.1.0` tags anyway. `[observed]` — the build log named
`docker.io/library/stozher-gateway:0.1.0`, and afterwards both the plain and the `-clinical` tags
pointed at my build (`c7dc7f1e` / `2017f8aa`), while the running production container still holds a
different, now-untagged image id (`c1fdb1f8e3dc`).

The mechanism is three lines at the top of `deploy/gate/clean-install.sh`:

```sh
KERNEL_IMAGE="${STOZHER_KERNEL_IMAGE:-stozher-kernel:0.1.0}"
GATEWAY_IMAGE="${STOZHER_GATEWAY_IMAGE:-stozher-gateway:0.1.0}"
export STOZHER_KERNEL_IMAGE="$KERNEL_IMAGE" STOZHER_GATEWAY_IMAGE="$GATEWAY_IMAGE"
```

They run **before** `.env` is read, and in docker compose an exported environment variable beats the
`.env` file. So the script exports the *default* tags into its own environment, `.env` is then
ignored for interpolation, and the `docker image rm -f` and the `--no-cache` rebuild both land on the
host-wide tags. The script's own comment block claims the opposite — it says it carries these keys
out of `.env` and that "`.env.example` tells an operator to put all three here". `.env.example` does
not mention either image variable at all. `[observed]`

This is not a cosmetic doc bug. The README names the exact consequence — "the first install's next
`docker compose up` silently starts the *other* checkout's build" — and then the shipped gate causes
it while the operator is following the instruction meant to prevent it. **Docs that lied: two, in the
same paragraph, about the same fact.**

(Other evaluation agents were running the same gate on this host concurrently, so I cannot claim my
run alone caused it. The mechanism above is reproducible from the source regardless.)

---

## Question 1 — Is the pending approval queue a daily driver?

### What the queue shows an approver: better than I expected

`spec/06 §4.4` is honoured. For every gateway-originated request the queue carries `arguments`
verbatim alongside `args-hash`, with `arguments-supplied: true`. `[observed]`

```
trials.delete_subject_data     {'subject_id': 'SUBJ-0902'}
trials.unblind_subject         {'reason': 'suspected SUSAR', 'subject_id': 'SUBJ-0902'}
trials.export_dataset          {'protocol_id': 'ONC-7741', 'sponsor': 'Ardent-Bio'}
trials.email_participant       {'body': 'Please attend C2D1 on 18 Aug...', ...}
```

And `/console/pending` does four things I have not seen an approval UI do:

1. Prints the arguments and then tells you **not to trust the page**, with a runnable recipe
   (`printf %s "$(cat FILE)" | shasum -a 256`) and the digest it must produce. I ran that recipe
   against a real request and it reproduced the `args-hash` exactly. `[observed]`
2. States the authority chain — which mandate, granted by which named human.
3. Says **"approver ping: not delivered"** rather than showing silence, and carries a standing banner
   that no notification channel is configured.
4. Carries an approval-fatigue detector citing `spec/09 §7`. Mine fired: *"22 parked in the last 300
   seconds … below the cap of 30"*. `[observed]`

Point 3 and point 4 are the marks of somebody who has actually thought about an approver as an
attackable human. I would sign my name to a `trials.delete_subject_data {"subject_id": "SUBJ-0902"}`
row, because I can see the subject and verify the digest myself.

### Why my coordinators still would not live in it

**a. The queue is blind for the decision that matters most.** For `kernel.publish_policy` — the act
that decides what is gated at all — `arguments-supplied: false`, `arguments: null`. `[observed]` The
console is honest about it ("You would be approving an action whose arguments you cannot read"), but
the approver is looking at `args-hash: 1be63c37…` and `target: policy:2026.08.1` and nothing else.
The tool that *built* the request, `bin/stozher-publish-policy`, prints the request hash and does not
print the args-hash or name the file to hash. The mechanism to verify exists and works — I proved it
— but nothing on either surface connects the two. The most consequential approval in the system is
the one with the least legibility.

**b. Every new tool costs two approvals, and the second one is a decision the approver cannot
understand.** Each first call parks *twice*: the action, plus a `kernel.seed_catalog_entry` asking to
classify the tool permanently. Nine tools produced 18 queue rows. `[observed]` The seed row renders
identically to an action row, with arguments `{"class": "read", "server": "trials", "tool":
"read_chart"}`. Nothing tells the approver they are setting a standing rule, or what `read` will mean
for future calls.

**c. That second approval was, in my case, a no-op — and nothing said so.** I approved
`{"class": "read", ...}` for `read_chart`. The next call with different arguments parked again at
`classification: consequential, tier: org-seeded`. `[observed]` The cause is in
`gateway/src/stozher_gateway/policy.py`:

```python
unknown = str(classification.get("default-unknown", "consequential"))
if catalog_class in CLASSES and class_weight(str(catalog_class)) > class_weight(unknown):
    return str(catalog_class)
return unknown
```

Under the shipped `baseline-conservative` profile `default-unknown` **is** `consequential`, so a
seeded class weaker than `consequential` can never take effect. `read` and `benign` seeds are
discarded at classification time; only `prohibited` would win. The reasoning in the docstring is
sound (a component must not quietly downgrade below what the kernel can see). The result is that the
approval ceremony presents a human with a decision, takes their signature, writes a signed envelope
for it — and the decision has no effect. **A gate that records a signature for a no-op is worse than
no gate, because the audit trail now says a human decided something they did not decide.**

**d. Approvals are single-use, and there is no batching.** `single-use: true` on every gate decision.
`[observed]` The same call with identical arguments, made twice, parks the second time. There is no
"approve chart reads for protocol ONC-7741 for today". With 30 trials this is not a queue, it is a
second full-time job. `stozher-approve` itself is fast — 0.62–0.85 s wall clock `[observed]` — so the
cost is entirely human attention, not machinery.

**e. No notification channel is configured by default, and a parked request expires in one hour.**
`notified=0, notify-failures=0` on all 21 rows. `[observed]` The bootstrap warns about this in
prose. In a hospital, "the console is the only place it becomes visible, and only if someone happens
to look" means a `submit_ae_report` parked at 16:00 on Friday is silently `blocked` by 17:00.

### Verdict on Q1

**The queue is a good audit surface and a bad daily driver.** It shows an approver enough to sign
honestly — for gateway tool calls. It is not usable as a daily workflow at my volume: single-use
approvals with no batching, two approvals per new tool, a one-hour expiry with no ping by default,
and a fatigue cap of 30 requests per 300 s that a single coordinator's morning would blow through.
I would live in it for `submit_ae_report`, `unblind_subject`, `export_dataset` and
`delete_subject_data` — about ten decisions a day. I would not survive it for anything else.

---

## Question 2 — Does the four-class taxonomy survive clinical research?

I published a real policy for my domain through the documented ceremony (grant → submit-mandate →
policy-draft → edit → policy-sign → publish → approve → resume; five commands plus an edit, about
three minutes of hands-on `[observed]`) and re-ran every action. The classification took effect
immediately.

| My action | Class I published | Did it work? | What the class could not say |
|---|---|---|---|
| `read_chart` | `read` | ✅ flows, no gate | **It is a regulated disclosure.** See below — the record loses the subject. |
| `screen_candidate` | `read` | ✅ | same |
| `schedule_visit` | `benign` | ✅ per-call envelope + args payload | — |
| `draft_ae_report` | `benign` | ✅ | — |
| `submit_ae_report` | `consequential` | ✅ parks | Cannot express "within 24 h for a SUSAR, auto-escalate". |
| `email_participant` | `consequential` | ✅ parks | **Cannot vary by protocol.** Blinded vs open-label is a per-record fact; the class is per-action. |
| `export_dataset` | `consequential` | ✅ parks | Cannot say "prohibited for any subject who has withdrawn". |
| `unblind_subject` | `consequential` | ✅ parks | Cannot require *two* approvers, or a specific one (the medical monitor). |
| `delete_subject_data` | `consequential` | ✅ parks | Cannot express "this one is mandatory and must complete". |

**The four classes fit the gate question. They do not fit anything else, and they are load-bearing
for three other things at once.** A class simultaneously decides:

1. whether a human signs (`gate-rules`),
2. how long the evidence payload is kept (`evidence-ttl`),
3. what happens offline (`offline`),
4. **and whether the effect gets its own envelope or is folded into a count** (`read` aggregates).

Those four need to vary independently in my domain and cannot.

### The hard case, measured: a chart read

Classified `read`, three chart reads produced **one** envelope: `[observed]`

```json
{"kind":"aggregate","classification":"read",
 "counts":{"by-action":{"trials.read_chart":2,"trials.screen_candidate":1},"total":3},
 "sample-hashes":["e3376c44820f…","c690ab5205a5…","5ae07186a71e…"],
 "window":{"from":"…16:58:30.581Z","to":"…16:58:31.512Z"}}
```

No evidence payload — `evidence-ttl.read` is `P0D`. **The audit trail cannot tell you whose chart was
read.** That fails HIPAA §164.528 accounting of disclosures and GDPR Art. 30 outright.

Worse, the pseudonymity of `sample-hashes` is illusory. `args-hash` is `object-hash` over a tiny
argument space. I recovered **two of three** sample hashes by guessing three subject IDs, in one line
of Python: `[observed]`

```
recovered e3376c44820f -> {'subject_id': 'SUBJ-0417'}
recovered c690ab5205a5 -> {'subject_id': 'SUBJ-0902'}
```

So the aggregate is simultaneously *insufficient* as an accounting record (an auditor is not supposed
to have to brute-force it) and *a disclosure* to anyone holding the subject list. Note also that
`args-hash` covers arguments only, not the action: the hash for `read_chart {"subject_id":
"SUBJ-0902"}` is byte-identical to the one for `delete_subject_data {"subject_id": "SUBJ-0902"}`.

The escape hatch exists and it is `benign` — per-call envelope, arguments payload, no gate. I
verified the payload route serves exactly that, and that it hashes to the commitment: `[observed]`

```
GET /v1/payloads/c0e378257e7c…  ->  {"arguments":{"date":"2026-08-18","subject_id":"SUBJ-0417",
                                     "visit":"C2D1"},"server":"trials","tool":"schedule_visit"}
recomputed object-hash == payload-hash: MATCH
```

So the right answer for a chart read is "class it `benign`". I cannot write that in an SOP. A
regulator reading "reading a patient's chart is classified benign in our system" will stop reading.
**This is a naming problem with regulatory consequences, and it is cheap to fix:** the four classes
want to be `read` / `recorded` / `gated` / `denied`, and the *record granularity* wants to stop being
a synonym for *gate decision*.

### Actions the four classes could not express at all

- **Two-person integrity.** Unblinding needs the investigator *and* the medical monitor.
  `gate-rules.approvers` is a list, and any one of them suffices.
- **Per-record classification.** "Email a participant" is benign in an open-label trial and
  potentially unblinding in a masked one. `reclassify` matches subject/action/resource, and the
  resource for an MCP tool is `mcp:trials` — the protocol is inside the arguments, which policy
  cannot see.
- **State-dependent prohibition.** "Export is prohibited for any subject who withdrew consent" is the
  single most important rule I have. The taxonomy has no way to make a class depend on data state.
- **Mandatory actions.** `delete_subject_data` must *complete*, and a class that only decides whether
  something is allowed cannot say "and it must happen".
- **Retention that differs from the gate.** HIPAA wants six years; EU CTR wants twenty-five.
  `evidence-ttl` is per class, so lengthening it for chart reads lengthens it for every `benign`
  action in the deployment.

### Verdict on Q2

**The taxonomy survives as a gate vocabulary and fails as a compliance vocabulary.** Every action I
had could be *classified*; roughly half were classified wrongly for reasons that had nothing to do
with the gate. The single change with the highest value would be to split `class` into
`gate` × `record-granularity` × `retention`.

---

## Consent withdrawal — the verdict

This is the test I cared about most, and it is where I would stop the pilot.

**Setup.** A live agent session reading `SUBJ-0417`'s chart every 5 s. Mid-session I ran the
documented withdrawal: `./bin/stozher-revoke <mandate> --root human:gate-operator --reason
"SUBJ-0902 withdrew consent 2026-08-04"`. It returned in 0.85 s. `[observed]`

**Propagation, measured.** `[observed]`

| Event | Time |
|---|---|
| revocation recorded by the kernel | 17:04:28.597Z |
| **a chart read succeeded under the withdrawn mandate** | **17:04:31.4Z (+2.8 s)** |
| gateway's feed re-pulled and verified the revocation | 17:04:36.447Z (**+7.85 s**) |
| first refusal returned to the agent | 17:04:36 |

7.85 s here; the bound is the poll interval, `policy_refresh_seconds = 30`, so worst case ~30 s
`[inferred from config + code]`. Setting `revoke-cached: true` in policy forces a re-pull before every
consequential action, which would make the withdrawal near-instant for gated calls — but `read` and
`benign` calls never consult it, so **chart reads would still leak for up to a poll interval.** For a
GDPR erasure request that is defensible. For "stop processing this subject now" it is one disclosure.

**A revocation from an unresolvable signer is refused, precisely.** I generated a fresh seed the
deployment has never seen, signed a revocation with it, and submitted it with the deployment
credential: `revocation-not-authorized: ed25519:edbfacd7… may not revoke ba21626a…`, HTTP 422, and
the refusal is itself a chained record in the rejection stream. `[observed]` Holding the deployment
token buys delivery and nothing else — that property is real.

The component side is weaker: `_is_verifiable` in `gateway/src/stozher_gateway/revocation.py` checks
only that a revocation's signature verifies against the key *embedded in it*, not that the signer has
standing. It over-honours, which is the safe direction. But a revocation the gateway drops is dropped
with `logger.error` and nothing else — no envelope, no kernel-side record, no console surface.
**"Did the withdrawal reach the processor?" has no auditable answer.** `[observed in code]`

### And then the record stopped

The moment the revocation propagated, the gateway's stream wedged — as documented. What is *not*
documented is what that costs the record:

- The gateway kept working locally, correctly refusing every call and recording each refusal as
  `outcome: "blocked"`. It built local seq 14 → 38. `[observed]`
- The kernel refused seq 14 (`mandate-revoked`) and the gateway stopped pushing. Seq 15–38 were never
  even attempted (`pushed_at: NULL`, `push_error: NULL`). `[observed]`
- Among them, local seq 38 is the aggregate covering **the six chart reads** — window
  `17:04:03.994Z → 17:04:31.421Z`, i.e. including the one 2.8 s after the withdrawal. `[observed]`

So the audit trail's last accepted entry is a `session_open` at 17:04:02. **Everything the component
did after the consent was withdrawn — the disclosure that slipped through, and the twenty-four
refusals proving it then complied — exists only in the gateway's local SQLite.** The kernel-side
trace is one rejection row: `claimed-seq 14, claimed-kind effect, mandate-revoked`. It does not name
the action. `[observed]`

### The recovery path does not exist in a deployment the product's own quick-start produces

`spec/04 §7.2` provides the exit: a `kernel.resume_stream` envelope, root-approved. I ran it.

1. `grant` a mandate for `kernel.resume_stream` to the only root →
   `config-malformed: the root cannot grant to itself — spec 03 section 1 forbids self-grant`. `[observed]`
2. Grant it to `agent:bootstrap` instead, submit it, build the resume request. `resume-request` takes
   `--requester <human:name>` and has no `--role`, so it signs with the root key.
3. Park it, approve it →
   `gate-self-approval: ed25519:b4891100… decided its own request`, HTTP 422. `[observed]`
4. Re-built the request with `--requester agent:bootstrap`. Same key, same refusal. `[observed]`

**A single-root deployment cannot resume a wedged stream, and revocation wedges a stream every
time.** `bin/stozher-bootstrap` creates a single root by default and warns only that a single root
"loses the ability to change the root set". It does not say you also lose the ability to record
anything after your first consent withdrawal. Nothing in the revocation section of `deploy/README.md`
mentions a second root either. This is a designed-in dead end that the install path walks you into.

**Consent-withdrawal verdict: fails.** Not because the mechanism is wrong — the cryptography and the
authorization rule are right, and the "preventive rather than detective" choice is the correct one.
It fails because the act of stopping processing also stops the record of stopping, and the documented
way out is unreachable from the deployment the documentation tells you to build.

---

## Auditor export — the verdict

**This is the best part of the product, and it is genuinely good.**

I produced `GET /console/audit/export?format=ndjson` and then wrote ~90 lines of Python using only
the stdlib, PyNaCl, and `spec/01` (JCS RFC 8785; `id(S) = object-hash(S)` over the complete object
including `sig`). **No Stozher code, no kernel, no network.** Result: `[observed]`

```
records: 21   crypto: PyNaCl
stream gw:katsarov-Pro-M4:claude-code  (13 envelopes, seq 0..12)   all sig=OK link=OK
stream kernel:core                     (8 envelopes,  seq 0..7)    all sig=OK link=OK
--- can an outsider walk authority back to a human? ---
  trials.draft_ae_report       -> grantor human:gate-operator (human)
  trials.schedule_visit        -> grantor human:gate-operator (human)
  kernel.publish_policy        -> grantor human:gate-operator (human)
  ...
summary: bad ids=0 bad sigs=0 bad links=0
```

**Tamper test.** I changed one field of one envelope in the export and re-ran the verifier: that
envelope's signature failed and the next envelope's link failed. `[observed]` Two independent
detections from one byte. This is what I need to be able to say to a regulator, and I can say it
without asking them to trust me or my vendor.

**Does it account for the arguments of calls that ran?** Yes, via the route ADR-0030 describes, and
it holds up:
- `X-Stozher-Payload-Route: /v1/payloads/{payload-hash}` on the NDJSON response. `[observed]`
- The HTML rendering states it twice and opens by disclaiming itself: *"This is a reading of the
  record, not the record."* `[observed]`
- Payloads served back hash to the commitment in the envelope — 5 of 5 stored payloads. `[observed]`

### Three things that would fail an audit

**1. The 410 tells the auditor a false story, in the operator's favour.** `[observed]`

```
GET /v1/payloads/9e91376d…   (retain-until 2027-08-04, i.e. not expired)  -> 410
GET /v1/payloads/0000…0000   (a hash that has never existed)              -> 410
   {"result":"decayed","reason":"the payload has decayed; the hash remains the commitment"}
```

Both return byte-identical bodies to a genuinely-swept payload. Three distinct states — *stored*,
*retained-then-lawfully-deleted*, *never recorded* — collapse into one, and the surviving one asserts
lawful deletion. For a project that elsewhere insists a source it could not query is written
`[unknown]` and never omitted, this is the same error it is careful about everywhere else. An
auditor asking "was this evidence ever captured?" gets an answer that says "yes, and we deleted it on
schedule", with no way to tell.

**2. The export does not mark decayed evidence.** After the sweep, the HTML export still lists the
two swept payload hashes as evidence rows with a route to fetch them. Zero mentions of decay,
expiry, or absence anywhere in the document. `[observed]` The auditor discovers the gaps one 410 at
a time.

**3. The auditor needs live authenticated access, and the only credential is the god token.** The
arguments are not in the export bytes (correct — they are erasable precisely because no signature
covers them), so handing over a file is not handing over the record. To read them the auditor needs
`STOZHER_KERNEL_TOKEN` — which is the *same* single caller token the gateway uses to ingest, to force
a retention sweep, and to read every payload in the store. `config/kernel-config.json` has exactly
one `callers` entry and no roles. `[observed]` There is no read-only auditor credential and no
scoping, so "let the regulator verify" and "give the regulator write access to my audit system" are
the same act.

**Auditor-export verdict: passes on integrity, fails on completeness.** The chain is genuinely
verifiable by an outsider — I proved it with my own code — and I would defend it in front of an
inspector. But I cannot hand over a self-contained artefact, I cannot hand over a read-only
credential, and the artefact I can hand over misrepresents missing evidence as expired evidence.

---

## Retention — what survives a clock advance

Declared `"clock-advance": {"advance": "P60D", "acknowledged": "…"}` in `config/kernel-config.json`
and restarted. The kernel logged the acknowledgement as a warning and came up at an effective
`2026-10-03`. `[observed]` Forced a sweep:

```json
{"at":"2026-10-03T17:12:18.543Z",
 "decayed-hashes":["211d9ae5…","c0e378257e…"],
 "payloads-deleted":2,
 "streams-checkpointed":["gw:katsarov-Pro-M4:claude-code@0"]}
```

- The two `benign` payloads (`P30D`, retain-until 2026-09-03) were deleted. `[observed]`
- The `consequential` ones (`P365D`) survived. `[observed]`
- Every envelope still carries its `payload-hash` **and its original `retain-until`**, so the record
  says what was committed to and when it was due to go. `[observed]`
- The chain still verifies, with `"payloads-consulted": 0` — verification never touches a payload.
  `[observed]`
- The affected stream was checkpointed *before* the deletion. `[observed]`

This is exactly what the README promises and I have no complaint about the mechanism. What the record
says about what is gone is the problem, and it is finding #1 above: it says `decayed`, in the same
words it uses for evidence that was never there.

The clock control itself is well-built. The advance is bounded, forward-only by grammar, declared
into the chain, and ratcheted. I would ship this to a customer.

---

## Ranked adoption blockers

1. **Revocation wedges the stream, and a single-root deployment cannot un-wedge it.** Consent
   withdrawal is my most common privileged operation and it permanently silences the audit trail of
   the component it was aimed at. Fix: `bin/stozher-bootstrap` should refuse to produce a
   single-root deployment, or `deploy/README.md` §"Withdrawing a mandate" must say in bold that you
   need two roots *before* your first revocation.
2. **A `read` classification destroys the per-disclosure record, and `benign` is the only class that
   keeps it.** I cannot write "chart access is benign" in a regulatory submission. Split gate
   decision from record granularity, or rename the classes.
3. **A seeded catalog class weaker than `default-unknown` is silently discarded after a human signs
   for it.** An approval ceremony that produces a signed no-op is an integrity problem, not a UX one.
4. **`410 decayed` for a payload that never existed.** Add a third state.
5. **Single credential for ingest, read, payload access and maintenance.** No read-only auditor role,
   no minimum-necessary scoping.
6. **`clean-install.sh` clobbers host-wide image tags despite `.env`,** and its comments assert the
   opposite (§0).
7. **Single-use approvals with no batching and a 1 h expiry, no notification channel by default.**
   At 30 trials this is the difference between a control and a bottleneck.
8. **The policy-change approval shows no arguments,** and nothing links the approver to the file they
   should hash. The mechanism works; the guidance does not exist.
9. **~20 Harbormaster native tools are exposed through the gateway with `govern_native_tools = false`
   by default** (`delegate_task`, `ask_project`, `record_delegation_result`, …). `[observed]` in the
   tools list. A documented blind spot in the audit surface, enabled by default.
10. **No checkpoint exists for the first hour**, so `stozher-anchor` on a fresh install returns
    *"no checkpoint has been recorded yet"* and the day-one export cannot be anchored off-box.
    `[observed]`

## What genuinely worked

- **Outsider verification of the export.** Signatures, hash-linkage, and the walk back to a named
  human, all reproducible from the file with no vendor code. This is the thing I came for and it is
  real.
- **Tamper evidence.** One changed byte, two independent failures.
- **The payload route.** Arguments of calls that ran are retrievable and hash to their commitment.
- **The approver page's refusal to be trusted.** Printing a verification recipe against yourself, and
  refusing to render an approve button because the browser must never hold a signing key, is the
  correct instinct and I have not seen it elsewhere.
- **"approver ping: not delivered"** and the fatigue-spike banner. Both are the product telling on
  itself.
- **`revocation-not-authorized`.** Holding the deployment credential buys delivery, not authority,
  and the refusal is itself a chained record.
- **`gate-self-approval` and the self-grant refusal.** They are the reason blocker #1 exists, and
  they are also *correct*. I would not want either of them removed.
- **Retention.** Payload gone, hash and chain position intact, chain still verifies, checkpoint
  taken first. Exactly as advertised.
- **The clock advance.** Forward-only by grammar, declared, ratcheted, bounded.
- **Publishing a domain policy took three minutes** and worked first time, including a signed
  human approval of the exact document.

## Would I run this over real patient data?

**No — not yet, and for one reason.** The system does the hard cryptographic part better than
anything I have evaluated, and I could defend its audit trail to an inspector. But the first time a
subject withdraws consent, the component that was processing them stops being able to record
anything, and the deployment the documentation tells me to build has no way to fix that. I would run
it in parallel with our existing paper trail for a month, on de-identified screening data only, and
I would revisit the moment a two-root install is the default and a chart read can be recorded
per-disclosure without being called benign.
