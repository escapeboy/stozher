# Stozher — design-partner evaluation from platform SRE

**Evaluator role:** platform SRE, ~300-service fleet. Target use: AI agents on the on-call rotation
doing metrics/log reads, restarts, rollbacks, cluster scaling, node drains, secret rotation, DB
migrations, and paging humans — mostly at 03:00, unattended.

**Commit:** `96b9811` (worktree clone). **Isolation:** compose project `stozher-sre`, kernel on
127.0.0.1:8836, image tags `stozher-sre-{kernel,gateway}:0.1.0`. The live `stozher` project on 8787
was never touched; no `down`, no prune.

Everything below was run, not read. Where I could not verify something I say so.

---

## 0. Verdict first

**No. I would not put this in the path of my 03:00 automation** — because a component whose stream
gets wedged cannot be brought back by any shipped command, and the one failure that wedges it
(revoking a mandate) is a routine security action I perform during exactly the incidents I would be
relying on the agent for.

That is a fixable defect, not a broken thesis. The thesis — a chokepoint that makes agent effects
signed, chained and human-approved — is sound, and several parts of it are better than what I run
today. I would re-evaluate on a build that closes blockers 1 and 2.

---

## 1. Question 1 — is the pending approval queue a daily driver?

**Answer: no, and it must not be. The queue is not the mechanism that makes unattended work
possible; publishing policy is. The queue is the thing you use to *avoid* needing the queue.**

That is the good news and it is understated in the docs.

### What I actually observed

A tool the deployment has never seen parks on first call (`default-unknown: consequential`). I then
established, from code and from a live run, that **approving that first call buys you almost
nothing**:

`gateway/src/stozher_gateway/policy.py:97` `Policy.classify` takes the **stronger** of the org
catalog's class and `default-unknown`. Its own docstring says so. So an approver who classifies
`notes.read_note` as `read` via first-call gating gets a catalog entry — and the effective class
stays `consequential`, because `default-unknown` is `consequential` and stronger wins:

```
classification: "consequential", classification-tier: "org-seeded"
```

Observed live: after the seed was signed into force, a call with different arguments parked again at
tier `org-seeded`, class `consequential`. The catalog is real; it just does not lower the class.

The working escape is the one `classify.py`'s module docstring names: **publish a policy that names
your actions in `by-action`**. I did it end to end. After publishing `2026.08.2` with
`notes.write_note: benign` and `notes.read_note: read`, calls ran with **no human in the loop at
all** — including with the kernel stopped.

### So can a 03:00 job run without a human? Yes — with caveats

Verified with the kernel genuinely stopped (`docker compose run --no-deps`, kernel confirmed down
before *and* after — see §6 for the trap here):

```
notes__read_note  -> is_error: false   (read,   served from cache)
notes__write_note -> is_error: false   (benign, served from cache)
```

`consequential` never runs unattended, by design, and I agree with that design. During a real
outage the refusal is honest:

```
"pending request 05794c14... (held locally; the kernel was unreachable, so nothing was queued
 for a human to see)"
```

That sentence is a genuine fix of a defect a previous evaluation reported. Credit where due — it is
exactly what an operator needs to not go hunting an empty queue.

### What I had to grant to get there, and would I sign it?

**No, I would not sign what the ceremony grants by default.** `bin/stozher-bootstrap` auto-issues the
gateway this standing mandate, with no operator choice
(`deploy/secrets/gateway/mandate.json`, read verbatim):

```json
"scope": { "actions": ["*"],
           "classes": ["read","benign","consequential","prohibited"],
           "components": ["gateway"], "resources": ["*"] },
"not-after": "2026-09-03T16:48:00.670Z"        // 30 days
```

All actions, all four classes (including `prohibited`), all resources, 30 days. Policy still
hard-blocks `prohibited` independently, so this is not as dangerous as it looks — the mandate is
necessary, not sufficient. But it is the blast radius if the agent's device key leaks, and for a
300-service fleet I would want it scoped per action family and measured in hours. There is no flag
on `stozher-bootstrap` to narrow it; you re-grant afterwards by hand, which I did in §4 and which
took two commands plus a file swap.

The grants I *would* sign, and did: `kernel.publish_policy` and `kernel.resume_stream`, each
`--components kernel`, `--days 1`. The `--components kernel` requirement is a genuine trap the docs
warn about ("the step this page cost people twice") — the warning is accurate and I would have hit it
without it.

### Signature count for this evaluation

Seven approval attempts to: classify two tools, publish one policy, recover one wedge. Of those,
**four were pure first-call ceremony that publishing policy would have made unnecessary**, one was
refused as self-approval, one was wasted on a bad resume (§4). That ratio is the whole answer: the
queue is a bootstrapping cost, and if an org treats it as a daily driver they have mis-configured
the product.

**Recommendation to the project:** say this in `README.md` and `deploy/README.md` §3 in one sentence
at the top — *"the queue is for classifying, not for operating; publish policy and the queue goes
quiet."* Right now an evaluator discovers it by reading `classify.py`.

---

## 2. Question 2 — does the four-class taxonomy survive my domain?

**Answer: no, not on the gateway path — the path the README sells as "zero changes on the agent
side". The taxonomy has the right shape and the wrong resolution.**

My canonical case: `restart_service` is **benign** on a stateless worker and **consequential** on the
primary database. Same action name, different target.

### The taxonomy *can* express it in the spec

`spec/05 §3.1` gives `reclassify` three dimensions — `subject`, `action`, `resource` — with a
specificity score. That is exactly the right model.

### The gateway cannot populate the resource dimension

`gateway/src/stozher_gateway/enforce.py:462`:

```python
def _target(self, call: Call) -> str:
    ...
    return f"mcp:{call.server}"
```

The docstring is candid: *"The gateway can name the server it is fronting; it cannot in general name
the row, repo or channel inside it without reading arguments whose meaning only a manifest declares
(§08)."* And `spec/08` manifests declare a class **per action** and a `target-kind` *label* — there is
no mechanism anywhere for a manifest to say "the target is argument `service_name`".

So for every tool behind the gateway, the classification tuple is
`(subject, action, mcp:<server>)`. The arguments live only in `args-hash`, which is not a
classification dimension.

### I proved it, with a working control

I published a signed, root-approved policy `2026.08.2` containing exactly the rule an SRE would
write, plus a control:

```json
{ "subject":"*", "action":"notes.write_note", "resource":"svc:db-primary",
  "class":"consequential", "reason":"SRE INTENT: restarting the primary database is consequential" },
{ "subject":"*", "action":"notes.read_note",  "resource":"mcp:notes",
  "class":"benign",       "reason":"CONTROL: proves reclassify-by-resource works" }
```

Result:

```
notes__write_note {"name":"db-primary","body":"RESTART PRIMARY DATABASE"} -> is_error: false
notes__write_note {"name":"worker-07", ...}                              -> is_error: false
```

Audit trail:

```
seq=15  benign  notes.write_note  target='mcp:notes'  outcome=applied  args=4416ddc1d8
seq=14  benign  notes.write_note  target='mcp:notes'  outcome=applied  args=172bb40c12
seq=16  benign  notes.read_note   target='mcp:notes'  outcome=applied
```

**"RESTART PRIMARY DATABASE" was applied with no human approval, under a policy that a root had
signed saying that exact resource is consequential.** The rule matched nothing and nothing warned
me — not `policy-sign`, not the kernel's acceptance of the policy, not the console.

The control entry (`resource: "mcp:notes"`) **did** match and moved `read_note` from `read` to
`benign` (seq=16). So the matcher is correct and well-implemented. **The vocabulary is the failure.**

Second-order damage: seq 14 and 15 are indistinguishable in the audit trail. An auditor asking "did
an agent ever restart the primary?" cannot answer from the trail — only `args-hash` differs, and at
class `benign` the evidence payload has a 30-day TTL after which only the hash survives.

### The four escapes, and why each costs something

1. **Over-classify** (everything `consequential`): correct, and it means the fleet halts at 03:00
   waiting for a signature. This is nightmare (a) from my brief, delivered by the taxonomy.
2. **Under-classify** (`benign`): what I demonstrated above. Nightmare (b), with a signed policy
   asserting the opposite.
3. **Split the tool** — `ops.restart_worker` vs `ops.restart_database`, so the distinction lives in
   the action name where prefix patterns work. This is the only clean answer today, and it pushes
   the safety boundary into *tool naming*, which for third-party MCP servers I do not control.
4. **Write a native component** that authors its own envelopes with `execution.target =
   "svc:db-primary"`. Then `reclassify.resource` works — but you have abandoned "zero changes on the
   agent side", and you inherit a pattern limitation: `_dimension_score`
   (`policy.py:29`) only does exact, `*`, or a `.`-segment prefix. `svc:worker-07` will **never**
   match `svc:worker.*`. For 300 services you either write 300 exact entries or adopt an undocumented
   naming discipline (`svc:worker.07`) that makes prefixes work. `spec/05 §3.1` actively steers you
   away from this by saying prefix patterns are *"only useful on `action`"*.

**This is a real finding against the project's own open question, and it is not fatal.** The fix is
small and lives in `spec/08`: let a manifest declare which argument yields `execution.target`. Then
option 4 collapses into option "it just works", and the resource dimension earns its place.

---

## 3. Availability and blast radius — kernel down

**This part works, and it is the best-engineered thing here.** Verified with `--no-deps`, kernel
confirmed stopped before and after:

| Class | Kernel down | Matches `spec/05 §7`? |
|---|---|---|
| `read` | served from cache | yes (`offline.read: allow`) |
| `benign` | served from cache | yes (`offline.benign: allow`) |
| `consequential` | blocked, honest reason | yes (`offline.consequential: block`) |

Blast radius of a kernel outage is therefore **exactly the gated work**, which is the trade the
product advertises and the right one. My read-only agents keep working; my restart agents stop. I
can live with that.

One nit: the offline `consequential` refusal carries `reason-code: "gate-parked"`, not `blocked`,
even though `offline.consequential` is `block`. The human-readable `reason` is correct and explicit;
a runbook keyed on reason codes would mis-route. Low severity.

### Bundle expiry — works, but not as documented

Exported a bundle, advanced the clock `P10D` (ADR-0023, declared in both components), restarted.
The kernel logs the acknowledgement loudly on every boot:

```
WARN records emitted by this deployment are not evidence of when anything happened
     advance=P10D effective=2026-08-14T17:09:17.582Z
```

The expired bundle produced the single best error message in the product:

```
the policy bundle was refused — bundle-expired: /var/lib/stozher/gateway/policy-bundle.json was
exported 2026-08-04T17:07:18.181Z with max-age P7D and expired 2026-08-11T17:07:18.181Z; it is now
2026-08-14T17:10:00.614Z. Export a fresh bundle — a component does not run on a policy nobody can
vouch for any more
```

File, export time, max-age, expiry, current clock, and the remedy. That is how every error in this
product should read.

**But `deploy/README.md` says "an expired bundle refuses to start", and it does not refuse to
start.** The process starts, the MCP session opens, and every governed server is replaced by a
`<server>__unavailable` stub (`gateway-enforcement-unavailable`). Functionally that is a fail-closed
degrade and arguably better than dying — but an SRE writing a liveness check on "process exits" gets
it wrong, and the doc should say "refuses to serve" instead.

### The ungoverned side-channel that survives every failure state

With enforcement fully unavailable (expired bundle), I called a native Harbormaster tool:

```
list_projects -> is_error: false
```

The ceremony ships `govern_native_tools = false`. The config comment explains the reasoning (show
the partner *their* tools first), so this is deliberate and documented — but it means the host's own
tools, which for Harbormaster include `delegate_task`, remain callable and unaudited in **every**
failure mode I induced: kernel down, stream wedged, bundle expired. For a governance product that is
the wrong default to ship in a generated config.

---

## 4. Availability and blast radius — the wedge. This is the blocker.

I did the thing an SRE does during an incident: **revoked a mandate** ("laptop lost"). The docs are
straight about the consequence, and the behaviour is exactly per spec.

```
reason-code: "mandate-revoked", result: "blocked", retryable: false
reason: "the kernel refused this stream at seq 25 (mandate 3f6877... was revoked at
         2026-08-04T17:02:25.944Z); nothing this component emits is reaching the audit,
         so it is not acting"
```

`mandate-revoked` is in the `mandate-*` family, so per `spec/05 §7.1` clause 4 there is **no grace
for any class** — `read` and `benign` blocked immediately. Correct, and I want that. The message is
excellent.

Then I tried to recover, following `spec/04 §7.2`.

### 4a. The operator docs never mention the exit

`deploy/README.md` says, **twice** (lines 557 and 632), that the stream is *"wedged at that position
until an operator intervenes"* — and never says how to intervene. `grep -rn 'wedge'` across
`README.md`, `deploy/README.md`, `gateway/README.md` returns those two lines and nothing else.

`resume-request` / `resume-publish` exist only in `stozher-kernel --help` and in one cell of
`docs/spec-debt.md`. At 03:00 the operator reading the page that *caused* their outage has no path
out of it.

### 4b. `--requester human:<name>` deadlocks a single-root deployment

`resume-request --requester <human:name>` is what `--help` prescribes. Doing that, then approving
with the only enrolled root:

```
{"reason":"ed25519:f1373cb3... decided its own request",
 "reason-code":"gate-self-approval","result":"rejected","retryable":false}   HTTP 422
```

`clean-install.sh` — the project's own quick start — produces exactly one root, and `README.md` is
explicit that a deployment starting with one root can *never* add a second. **Followed literally, a
quick-start deployment cannot ever unwedge a stream.**

The escape is `--requester agent:bootstrap`, which the help text does not suggest. Approval then
succeeded.

### 4c. The position is validated *after* the human signs

I deliberately used the `envelope-id` the agent reported (`aa7e57d0…`) instead of the rejection
record's `object-hash` (`e74190d3…`) — an easy 03:00 confusion, since the agent's error surfaces the
former and only `/v1/rejections` carries the latter.

`resume-request` accepted it. `park` accepted it. It failed only at `resume-publish`, **after** a root
had signed, burning a single-use approval. `spec/04 §7.2` rule 5 names
`stream-resume-position-unknown` for this; nothing checks it until the last step.

### 4d. `resume-publish` needs a flag that is in no help text and no doc

With the correct hash and an agent requester, `resume-publish` still failed:

```
{"reason":"mandate is held by ed25519:bb8b5be8..., envelope signed by ed25519:f1373cb3...",
 "reason-code":"mandate-grantee-key-mismatch"}
```

`resume-publish` signs with role 0 (human root) by default. Its `--help` lists
`[--evidence] [--stream] [--token-env] [--config]` — **no `--role`/`--index`**, unlike
`policy-publish` which documents both. I guessed:

```
resume-publish ... --role 1 --index 0   ->  {"result":"accepted","seq":14,"stream":"kernel:core"}
```

Accepted. So recovery *is* possible in a single-root deployment — via an undocumented flag arrived at
by reasoning about which key signs what. I would not expect a tired human to get there.

### 4e. And after all that, the component is still down. Permanently.

The resume envelope is on `kernel:core`. I swapped in a fresh, valid gateway mandate. Then:

```
notes__read_note -> reason-code: "mandate-revoked", result: "blocked"      (unchanged)
```

Root cause, established by reading the code and confirmed against the live store:

- `store.clear_wedge()` has **exactly one caller**, `emitter.py:273`, reached only when
  `response.accepted` is true.
- `emitter.push_pending()` skips every envelope on a wedged stream *before* it can call
  `self._kernel.ingest(...)`:
  ```python
  if stream in wedged or self._store.wedge(stream) is not None:
      wedged.add(stream); continue
  ```

So the only event that clears a wedge is an acceptance, and no submission is ever attempted while
wedged. **The loop is closed.** `spec/05 §7.2` clause 2 requires the component to clear the wedge
"once the kernel accepts a submission on that stream again" — it never can, because nothing is ever
submitted. There is no channel by which the operator's root-approved resume reaches the component.

Live state after a correct, root-approved resume:

```
wedges: {'stream':'gw:katsarov-Pro-M4:claude-code', 'seq':25,
         'reason_code':'mandate-revoked', 'grace_served':0}
unpushed envelopes (local chain not in the audit): 8
```

`stozher-gateway --help` offers `{config, pending, catalog, keygen, approve, deny}` — **no unwedge,
no retry, no resume**. The only exits I can see are hand-editing `gateway.db` or deleting the
gateway's state file, which destroys the local chain — the very evidence of what the component did
while wedged.

**Blast radius, stated plainly: one revoked mandate permanently removes one component from the
fleet, and the documented recovery act does not recover it.** For a fleet where mandate rotation is
routine, this is an outage generator, not an availability control. This is my #1 blocker and it is
the reason for the verdict.

---

## 5. The clean-install gate fails on this commit

`README.md` headlines **"Wipe to first audited envelope: 169 seconds"**, measured by
`deploy/gate/clean-install.sh`. On my machine, on `96b9811`, that gate **fails**:

```
[ 119s] 5  the same call again — now it applies, and the downstream is actually invoked
  {"tool": "notes__write_note", "is_error": true,
   "text": "Error executing tool notes__write_note: 'NoneType' object is not subscriptable",
   "refusal": null}

GATE FAILED: the approved call did not reach the downstream server — the approval bought nothing
```

Reproduced **twice independently** — a second design-partner agent ran the gate concurrently and its
run, with a different root key and different request hashes, failed at the same step with the same
message. I then reproduced it by hand a third time.

### Root cause

The first call parks **two** requests: the call's own (`6190a58f…`) and a catalog seed
(`kernel.seed_catalog_entry`, `64a69e8a…`). The agent's refusal `hint` names **only the first**:

> *"pending request 6190a58f…; once approved, the same call may be made again"*

That is false. Approving only that one and retrying crashes in `enforce.py:1159`:

```python
seed_hash = str(parked.seed["decision"]["request-hash"])
```

`_seed_catalog` guards `parked.seed is None` but not `parked.seed["decision"] is None`.

And it is **not recoverable by approving the second request afterwards**, because
`store.pending()` is:

```sql
SELECT * FROM parked WHERE decision_json IS NULL ORDER BY created_at
```

`_collect_decisions` iterates `pending()` and only then calls `_collect_seed_decision`. Once the
call's decision is recorded the row leaves that query forever, so the seed decision can never be
attached. Verified in the live store — `seed.decision: None` on every row, including one whose seed
request I had successfully approved at the kernel.

### Proof of the ordering dependency

Fresh tool, both requests approved **before** any retry:

```
notes__read_note -> is_error: false, "no note called 'sre'"     ✅
```

Same tool family, call approved first, retry, then seed approved:

```
notes__write_note -> 'NoneType' object is not subscriptable     ❌ forever
```

### Why this matters more than a crash

- The tool is **permanently dead** for that argument set. No reason code, `refusal: null`, and
  **zero server-side log output** — I captured the gateway's stderr and it was empty. Nothing to page
  on, nothing to grep.
- The failure is triggered by following the product's own instructions.
- It breaks the measurement on line 18 of the README, which is currently not reproducible.

---

## 6. Docs that lied, and places I got stuck

| # | Doc / surface | What it said | What happened |
|---|---|---|---|
| 1 | agent refusal `hint` | "pending request X; once approved, the same call may be made again" | Two requests park; approving X alone kills the tool permanently (§5) |
| 2 | `deploy/README.md` ×2 | "wedged … until an operator intervenes" | Never says how. `resume-request`/`resume-publish` appear in no operator doc |
| 3 | `resume-publish --help` | lists `[--evidence] [--stream] [--token-env] [--config]` | Needs undocumented `--role 1 --index 0` to work at all (§4d) |
| 4 | `resume-request --help` | `--requester <human:name>` | Doing that deadlocks on `gate-self-approval` in a one-root deployment (§4b) |
| 5 | `deploy/README.md` bundle | "an expired bundle **refuses to start**" | Starts; degrades to `__unavailable` stubs (§3) |
| 6 | `deploy/README.md` bundle | example path `ci/policy-bundle.json` | `ci/` is not a mount in the shipped `docker-compose.yml`; the gateway cannot see it. Had to relocate under `secrets/gateway/` |
| 7 | `spec/05 §3.1` | prefix patterns "only useful on `action`" | True *given* the separator, but it steers operators away from the one resource-naming discipline that makes fleet-scale policy tractable (§2) |
| 8 | `policy export-bundle` | `--revocations` defaults to none | I had an active revocation; the bundle says "0 revocation(s)" and a **root signs that assertion**. Honest output, dangerous default |
| 9 | console nav | tab labelled "refused" | Route is `/console/rejections`; `/console/refused` returns empty. Cosmetic |

**Where I got stuck, in order:** (a) the gate failing at step 5 with an unstructured `TypeError` and
no logs — 40 minutes to root-cause, and I only got there by reading `store.py`; (b) finding
`--refused-object-hash` at all, which lives only in `/v1/rejections` and not in the refusal the agent
sees; (c) the self-approval deadlock, where the help text's own prescribed flag is the one that
cannot work; (d) `resume-publish`'s missing `--role`; (e) discovering after all of it that the
component stays wedged regardless.

**Methodology trap worth reporting:** `docker compose run gateway` honours `depends_on:
service_healthy` and **restarts a stopped kernel**. My first offline test was therefore invalid — the
kernel was back up before the gateway started. I re-ran everything offline with `--no-deps` and
confirmed the kernel was down before *and* after each call. Anyone testing this product's offline
story will hit this and may report a false pass; it belongs in `deploy/README.md`.

---

## 7. Ranked adoption blockers

**P0 — would prevent deployment**

1. **A wedged component can never be unwedged** (§4e). `clear_wedge` is reachable only via an
   accepted push; `push_pending` skips wedged streams. No CLI command. Contradicts `spec/05 §7.2`
   clause 2. One routine revocation = one permanently dead component + stranded local chain.
2. **Approve-then-retry permanently kills a tool** (§5). Crash with no reason code and no log;
   unrecoverable by later approval because of the `pending()` filter; breaks the project's own
   headline gate.

**P1 — would block my use case specifically**

3. **The taxonomy cannot express per-target class on the gateway path** (§2). Signed policy naming a
   resource silently matches nothing; a primary-DB restart applied as `benign`. Needs a manifest
   argument→target mapping in `spec/08`.
4. **Recovery is undocumented end to end** (§4a–4d): no operator doc, a prescribed flag that
   deadlocks, a required flag that is undocumented, and validation that fires only after a human has
   signed.

**P2 — would make me nervous in month two**

5. **Ceremony auto-grants `actions:["*"]` / all classes / `resources:["*"]` / 30 days**, with no way
   to narrow it at bootstrap (§1).
6. **`export-bundle` defaults to an empty revocation set** and gets a root signature over it (§6/#8).
7. **`govern_native_tools = false` ships in the generated config**, leaving an unaudited tool path
   that survives kernel-down, wedged and bundle-expired states (§3).
8. **No notification channel by default.** The console says so honestly — "*this page is the only
   place a park becomes visible*" — which I respect, but for unattended work the webhook should be
   configured by the ceremony, not left as an exercise.

**P3 — polish**

9. `reason-code: gate-parked` where `offline.consequential: block` applies (§3).
10. `compose run` restarting a stopped kernel, undocumented (§6).
11. Doc fixes #5, #6, #9 in §6.

---

## 8. What genuinely worked

I want to be specific here, because most of this report is failures and that would misrepresent the
build.

- **Offline degradation is exactly right** (§3). `read`/`benign` from cache, `consequential` blocked,
  verified against a genuinely stopped kernel. This is the product's core availability claim and it
  holds.
- **Wedge *semantics*** are precisely per spec — `mandate-*` family gets no grace for any class, and
  the refusal explains itself in one sentence an on-call engineer can act on ("*nothing this
  component emits is reaching the audit, so it is not acting*"). The behaviour is right; only the
  exit is missing.
- **Refusal objects are the best part of the product.** Structured, verbatim kernel reason codes,
  `retryable` flags, and human sentences that name the cause. The bundle-expiry message (§3) is a
  model.
- **Backup/restore is production-grade.** Refused to overwrite a live store, required `--force`,
  moved the previous state aside with a timestamped suffix rather than deleting, restarted, and
  verified all three streams including the resumed `kernel:core`. I would trust it.
- **The self-approval check is real and it caught me** (§4b). Comparing the person rather than the
  keypair is the correct call, and it fired on a path I did not expect it to.
- **A previously-reported defect is genuinely fixed.** The offline park now says "*nothing was
  queued for a human to see*" instead of blaming the network. That is the right kind of fix.
- **The clean-install gate's own isolation flags** (`COMPOSE_PROJECT_NAME`, `STOZHER_*_IMAGE`,
  `--port`) let me run a full wipe-and-rebuild beside a production install without touching it. The
  header comments explain exactly why each exists, including the incident that motivated them. Rare
  and appreciated.
- **`--components kernel` warning** in `deploy/README.md` saved me a failure it says cost others
  twice. Docs that name their own scar tissue are worth reading.

---

## 9. Would I keep it after a month, and what would make me turn it off?

**Keep** — conditionally. The audit trail is real, the offline story is honest, and the gate is not
bypassable in any way I found. For a *read-heavy* agent fleet — metrics, logs, dashboards,
diagnostics, paging — I would run this today and consider it a net gain, because policy publication
makes the queue go quiet and the failure modes are loud.

**I would turn it off the first time a wedge takes a component out during an incident.** Not because
of the wedge — that is the product working — but because there is no shipped way back, and during an
incident I cannot afford to reverse-engineer `emitter.py` to find out that there is no way back. One
occurrence and it goes.

The second thing that would end it: discovering, in an audit, two `benign` envelopes with identical
`target` where one of them restarted a primary database (§2). That is the failure the product exists
to prevent, and today it can produce it under a signed policy that says otherwise.

**One plain sentence:** No — I would not put this in the path of my 03:00 automation, because a
routine mandate revocation permanently removes a component from the fleet and no shipped command
brings it back.

---

## Appendix — reproduction

Scratch drivers written into the worktree (nothing committed, no source modified):

- `deploy/sre-probe.sh` — env-loading MCP probe / kernel API driver (`SRE_NO_DEPS=1` for real
  offline tests)
- `deploy/sre-mandate.sh`, `deploy/sre-draft.sh`, `deploy/sre-sign.sh` — the policy-publish path
- `deploy/sre-recover.sh`, `deploy/sre-resume.sh`, `deploy/sre-resume2.sh`,
  `deploy/sre-resume-publish.sh` — the wedge recovery attempt
- `deploy/sre-bundle.sh` — anchor + `export-bundle`
- `deploy/sre-pending.py`, `deploy/sre-audit.py` — console/audit renderers
- `deploy/config/policy-next.json`, `deploy/config/policy-2026.08.2.json` — the SRE fleet policy with
  the intent rule and the control rule

Clock advanced `P10D` in `deploy/config/kernel-config.json` and `deploy/config/stozher-gateway.toml`;
per ADR-0023 that is irreversible for this deployment, which is why it was done last.
