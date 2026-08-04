# Design-partner report — Stozher at a 40-person litigation firm

**Evaluator:** prospective design partner, litigation firm, ~40 people. AI paralegal over case files.
**Build:** worktree clone of `main @ 96b9811`. Own compose project `stozher-legal`, kernel on 8832,
own image tags. The live `stozher` project was not touched.
**What I ran:** `./deploy/gate/clean-install.sh --port 8832`, then a real firm policy, a real
downstream MCP server with the paralegal's ten tools, approvals through the CLI and the console,
`clock-advance` to compress two hours and then thirty-two days, mandate expiry and recovery, a true
offline run, retention sweep, and chain verification.
**Docs I used:** `README.md` §Quick start, `deploy/README.md`. Nothing else, until a failure forced
me into the source.

---

## Answer 0 — the thing that has to be said first

**The shipped release gate fails, on the documented quick start, on the first try, on the hardware
the README benchmarks.**

```
[ 138s] 5  the same call again — now it applies, and the downstream is actually invoked
  {"event": "call", "tool": "notes__write_note", "is_error": true,
   "text": "Error executing tool notes__write_note: 'NoneType' object is not subscriptable"}

GATE FAILED: the approved call did not reach the downstream server — the approval bought nothing
```

That is `deploy/gate/clean-install.sh`, unmodified, first run. Not a flake — I reproduced it four
times by hand, including once on a completely untouched tool following `deploy/README.md` §3 word
for word.

### What it is

`_seed_catalog` in `gateway/src/stozher_gateway/enforce.py` dereferences a decision that the
documented approval route can never supply:

```python
if parked.catalog_class is None or parked.seed is None:   # guards the wrapper …
    return False
...
seed_hash = str(parked.seed["decision"]["request-hash"])   # … but "decision" is None
```

A first call parks **two** requests — the call, and a separate `kernel.seed_catalog_entry` asking
what class the tool is. `bin/stozher-approve <hash>` answers one of them. The retry then reads
`parked.seed["decision"]`, which is `None`, and raises `TypeError`.

Confirmed against the gateway's own store (`?mode=ro`, nothing written):

```
[0] <-- decided_for picks this
    action         notes.write_note
    call decision  signed
    seed decision  None
```

Approving the second request afterwards **does not fix it**. `_collect_seed_decision` is only
reachable from `_collect_decisions`'s loop over `store.pending()`, and `pending()` is
`WHERE decision_json IS NULL` — the row left that set the moment the call was answered. I approved
the seed request and retried: same `TypeError`. The call is wedged permanently.

### Blast radius, measured

| tool | first call | approve | retry |
|---|---|---|---|
| `github.create_issue` — in the shipped catalog | parks | ok | **applies** |
| `notes.write_note` — not in the catalog | parks | ok | **TypeError, forever** |
| `notes.read_note` — not in the catalog, clean run | parks | ok | **TypeError, forever** |
| every one of my ten paralegal tools | parks | ok | **TypeError, forever** |

The shipped catalog is 19 servers of developer tooling. **A law firm's tools are all uncatalogued
by definition**, so on the documented path the product does no work at all for the domain it is
being evaluated for.

### Three things that make it worse than a crash

1. **No traceback anywhere.** Gateway stderr was empty on every reproduction. The agent gets
   `'NoneType' object is not subscriptable` and that string is the entire diagnostic.
2. **No refusal document and no envelope.** `result`/`reason-code` are absent; the audit trail has
   no record that an approved action failed. After the gate run the chain held a signed
   `gate-decision` approving `notes.write_note` and **no corresponding effect** — an auditor sees a
   partner authorising a filing with nothing saying whether it happened.
3. **The only working approval route is undocumented and unusable.** `stozher-gateway approve
   --classify` writes both parts. It is not in `deploy/README.md`, it needs the approver's private
   seed mounted into the agent-facing container — destroying the "signing has no network; the
   network has no key" property that is the product's central claim — and it rejected the
   ceremony's own root seed anyway (`ed25519:bf11… is not enrolled as human:gate-operator`: it
   reads the raw seed where `stozher-kernel decide` derives SLIP-0010 role 0 index 0).

### The workaround, and why it changes the pitch

`first_call = not classification.known and not classification.policy_named`. Publish a policy naming
every action in `by-action` and the seed park never happens. I did this — draft, sign, park, approve,
publish, five commands — and everything worked cleanly from then on.

But that inverts the README's headline promise. "*Unknown is not ungoverned; unknown is expensive
until classified*" is false as shipped. **Unknown is fatal until classified**, and the classification
has to happen through a five-command signed policy change *before the agent ever runs*. Every new
tool the paralegal gains is a dead tool until a policy version ships. For a firm that adds a tool a
month, that is a release process for a feature flag.

---

## Answer 1 — Is the pending approval queue a daily driver?

**No. A partner would route around it inside a week, and I can put numbers on why.**

### The queue after twenty minutes of one agent on one matter

```
queue depth: 36
expired:     31
undecided:   36
[('kernel.seed_catalog_entry', 13), ('paralegal.file_with_court', 4),
 ('paralegal.delete_document', 4), ('paralegal.email_opposing_counsel', 4),
 ('paralegal.serve_discovery_response', 4), ('paralegal.export_case_file', 1), ...]
```

`/console/pending` was **154,274 bytes** of HTML. Four `<h2>` sections, all 36 rows in the first
one, expired and live interleaved. There is no filter, no archive, no dead-letter section, nothing
prunes. Scale that to forty people and the page is the problem, not the control.

### Six specific things that break it

1. **One hour to answer.** Parked requests carry `not-after` = +1h. I advanced the clock two hours —
   one deposition, one motion hearing, one flight — and came back to:
   ```
   27 in queue, 27 expired
   ```
   Every one. This is malpractice-adjacent in my domain: a filing deadline does not care that the
   partner was in court. And `arguments-supplied` flipped to `False` on expiry — the kernel erases
   the arguments — so the partner cannot even read what was asked. They see 27 rows of "expired",
   with no content, and no way to tell whether one of them was the reply brief due today.
2. **Nothing pings anyone.** The console says so itself: *"No notification channel is configured.
   Nothing pings an approver when something parks — this page is the only place a park becomes
   visible."* The docs are honest about this. It is still a queue, not a control.
3. **Thirteen of the 36 rows were "what class is this tool?"** A partner is not qualified to answer
   `kernel.seed_catalog_entry` for `tool:paralegal/serve_discovery_response`, and it is noise between
   them and the four decisions they actually own.
4. **Approving is a terminal command with a 64-character hash.** The console has no approve button
   by design (ADR-0008) — you copy a hash out of a web page into a shell. The design record makes an
   honest case for this. It is still not something a litigation partner does forty times a day.
5. **The console instructs the approver to verify the args-hash by hand**: paste the JSON into a
   file, run `shasum -a 256`, compare to a 64-hex string, *"Check that yourself, rather than trusting
   this page."* This is correct security advice and it will be done zero times in production. If it
   is skipped, the console page is a trusted rendering channel — which ADR-0011 already identified
   as a social-engineering surface and only half-closed.
6. **One approver, permanently.** The quick-start ceremony enrols exactly one root and warns you
   that changing the root set needs two. So a firm that installed the documented way has *one human*
   who can approve *everything*, forever, with no path to add a second. That is not an approval
   queue, it is a single point of failure with a signature on it.

### What I would actually do in week two

Publish a policy reclassifying `file_with_court` and `email_opposing_counsel` as `benign` so the
work flows, and keep the gate on `delete_document` only. Which is exactly the failure mode the
product exists to prevent — and the taxonomy gives me no way to keep the gate *and* make it
answerable, because there is no class between "one signature, right now, within the hour" and
"nobody is asked".

### What genuinely works here

Approval fatigue detection is real and I did not expect it. The pending page surfaced
`agent:claude-code/katsarov-Pro-M4 | 25 parked in window | below the cap of 30` as a *finding*, with
the text *"do not answer a run of near-identical requests without asking why there is a run."* That
is the right control and I have not seen it anywhere else.

---

## Answer 2 — Does the four-class taxonomy survive my domain?

**Partly. The classes are the right *axis*. They are the wrong *resolution*, and two of my highest-
risk actions cannot be expressed at all.**

Here is the whole tool surface, with what the classifier proposed on first contact (read out of the
kernel's own gate queue) and what the firm actually needs.

| action | classifier proposed | what the firm needs | verdict |
|---|---|---|---|
| `read_docket` | `read` | read | ✅ clean |
| `search_discovery` | `read` | read | ✅ clean |
| `calendar_deadline` | **`consequential`** | benign | ❌ over-gated |
| `draft_motion` | **`consequential`** | benign | ❌ over-gated |
| `file_with_court` | `consequential` | consequential, **partner only** | ⚠️ class right, granularity wrong |
| `serve_discovery_response` | `consequential` | consequential, **deadline-bound** | ⚠️ granularity |
| `email_opposing_counsel` | `consequential` | consequential, any attorney | ⚠️ granularity |
| `delete_document` | `consequential` | consequential, **records manager + hold check** | ⚠️ granularity |
| `fetch_privileged_material` | **`read`** | *no class exists* | ❌ **taxonomy hole** |
| `export_case_file` | **`consequential`** | `prohibited` externally, gated internally | ❌ **taxonomy hole** |

### Hole 1 — there is no class for "allowed, but this is the record that matters"

Reading privileged client material is not dangerous. *Not being able to prove afterwards which
client's file the agent opened* is disbarment-grade. The taxonomy welds authority to retention:

```json
"evidence-ttl": { "read": "P0D", "benign": "P30D", "consequential": "P365D", "prohibited": "P3650D" }
```

The honest class for `fetch_privileged_material` is `read`. Under the shipped baseline that means
**the evidence payload is deleted the same day**, and worse — `read` folds into an aggregate:

```json
{ "kind": "aggregate", "classification": "read",
  "counts": { "by-action": { "paralegal.read_docket": 1, "paralegal.search_discovery": 1 }, "total": 2 },
  "sample-hashes": ["858aa94e…", "a4ab379f…"] }
```

No target. No client. No matter. The aggregate can tell me the agent fetched privileged material
seven times and cannot tell me **whose**. That is the single question a malpractice carrier will ask.

I could not fix this with a class, so I lied. I published `fetch_privileged_material` as **`benign`**
— not because reading privileged material is benign, but purely because `benign` is not folded and I
could set its TTL to seven years. It worked:

```json
{ "classification": "benign", "execution": {"action": "paralegal.fetch_privileged_material",
  "outcome": "applied"}, "evidence": {"retain-until": "2033-08-02T19:01:36.400Z"} }
```

**My audit trail now asserts, under signature, that reading attorney-client privileged material is
"benign".** I chose that. I would not defend it to a bar committee. The missing thing is one bit that
is orthogonal to the other four — *witnessed* / *high-evidence* — or, more simply, retention and
folding being policy dimensions in their own right rather than a function of the gate class.

### Hole 2 — nothing reaches `prohibited` on its own, and `prohibited` is absolute

`export_case_file` to `s3://outside-the-firm/dump` — the whole matter, out of the building — was
proposed **`consequential`** by the conservative heuristic. Nothing in the classifier can ever
propose `prohibited`; it is reachable only by an operator typing it into `by-action`. So the
disbarment-grade action arrived in the same queue as "calendar a deadline", one signature away, from
the one approver the deployment has.

When I *did* declare it `prohibited`, it worked exactly as advertised — hard-denied whatever the
mandate says, and recorded:

```json
{ "classification": "prohibited", "execution": { "action": "paralegal.export_case_file",
  "outcome": "attempted" }, "evidence": { "retain-until": "2036-08-01T19:01:37.353Z" } }
```

That record is genuinely excellent. But `prohibited` is now absolute, and transferring a matter to
successor counsel is an *ethical obligation*, not an option. The real rule is "prohibited unless two
partners and the GC sign" and there is no way to say it: `gate-rules` has a closed member vocabulary,

```rust
if !["classes", "decision", "approvers"].contains(&key.as_str()) {  // policy.rs:443
```

so there is no quorum, no threshold, no escalation tier. `deny` and `gate` are the only two decisions
and the gap between them is where every genuinely dangerous-but-sometimes-necessary act lives.

### Hole 3 — the class is right, the granularity is per-class

All four of my consequential actions share **one** approver list, because `approvers` hangs off
`classes`, never off an action. I cannot express:

- filings → a partner;
- discovery service → the associate of record;
- deletion → the records manager, and only after a litigation-hold check;
- email → anyone admitted.

Everything `consequential` is one flat pool, and any member of it can approve anything in it. For a
firm this is the difference between a control and a rubber stamp.

### Hole 4 — the envelope has no room for a matter

Every effect I generated recorded the same target:

```json
"execution": { "action": "paralegal.file_with_court", "target": "mcp:paralegal" }
```

`target` is the **server**, not the case. And `reclassify` matches on `subject` / `action` /
`resource` where `resource` is that same target (`policy.rs:611-618`). So:

- I cannot write "export is prohibited to an external destination, consequential internally" —
  the destination is inside `args-hash`, which is a hash;
- I cannot write "deletion is prohibited on matters under litigation hold" — there is no matter;
- an auditor cannot ask **"what did the agent do on the Acme matter?"** from the envelope stream at
  all. Every answer requires dereferencing evidence payloads, which have a TTL.

In my domain the unit of authority is the *matter*. The envelope has no field for it, and
`args-hash` is deliberately opaque, so the one dimension policy most needs is the one dimension
policy structurally cannot see.

### Summary on the taxonomy

The four classes survive as a **triage axis** — I mapped eight of ten tools onto them without
argument, and the `read`/`benign` split did real work. They fail as a **policy language**: no
resource dimension below the server, no per-action approvers, no quorum, no tier between `gate` and
`deny`, and retention/folding welded to the gate class so that choosing the honest class throws away
the evidence.

---

## Everything else I hit, in the order I hit it

1. **`deploy/README.md` §"Changing policy" `$K` does not work as printed.** No `--network`, no
   `STOZHER_KERNEL_TOKEN`. `policy-draft --url` exits 1 with *"STOZHER_KERNEL_TOKEN is unset"*. I had
   to write my own wrapper. The §"Changing the root set" block *does* show both, so the file
   contradicts itself two hundred lines apart.
2. **`bin/stozher-publish-policy -h` omits `--mandate`, which is required.** Running it without gives
   a good error, but the script's own usage text is wrong.
3. **`/console/mandates` shows a 12-character mandate id** (`dd359850c599`) and `--mandate` needs the
   full 64 hex. The README says *"Reuse the id shown on /console/mandates."* You cannot; I had to go
   back to the ceremony's scrollback.
4. **The documented `grant` recipe mints an expired mandate on a clock-advanced deployment.** Commit
   `d77a92c` added `--config` to `grant` and `decide` for exactly this. `bin/stozher-approve` passes
   it. **`deploy/README.md`'s `$OFF grant …` block does not**, and there is no wrapper for `grant`.
   My first re-grant came back `not-after 2026-09-03` against an effective now of `2026-09-05` —
   born dead. The fix shipped; the documentation the fix exists to serve did not get it.
5. **`submit` vs `submit-mandate`.** Submitting a mandate with `submit` gives
   `{"reason":"grantee","reason-code":"schema-unknown-member"}`, which reads like the mandate is
   malformed rather than like the wrong verb was used.
6. **Mandate expiry presents to the agent as `Unknown tool`.** At day 32 the paralegal's standing
   mandate had lapsed and every call returned:
   ```
   paralegal__file_with_court    Unknown tool: paralegal__file_with_court
   ```
   The truth is available — `paralegal__unavailable` returns
   `"mandate-expired: the session mandate has expired"` — but only if the agent knows to call a
   placeholder tool it has no reason to try. A real Claude Code session reports "that tool doesn't
   exist" and the paralegal files an IT ticket. **And nothing was written to the audit trail**: ten
   attempted actions on day 32 produced zero envelopes. A firm reconstructing "why did nothing get
   filed that day" gets silence from the record.
7. **`bin/stozher-bootstrap` hardcodes `--days 30`** while policy allows `P90D`. So the default
   deployment self-destructs at day 30, via failure mode (6), with no notification. The mandates page
   does say *"1 expiring within 7 days"* — on the page nobody is pinged about.
8. **`docker compose run gateway` restarts a kernel you deliberately stopped**, via
   `depends_on: service_healthy`. My first offline test was invalid because of this. It means you
   cannot take the kernel down for maintenance while an agent is pointed at it by the documented
   command — the agent brings enforcement back up underneath you. `--no-deps` is the real offline
   test, and it is not in the docs.
9. **Adding your own tools means rebuilding the gateway image.** `deploy/demo/` is `COPY`'d in at
   build time and there is no bind mount for downstream servers. I got round it by dropping files
   into `./var/notes`, which is mounted read-write into the enforcement container — that works, and I
   would not do it in production.
10. **`classification-tier` reports `heuristic` for actions my policy names explicitly.** Minor, but
    an auditor reading "heuristic" next to a filing will ask a question with a confusing answer.

---

## What genuinely worked — and it is not a short list

- **The clean-install script is the most honest build gate I have read.** It failed, and it failed
  *loudly, at the right assertion, with the right sentence*: "the approved call did not reach the
  downstream server — the approval bought nothing." A gate that catches its own product's headline
  defect is doing its job. That it shipped red is a release-process failure, not a gate failure.
- **Chain verification.** After thirty-two simulated days, a kernel restart, a stop/start, an expired
  mandate, a re-grant and an offline window: `all 3 streams verify`, 45 + 11 + 3 envelopes, all
  anchored. Nothing I did produced a corrupt chain.
- **The approval object is exactly what a general counsel needs.** Approver key, decision time,
  `single-use: true`, `not-after`, and the complete request bound field-by-field. If a filing is ever
  challenged, this is the artefact I would hand the court.
- **The prohibited-attempt record.** An attempted exfiltration of a whole matter, signed, on the
  chain, retained ten years, with the effect never reaching the world. That is the single most
  valuable object this system produced for me.
- **Offline degradation is correct and honestly reported.** Kernel down, `--no-deps`: reads served
  from cached policy, consequential parked locally, and the hint said so —
  *"(held locally; the kernel was unreachable, so nothing was queued for a human to see)"*. That
  distinction between "queued" and "held" is a real piece of engineering judgement.
- **Expiry refusals are legible.** *"decided at 2026-08-04T19:01:25Z, the request expired at
  2026-08-04T17:56:09Z"* — I knew exactly what happened and why.
- **`clock-advance` works and warns on every start.** `WARN records emitted by this deployment are
  not evidence of when anything happened`. Compressing a month took two config edits.
- **The docs tell the truth about what is missing.** The README's *"What this is not"* section named
  the notification gap, the waived design partner, and the attested-not-published review before I
  found any of them. That earns real credit and it is why this report is as long as it is — the
  project made it cheap to find the right things to complain about.

---

## Ranked blockers to adoption

| # | Blocker | Severity |
|---|---|---|
| 1 | Approving a first call crashes the retry with an unhandled `TypeError`. Every uncatalogued tool — i.e. every tool a law firm has — is permanently unusable on the documented path. No traceback, no refusal, no audit record. **The project's own release gate fails on this.** | **Ships-broken** |
| 2 | No approver notification of any kind out of the box, and parked requests die in one hour. A partner in a three-hour hearing loses the entire queue *and* the arguments. | **Blocker** |
| 3 | No class or dimension for "allowed but must be provable." Choosing the honest class for privileged reads (`read`) means same-day payload deletion and folding into a resource-less aggregate. I had to misclassify to keep the evidence. | **Blocker** |
| 4 | Approvers hang off classes, never actions. One flat pool for filings, deletions, service and email. No quorum, no tier between `gate` and `deny`. | **Blocker** |
| 5 | `target` is the server; the envelope has no matter/case/client dimension, and `reclassify` can therefore only discriminate per-server. Argument-level policy is structurally impossible. | **Blocker** |
| 6 | The quick-start install enrols one root and can never enrol a second. One human approves everything, forever. | **Blocker for a 40-person firm** |
| 7 | Mandate expiry (default 30 days, hardcoded) presents as `Unknown tool` with **nothing in the audit trail**. Recovery needs an undocumented `grant` invocation whose documented form is itself wrong on a clock-advanced deployment. | High |
| 8 | The pending page has no filtering or archiving. 154 KB and 36 rows, 31 dead, after twenty minutes of one agent. | High |
| 9 | Adding a tool requires a five-command signed policy change *before first use*, or the tool is bricked by #1. | High |
| 10 | Doc defects on the operator's critical path: `$K` missing network and token; `--mandate` absent from usage; truncated mandate ids; `submit` vs `submit-mandate`; `--config` missing from the `grant` recipe; `--no-deps` undocumented. | Medium |

---

## Would I keep it after a month, and what would make me turn it off?

**I would keep the audit trail. I would turn off the gate within a week.**

The evidence layer earned its place in one afternoon: a signed, verifying, restart-surviving chain
that records an attempted exfiltration of a whole matter and a court filing with the approving
partner's signature bound to the exact bytes. I would run that on real matters tomorrow if it were
decoupled from the gate.

What turns the gate off is not one thing, it is the compounding of the one-hour expiry, the absence
of any notification, and the single approver. The first Friday a partner is in an all-day mediation
and comes back to a queue of expired requests with the arguments erased — one of which was a
time-sensitive filing — that partner reclassifies `file_with_court` as `benign` and never turns it
back on. I know that because it is what *I* concluded after twenty minutes, and I have nothing at
stake.

### One plain sentence

**No — I would not run this on real client matters today, because the documented approval path
crashes on every tool my firm actually has, and even after I worked around that, the gate cannot
express the two rules that matter most to me: which human approves which action, and which matter an
action touches.**

Ask me again when (1) the first-call seed crash is fixed and the release gate is green, (2) a parked
request survives a day in court and pings somebody, and (3) `gate-rules` can name an action and an
approver in the same breath. Those three, and I would pilot it on a live docket — because the part of
this that is finished is the part that is hardest to build, and I have not seen anyone else build it.
