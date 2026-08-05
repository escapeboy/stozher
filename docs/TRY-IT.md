# Trying it, as a human, in about an hour

Four agent evaluations ran this on 2026-08-04 and every one of them lost time to the same handful of
places. This is the path with those places marked. It is not a tour — it asks you to do the four
things that decide whether the system is worth keeping, and tells you what each one is supposed to
prove.

**Nothing here is a shortcut.** Every command is one `deploy/README.md` documents. Where this file
disagrees with that one, that one is right and this is a bug.

---

## Before you start: one decision, and it is permanent

**Do you want to keep this deployment?**

- **No — you are trying it out.** Use the disposable path in §1a. It wipes the directory it runs in
  and it can never recover from a wedged stream. That is fine for an evaluation and fatal for
  anything else.
- **Yes.** Then you need a second person before you type anything (§1b). Changing the root set needs
  two roots, so a deployment that starts with one can never gain a second — and a single root cannot
  un-wedge a stream, because the recovery act needs an approval and a root may not approve its own
  request. `bin/stozher-bootstrap` refuses a single-root install for this reason (DEF-19).

There is no third option and no way to change your mind afterwards.

---

## 1a. The disposable install

```bash
git clone https://github.com/escapeboy/stozher && cd stozher
./deploy/gate/clean-install.sh
```

Runs the whole thing and ends by proving a real audited envelope: a call that was gated, parked,
signed for by a named human, applied, and chained. Budget ~15–30 minutes, most of it a Rust compile.

**If it fails, read the line that says `GATE FAILED`** — it says which assertion, and the script
prints a verdict on every exit path including the ones it did not predict.

## 1b. The install you keep

Your colleague, on **their** machine, once:

```bash
docker run --rm ghcr.io/escapeboy/stozher-kernel:0.1.0 stozher-kernel keygen
# they keep the seed; they send you the ed25519:… public half
```

You, in `deploy/`:

```bash
bin/stozher-bootstrap --root human:<you> \
  --second-root human:<them> --second-root-key ed25519:<what they sent>
```

They need not be present again until something has to be approved twice.

---

## 2. The first call, and the thing that surprises everyone

Point an agent at the gateway (`deploy/README.md` §2), then have it call a tool.

**A first call to a tool nobody has classified parks _two_ requests, not one.** The call itself, and
a separate question about what class the tool is — §10 §4.3 makes classifying a tool its own
signature on purpose. All four evaluations approved one of them, retried, and were confused.

```bash
bin/stozher-approve <request-hash> --root human:<you>   # the call
bin/stozher-approve <seed-hash>    --root human:<you>   # the classification
```

`bin/stozher-console` lists both. Approve both, then retry the call.

**And if you want to ask "what happened on the Acme matter?" later**, set `gateway.correlation_ref`
before you start — it stamps every envelope, and the kernel answers
`GET /v1/envelopes?correlation-ref=` over it. It is per gateway process, so one process per matter.

**Approving the classification may do nothing, and it will now tell you so.** The published policy's
`default-unknown` is `consequential`, and a seeded class weaker than that is discarded — the log says
which action and what to publish instead. That is the design, not a fault (DEF-15).

---

## 3. The four things worth actually testing

Each of these is a question the four evaluations answered *no* to, in four different domains. If you
disagree with any of them, that is the most useful thing you can tell us.

### 3.1 Would you live in the approval queue?

Drive twenty or thirty gated calls. Read the queue rows honestly — the arguments are there verbatim,
and `/console/pending` prints a command you can run to recompute `args-hash` yourself.

**Watch for the moment you stop reading them.** One evaluation wrote a batch-approval script at the
second queue entry, ~35 minutes in, then approved ten refunds in seven seconds — one of them
€50,000, all correctly signed. If that happens to you, it is the finding, not a personal failing.

Note the cap: 30 parks per subject per 300s. The excess is refused, and since 2026-08-05 that
refusal is `retryable` and carries `retry-after-seconds` — it used to say `retryable: false`, which
meant an agent never came back and the work simply vanished (DEF-18). What is still open is the
question underneath: an organization *steadily* above the cap has no queue to fall into, only a
slower loop.

### 3.2 Do the four classes fit your work?

Map your real actions onto `read` / `benign` / `consequential` / `prohibited`. Then look for the two
places all four evaluations got stuck:

- an action that is `read` but whose *individual* occurrences you must be able to name later —
  `read` folds into a counted aggregate with no per-event record, so keeping one means classifying
  it as `benign`, which may be a sentence you cannot sign;
- the same action name that is harmless on one target and severe on another. `execution.target` can
  only be `mcp:<server>`, so a policy rule keyed on anything finer matches nothing, silently. A gate
  rule *can* now name the actions it is about (`gate-rules[].actions`, §05 §3.2), so "filings need a
  partner, everything else needs an associate" is writable — but the target still is not.

Both are recorded in ADR-0034, undecided. Your answer changes what gets built.

### 3.3 Break it on purpose: wedge a stream and recover it

```bash
bin/stozher-revoke <mandate-id> --root human:<you>   # an ordinary incident action
```

The component's stream wedges — correctly, per §05 §7.1. Now bring it back:
`resume-request` then `resume-publish`, root-signed, approved by your **second** root. Time yourself.
This is the procedure someone will be running at 3am.

If you did the disposable install, this is where it ends. That is the point of §1b.

### 3.4 Verify the audit trail without trusting us

```bash
docker compose exec -T kernel stozher-kernel verify --config /etc/stozher/kernel-config.json
```

Then do it *yourself*: export the records and re-derive every id, signature and chain link with your
own code against `spec/01`. One evaluation did this in ~90 lines of Python with only `PyNaCl`, then
changed one byte and got two independent failures. **This is the part of the system that held up
best under four hostile evaluations**, and it is the part you should be most suspicious of us about,
so check it rather than believe it.

---

## 4. What is known to be wrong before you find it

`docs/open-defects.md` is the register. Open and unfixed as of 2026-08-05:

| | |
|---|---|
| DEF-14 / ADR-0034 | one `classification` decides gate, retention, offline behaviour and record granularity at once |
| DEF-22 | no quorum: `authorization` carries one `decision`, so "two partners must both sign" cannot be written |
| DEF-18, residue | an organization steadily above the park cap has no queue to fall into, only a slower loop |

Everything else the four evaluations found is closed, with a test that fails when the fix is
reverted. `docs/open-defects.md` has the list and what each one turned out to be — including the two
where the report was wrong in the system's favour and the row says so.

And the two things no amount of engineering closes: **no human has ever operated this** — the four
evaluations were agents, which is reproducible operational evidence and not market signal — and the
external security review (`docs/validation/security-review-2026-08-04.md`) named its scope and that
scope excluded `console.rs`, `http.rs`, `deploy/`, and most of the gateway.

## 5. Telling us

Open an issue with what you were doing, what you expected, and what happened. A report that says
"this is where I stopped" is worth more than one that says "this is broken" — every finding in
`docs/validation/design-partners/` came from someone writing down the moment they got stuck.
