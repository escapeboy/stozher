# Installing Stozher

Single-tenant, self-hosted, two containers. One organization per deployment — org contexts never
mix, and there is no tenant column to get wrong (maxim 4). Everything below runs on a laptop, and
everything below runs offline once the images are built (maxim 5: solo is not a mode).

---

## 0. What you are installing

| | |
|---|---|
| **kernel** | the append-only hash-chained event store, the validating ingest API, versioned policy distribution, the gate queue, the approver ping and the console — one static binary, ~8 MB, in a 17 MB image. Started by `docker compose up`. |
| **gateway** | Harbormaster with enforcement mode: an MCP proxy that classifies, mandates, gates and records every tool call an agent makes. Spoken to over stdio, **one process per connecting client**, so it is started by the MCP client rather than by `up`. |

That is the whole list. No Redis, no database server, no reverse proxy, no sidecar. SQLite is the
store; Postgres is a documented future seam, not a service here (ADR-0003).

### Prerequisites

* Docker with Compose v2 (`docker compose version`).
* `python3` — only for `bin/stozher-console` and the gate's MCP client. Nothing the running system
  needs.
* **A second human.** Read the next section before you run anything.

### The one prerequisite people discover too late

`spec/03 §1` forbids self-grant: a human acting directly cannot satisfy `mandate-ref`, so they act
only under a mandate *another* human granted. **Changing the root set is therefore a two-person
operation, and a deployment with one enrolled root cannot change its root set at all** (ADR-0006 §3).

That is the right posture for the most privileged action in the system, and it is a prerequisite
rather than a surprise. Before the ceremony, have your second root generate their own seed **on
their own machine** and send you the public identifier only:

```sh
stozher-kernel keygen  --out ~/.stozher/mira.seed
stozher-kernel identity --key ~/.stozher/mira.seed --role 0     # -> ed25519:...
```

You will pass that to `--second-root-key`. Their seed never comes near yours.

A one-root install works and is supported — the ceremony warns and continues. It is the right
choice for an evaluation and the wrong one for anything you would miss.

---

## 1. Install

```sh
cd deploy
./bin/stozher-bootstrap --root human:ivan \
    --second-root human:mira --second-root-key ed25519:<theirs>
```

Roughly two minutes on a cold machine, most of it compiling Rust. It does eight things, and it is
worth knowing which:

1. **Builds the kernel image.** Multi-stage; the runtime layer holds the binary and a CA bundle.
2. **Generates three seeds on this machine**, each at mode 0600, refusing to overwrite:
   * `secrets/operator/operator.seed` — your **human root** key (SLIP-0010 role `0'`), the bootstrap
     subject key (`1'`) and the organization's **policy** key (`4'`). One secret to back up, three
     subjects to recover (`spec/01 §6`).
     **This file never goes to a server.** A server that holds it is a server that can sign its own
     approvals, which is exactly what `spec/06` exists to make impossible. The `kernel` service does
     not mount it; only throwaway operator containers do.
   * `secrets/kernel/kernel.seed` — the **checkpoint** key (`3'`) and nothing else. This one is on
     the server because it must be. It can authorize nothing: it signs checkpoints.
   * `secrets/gateway/gateway.seed` — the gateway's **device** key (`2'`), one per (caller, device).
3. **Runs the ceremony offline.** `stozher-kernel genesis` opens no socket and reads no
   configuration: it signs two envelopes and writes them, plus a complete kernel configuration that
   holds **no token**, only SHA-256 digests.
4. **Writes `.env`** at mode 0600 — the only file here that holds a secret.
5. **Starts the kernel.**
6. **Submits the two genesis envelopes** through the ordinary `POST /v1/ingest`.
7. **Grants the gateway a standing mandate**, signed by your root, because §10 §1.4 refuses a
   session with no resolvable mandate and §03 §1 forbids the gateway from granting itself one.
8. **Verifies the chain.**

### Start with the ceremony, not with `docker compose up`

`bin/stozher-bootstrap` is the install. There is no shorter path that ends anywhere useful, because
every file the two services mount — the store, the seeds, both configuration files — is written by
the ceremony and by nothing else. Running `docker compose up` first therefore stops with

```
Error response from daemon: invalid mount config for type "bind":
bind source path does not exist: .../deploy/var
```

That message is the intended outcome and it costs you nothing: every bind mount here declares
`create_host_path: false`, so docker refuses rather than inventing the missing paths. Left to its
default it would *create* them, and for a file-shaped mount it creates a **directory** — which is
how `config/kernel-config.json` used to end up as a directory, the kernel logged
`config-unreadable: Is a directory (os error 21)`, and `restart: unless-stopped` looped on it. Run
the ceremony and the message goes away.

### Two installs on one host

Set `COMPOSE_PROJECT_NAME` in `deploy/.env` **before** running the ceremony, one value per checkout:

```sh
cd deploy
printf 'COMPOSE_PROJECT_NAME=stozher-staging\n' > .env
./bin/stozher-bootstrap --root human:ivan --port 8801
```

The ceremony rewrites `.env` — every credential in it is generated, so it has to — but it reads your
keys back out first and re-emits them, `COMPOSE_PROJECT_NAME` among them. Compose then namespaces
the containers, the network and the volumes of each install separately, and neither service pins a
`container_name`, so nothing else has to change. Give each install its own `--port` as well: both
publish on `127.0.0.1`, and two of them cannot have the same one.

### What the ceremony actually is

Genesis is **two fully-validated envelopes**, not a bypass (ADR-0006 §2):

| `seq` | kind | what it is |
|---|---|---|
| 0 | `mandate` | a named human root grants the bootstrap subject an *interactive* mandate over `kernel.*`, for eight hours |
| 1 | `policy-change` | that subject publishes the first policy, carrying an approval the root signed over the document's exact `object-hash` |

There is no pre-installed policy row and no privileged append path. Every envelope after these two
is refused `policy-not-published` until they land, and the carve-out cannot be taken twice. If the
kernel refuses one of them, the install stops rather than continuing into a deployment whose first
two records are missing.

You can read what was signed before submitting it — the ceremony writes `genesis/` and submits from
there:

```sh
./bin/stozher-bootstrap --root human:ivan   # writes genesis/, then submits
cat genesis/policy-document.json            # the policy that took effect
cat genesis/01-root-mandate.json            # seq 0, verbatim
```

### The baseline policy profile

Tier 1 of `docs/design/policy-model.md`: an organization writes nothing on day one.

* `consequential` → **gated**, approvers = your enrolled root.
* `prohibited` → **hard-blocked**, whatever any mandate says.
* `read` / `benign` → allowed; mass reads fold into aggregation records.
* `default-unknown` → `consequential`. **This is the first-call gate.** A tool the policy has never
  heard of parks and waits for a human, once.
* `gateway.session_open` → `benign`. `spec/10 §1.6` requires that class, but `default-unknown` would
  make it `consequential`, and the gateway refuses to start rather than gate its own session opens
  (ADR-0007 §4). A shipped baseline that cannot run the shipped gateway is not a baseline.
* `offline.consequential` → `block`. A kernel outage degrades the availability of gated work,
  deliberately, rather than the availability of enforcement.

To classify tools your organization uses, publish a new policy version — a `consequential` change
that passes the same gate as anything else. `stozher-gateway catalog policy-fragment` prints the
`by-action` map to start from.

---

## 2. Point an agent at the gateway

The command the bootstrap prints, verbatim:

```sh
claude mcp add stozher -- docker compose -f /absolute/path/to/deploy/docker-compose.yml run --rm -T gateway
```

Cursor, Zed, or anything else that speaks MCP over stdio, in `mcp.json`:

```json
{
  "mcpServers": {
    "stozher": {
      "command": "docker",
      "args": [
        "compose", "-f", "/absolute/path/to/deploy/docker-compose.yml",
        "run", "--rm", "-T", "gateway"
      ]
    }
  }
}
```

`--rm -T` matters: one container per session, and no TTY between the client's pipes and the server's.
The path must be absolute — the client's working directory is not yours.

Nothing changes on the agent side. It sees ordinary MCP tools, and it imports nothing of ours.

### Adding your own downstream servers

The image ships one demo server (`notes`) so the first session has something to call. Yours are
declared in `config/stozher-gateway.toml`:

```toml
[[servers]]
name = "github"
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
```

The command has to exist **inside the gateway container**. For servers the image does not carry,
either add them to `Dockerfile.gateway`, or run the gateway on the host instead:

```sh
pip install harbormaster-mcp 'stozher-gateway[crypto]'
STOZHER_GATEWAY_CONFIG=/path/to/deploy/config/stozher-gateway.toml \
STOZHER_KERNEL_TOKEN=... STOZHER_GATEWAY_CALLER_TOKEN=... \
  python -m harbormaster --transport stdio
```

An audit boundary should be declared, not inferred (ADR-0005) — which is why the gateway cannot read
`harbormaster.toml` and cannot auto-discover your servers.

---

## 3. The first fifteen minutes

Call a tool. Because the baseline classifies nothing about your tools, the first call to each one
parks:

```json
{"result": "parked", "reason-code": "gate-parked", "classification": "consequential",
 "classification-tier": "heuristic", "request-hash": "8c5e60...", "retryable": false}
```

The parked request is in the console pending queue, and an approver is pinged if a channel is
configured. Answer it:

```sh
./bin/stozher-approve 8c5e60... --root human:ivan
./bin/stozher-approve 8c5e60... --root human:ivan --deny "we do not file public issues"
```

Then make **the same call again**. The approval binds a later *identical* request — identical by
`request-hash`, therefore the same call and not a similar one (`spec/06 §4.2`). It applies, and the
effect lands in the audit trail with the approval embedded in it.

### Why approving is two commands and not a button

`stozher-kernel decide` reads your own owner-only seed, signs, and prints. It opens no socket and
needs no kernel configuration. `stozher-kernel answer` carries that object to the console and holds
no key. **Signing has no network; the network has no key.**

The kernel holds no approver key material, has no route that produces an approver's signature, and
therefore cannot manufacture an approval — not for an operator with a shell on the box, not for a
compromised kernel process, not for its own maintenance code. The party that enforces the gate is
structurally unable to satisfy it. That is a property, not a slogan, and the copy-paste step is what
buys it (ADR-0009 §2).

### Reading the console

```sh
./bin/stozher-console          # http://127.0.0.1:8788/console
```

The console authenticates with the kernel's Bearer credential — the same credential as every other
route, because a console-only login would be a second credential path to keep correct. A browser
will not attach an `Authorization` header to an address-bar navigation, so `bin/stozher-console`
injects it, on your machine, for as long as that process is in the foreground. It binds `127.0.0.1`
only and forwards `GET` only. Closing the window closes the access.

Binding loopback is not on its own a boundary, so it does one more thing: it answers only for its
own address. Any page you visit in the same browser can re-point its own domain at `127.0.0.1` once
the DNS TTL expires and then read whatever it fetches from this port — the audit trail included.
The one header that still tells that page apart from your own tab is `Host`, so a request naming
anything else gets `403` before the credential is spent, as does one whose `Origin` or `Referer` is
a different origin. Reach it at `127.0.0.1` or `localhost`; a hostname of your own pointed at
loopback will be refused, by design.

A console **session scheme** was left open at S3 as an S5 decision (ADR-0008). The decision is
recorded in this stage's ADR; the short version is that a cookie would buy browser access to a
read-only view while adding a second credential path, and the friction actually worth removing —
one-click approve — needs browser-side Ed25519 signing with a per-device approver key enrolled in
the root set. That is a key-lifecycle decision, and shipping half the pair leaves the friction and
pays the whole cost.

---

## 4. Backup and restore

```sh
./bin/stozher-backup                       # -> backups/stozher-<utc>.tar.gz, mode 0600
./bin/stozher-backup --no-keys             # an archive that is not a secret, and cannot restore alone
./bin/stozher-restore backups/stozher-<utc>.tar.gz
```

The store is snapshotted with `VACUUM INTO` **through the running kernel** — no downtime, no
separate `sqlite3`, and a copy that is consistent at one instant. Copying the three SQLite files
with `cp` while a writer is mid-transaction produces an archive that usually restores, which is the
worst property a backup can have.

Three things are archived, and losing any one is a different loss:

* **the store** — the audit trail. Losing it loses the record.
* **the keys** — losing `operator.seed` means no further policy can be published and no root set can
  change. The deployment becomes read-only for ever.
* **the configuration** — which roots are enrolled and which callers exist.

**Restore is not complete until the chain verifies**, and the script treats that as the assertion
rather than a formality: it runs `stozher-kernel verify` over every stream and exits non-zero if any
of them fails. Nothing is deleted — the previous store, config and secrets are renamed
`.superseded-<utc>` first, so a restore from the wrong archive is itself reversible.

**A failed verification is undone, not just reported.** The check can only run after the archive is
installed and the kernel is up — that is the only way to ask the kernel about a store — so a script
that stopped at the refusal would leave the deployment *running*, serving the chain it had just
rejected, with the good store renamed out from under it. Instead the deployment comes down, the
material from the archive is renamed `.rejected-<utc>`, and the previous state goes back under its
own names. You get an exit status of 1, a kernel that is not running, and this:

```
== rolling back
  the restored var/stozher.db is now var/stozher.db.rejected-20260731T062559Z
  ...
  put var/stozher.db back
  put config/kernel-config.json back
```

Nothing is deleted on that path either. An archive that fails to verify is an archive worth keeping.

Verify any time, without a restore:

```sh
docker compose exec -T kernel stozher-kernel verify --config /etc/stozher/kernel-config.json
```

### Undoing a restore by hand

`bin/stozher-restore` rolls itself back when the chain fails to verify. The case this section is for
is the other one: the archive verified, the restore succeeded, and it was the *wrong archive* — so
you want the `.superseded-<utc>` state back, and no script is going to do it for you.

**Move all three SQLite files, together.** This is the whole warning. The store is `stozher.db`
plus `stozher.db-wal` plus `stozher.db-shm`, and in a running deployment almost everything is in the
write-ahead log — a live store here measured 4096 bytes with 997 KB sitting in its `-wal`. Move back
only the file with the obvious name and SQLite opens a database with no content in it. It does not
error. `verify` reports:

```
all 0 streams verify
```

and exits **zero**. An empty audit trail that says it is valid is worse than one that says it is
broken, and at that point the `-wal` you needed has been superseded by a fresh one.

So, with the deployment stopped and `<utc>` the stamp the restore printed:

```sh
docker compose down
for f in var/stozher.db var/stozher.db-wal var/stozher.db-shm var/gateway/gateway.db \
         config/kernel-config.json config/stozher-gateway.toml secrets .env; do
    [ -e "$f.superseded-<utc>" ] && mv "$f.superseded-<utc>" "$f"
done
docker compose up -d kernel
docker compose exec -T kernel stozher-kernel verify --config /etc/stozher/kernel-config.json
```

Read the last line before believing the rest. A **stream count** that matches what this deployment
had is as much a part of the check as the word `verify` — `all 0 streams verify` means you moved
back a header and left the data behind, not that you succeeded.

---

## 5. Retention — and the one thing this install does not do for you

The root README sells "closed loops decay to signed hashes" as a property of the system. It is
implemented, it is authenticated, and it works:

```sh
# from deploy/, with the kernel up
set -a; . ./.env; set +a
curl -s -X POST -H "Authorization: Bearer $STOZHER_KERNEL_TOKEN" \
     "http://127.0.0.1:${STOZHER_KERNEL_PORT}/v1/maintenance/decay"
# -> {"at":"...","decayed-hashes":[],"payloads-deleted":0,"streams-checkpointed":[]}
```

**Nothing calls it.** Not compose, not a timer in the kernel, not a cron entry this install writes.
Until that changes it is an operator duty, and it is stated here rather than left to be discovered:
a deployment nobody schedules decay on keeps every payload for ever, and the property the pitch
claims is one you are providing, not one you are receiving.

Schedule it however you already schedule things. A two-line script beside the deployment, and one
cron entry — a wrapper rather than an inline command because crontab has no line continuation, and
because `$` in a crontab is the shell's only after cron has finished with the line:

```sh
cat > bin/stozher-decay <<'SH'
#!/usr/bin/env sh
# Reads deploy/.env for the credential rather than keeping a second copy of it.
set -eu
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
exec curl -fsS -X POST -H "Authorization: Bearer $STOZHER_KERNEL_TOKEN" \
     "http://127.0.0.1:${STOZHER_KERNEL_PORT}/v1/maintenance/decay"
SH
chmod 700 bin/stozher-decay
```

```cron
# Nightly at 04:17, as the operator whose uid the deployment was installed with.
17 4 * * * /path/to/stozher/deploy/bin/stozher-decay >/dev/null
```

`curl -f` matters: without it curl exits zero on a `401`, and a retention job that has silently
stopped authenticating is the failure you would least like to be quiet. `set -e` in the wrapper
means cron gets a non-zero status and mails you, which is the point of running it under cron at all.

**This is an interim measure and should be read as one.** The right owner of that schedule is the
kernel: it already owns a periodic interval for checkpoints, decay checkpoints streams as part of
its own work, and the endpoint takes the kernel's own bearer credential — so every external
scheduler is a second place on the host where that credential has to live, for nothing gained.
A third compose service to hold a cron daemon is not available either; ADR-0003 fixes the count at
two, deliberately. A property the product advertises should not depend on a crontab line, and the
recommendation from this side of the repository is a kernel-owned timer with the interval in
`kernel-config.json`, next to the checkpoint interval that is already there. Until it exists, the
cron entry above is the whole of the mechanism.

---

## 6. Security posture — what is and is not protected

### Protected

* **The gate cannot be satisfied without a human signature.** `Store::append` is crate-private and
  `Ingest::submit` is its only caller. No header, parameter, environment variable, trusted-component
  list or administrative route satisfies a gate rule (`spec/06 §2`). The kernel's own test suite
  attempts it, and the gate has been mutation-tested twice, independently (ADR-0009 §3).
* **The enforcer cannot forge an approval.** No approver key material exists anywhere in Stozher.
* **Tampering is detectable.** Every envelope is signed and hash-chained; every stream is
  checkpointed by the kernel's own key, so a rebuilt chain contradicts a published head.
* **Key files are owner-only, and this is a refusal rather than a warning.** The kernel will not
  start on a seed anyone but its owner can read (`key-file-permissions`, `spec/09 §8`).
* **No plaintext secrets in configuration.** `kernel-config.json` holds SHA-256 digests of caller
  tokens and *names* of environment variables for channel credentials; the literal spellings
  (`webhook-url`, `password`) are not members of any channel, so writing one is a startup failure
  rather than a secret living in a file. `.env` is mode 0600 and git-ignored, and the repository
  ignores `secrets/`, `keys/` and `*.seed` at any depth.
* **Approval fatigue is bounded.** `spec/09 §7`: gate requests are rate-limited per subject per
  window, and a spike is surfaced on the pending page as a *finding*, not as a longer queue.

### Not protected — stated rather than implied

* **Root on the host.** Someone with root can read the kernel's seed from memory, forge anything
  that key can sign, and delete data. `spec/09 §8` does not defend against this; it makes it
  non-silent. Export checkpoints off-box (`spec/04 §4.7`) so a post-hoc rebuild contradicts
  something.
* **TLS is not terminated by these images.** `spec/09 §8` requires component↔kernel traffic to be
  TLS. The compose file publishes the kernel on `127.0.0.1` only for exactly this reason. Exposing
  it beyond the host is a deliberate act that needs a TLS terminator in front of it — nginx, Caddy,
  a load balancer, whatever you already run. The audit's *integrity* does not depend on TLS (every
  object is independently signed), but caller authentication and policy freshness do.
* **A malicious approver acting in scope** is not an attack the audit prevents. It is one the audit
  *records*, with a name, a timestamp and a signature over the exact action. That is the designed
  outcome, and it is why approvals are single-use with a short `not-after`: the blast radius of one
  signature is one action.
* **A compromised agent** can do anything its mandate scope allows without a gate. Scope your
  grants; `bin/stozher-bootstrap` writes a deliberately wide one (`--actions '*'`) so the first
  session works, and narrowing it is the first thing to do after it does.
* **Availability.** A kernel outage blocks gated work by design (`offline.consequential = block`).
  That is enforcement staying up while convenience goes down, and it is the intended trade.
* **The chain proves integrity, not truth.** It proves an emitter said this and nobody changed it
  afterwards. Whether the emitter was honest is what mandates and gates are for.
* **Not reviewed externally yet.** `docs/build-plan.md` requires an external crypto and security
  review before anything is called v1. The hand-rolled calendar arithmetic in `clock.rs` is flagged
  in ADR-0006 as the highest-value thing for a reviewer to attack.

---

## 7. The gate

```sh
./gate/clean-install.sh
```

From nothing — no store, no keys, no configuration, both images deleted and rebuilt `--no-cache` —
to a real audited envelope whose chain verifies, with the wall clock printed and asserted under
thirty minutes. It runs the path documented above, using the same scripts, and the MCP client it
drives is a hundred lines of standard library so that it exercises the **exact** command this page
tells you to paste.

**It wipes the directory it runs in.** `var/`, `secrets/`, `genesis/`, both configuration files and
`.env` — that list is exhaustive, and it is the same list the script's own header gives. `backups/`
is deliberately not on it: nothing in there can affect the measured install, and a wipe that reaches
past what it is measuring is not a cleaner wipe. Everything else in that list is gone, though, so if
this directory is also a real deployment, take a backup and put it somewhere else first.

---

## 8. Files

```
deploy/
  docker-compose.yml        two services; `gateway` is behind a profile because stdio has no daemon
  Dockerfile                kernel: rust:alpine -> static musl binary -> alpine
  Dockerfile.gateway        gateway: harbormaster-mcp + stozher-gateway[crypto]
  bin/stozher-bootstrap     the ceremony, start to finish
  bin/stozher-approve       sign in one process, submit in another
  bin/stozher-console       localhost header-injecting proxy, so a browser can read the console
  bin/stozher-backup        VACUUM INTO snapshot + keys + config, mode 0600
  bin/stozher-restore       restore, then refuse to call it restored until the chain verifies
  gate/clean-install.sh     THE GATE
  gate/mcp_probe.py         a stdlib MCP client, so the gate drives the documented command
  demo/notes_server.py      an ordinary downstream MCP server, so the first session has a target
  config/                   written by the ceremony; git-ignored
  secrets/                  written by the ceremony; git-ignored at any depth
  var/                      the store and the gateway's local chain; git-ignored
```

### Moving a deployment to a real server

`secrets/operator/` stays on your laptop. `secrets/kernel/`, `secrets/gateway/`, `config/` and
`var/` are what the server needs. Run the operator-side commands (`genesis`, `grant`, `decide`)
locally against the remote kernel's URL; they are the only ones that touch the root key, and none of
them needs to run where the service runs.
