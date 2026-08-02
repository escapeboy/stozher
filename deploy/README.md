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

`stozher-kernel` is the binary inside the kernel image, and there is nothing to install on their
machine: they need this checkout and docker, and they run it out of the image the same way the
ceremony does. From their own `deploy/`:

**This is the second root, and they must not run the ceremony** — `bin/stozher-bootstrap` is the
first root's, once. The second root only produces a key and reads its identifier.

`docker compose` interpolates the whole file on every invocation and `user:` has no default, so a
fresh clone with no `.env` refuses to build before anything else happens. Write the two lines it
needs first; the ceremony rewrites the file later and preserves what matters.

```sh
printf 'STOZHER_UID=%s\nSTOZHER_GID=%s\n' "$(id -u)" "$(id -g)" > .env
mkdir -p ~/.stozher && docker compose build kernel
docker run --rm -u "$(id -u):$(id -g)" -v ~/.stozher:/keys stozher-kernel:0.1.0 \
    keygen --out /keys/mira.seed
docker run --rm -u "$(id -u):$(id -g)" -v ~/.stozher:/keys stozher-kernel:0.1.0 \
    identity --key /keys/mira.seed --role 0                     # -> ed25519:...
```

If this host already runs an install, `stozher-kernel:0.1.0` is *its* tag and these commands would
use its image. Set `STOZHER_KERNEL_IMAGE` in `.env` first and substitute it above.

`--role 0` is the one that matters. `keygen` also prints a *checkpoint* key on its way out; that is
role `3'`, it belongs to a kernel rather than to a human, and it is not what goes in a root set.

You will pass the `identity` line's output to `--second-root-key`. Their seed never comes near
yours — `-v ~/.stozher:/keys` is their directory on their machine, and the container is gone by the
time the command returns.

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

**One thing is not namespaced: the image tags.** `stozher-kernel:0.1.0` and
`stozher-gateway:0.1.0` are the docker daemon's, not the compose project's, so the second install's
`docker compose build` moves those tags off the first install's images and onto its own. The running
container is unaffected — it holds an image *id* — but that id is now untagged, which means the
first install's next `docker compose up` silently starts the *other* checkout's build, and a
`docker image prune` deletes the image its running kernel came from. If the two installs are not the
same commit, give each its own tags:

```sh
export STOZHER_KERNEL_IMAGE=stozher-kernel-staging:0.1.0
export STOZHER_GATEWAY_IMAGE=stozher-gateway-staging:0.1.0
```

Both default to the plain names and every script here reads them, so **put them in `.env`** — the
ceremony preserves both, alongside `COMPOSE_PROJECT_NAME`.

Exporting them in your own shell is *not* enough, and the failure is a long way from its cause: the
MCP client spawns `docker compose` from its own environment, where the defaults come back and
resolve the other install's image. What a first-time operator then sees is the kernel crash-looping
on `x-schema-version-ahead: the store is at schema version 5; this build understands 3` — a store
written by one build being opened by another, with nothing pointing at the tag that selected it.

(This paragraph said the opposite until an operator followed it and lost an afternoon to that
message. `.env` was the wrong place when nothing preserved these two keys; `bin/stozher-bootstrap`
now does.)

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

### Being told that something is waiting

None of the above helps if nobody knows there is anything to sign. A fresh install notifies no one:
the request lands on `/console/pending`, the agent receives a terminal `parked` refusal, and the
only thing joining the two is an operator remembering to open a web page. An incident responder
evaluating this product found nine requests waiting that way and wrote that the control which
stopped the incident was a page someone had to remember to look at. **A gate nobody is pinged about
is a queue, not a control.**

Set `park_notify` in the gateway's config to an argv — a script that posts to Slack, sends a push,
writes to a pager, whatever your team already reads:

```toml
[gateway]
park_notify = ["/usr/local/bin/notify-approver"]
park_notify_timeout_seconds = 10.0
```

It receives one JSON object on stdin: the request hash, subject, action, target, classification and
the time it parked. Three things it deliberately does not do, each of which could have gone the
other way:

- **It never carries the call's argument values.** Those have a retention ceiling and an
  authenticated route; a notification is delivered wherever you wired it and has neither. What you
  get is a pointer — take the request hash to `/console/pending` to read the arguments.
- **It cannot fail the call.** A non-zero exit or a timeout is logged and changes nothing the agent
  sees. A notifier able to turn a park into an error would make the gate less available than no
  notifier at all: the agent would get a broken tool because a chat server was down.
- **It never delays the refusal.** It runs alongside; a hook that hangs is abandoned after its
  timeout and the caller is answered immediately either way.

Parked requests expire after an hour (`spec/06 §4.3`), so a notifier that nobody reads is not much
better than no notifier — the practical minimum is a channel someone is actually on.

### Changing policy

```sh
K="docker run --rm -i -u $(id -u):$(id -g) -v $PWD:/work -w /work ${STOZHER_KERNEL_IMAGE:-stozher-kernel:0.1.0}"

# 1. start from the document actually in force, not from the shipped baseline
$K policy-draft --url http://kernel:8787 --version 2026.08.1 --out config/policy-next.json
$EDITOR config/policy-next.json
# 2. sign it with the organization's policy key (role 4'), on your own machine
$K policy-sign --document config/policy-next.json --key secrets/operator/operator.seed \
               --out config/policy-2026.08.1.json
# 3. park the change; 4. a root answers it; 5. publish what they approved
./bin/stozher-publish-policy config/policy-2026.08.1.json --root human:ivan --mandate <64 hex>
./bin/stozher-approve <request-hash> --root human:ivan
./bin/stozher-publish-policy config/policy-2026.08.1.json --root human:ivan --resume
```

(`policy-draft` needs the kernel's network; the other `$K` line does not, and `--network none` on it
is a reasonable habit. Step 1 starts from `/v1/policy/current` rather than from the baseline for a
reason worth stating: a deployment three versions in would otherwise silently revert every
classification it has added since.)

**Policy is audited by the mechanism it enforces** (`spec/05 §5`). A policy change is a
`consequential` effect: judged by the policy *already in force*, carried by a mandate, and approved
by a named human who signed over the `object-hash` of the exact document that takes effect.
Approving "a policy change" in the abstract is not representable, and there is no privileged path —
the ceremony's first policy is the only one that judges itself, and it is `seq` 1 of `kernel:core`
where anyone can see it.

That is why this is two invocations with a human in between rather than one command. The script
could sign the approval — it has the seed — and an approval produced by the thing performing the
change is a rubber stamp with a signature on it. Run `bin/stozher-approve` yourself, from the
machine that holds the root seed, having read what you are approving.

`--mandate` is the mandate the publishing subject acts under; it must cover `kernel.publish_policy`
at class `consequential`. The ceremony's own is an *interactive* mandate that expired eight hours
after the install (§2's table, `seq` 0), so a later publish needs one a root signs — offline, in the
same shape `bin/stozher-bootstrap` uses:

```sh
docker run --rm -i -u "$(id -u):$(id -g)" --network none -v "$PWD:/work" -w /work \
  "${STOZHER_KERNEL_IMAGE:-stozher-kernel:0.1.0}" \
  grant --key secrets/operator/operator.seed --root human:ivan \
        --grantee agent:bootstrap --grantee-key "$(…identity --key … --role 1 --index 0)" \
        --actions 'kernel.publish_policy' --classes consequential --days 1 \
        --out var/publish-mandate.json
```

`grant` writes a signed mandate **object**, not an envelope: its signature covers the grant, and the
chain position is not the grantor's to assert. Putting it on the chain is a second command, run by
whoever holds a key on the stream it goes to:

```sh
docker run --rm -i -u "$(id -u):$(id -g)" --network "$(…kernel network…)" -v "$PWD:/work" -w /work \
  -e STOZHER_KERNEL_TOKEN="$STOZHER_KERNEL_TOKEN" "${STOZHER_KERNEL_IMAGE:-stozher-kernel:0.1.0}" \
  submit-mandate --url http://kernel:8787 --mandate var/publish-mandate.json \
                 --key secrets/operator/operator.seed --subject human:ivan
```

Until 2026-08-02 this page told you to use `stozher-kernel submit`, which takes envelopes and
answers a bare mandate with `schema-unknown-member: grantee` — a complaint about the mandate, which
is fine, when the wrapping is what was missing. There was no command that did it, so **no mandate
signed after the install could be made resolvable**, and the root-set ceremony below could not
complete. Anything citing an unpublished mandate is refused `mandate-unresolved`.

There is deliberately no `bin/stozher-grant` wrapper. A standing mandate to rewrite policy is the
most valuable grant in the deployment, and a one-liner that issues it — with defaults somebody would
eventually widen — is the wrong thing to make convenient. `--days 1` above is not caution for its own
sake: the mandate only has to outlive the four steps below it.

### Rotating a key or a mandate

`spec/03 §8`: rotation is **grant + revoke, never mutation** — a mandate object is immutable because
its id is its content hash. So there is no `rotate` command; there is an order, and the order is the
whole of it:

1. `grant` the new mandate (new `nonce`, new `not-after`, same or narrower scope) and submit it.
2. Point the holder at the new `mandate-ref` and let it pick the change up.
3. `bin/stozher-revoke <old-mandate-id> --root human:you`.

**Doing it the other way round stops the component.** Between the revocation and the holder's next
pull of `/v1/revocations` it keeps emitting under a mandate the kernel now refuses; §04 §3 admits no
gap in a stream, so its stream wedges at that position until an operator intervenes. Nothing is lost
and nothing is silently accepted — but an incident is a poor place to learn the ordering.

Rotating a *subject's key* is the same shape: the new key needs its own mandate, and envelopes the
old key already signed stay valid forever. Retiring a key MUST NOT invalidate history, which is the
point of an audit log rather than a concession.

### Changing the root set

```sh
K="docker run --rm -i -u $(id -u):$(id -g) -v $PWD:/work -w /work ${STOZHER_KERNEL_IMAGE:-stozher-kernel:0.1.0}"

# ivan asks. --mandate is a mandate MIRA granted him: §03 §1 forbids self-grant, and an effect
# needs one, which is the whole reason this takes two humans.
$K root-request --requester human:ivan --key secrets/operator/operator.seed \
                --mandate <64 hex> --in-force "$($K policy-current --url http://kernel:8787)" \
                --enrol ed25519:<their root key> --subject human:third \
                --out var/enrol.json
$K park --url http://kernel:8787 --file var/enrol.json     # needs the kernel's network

./bin/stozher-approve <request-hash> --root human:mira      # MIRA answers, not ivan

$K root-publish --url http://kernel:8787 --request var/enrol.json \
                --key secrets/operator/operator.seed
```

**`--subject human:<name>` is not a label.** The root set is `(key, subject)` pairs and the subject
is what §06 §5 compares when it refuses a self-approval — *a human holding a second key is still the
same human*. It travels as the evidence bound by `args-hash`, so the name recorded is the name the
approving root signed over, and an enrolment that omits it is refused (`root-enrollment-malformed`).

`--retire ed25519:<key>` is the same ceremony with no `--subject`: the name is already recorded, and
retirement is not retroactive — every envelope that key ever signed still verifies (§03 §8).

**A one-root deployment cannot do this at all**, which is the warning at the top of this file in its
executable form. Ivan cannot answer his own request (`gate-self-approval`), and he cannot act
without a mandate somebody else granted.

### Withdrawing a mandate

```sh
./bin/stozher-revoke <mandate-id> --root human:ivan --reason "laptop lost"
```

The same two-process split, for the same reason: the revoker signs, a second process with no seed
mounted submits. The mandate id is on `/console/mandates`, and `--root` must name a human the
ceremony enrolled — §03 §7 admits the mandate's grantor, the grantor of any ancestor in its chain,
or an enrolled root, and *nobody else*. Being able to reach the route is not being able to revoke:
the kernel wraps what you signed for chain position and re-checks the inner signature against that
list, so the deployment credential buys delivery and nothing more.

**Revocation is preventive only once the holder has seen it, and it is not free.** Components poll
`GET /v1/revocations` and evaluate the cached set locally, so between the revocation and the
holder's next poll it keeps building its local chain under a mandate the kernel will now refuse.
Every one of those envelopes is rejected — recorded, not silently dropped — and `spec/04 §3` admits
no gap in a stream, so **the component's stream is wedged at that position until an operator
intervenes.** Nothing is lost and nothing is accepted that should not be. But an operator who
expects revocation to be free finds a stopped component and, unless they read this, no explanation.

A revocation applies from its `revoked-at` forward, to the mandate and everything delegated beneath
it. Effects already recorded stay valid: the audit says what was permitted at the time, and
rewriting that is not a feature. Backdating to erase a window of authority is refused outright
(`revocation-before-issue`), which is why `revoke` stamps the current time rather than taking a flag.

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
./bin/stozher-restore backups/stozher-<utc>.tar.gz --force   # when a store is already here
```

**`--force` is not optional as often as it looks.** The bare form restores only onto a deployment
with no `var/stozher.db` — the total-loss case. Every other restore you are likely to run, the
rehearsal that proves the archive is good and the roll-back-a-bad-upgrade of §5a among them, is a
restore *over* a store, and the bare form stops with

```
var/stozher.db exists. Restoring over a live deployment replaces its audit trail.
Re-run with --force if that is what you mean; the current state is moved aside, not deleted.
```

That refusal is the right default — replacing an audit trail should be typed out — and the flag
changes nothing else: the current state is still renamed `.superseded-<utc>` rather than deleted.

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

### Anchoring the chain off-box

`verify` answers "has this store been *edited*?". It does not answer "was this store *rebuilt*?" —
and neither does a checkpoint, as long as the checkpoint lives here. Whoever could rebuild the
records could rebuild the checkpoints attesting them, so a deployment attesting its own history is
the party under examination vouching for itself. `spec/04 §4.7` names the fix and this is the
command for it:

```sh
./bin/stozher-anchor --out anchors/$(date -u +%Y-%m-%dT%H%M%SZ).json
```

It prints every stream's newest checkpoint head — the covered range, the head hash, and the id of
the signed checkpoint envelope that attests it — and stops. **It sends nothing anywhere, and that is
the mechanism, not a missing feature.** A copy this deployment mailed to a server this deployment
configured would move the problem one hop and solve none of it. Put the file where this deployment
has no credential:

- a git commit in a repository it cannot write to, on a schedule (weekly beats never; daily beats weekly)
- an email to a list that includes somebody outside the operating team
- handed to the auditor alongside the NDJSON export, so a later export can be checked against it

To check one later: for each head, fetch `/v1/envelopes/<checkpoint-envelope>`, verify its
signature, and confirm it commits to `head-hash` at `to-seq`. A store rebuilt after the anchor was
taken cannot produce a chain that both reaches those heads and omits what they covered.

The command refuses to write a file when no checkpoint exists yet — a document that attests nothing
while looking like it does is worse in an auditor's hands than no document. A deployment younger
than one checkpoint interval has simply not reached its first.

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

## 5. Retention — which this install does do for you

The root README sells "closed loops decay to signed hashes" as a property of the system. The kernel
owns the schedule: it sweeps once every `decay-interval`, and a deployment that configures nothing
sweeps **daily**. There is nothing for you to schedule and no credential to copy anywhere.

Until v0.3 that was not true — the endpoint existed and nothing called it, so an install nobody
wrote a crontab entry for kept every payload for ever, and the property the pitch claims was one the
operator was providing rather than one they were receiving. If you followed the previous edition of
this section and wrote a `bin/stozher-decay` wrapper and a cron entry, **delete both.** They are now
a second copy of the kernel's bearer credential on the host, doing work the kernel already does.
Nothing breaks if you leave them: decay is idempotent, so an extra caller deletes nothing extra.

To sweep more often than daily, put a duration in `config/kernel-config.json`:

```json
{
  "decay-interval": "PT6H"
}
```

It is an ISO 8601 duration and it must be positive. There is no way to switch decay off, and that is
deliberate: **retention is policy's to decide, not the timer's.** How long a payload may be kept is
the `retention` ceiling in the published policy document; the timer only decides how often the kernel
gets round to acting on what policy already said. A kernel that never swept would not retain anything
longer — it would only stop enforcing the retention its own policy promises.

The endpoint is still there, and running it by hand is still the way to force a sweep now rather than
at the next tick — after tightening a retention ceiling, say:

```sh
# from deploy/, with the kernel up
set -a; . ./.env; set +a
curl -fsS -X POST -H "Authorization: Bearer $STOZHER_KERNEL_TOKEN" \
     "http://127.0.0.1:${STOZHER_KERNEL_PORT}/v1/maintenance/decay"
# -> {"at":"...","decayed-hashes":[],"payloads-deleted":0,"streams-checkpointed":[]}
```

`curl -f` matters: without it curl exits zero on a `401`, and a retention job that has silently
stopped authenticating is the failure you would least like to be quiet.

A sweep checkpoints every affected stream *before* it deletes anything (§04 §4.6, §5.4), so the
pre-deletion head is publicly fixed first. Deleting a payload changes no signed byte: the hash stays
in the envelope that committed to it, chain verification never reads a payload, and an auditor
holding the content independently can still prove it is what was recorded. That is why decay is safe
to run on a timer at all.

---

## 5a. Upgrading

The store carries a schema version (`PRAGMA user_version`), and the kernel migrates it forward on
start. The procedure is:

```sh
# from deploy/
bin/stozher-backup                      # 1. a consistent copy, before anything changes
git pull && docker compose build kernel gateway  # 2. both images — see below
docker compose up -d kernel             # 3. it migrates on start
docker compose logs kernel | tail -20   # 4. read what it did
docker compose exec -T kernel stozher-kernel verify --config /etc/stozher/kernel-config.json
```

**Name the gateway in step 2, or it is not rebuilt.** It sits behind `profiles: ["mcp"]`, and a bare
`docker compose build` skips profiled services — so an upgrade that only named `kernel` left the old
gateway image in place, emitting against a kernel that had already migrated. That mismatch is silent:
both halves start, both look healthy, and the disagreement shows up only in the audit trail.

**Step 1 is not optional.** A migration is forward-only — there is no downgrade, because a downgrade
would have to discard records — so the backup is the only way back to the previous version.

Step 3 does the work, and the properties it holds to are worth knowing because they decide what a
failure means:

* **The whole migration is one transaction.** If any step fails, nothing is applied and the store is
  still at the version it started at. A failed upgrade leaves a store the previous image can serve.
* **The chain is re-verified after applying, before the kernel serves anything.** If the records do
  not verify, the kernel refuses to start rather than serving an audit trail an upgrade damaged.
  This is why the first start after an upgrade is slower than a restart: it reads every stream. Later
  restarts apply nothing and verify nothing.
* **Chain-bearing tables are additive-only.** A migration may add a nullable column or an index; it
  may not rewrite `canonical_json`, `id`, `prev_hash` or `seq`, and a migration that dropped one of
  the append-only triggers is refused and rolled back rather than committed.

Step 4 tells you which of the two happened. A migration prints one line naming the versions applied;
a start that applied nothing prints none, which is the normal case for a restart.

### Version compatibility

**Newer kernel over an older store: supported.** That is the upgrade above.

**Older kernel over a newer store: refused, deliberately.** The kernel exits with
`x-schema-version-ahead` and does not touch the database. A build that does not know what a column
means must not serve the chain that has it, and rolling the binary back is not a rollback — the
store has already moved. If you need the previous version, restore the backup from step 1 with
`bin/stozher-restore`, which verifies the restored chain and walks the whole restore back if it does
not verify — so a refused restore never leaves a kernel serving a chain it rejected.

A store the current kernel has never opened reports version 0 and is adopted at first start: every
statement in the baseline schema is `CREATE ... IF NOT EXISTS`, so an install that predates schema
versioning is stamped and re-verified rather than rebuilt.

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
  non-silent — but only if a head of the chain exists somewhere they cannot reach. `bin/stozher-anchor`
  takes that copy; see *Anchoring the chain off-box* below. Until you run it on a schedule and put
  the output somewhere this deployment has no credential for, a post-hoc rebuild contradicts nothing.
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
* **The external review is an attestation, not a report.** The owner attests that a review was
  performed and produced no findings (ADR-0022), and v1.0 was declared on that (ADR-0024). No
  reviewer name, date or statement of scope is held in this repository, so "no findings" is a claim
  about a scope nobody here can read. `SECURITY.md` says the same at more length; weigh it as an
  owner's word. The hand-rolled calendar arithmetic in `clock.rs` is flagged in ADR-0006 as the
  highest-value thing for a reviewer to attack.

---

## 7. The gate

```sh
./gate/clean-install.sh
./gate/clean-install.sh --port 8801        # on a host that already has an install on 8787
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

### The conformance gate

```sh
./gate/conformance.sh
```

`spec/08 §3.3` is "no green conformance run, no registration". This performs one: the Rust harness
certifying the Python gateway's self-test, cross-language, all seven groups of `spec/08 §4`.

It is a **second** gate rather than a step inside the first, and deliberately. `clean-install.sh`
lives entirely in Docker; the harness spawns its component as a local subprocess, so folding them
together would produce a step whose failures were about container plumbing rather than about
conformance. This one needs only `cargo` and a Python interpreter with the gateway installed
(`--python <path>` if it is not `gateway/.venv/bin/python`).

It touches no deployment. Every run builds its own kernel in memory, performs its own ceremony,
mints its own mandate, and discards all of it — which is what makes it safe to point at a manifest
that arrived by e-mail from a stranger, and what makes the run re-runnable and deterministic as §4
requires.

**A green run is evidence, not a registration.** It prints a manifest hash and stops. `spec/08 §3.1`
wants a human signature over that hash, and a harness that submitted its own result would be a
program deciding that a third party's code may run here.

---

## 8. Files

```
deploy/
  docker-compose.yml        two services; `gateway` is behind a profile because stdio has no daemon
  Dockerfile                kernel: rust:alpine -> static musl binary -> alpine
  Dockerfile.gateway        gateway: harbormaster-mcp + stozher-gateway[crypto]
  bin/stozher-bootstrap     the ceremony, start to finish
  bin/stozher-approve       sign in one process, submit in another
  bin/stozher-revoke        the same split, for withdrawing a mandate
  bin/stozher-publish-policy  the four steps spec 05 section 5 requires, with the human in the middle
  bin/stozher-console       localhost header-injecting proxy, so a browser can read the console
  bin/stozher-backup        VACUUM INTO snapshot + keys + config, mode 0600
  bin/stozher-restore       restore, then refuse to call it restored until the chain verifies
  gate/clean-install.sh     THE GATE
  gate/conformance.sh       spec 08 section 4, across both implementations
  gate/mcp_probe.py         a stdlib MCP client, so the gate drives the documented command
  demo/notes_server.py      an ordinary downstream MCP server, so the first session has a target
  config/                   written by the ceremony; git-ignored
  secrets/                  written by the ceremony; git-ignored at any depth
  var/                      the store and the gateway's local chain; git-ignored
```

### Moving a deployment to a real server

`secrets/operator/` stays on your laptop. `secrets/kernel/`, `secrets/gateway/`, `config/` and
`var/` are what the server needs. Run the operator-side commands (`genesis`, `grant`, `decide`,
`revoke`) locally against the remote kernel's URL; they are the only ones that touch the root key,
and none of them needs to run where the service runs.
