# Stozher

**An accountability kernel for agentic work.** Every effect an AI agent has on the world becomes a
signed, hash-chained event under a mandate that terminates at a named human — and a consequential
action does not happen until a human signs for it.

> *стожер* — the central pole of a threshing floor: the thing everything turns around and is
> tethered to. Central axis plus tethering: mandate.

```
docker compose up  →  root key ceremony  →  point your own Claude Code at the gateway
                   →  its tool calls appear classified in the audit trail
                   →  an unknown tool parks at a gate
                   →  you approve it with a key the kernel has never held
                   →  the call proceeds, and the chain walks back to you
```

**Wipe to first audited envelope: 169 seconds** on an M4 Pro with the base images already pulled,
measured by `deploy/gate/clean-install.sh`. Not a clean *machine*: `git clone` and the base image
pulls are outside it, so a first run on a new host is slower.

**Status: v1.0 declared, 2026-08-02 (ADR-0024).** The engineering scope is finished: every operation
the specification requires of an operator now has a command, and every one of those commands has
been run as a process against a live kernel. **The plan's remaining condition — one design partner
running this in anger for a month — was waived, not met**, so both empirical questions below are
still open and the label means *the engineering is finished*, not *this has been operated by someone
with something to lose*. Read *What this is **not*** before deploying anything.

---

## The problem this exists for

Organizations are deploying agents. The question that blocks those deployments is not *can it do the
work* — it is **who did what, under whose authority, and how do you prove it** to the board, the
auditor, or the regulator.

The market competes on capability. Nobody competes on auditability. Under the EU AI Act, human
oversight and traceability stop being a nice-to-have.

Stozher is not an agent platform and does not want to be. It governs *effects*, whatever produced
them. It is orchestrator-agnostic on purpose: your agents keep running wherever they run.

## The primitive

> Every effect is a signed event under a traceable mandate; everything durable is a fold of such
> events.

One envelope shape, for everything:

```
identity → mandate → policy(classification) → execution → evidence → memory-ref? → commitment-ref?
```

Two layers, borrowed from git's model: **envelopes are the log; durable objects are refs folded from
transition events.** Sessions, commitments, tools and notes are all folds — each transition itself an
envelope.

Cognition is deliberately **out of scope**. Audit effects, not thoughts. A thought becomes
accountable the moment it materializes.

## How an agent gets governed without changing the agent

An employee's Claude Code, Cursor, or LangGraph script points its MCP config at the **gateway**
instead of directly at its tools. The gateway is an MCP server that is also an MCP client: every
proxied call transits exactly one chokepoint where it is classified, emitted as an envelope, and —
if policy says so — parked for a human.

**Zero changes on the agent side.** The MCP client is stock — it is configured with a command, not a
library. A test AST-parses the **downstream server** fixture and asserts it imports nothing of ours;
the client side is asserted only to speak plain MCP, because the file driving it in the test suite is
the test suite, which does import the gateway in order to inspect it.

Classification runs in tiers: a component's own **manifest** → a **shipped catalog** of 19 popular
MCP servers / 174 tools → a **conservative heuristic** for anything unknown. An unknown tool always
parks on first call, and the approver's decision seeds the org's catalog. *Unknown is not ungoverned;
unknown is expensive until classified.*

Authority granted this way can be withdrawn the same way: `bin/stozher-revoke <mandate-id> --root
human:you` signs a revocation on your own machine and a second process delivers it. Components poll
the revocation feed and evaluate it locally, so the withdrawal is preventive rather than a refusal
after the fact — at the cost of wedging the holder's stream at its next append, which
`deploy/README.md` §3 states in full because an operator should not learn it from a stopped
component.

## The gate, and why it cannot be bypassed

The design's central lesson came from studying a prior system that bypassed its own approval gate
through an ambient container binding — a flag any code could flip. Here:

- **`approved` is never a boolean.** An action request carrying an `"approved": true` member is
  rejected as `schema-unknown-member`. The bypass cannot even be expressed.
- **The approval signature travels inside the envelope**, bound field-by-field to the exact effect —
  subject, key, component, mandate, policy version, classification, action, target, and `args-hash`.
  A valid approval for action A cannot authorize action B.
- **The kernel holds no approver key material** and has no route that produces an approver's
  signature. It therefore cannot manufacture an approval — not for an operator with a shell on the
  box, not for a compromised kernel process. *The party that enforces the gate is structurally unable
  to satisfy it.* The honest cost: approving involves a copy-paste from a CLI that signs in your own
  process. That friction is what buys the property.
- **One write path.** `Store::append` is crate-private with `Ingest::submit` its only caller — a
  guarantee of the type system. At the storage layer, triggers refuse every UPDATE and DELETE on
  chain-bearing tables, and refuse an INSERT into `envelopes` that does not extend its stream. Tests
  *actively attempt* all three, and the migration runner probes the refusals by performing them
  rather than by looking for triggers.
- **What the storage layer does not catch, stated because it matters more than what it does.**
  The INSERT guard enforces *linkage*, not authenticity: a correctly-linked forged tail, or a forged
  new stream at seq 0, is accepted by SQLite and survives `verify` — because chain verification reads
  the signing key from the object it is verifying, by design, and asks no mandate or gate question.
  Only guards on `envelopes` exist; the other chain-bearing tables have none. Detecting either needs
  off-box checkpoints and an independent notion of which streams and which keys ought to exist. If
  someone can write your database file, signatures tell you who signed, not who was allowed to.

## Retention: closed loops decay to signed hashes

Evidence payloads carry a TTL by weight class. On expiry the payload is deleted; **the hash and its
chain position remain forever.** An auditor can still prove nothing was tampered with, without the
organization storing content until the end of time — and a personal-data erasure request is
compatible with chain integrity by construction.

## What is verified, and how

| | |
|---|---|
| Kernel (Rust) | **278 tests** |
| Gateway (Python) | **120 tests** |
| Cross-language vectors | **295 vectors / 517 assertions**, across 18 files |
| Conformance harness (`spec/08 §4`) | **7 groups**, run cross-language: Rust harness × Python component |
| Wipe → first audited envelope | **169 s** on one M4 Pro, base images cached — a measurement, not a checked property: the gate asserts only its 1800 s budget |
| `clippy -D warnings`, `cargo fmt`, `ruff`, `mypy --strict` | clean |
| `cargo audit` | passes, **no vulnerabilities** — but carries one *unsoundness* advisory in a transitive dependency (RUSTSEC-2026-0221, `event-listener` via `sqlx`), which is reported rather than silenced |
| `#[allow(...)]` anywhere, suppression baselines | **zero** |
| `# type: ignore` in shipped source | **one** — `money.py:101`, narrowing `Decimal.as_tuple().exponent`, which typeshed types as `int \| Literal["n","N","F"]` |

**The test vectors are not self-graded.** They are generated by an independent Python/PyNaCl
implementation and validated by the Rust/ed25519-dalek kernel — two separate crypto stacks that must
agree byte-for-byte. Regenerating the corpus produces zero diff. Without vectors, two implementations
cannot verify each other; with them, a disagreement is a build failure.

**The gate was mutation-tested.** A gate that has never failed is an untested gate. Reintroducing the
ambient-approval bypass makes the deny-path tests fail — verified twice, independently, with two
different injections. Likewise the security fixes each carry a test that was written *before* the
fix and observed failing against the unfixed code.

**Enforcement is structural, not conventional**, wherever it could be: crate-private append, DB-level
append-only triggers, a closed member vocabulary, and a self-approval check that compares the
*person* rather than the keypair.

## What this is **not** — read this before judging it

This is honest engineering, not a finished product. For a system whose entire pitch is provable
auditability, overclaiming would be self-defeating:

- **The external security review is attested, not published.** The owner attests that a review was
  performed and produced no findings (ADR-0022). No report, reviewer, engagement date or **scope** is
  held here — and without a scope, "no findings" cannot be used by anyone who was not party to it. A
  clean result over the gate algorithm and the canonicalizer is a different statement from a clean
  result over this README, and nothing here lets you tell them apart. Read `SECURITY.md` before
  weighing it.
- **Half the release gate was waived, not met.** The plan's definition of done for v0.9 was *an
  independent implementation, written from `spec/` alone by someone who has not read this code,
  passing the vector corpus.* No such implementation exists. The corpus is exercised by two
  implementations, both written here, from the same reading of the same text.
- **The release before this one found twelve real defects** — eleven disagreements between those two
  implementations, found by *reading clauses* rather than running tests, plus one in the parser
  `SECURITY.md` had already named the highest-value target. **All twelve were green under the vector
  corpus at the time.** That is a good sign about the method and a bad sign about the remaining count.
- **The four-class taxonomy is still under-validated.** The conformance harness now exercises it, but
  we wrote both halves — harness and component. "Does it survive a foreign domain?" can only be
  answered by a component we did not write. As of v1.0 an operator can register such a component
  with shipped commands — before 2026-08-02 the only path was a helper in our test kit, which is
  what v0.4's gate was actually graded against. **The path exists; the evidence does not.**
- **No design partner has run this.** v1.0 was declared with that condition waived (ADR-0024 §2), so
  "is the pending queue a daily driver" is now being asked after the label rather than before it.
  The plan is explicit about the stakes: if the answer is no, v1 scope is wrong.
- **Most of what the spec gained in v0.9 is not corpus-checkable.** Sixteen rules moved out of ADRs
  into `spec/` and sixteen quarantined `x-` codes were adopted — but ADR-0019 §3 states plainly that
  most of those rules are claims about a *running kernel over time*. The corpus is a floor, not a
  proof.
- **Still absent:** TLS (terminated externally, by design) and streaming for very large exports —
  the latter deferred on evidence, per the design note's own condition that it waits for a design
  partner's log to make the in-memory body impractical.
- **Single-tenant by construction.** Org contexts never mix; there is no multi-tenancy to
  misconfigure. That is a design decision, not a gap.

## "Why are there private keys in `spec/vectors/`?"

Because test vectors require known keypairs — that is what makes two implementations comparable.
Every one of them is public test data:

- The SLIP-0010 vectors use the seed values **published in the SLIP-0010 specification itself**
  (`000102030405060708090a0b0c0d0e0f…`).
- The rest are derived deterministically from a public label:
  `sha256("stozher/0.1 test vector key: " + label)`.

Real deployments generate keys with `getrandom`; no committed key is ever operational. Key material
is excluded by `.gitignore` and `.dockerignore`, and no seed, `.env`, or store file appears in any
commit on any branch.

## Layout

| Path | What |
|---|---|
| `spec/` | The normative specification, sections 01–10 |
| `spec/vectors/` | **The contract between implementations** — language-neutral JSON, consumed by both test suites |
| `kernel/` | Rust: `stozher-core` (envelope, mandate, chain, crypto) and `stozher-kernel` (store, ingest, gates, console) |
| `console/` | Server-rendered templates, embedded in the kernel binary. No SPA, no build step |
| `gateway/` | Python MCP gateway, shipping as an optional enforcement mode for Harbormaster |
| `deploy/` | `docker compose`, the root key ceremony, backup/restore, and the clean-install gate |
| `docs/adr/` | **Twenty-two ADRs.** Read these first if you want the reasoning |

## The design record is the interesting part

Five of the first twelve ADRs exist because a design premise turned out to be **false about the code
it described** — each caught by contact with reality rather than by review:

- **ADR-0004** — the design said the gateway would extend an existing MCP proxy path. There was no
  proxy path; it had to be authored.
- **ADR-0005** — shipping the obvious config surface would have made the *unmodified* host tool fail
  to boot. The inverse of the requirement it was meant to satisfy.
- **ADR-0006** — the spec's own bootstrap was circular. Resolved with two fully-validated envelopes
  and no privileged append, so even genesis carries real signatures.
- **ADR-0008** — a spec clause obliged the kernel to record something only another party could
  observe, with no legal envelope to report it.
- **ADR-0011** — the console promised an "evidence preview" the protocol cannot carry. Rendering
  unverified arguments next to an approve button was rejected as a *social-engineering* channel, not
  merely an escaping problem.

Deviation from a design document is allowed here **only** via an ADR that states what changed and
why. Never silently.

## Quick start

**If you are evaluating this rather than reading it, start at [`docs/TRY-IT.md`](docs/TRY-IT.md)** — the same
commands, with the four places every evaluation lost time marked, and the four questions worth answering.

```bash
git clone https://github.com/escapeboy/stozher && cd stozher
./deploy/gate/clean-install.sh        # wipes, rebuilds, measures, and proves the chain
```

**"Wipes" means the directory it is run in** — store, keys, config and ceremony output. Run it on a
fresh clone, never on a deployment you want to keep.

**And it leaves you with one root, permanently.** The gate bootstraps a single
`human:gate-operator`, and there is no post-install enrolment: changing the root set requires two
roots, so a deployment that starts with one cannot ever add the second.

**What that costs, said plainly, because two design partners found it the hard way (DEF-19):** a
single-root deployment can never un-wedge a stream. Revoke or expire a mandate — an ordinary
incident action — and the component's stream wedges as specified; the exit (`spec/04 §7.2`) needs an
approval, and one root approving its own request is refused `gate-self-approval`, correctly. So the
first wedge ends that install. The gate accepts this and says so — it passes
`--accept-unrecoverable`, because it wipes the directory it runs in and is measuring an install
rather than producing one.

**`bin/stozher-bootstrap` now refuses a single-root install** unless you pass that same flag. If you
are keeping the deployment, have a colleague run `stozher-kernel keygen` on their own machine and
send you the public half:

```bash
cd deploy
bin/stozher-bootstrap --root human:<you> \
  --second-root human:<colleague> --second-root-key ed25519:<their key>
```

They do not need to be present again until something has to be approved twice. The full install,
the key ceremony, backup/restore and the security posture are `deploy/README.md`.

Then point an agent at it:

```bash
claude mcp add stozher -- docker compose -f /abs/path/deploy/docker-compose.yml run --rm -T gateway
```

`deploy/README.md` covers the real install, the key ceremony, backup/restore, and the security
posture. Generate root keys on your own machine, never on the server, and enrol a second root before
you need one — changing the root set requires two, because self-grant is forbidden.

## License

Apache-2.0. Copyright 2026 PRICEX LTD. See `LICENSE` and `NOTICE`.

Cryptography is inherited, not invented: Ed25519, SLIP-0010, RFC 8785 JCS + SHA-256.
