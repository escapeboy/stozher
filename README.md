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

**Clean machine to first audited envelope: 110 seconds.**

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

**Zero changes on the agent side.** The MCP client is stock; it imports nothing of ours. That is
asserted by a test that AST-parses the client process.

Classification runs in tiers: a component's own **manifest** → a **shipped catalog** of 19 popular
MCP servers / 174 tools → a **conservative heuristic** for anything unknown. An unknown tool always
parks on first call, and the approver's decision seeds the org's catalog. *Unknown is not ungoverned;
unknown is expensive until classified.*

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
- **One write path.** `Store::append` is crate-private with `Ingest::submit` its only caller, and
  append-only is enforced by database triggers. A test *actively attempts* an administrative append
  rather than assuming it is impossible.

## Retention: closed loops decay to signed hashes

Evidence payloads carry a TTL by weight class. On expiry the payload is deleted; **the hash and its
chain position remain forever.** An auditor can still prove nothing was tampered with, without the
organization storing content until the end of time — and a personal-data erasure request is
compatible with chain integrity by construction.

## What is verified, and how

| | |
|---|---|
| Kernel (Rust) | **153 tests** |
| Gateway (Python) | **80 tests** |
| Cross-language vectors | **161 vectors / 351 assertions** |
| Clean install → first audited envelope | **110 s** |
| `clippy -D warnings`, `cargo fmt`, `cargo audit`, `ruff`, `mypy --strict` | clean |
| `#[allow(...)]`, `# type: ignore`, suppression baselines | **zero** |

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

- **No external security review has been done.** The design's own rule is that one is mandatory
  before anything is called v1. Two specific targets are already named for it: hand-rolled calendar
  arithmetic in `clock.rs` (adopted to remove a CVE on an untrusted-input path — exhaustive
  round-tripping over *valid* dates proves nothing about malformed input), and the gate verification
  path.
- **The spec lags the implementation.** ADRs 0006–0012 contain normative text not yet folded into
  `spec/`, and 11 conditions sit in a quarantined `x-` register standing in for missing spec
  language. An independent implementation could diverge legally today.
- **The four-class taxonomy is under-validated.** It was exercised only through the gateway's
  boundary classification, never by a component that classifies natively — so "does it survive a
  foreign domain?" is an open question, not a settled one.
- **Budgets are not implemented.** Mandates carry budget dimensions and cognition envelopes carry
  cost, but nothing accumulates spend — so the console's budgets page was deliberately *not built*
  rather than invent its numbers.
- **Also missing:** pagination on the audit explorer, Tier-A manifest loading and the conformance
  harness, TLS (terminated externally by design), and streaming for very large exports.
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
| `docs/adr/` | **Twelve ADRs.** Read these first if you want the reasoning |

## The design record is the interesting part

Five of the twelve ADRs exist because a design premise turned out to be **false about the code it
described** — each caught by contact with reality rather than by review:

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

```bash
git clone https://github.com/escapeboy/stozher && cd stozher
./deploy/gate/clean-install.sh        # wipes, rebuilds, measures, and proves the chain
```

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
