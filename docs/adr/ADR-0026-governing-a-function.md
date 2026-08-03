# ADR-0026 — Governing an ordinary function, and a mistaken reason for not doing it

**Date:** 2026-08-02
**Status:** accepted

## The rejection

An engineer with a working Python agent system evaluated Stozher and rejected it. Their tools were
plain functions in a registry. The only way in was to re-expose every one as an MCP server and point
the gateway at it:

- 134 lines of adaptation against a 123-line application — **the adapter was larger than the thing
  it governed**;
- thirteen concepts to learn before the first governed call;
- and their tool state left their process, so their own driver's assertions read an empty ledger.

Their verdict named the flip condition precisely: *"a supported in-process API. `pip install`,
`@governed` on my existing function, tools stay in my process. The `Enforcer` already takes a
`forward` callable — publish it, document it, ship one example that is not an MCP server."*

## The reason I gave for not doing it, and why it was wrong

Twice I deferred this on the grounds that in-process would relax the property every evaluation
confirmed by attack: *the key that can approve is never on the machine that runs the agent.*

**That reasoning does not survive reading the code.**

- The gateway holds exactly one private key: its own emitter seed (`identity.seed_file`).
  `org.roots` holds `RootConfig` entries whose `key` matches `^ed25519:[0-9a-f]{64}$` — public key
  ids, used to *verify* approvals. No approver's private key is in the process, in either topology.
- The gateway process is spawned **by the agent's MCP client**, over stdio, as the same user on the
  same host. An evaluator observed that one edit to their own `~/.claude.json` routes around it, and
  that nothing attests a client went through the gateway at all — so a clean audit trail and a
  bypassed one are indistinguishable *today*.

The subprocess boundary was never a boundary against the operator. It was a transport choice, and it
was the entire cost of adoption. Deferring on a security argument that did not hold cost this
product its clearest rejection, and the argument should have been checked the first time it was
made rather than the third.

## Decision

Ship `Governor` — a context manager that opens the same session `Gateway.open_session` opens, and a
`@governor.governed(server=…)` decorator that puts a call through `Enforcer.call`.

It is not a second enforcement path. It is the wrapping `Gateway.native_handler` has always applied
to Harbormaster's own tools, exposed for any callable: same classifier, same eleven steps, same
envelopes, same refusals. Roughly ninety lines, most of them explaining themselves.

Two details that are not incidental:

- **Arguments are bound to names before hashing.** `signature.bind(...)` then `apply_defaults()`, so
  `f("ORD-1", 500)` and `f(order_id="ORD-1", amount_cents=500)` commit to the same `args-hash`.
  Without it one approval would bind one spelling of what is visibly one action, and an approver
  asked twice for the same thing learns to stop reading.
- **`Governor` is exported through `__getattr__`, not imported.** `__init__.py` promises nothing
  runs at import time; a plain re-export would pull in the runtime, the emitter, the store and the
  proxy, turning that paragraph into a lie for anyone importing the package to read `__version__`.

## What it is honestly not

`@governed` is not a security boundary against the process it runs in. No in-process check is: the
undecorated function is right there. It never claimed to be — the thing being governed is what the
*agent* decides to do, not what a human with a debugger can do to their own program. The MCP
topology is not stronger here, for the reasons above; it is only more work.

## Found while building it

Writing the first test exposed a defect nothing else had: **first-call gating fired even for an
action the published policy named by name.** `first_call` read only the classifier's tier, so a tool
the organization had explicitly classified still parked, and the approval seeded a catalog entry
saying what policy already said.

That is the reason the escape this product documents did not work. An engineer measuring the daily
cost published exactly that policy and reported it *"did not help"* — every call still parked,
forever. `Policy.names` now answers "did the organization speak about this action", and §10 §4 gates
what is unknown *to the organization*, which is what it always meant. The paired negative lowers
`default-unknown` to `read`, because under the shipped `consequential` default an unknown tool parks
via the gate rule and the test would pass with §10 §4 deleted.

## Consequences

`gateway/tests/test_governed_functions.py` runs the integrator's own shape: ordinary functions, a
ledger that stays a list in the test's process, a gated function whose body does not run when the
call is refused, and a subprocess probe that fails if importing the package pulls in the runtime.
