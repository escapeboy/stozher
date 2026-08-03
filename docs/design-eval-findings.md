# Design — what four evaluators found, and what to do about it

**Status:** in build, branch `feat/evaluation-findings`, opened 2026-08-02.
**Input:** four independent adoption evaluations run on 2026-08-02, each by a persona holding a
named cheaper alternative and permission to reject. One rejected; three adopted with conditions.

## The forcing questions, answered from what they ran

### Who needs this? What are they doing today?

Not the team asking *what did my agents do*. That question was measured against the alternative and
the alternative won: 9 seconds of `grep` over an application log versus 2m11s through the console,
and the log gave the refund amount while the console gave a hash. Anyone buying Stozher for
forensics is buying a worse log.

The buyer is whoever must answer **what is this fleet still allowed to do, and how do I take it
away** — a question a log cannot answer at all, which the console answered in about twenty seconds
with a mandate table and a revoke command — or must show an outsider that an approval was not
manufactured by the machine that ran the agent.

Today they have a spreadsheet the auditor already accepts, or a policy dict in a decorator.

### What is the narrowest MVP someone would pay for?

Already built and confirmed by attack. Three independent attempts to defeat the core failed:
an approval signed with the kernel's own on-server key was rejected (`gate-approver-not-permitted`);
a replayed approval re-parked; and fifteen minutes of dropping all 27 append-only triggers and
rewriting an indexed column still produced a correct `verify` and a truthful console, because the
signed canonical bytes were untouched.

Nothing in this sprint touches that core. Everything here is the edge around it.

### What would make someone say "whoa"?

It already happened three times, and each time it was **a refusal that carried evidence**:

> the denied call's retry came back carrying `"reason": "payroll data is out of scope for this
> agent"`, `"decided-by": "ed25519:8de5bcf9…"`. The refusal itself was signed evidence, not a log
> line.

The failure is that the same surface stays silent at the moments that matter *against* the product.

### How does this compound?

The dominant finding is not a defect list. **Three of the four "worst defects" reported do not
exist as capabilities gaps — they are the product doing the considered thing and not saying so.**

| Reported as worst defect | What the code does |
|---|---|
| "a pure read requires a human signature" (×2 evaluators) | `enforce.py:571` — first-call gating parks an *unknown* tool by §10 §4, and the approval seeds a signed catalog entry (`_seed_catalog`, §10 §4.3) so the next call resolves without parking. Once per tool, not once per call. Neither evaluator made the second call. |
| "applied effects retain no arguments, only a hash" | `enforce.py:1041` — the payload is `{"server", "tool", "arguments"}`, retained under `retain-until` and served by `GET /v1/payloads/<hash>` (`http.rs:69`). The export just never mentions it. |
| "no off-box anchor" | **Real.** `spec/04 §4.7` says checkpoints SHOULD be exported off-box; nothing in `deploy/bin/` does. |

That ratio is the design input. Silence at the point of refusal cost one outright rejection and two
conditional ones, from evaluators who were **right about what they observed and wrong about what it
meant**. A correctness project that communicates only through correct behaviour will keep paying
this, because the operator meets the product at its refusals and nowhere else.

So the compounding property is: *every refusal is a teaching surface, and the catalog seeding means
the cost of a refusal falls to zero the second time.* The product already has the second half.

## Scope

In, each traceable to an evaluator who was blocked by it:

- **A. A park says what approving it buys.** The refusal payload names the catalog seed. Kills the
  finding that produced the one rejection and two complaints.
- **B. The audit export points at the retained arguments.** `payload-hash` is already in the
  envelope; the export must make the route findable. Kills the incident responder's worst defect.
- **C. A human-readable export.** "NDJSON is not a document" — the compliance officer hand-wrote
  the cover memo because the product produces no artefact a lawyer reads.
- **D. An off-box anchor.** The one genuine capability gap. Ship the export, not a transparency-log
  integration: checkpoint heads to a file an operator commits or mails, and a console line saying
  when the last one left the building.
- **E. `stozher-bootstrap` validates its arguments before it compiles Rust for four minutes.**
- **F. A park notification hook.** "A gate nobody is pinged about is a queue, not a control" — nine
  requests were parked with nothing configured to tell anyone. Fire-and-forget, never blocks the
  gate, carries the request-hash and no arguments.

## Out of scope, deliberately, with the argument

**An in-process governed-function API** (`@governed` on an ordinary Python function, no MCP, no
subprocess). This is the integrator's stated flip condition and the single largest adoption lever:
their adaptation layer was 134 lines against a 123-line application, and their tool state had to
leave their process. `Enforcer.call(session, call, forward)` is already a real seam with a `forward`
callable, and `Enforcer` is already in `enforce.py.__all__`.

It is excluded because it is not a packaging change wearing a design change's clothes. In-process
means the signing key lives in the agent's own process, and the property the evaluations confirmed
by attack — *the key that can approve is never on the machine that runs the agent* — is exactly what
that would relax. The seam is nine lines from being exported and considerably further from being
honest. It needs its own ADR stating which of the current guarantees survive, and it should not be
decided inside a sprint whose other six items are about telling the truth more loudly.

The integrator's rejection therefore stands after this sprint. That is the correct outcome to
record, not to engineer around.
