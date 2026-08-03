# ADR-0027 — What eight adoption evaluations falsified, and what v1.0 rests on now

**Date:** 2026-08-03
**Status:** accepted
**Amends ADR-0024 §2. Does not withdraw the v1.0 label.**

## Why this exists

ADR-0024 declared v1.0 on 2026-08-02. Its §2 gave the engineering half of the case as: *every
operator operation has a command, and every command has been run as a subprocess against a live
kernel.*

**The first half was not true when it was written.** Putting a mandate on the chain had no command:
`grant` wrote a signed object, and the only code in the product that published one was the MCP
gateway, for its own session mandate, at session open. Every human-held mandate signed after the
install was therefore unresolvable, and with it root rotation, human delegation, and every recovery
path for the day the person who ran the ceremony leaves.

ADR-0024 is not edited. It records a decision taken on the evidence available that day, and
rewriting it would erase the thing worth keeping: that the evidence was wrong and how.

## How it was wrong

The sweep behind §2 asked *"which operation does the specification require of an operator that no
command performs?"* It found seven and closed them. It swept the **gated ceremonies** — policy,
roots, components, revocation — and not the **mandate lifecycle** that every one of them depends on.
A sweep stops where the shape it is looking for stops.

The test suite could not contradict it. `test_root_change_cli.py` had hand-assembled the
`kind: mandate` envelope in Python for a year, because that was the only way it could be assembled.
It was green throughout and proved the ceremony works *given* a published mandate, while imitating
the single step no operator could perform. That is now a recorded test smell: **when a fixture
constructs a protocol object by hand, ask which command produces it in production.**

## What the evaluations found

Eight personas, each holding a named cheaper alternative and permission to refuse: four rejections,
four conditional adoptions, **zero unconditional**. Everything below is now closed, on
`feat/evaluation-findings`.

| Finding | Where it landed |
|---|---|
| No command published a mandate — three personas, three directions, one day | `submit-mandate` |
| `config.json` enrolled a trusted approver on every boot, no envelope, chain head unchanged | ADR-0025 |
| The catalog was never seeded on the documented approval path — 22 approvals, 0 rows | seed request parked beside the call |
| First-call gating ignored an explicit policy classification, so the documented escape did nothing | `Policy.names`, ADR-0026 |
| A request the kernel refused to queue was reported `parked` | now `blocked`, kernel's own reason code |
| The genesis policy named one approver, who §06 §5 forbids from approving their own request | names every enrolled root |
| The only way in was MCP; the adapter exceeded the application it governed | `Governor`, ADR-0026 |
| `bin/stozher-anchor` did not run at all — `IMAGE` resolved before `.env` | fixed in all four scripts |
| The HTML export rendered every non-effect envelope as a blank row | `kind`, verdict and reason |
| The root-change ceremony could not complete from the documentation | grant shown, `--components kernel`, `--evidence` |

Three of the four "worst defects" reported in the first round were the product behaving correctly
and not saying so. That ratio is the standing lesson: **an operator meets a correctness product at
its refusals and nowhere else.**

## What v1.0 rests on now

Unchanged from ADR-0024 §5 and still true: the external review is an attestation whose scope is not
recorded here; no independent implementation has been written from `spec/` alone; no design partner
has operated this.

Changed, and this is the substance of this record:

- **The completeness claim is now checked rather than asserted.** The whole human ceremony —
  `grant` → `submit-mandate` → `root-request` → `park` → a second root approves → `root-publish` —
  was run on 2026-08-03 against a containerised deployment built from the branch, in an isolated
  copy with its own compose project and port. It completed: the enrolment was accepted, the third
  root appears under its human name, and every stream verifies. The two commands the branch adds
  were exercised through the docker invocations the documentation gives, not through the library.
- **Eight independent readings exist.** None of them adopted unconditionally, and their reports are
  the closest thing this project has to a design partner. They are not one: every persona was an
  agent given a brief, and none of them ran a business on it.
- **The label did not move and neither did the wire version.** `stozher/0.1` is unchanged; nothing
  in this round altered an envelope's shape.

## Not withdrawing v1.0

Considered and rejected. The label was declared by owner decision on a scope that was mostly met and
is now met; withdrawing it would relabel work that exists rather than correct a claim. What was
wrong was one sentence about completeness, and the honest repair is to say which sentence, why it
was wrong, and what replaced it — which is this document, pointed at from ADR-0024 §2.
