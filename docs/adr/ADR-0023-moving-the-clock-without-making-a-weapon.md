# ADR-0023: moving the clock without making a weapon

**Status:** Accepted · **Date:** 2026-08-01 · **Arises from** an external review finding · **Follows**
ADR-0022 · **Adds** `spec/04 §7.1`, `spec/09 §5.1` · **Adds** the `clock-advance` configuration
member

---

## 1. The finding, and why it is a fact about the product

An external reviewer spent an afternoon on a deployment and wrote:

> "The deployment offers no facility to advance or simulate time, and no payload had reached its
> retention ceiling, so **we did not observe retention enforcement at all**."

Their limitations paragraph closes: *"The period under review is four minutes of activity on a
deployment created for this engagement."*

That is not a complaint about the reviewer's method. Four of this kernel's enforcement behaviours are
decided by comparing its clock against a deadline, and **every deadline this system can express
outlives an engagement**:

| Behaviour | Decided by | Shortest deadline a policy can express |
|---|---|---|
| Payload decay | `retain-until` vs `now` | `spec/05 §6` expresses retention in **days** |
| Mandate expiry | `not-after` vs `now` | minutes, but a demonstration one proves nothing about a real one |
| Checkpoint interval | `policy.checkpoint-interval` vs elapsed | an hour by default |
| Quiet-stream surface (§09 §4.2) | `last-appended-at` vs `now` | the configured quiet threshold |

Decay is the one that matters most and is the one that is structurally unobservable: `deploy/` ships
a daily sweep against retention ceilings measured in days, so *no* engagement short of the ceiling
sees a single payload erased. The reviewer could read the code and take the property on trust. That
is the state ADR-0022 §3 already describes for the corpus half of the release gate, and repeating it
for the enforcement half is not acceptable in a product whose whole claim is that enforcement is
structural rather than promised.

## 2. The tension, stated before it is resolved

This kernel judges mandate validity, revocation, expiry and retention **by time**. A clock an
attacker can move is:

- **backwards** — an expired mandate is live again, a published revocation has not happened yet, a
  closed budget window is open;
- **forwards** — a payload is erased before its retention ceiling, destroying evidence irreversibly.

So a facility that ships in the production binary is a candidate vulnerability, and one that exists
only in `stozher-testkit` does not help the reviewer, who has a real deployment in front of them and
is auditing the artifact that runs, not one they compiled themselves.

## 3. Decision

Ship **`clock-advance`**: a configuration member that moves the kernel's clock **forward only**,
bounded, declared into the chain, and ratcheted so it cannot be undone.

Four properties, each of which is load-bearing and each of which has a test that fails without it.

**(a) It is an advance, not an offset — enforced by the grammar, not by a check.** The value is an
ISO 8601 duration of `spec/01 §2.4`, and that grammar **has no sign**: `-PT1H` is
`encoding-bad-duration`, not a negative hour. `AdvancedClock::new` refuses a non-positive advance as
well, for callers who build the struct by hand. The consequence is the whole safety argument:

> `AdvancedClock::now() >= base.now()`, on every input, under every configuration.

Nothing an operator can write produces a kernel whose clock reads earlier than the host's. Therefore
**this facility can never lengthen anybody's authority**. A mandate past `not-after` stays past it; a
revocation stays published; a budget window stays closed. This is not "we check for negative values"
— it is that the configuration language cannot say the sentence.

**(b) It is bounded** at ten years (`P3650D`). Retention ceilings are days, so ten years crosses any
commitment a policy can express, and the bound keeps the advance from pushing the fixed timestamp
form out of range.

**(c) It cannot run undeclared.** Before the kernel serves anything, `clock::declare_advance` writes
a record into the kernel's own rejection stream (`spec/04 §7.1`): signed by the kernel key, chained
to the record before it, in a table whose `BEFORE UPDATE` / `BEFORE DELETE` triggers abort the
statement. Its `received-at` and its `real` member carry the **host's** time while every record the
process goes on to emit carries the advanced one, so a reader subtracts one from the other and knows
exactly how far ahead everything after that point was written. **If the record cannot be written,
`Kernel::open` fails and there is no kernel.** A moved clock nobody can see afterwards is worse than
no facility at all, so it is not best-effort.

**(d) It ratchets.** At every start — advanced or not — the kernel compares the instant it would
start at against the newest declaration in the store, and refuses to start if it is earlier. A
deployment run forward cannot be returned to the host's clock. **Moving a deployment forward costs
you that deployment, permanently.** That is the intended price of pointing this at anything real, and
it closes the attack of choice: travel forward, delete, come back, deny.

The member is an object rather than a bare duration because it must carry
`"acknowledged": "records emitted by this deployment are not evidence of when anything happened"`,
verbatim. That stops no attacker and is not meant to. It is for the reader: configuration files get
diffed, reviewed and pasted into tickets, and the one thing everybody downstream needs to know about
a deployment running this way belongs in the same three lines as the number that made it true.

## 4. What this costs, stated rather than discovered

Two residuals. Both are real, neither is closed, and neither is hidden.

**Premature erasure.** An advance brings `retain-until` forward, so a config-writer can erase
payloads earlier than reality would have. This is a capability config-write did not previously have
— `roots` and `callers` were already there, but neither deletes anything — so it is a genuine
addition to the blast radius of a compromised configuration file. It is not prevented, because
preventing it means refusing to demonstrate decay, which is the finding. It is (i) forward-bounded,
(ii) preceded by the §04 §5.4 checkpoint like every other decay, and (iii) preceded in the same chain
by a declaration stamped with real time. The chain cannot lie about it afterwards. `SECURITY.md`
already records that payload decay has no second custodian; this sharpens that entry rather than
introducing it.

**The offline CLI still runs on real time.** `stozher-kernel genesis`, `mint` and `scope` build
documents for an operator to sign without loading a `Config`, so they stamp the host's clock. On an
advanced deployment a mandate minted by `mint --minutes 60` is already expired before it is
submitted, and a ceremony document is dated a year in the past. That is arguably right for a
ceremony — those documents outlive the demonstration — but it is a rough edge in the reviewer's
workflow, and the way through it is to pass explicit timestamps. Not fixed here because `main.rs` is
outside this change's surface.

**The gateway had no clock, and that turned the gate off.** Corrected 2026-08-03. This section
reasoned about the kernel and about the offline CLI and never about the *enforcing* component. The
gateway stamps an action-request's `not-after` from its own clock, so on an advanced deployment
every gated call arrived already expired and came back `gate-request-expired`, `result: blocked`,
`retryable: false` — not queued, not approvable, dead. Three independent evaluations reached that
state from three different scenarios; one could not approve a single call for the rest of its run,
and another reported the only mandate that would run its agent was one the console labels expired.
The facility built so a reviewer could observe the product disabled the product's central control.

An advance is now a property of the **deployment**: `[clock] advance` / `acknowledged` in
`stozher-gateway.toml`, the same two members and the byte-identical acknowledgement sentence the
kernel takes, pinned by `test_deployment_clock.py`. `bin/stozher-approve` and
`bin/stozher-publish-policy` now pass `--config` too — they never did, so an approval was stamped on
the host clock, refused `gate-approval-expired`, and *consumed the pending item on the way*, leaving
`console-csrf-invalid` on every retry and no way to re-answer.

**Early activation.** A mandate whose `not-before` is in the future becomes usable under an advance.
Narrow: to hold such a mandate you need the issuer's signature, and anyone who can obtain a
future-dated mandate can obtain a present-dated one. It bites only where an issuer deliberately
pre-signs a scheduled delegation. Named here because it is the one case where "an advance never
lengthens authority" is not the whole story.

## 5. Alternatives rejected

**A cargo feature or a separate build profile.** The clean answer, and it fails on the finding it is
meant to address. The reviewer's complaint is about *the deployment*, and a build they made
themselves is not the artifact any deployment runs. Moving the facility into a second binary moves
the unobservability up one level: they would then be reporting on enforcement in a build nobody ships.

**Leaving it in `stozher-testkit`.** Where it already is (`FixedClock`). It is why this repository's
own tests can prove decay works and an engagement cannot. Rejected for the same reason.

**Refusing entirely, and giving the reviewer a fixture deployment with a pre-aged history.** The
safest option and seriously considered. Rejected because a history the vendor generated is a history
the vendor chose: the reviewer would be observing enforcement over data we handed them, which is
weaker evidence than enforcement over data they created themselves, and it leaves *their own*
deployment exactly as unobservable as before. It also needs a fixture generator holding a root key
outside the harness — `SECURITY.md` §7 already names that as the most dangerous shape in the
repository.

**An absolute time rather than an offset.** Rejected: an absolute time is bidirectional by
construction. The direction is the entire safety argument, and a member whose safety depends on
comparing it against the host clock at startup is a member that is safe only when that comparison is
correct.

**A marker in every envelope emitted while the advance is in force.** Wanted, and not available.
`spec/02 §2` fixes the `kind` vocabulary at nine and every kind's member set is closed; a tenth kind
or a new member is a wire change that invalidates every existing document and all 293 vectors at
once — the same argument ADR-0010 made for keeping `decay-interval` out of policy. The alternative,
changing the kernel's own `identity.subject` while advanced, changes a value the console, the audit
query, the gateway and the checkpoint signer check all read. What replaces it: one chained
declaration carrying both timestamps, from which the advance on every subsequent record is
arithmetic. This is the weakest part of the decision and is written here so a reviewer can weigh it
rather than discover it — in particular, the declaration lives in the rejection chain, so an auditor
reading only `envelopes` will see timestamps ahead of real time with no explanation in that stream.

**A second out-of-band condition — a marker file, an environment variable, a CLI flag.** Rejected as
theatre. Anyone who can write `config.json` can write a file beside it or set a variable in the same
unit file, and `config.json` is already where root trust enters this deployment (`config.rs`: "the
root set enters through configuration, which is the honest place for it"). Adding a second thing an
attacker must also do, which costs them nothing, buys the appearance of a control rather than a
control. The direction and the ratchet are the real constraints; the acknowledgement is honest
labelling and is documented as such.

## 6. What now fails if this stops being true

| Claim | Test |
|---|---|
| No configuration produces a clock behind the host | `config.rs::no_configuration_can_ask_for_a_clock_that_reads_behind_the_host` |
| A negative advance cannot be constructed | `clock.rs::the_clock_advance_has_no_way_to_point_backwards` |
| The advance is positive and bounded at ten years | `clock.rs::an_advance_is_bounded_and_never_zero`, `config.rs::a_clock_advance_is_a_positive_bounded_duration_with_the_acknowledgement` |
| An advance never resurrects an expired mandate | `tests/clock_advance.rs::the_advance_cannot_bring_an_expired_mandate_back` |
| The advance is declared, signed, chained, and carries real time | `tests/clock_advance.rs::the_advance_is_declared_into_a_signed_chained_record_before_anything_is_served` |
| A deployment that has run ahead cannot go back | `tests/clock_advance.rs::a_deployment_that_has_run_ahead_will_not_go_back` |
| A deployment that does not ask for it pays nothing | `tests/clock_advance.rs::a_deployment_that_never_asks_for_an_advance_pays_nothing_for_it`, `config.rs::a_deployment_that_says_nothing_about_the_clock_gets_the_hosts` |
| The acknowledgement is required verbatim | `config.rs::a_clock_advance_without_the_acknowledgement_is_refused` |
| Both components read the same advance, spelled the same way | `gateway/tests/test_deployment_clock.py::test_the_gateways_advance_is_spelled_the_same_as_the_kernels` |
| The gate can still queue a request on an advanced deployment | `gateway/tests/test_governed_functions.py::test_a_gated_call_still_parks_on_a_clock_advanced_deployment` |
| The gateway's advance is forward-only and acknowledged | `gateway/tests/test_deployment_clock.py::test_the_clock_cannot_be_moved_backwards`, `::test_the_acknowledgement_is_required_and_exact` |

Every row above was true of the kernel on the day this was written, and the table did not say so —
which is how a facility with eight passing claims left the gate unable to queue anything. A claim
about "the deployment" needs a test per component, or it is a claim about one of them.
