# The persona evaluation program

> ## Read this before you read anything else
>
> **This is synthetic evidence produced by simulated evaluators.** Every persona in this document
> was an agent given a brief. None of them had money at stake, a job at risk, a colleague to answer
> to, or a production system that would page them at 3am. Nobody with money or a job at risk has
> operated this product.
>
> **It is a segmentation signal, not market validation.** What it can tell you is *which buyer this
> product is wrong for and why* — that is a claim about the product's own logic, and simulated
> readers can carry it. What it cannot tell you is whether anyone will pay, whether the refusals
> would survive a real procurement cycle, or whether an operator would keep using it in week three.
>
> **The two empirical questions in `docs/open-questions.md` remain open. This document does not
> close them and must not be cited as if it does:**
>
> 1. > **Is "pending approvals" a daily driver?** The console thesis rests on it. Test: dogfood on
>    > my own fleet from day 1 (Lattice + FleetQ gates through the kernel). If I don't open it daily
>    > within two weeks of S4, the surface thesis is wrong and v1 scope must be rethought — before
>    > any external user sees it.
>
> 2. > **Does the four-class taxonomy (read/benign/consequential/prohibited) survive a foreign
>    > domain?** Validated only against components I wrote. Test: first component not written by me
>    > (or first genuinely alien domain — e.g. a finance connector). If the manifest requires
>    > contortions, the taxonomy needs revision at manifest time, not production time.
>
> Question 1 needs a human who opens a console every morning because their own fleet depends on it.
> Question 2 needs a component this project did not write. **No persona was either.** ADR-0027 §"What
> v1.0 rests on now" says the same thing in the same words: *"They are not [a design partner]: every
> persona was an agent given a brief, and none of them ran a business on it."*

---

## 1. Three rounds, three techniques, three questions

They are not three samples of one study. Each round changed what the persona was holding, and that
is what changed what it could find. Do not average them.

| Round | Date | N | Question it answers | What the persona holds |
|---|---|---|---|---|
| **Usability** | 2026-08-01 | 6 | Does it work as documented? | a task |
| **Adoption** | 2026-08-02/03 | 8 | Is it worth it, and to whom? | a task, a **named cheaper alternative**, and permission to refuse |
| **Scenario** | 2026-08-03 | 5 | Does it survive use over time? | a **workflow**, plus state that accumulated before the workflow starts |

### The arithmetic, reconciled

**19 personas ran in total. The commonly-quoted "13 personas" is the adoption round (8) plus the
scenario round (5)** — the two rounds that produced *verdicts* rather than defect lists.

The usability round's 6 are excluded from that count deliberately, not by oversight. A persona
holding only a task can tell you that a command is missing or a page is wrong; it cannot tell you
whether the product is worth its cost, because it was never offered anything else. Six such runs
produced findings. They produced no verdict, because they were not asked for one.

The distinction is load-bearing in the other direction too: ADR-0027 records that **three of the
four "worst defects" reported in the first round were the product behaving correctly and not saying
so.** A task-holding persona meets a correctness product at its refusals and reads every refusal as
a bug. That is a real finding about the product's legibility — and it is not a verdict about its
value.

---

## 2. What the two verdict-bearing rounds returned

### Adoption round — 8 evaluated, 4 refusals, 4 conditional, **0 unconditional**

Not one of eight evaluators, each holding a named cheaper alternative, adopted this product
unconditionally. Four of them walked. That is the single most important number in this document and
it is a *negative* result about breadth, not a positive one about fit.

The findings the round produced are enumerated in `docs/adr/ADR-0027-what-eight-evaluations-falsified.md`,
which also records what it falsified: ADR-0024 §2 had claimed *"every operator operation has a
command"* — and **no command published a mandate to the chain**. Three personas found it from three
directions in one day. Root rotation, human delegation, and every recovery path for the day the
person who ran the ceremony leaves were all unreachable, and the test suite could not contradict the
claim because its fixture hand-assembled the envelope no command produced.

### Scenario round — 3 criticals, every one of them a fix the repository already contained

Five personas, each running an unrelated workflow over accumulated state. Three defects, and the
commit that closed them (`cf64bf7`) states the property that makes them worth recording: *"Three
defects, each found by more than one evaluation running an unrelated scenario, and each already
fixed elsewhere in the repository at the time."* Each fix was present and applied to **N−1 of its N
sites**:

- **The clock override was the kernel's alone.** The gateway stamped an action-request on its own
  clock, so on a time-advanced deployment every gated call arrived expired and the gate could queue
  nothing at all. *The facility built so the product could be observed turned its central control
  off.*
- **The launcher resolved its image before reading `.env`,** so the ceremony ran one binary while
  compose ran another.
- **The in-process Governor, one day old, handed its functions arguments the approver never signed.**

The pattern is the finding: a fix applied everywhere but one place is not a fixed defect, it is a
defect with a smaller cross-section. Only a persona running a *workflow over time* crosses the
remaining site — a task-holding persona never reaches it.

---

## 3. Methodology, stated so someone could repeat it

### The three brief rules that made the adoption round work

Verbatim, because the wording is the instrument:

1. *You have a named alternative and a budget; rejecting is a valid, expected outcome and costs you
   nothing — if you reject, name the cheaper thing you would do instead and what would change your
   mind.*
2. *Do not read `README.md` first — reach for it when stuck, and record the moment you did.*
3. *Judge the product you can run today; docs and ADRs are not deliverables to your employer.*

Rule 1 is what produced four refusals. Without a named alternative and explicit permission to walk,
an evaluator's cheapest path is to complete the task and report friction — which reads as adoption.
Rule 2 converts the README from a script into a measurement: the moment a persona reaches for it is
data about where the product stops explaining itself. Rule 3 removes the reward for grading the
repository instead of the artifact.

### Isolation constraints

Every persona ran in **its own git worktree, its own compose project, its own port, and its own
image tags.** Live deployment was explicitly out of bounds. This is not hygiene for its own sake:
personas run concurrently, and one persona's advanced clock or seeded store silently invalidating
another's run would have produced findings attributable to nothing.

### The caveat that changed a finding's severity

**A persona's observation is data; its cause is a hypothesis.** These are not the same evidence
class and must not be recorded as if they were. The observation ("this call arrived expired") is
something the persona ran into. The cause it proposes is a guess by a reader who has not read the
code.

One persona filed a finding whose **stated cause contradicted the code**. The correct response was
not to discard the finding — the observation was real — and not to accept the diagnosis. Pushing
back with the code in hand turned it into **the round's most severe finding**. A program that
accepts persona diagnoses uncritically produces a defect list with wrong root causes; a program that
discards findings whose diagnoses are wrong loses its best signal.

---

## 4. The Slack-shim episode — the program's single strongest result

One adoption persona's named cheaper alternative was **"a two-day Slack-approve shim."** Rather than
assert it, the persona *built* it.

**It shipped replay and a forged approver in its first run.**

The evaluator who was trying not to buy produced better evidence for the product's thesis than any
test in this repository. Every test here is written by someone who already believes approvals need
replay protection and signer binding; the shim was written by someone whose entire position was that
they do not. It is the closest thing the project has to an independent construction of the
alternative, and the alternative failed at exactly the two properties the gate exists for.

This is one run, by an agent, in a day. It is not proof that every Slack shim is broken. It is
strong evidence that **the naive alternative is harder than the people who propose it believe** —
which is a claim about the shape of the problem, and the kind of claim a simulated evaluator can
actually carry.

---

## 5. The measured comparisons — and the question the product loses

An incident-scenario persona timed four questions against the product and against a `grep`-able JSON
log, on the same incident.

| Question | Product | `grep`-able JSON log |
|---|---|---|
| What happened? | **4m02s** | **under 1s** — with the argument values inline (see below: so does the product, for a call that *ran*) |
| Who approved it? | 9s | **zero lines** |
| What else is currently permitted to do this? | 31s | **cannot answer at all** |
| Make it impossible. | 2m35s | no enforcement surface exists |

An earlier adoption persona ran the first question independently and measured **2m11s against 9s**,
reaching the same verdict by a different route.

**Record it plainly: the product loses question one.** 4m02s against under a second, on the question
an operator asks first and most often. A text file wins, and that stands.

**It loses on latency, not on data — and the difference matters, because this particular fact has
now been got wrong in both directions.** An earlier round filed *"applied effects retain no
arguments, only a hash"* among the product's worst defects and was **wrong**
(`docs/design-eval-findings.md`, the row beginning *"applied effects retain no arguments"* — cited
without a line number on purpose: that row moved while this document was being written, and its own
pointer into `enforce.py` had already drifted once). That file draws the right lesson from it: those
evaluators were *"right about what they observed and wrong about what it meant."* The correction
below must not become the same error with the sign flipped. Two answers are true at once:

- **A call that ran.** Its arguments are in the effect envelope's evidence payload. The gateway
  attaches `{server, tool, arguments}` to **every** effect body it emits
  (`gateway/src/stozher_gateway/enforce.py:1224`), the kernel serves it at
  `GET /v1/payloads/<payload-hash>` (`spec/04 §5.2`, the content-addressed payload store), and it is
  retained for the policy's `evidence-ttl` — **`P365D` for `consequential`, `P3650D` for
  `prohibited`** (`spec/04 §5.3`, `spec/05 §4`). An investigator gets the values, for a year.
- **A call that parked and was never answered.** Its arguments live only in the gate queue, and
  `spec/06 §4.4` rule 7 requires the kernel to **erase** them once the request's `not-after` passes.
  Nothing was applied, so no effect envelope and no payload was ever created.

**This persona's incident was the second case, which is why their measurement reads as it does.**
Their destructive call was **refused four times and never executed** — they reported all five
snapshots present and `purged: []`. They went looking for the arguments of a call that never
happened and correctly found only the commitment; their brute-force against the digest was the right
move for that case, and would have been unnecessary had the call run.

So the honest statement is narrower than "the product does not hold the argument values", which is
false for executed calls, and narrower than "it holds them always", which is false for expired
parks. What a `grep`-able log genuinely beats here is **time-to-answer**, and it beats it by three
orders of magnitude.

**That is the segmentation, and hiding it would make this document worthless.** The product's case
is questions two through four, where the log does not lose — it *cannot compete*: "who approved it"
returns zero lines, "what else is permitted to do this" is unanswerable in principle, and "make it
impossible" names a surface a log does not have. A buyer whose real question is question one should
buy `grep`. A buyer whose real question is two, three or four has no log-shaped option.

Anyone quoting this document to a customer must quote row one.

---

## 6. What this program is evidence *for*

- **For:** that the product's refusals are illegible before they are wrong; that the naive
  alternative is harder than its proponents believe; that four of eight evaluators with a cheaper
  option walk away; that "what happened" is not this product's question.
- **Against, as a matter of method:** anything requiring a human's sustained attention, a real
  budget, a foreign component, or three weeks of elapsed time. `docs/open-questions.md` #1 and #2
  are both in that set, and both remain open.

## Related

`docs/open-questions.md` · `docs/adr/ADR-0027-what-eight-evaluations-falsified.md` ·
`docs/adr/ADR-0024-declaring-v1.md` §2 (the claim ADR-0027 amends) ·
`docs/adr/ADR-0011-approver-legibility-and-the-args-commitment.md`, `spec/06 §4.4` and
`spec/04 §5.2`–§5.3 with `enforce.py:1224` (where the argument values live for a call that ran, and
where they are erased for one that did not) · commit `cf64bf7` (the three time-axis defects)
