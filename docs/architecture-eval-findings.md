# Architecture — the six changes

Companion to `design-eval-findings.md`. One section per item: the site, the change, and the
constraint that shapes it.

## A. A first-call park says what approving it buys

**Site:** `gateway/src/stozher_gateway/enforce.py`, the `refusal("parked", …)` at the end of
`_park_or_consume`. The method already receives `first_call: bool`.

**Constraint, and why it does not block this.** `spec/06 §4.1`: *"The refusal MUST NOT contain
guidance on how to obtain approval by other means, and MUST NOT suggest an alternative unapproved
action."* The comment at `enforce.py:653` reads that as a bar on operational guidance because the
first reader is the agent. A sentence stating that the approval also seeds a catalog entry is
neither of the two prohibited things — it names a consequence of the decision, not a route around
it. The same clause ends *"Being refused legibly is a feature: the agent can report accurately to
its user instead of retrying blind"*, which is precisely the failure two evaluators hit.

**Change:** on `first_call` only, the hint gains one clause — approving this request also classifies
this tool, and later calls resolve through that classification instead of parking. Not emitted on a
non-first-call park, where it would be false.

**Why `first_call` and not always:** a genuinely `consequential` action parks every time, by design.
Saying otherwise there would be the product lying in the other direction.

## B. The export points at the arguments it already retained

**Site:** `kernel/stozher-kernel/src/console.rs`, `export`; the envelopes already carry
`evidence.payload-hash`, and `http.rs:69` already serves `GET /v1/payloads/{payload_hash}`.

**Change:** the response gains a header naming the payload route, and the console's audit page gains
the same sentence. The exported NDJSON body is **not** modified — it is signed canonical bytes and
an independent verifier re-derives `id()` over it. Adding a member would break every verifier,
including the one the compliance evaluator shipped to their auditor.

That constraint is the whole design of this item: the fix must live everywhere *except* the bytes.

## C. A human-readable export

**Site:** same handler, selected by `?format=`. Default stays NDJSON — an existing caller must not
be changed by this.

**Change:** `format=html` renders a self-contained document: the filters that produced it, the
record count, and one row per envelope with subject, action, target, classification, outcome,
approver and time. It states in its own text that it is a rendering, that the NDJSON is the record,
and it carries the `payload` route for any row with evidence.

**The trap:** a rendering that looks authoritative is worse than no rendering. The document must say
what it is not.

## D. An off-box anchor

**Site:** new `deploy/bin/stozher-anchor`; kernel already computes checkpoints
(`checkpoint.rs::run_interval`) and stores heads (`store.rs::last_checkpoint`).

**Change:** a script that reads the current checkpoint head of every stream and writes a small
signed-envelope-referencing digest to stdout or a file, for the operator to commit to a repository
they do not control, or mail. Plus a kernel route serving those heads, and a console line showing
the last anchor time if one has been recorded.

**Deliberately not:** a transparency-log client, a mail sender, a git integration. `spec/04 §4.7`
names "the console's export, an operator's email, a git commit" — three destinations the operator
chooses. Shipping the export is the product's job; choosing the destination is not.

**Honesty requirement:** the console must not claim anchoring is happening because the facility
exists. If no anchor has been taken, it says so.

## E. `stozher-bootstrap` validates before it compiles

**Site:** `deploy/bin/stozher-bootstrap`.

**Change:** move argument validation ahead of the docker build. Today `--second-root` without
`--second-root-key` is discovered after roughly four minutes of Rust compilation.

## F. A park notification hook

**Site:** `enforce.py`, after `self._store.park(...)`; configuration in `GatewayConfig`.

**Change:** an operator-configured command invoked on park, receiving the request-hash, the action
and the classification on stdin as JSON.

**Three design decisions, stated because each could reasonably go the other way:**

1. **It never blocks the gate and never fails the call.** A notifier that can turn a park into an
   error makes the gate less available than no notifier at all.
2. **It carries no arguments.** The parked arguments are the sensitive half and they already have a
   retention ceiling and an authenticated route. A notification is a pointer, not a copy.
3. **A failure is logged and recorded as a failure, never swallowed silently** — otherwise
   "nothing pinged me" and "the ping failed" look identical, which is the exact class of defect
   this sprint exists to remove.
