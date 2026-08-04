# FINDINGS — blind sufficiency audit of `stozher/0.1`

Method: read `spec/*.md` only. No reference implementation, no generator, nothing outside the
sandbox. For each area I wrote down what the text told me, implemented it in `impl/`, ran the
`role: "primitive"` vectors, and recorded where the vectors — not the prose — supplied the answer.

Tags: `SILENT` (text does not address it; I guessed) · `AMBIGUOUS` (two defensible readings) ·
`VECTORS-ONLY` (unreachable from prose) · `WRONG` (prose contradicts vectors) · `CLEAR`.

**Result: 307/307 primitive vectors pass.** That number is not the finding. Eleven decisions
below could not have been made from the specification text, and four of them are load-bearing.

---

## 00-overview.md

- **§1, normative error codes.** `CLEAR`. Declaring `snake-case-in-backticks` identifiers to be
  machine-readable wire values, with `x-` marking a non-normative one, is exactly the contract a
  second implementation needs and most specs omit.
- **§1, the `x-` adoption paragraph.** `SILENT` (harmless). The list of the sixteen adopted names
  is in `docs/adr/ADR-0018`, which is not in the spec set. The MUST "treat `x-<name>` and
  `<name>` as the same condition" is therefore unimplementable from `spec/` alone — I can write
  the rule but cannot check it against the intended list. Not exercised by any vector.
- **§5, precedence (vectors > spec > reference implementation).** `CLEAR`, and it is what makes a
  `VECTORS-ONLY` entry below a defect in the prose rather than in my reading.
- **§4.** "Approved is not a boolean" is honoured throughout §06; recorded as context.

## 01-canonicalization-and-crypto.md

Implemented: JCS, ECMAScript `Number::toString`, SHA-256, strict Ed25519, SLIP-0010, signed-object
pattern. **65/65 first run, no corrections.** This is the strongest file in the set.

- **§3.4, the number-serialization table.** `CLEAR`, and I expected this to be the worst part of
  the exercise. Giving the shortest-digits/`k`/`n` procedure as a five-row table — rather than
  saying "do what ECMAScript does" — is why all 22 JCS vectors passed first try.
- **§3.2, UTF-16 code-unit ordering.** `CLEAR`. Naming the three wrong default comparators
  (Rust `BTreeMap`, Go `sort.Strings`, Python `sorted`) pre-empted the exact bug.
- **§2.3, timestamp round-trip.** `CLEAR`. Stating the round-trip property as *the* rule and leap
  seconds / year 0000 as its consequences meant one `datetime` round-trip implemented all three.
- **§2.1–2.2, hex encoding.** `WRONG` / `VECTORS-ONLY`. The text binds
  `encoding-not-lowercase-hex` to one condition — "An uppercase hex digit is a rejection" — and
  names **no** code for a digest of the wrong length, though §2.2 fixes the length at 64. The
  vector `envelope-shape/short-hex-hash` feeds a 32-character *lowercase* hex string and requires
  `encoding-not-lowercase-hex`. I had chosen `schema-type-mismatch`; the corpus overloads the
  case-specific code to mean "malformed hex encoding" generally. Cost: 1 vector.
- **§5 rule 3, `sig-input-mismatch`.** `SILENT` / unreachable. The code is defined as what happens
  "on verification" when a producer removed a member other than `sig` before signing — but a
  verifier cannot distinguish that from any other bad signature; it just fails `sig-invalid`. The
  code appears once in the spec and in no vector. It cannot be emitted by a conformant verifier.
- **§3.1, defect precedence.** `SILENT`. Which code wins when one input has two defects (a
  duplicate key *and* a lone surrogate) is not stated. No vector constructs one, so my ordering is
  untested rather than correct.
- **§3.1, in-memory integers.** `SILENT`. `jcs-non-finite-number` covers a non-finite reaching the
  in-memory API; nothing covers an integer outside binary64 reaching it (a Python `int`, a Rust
  `i128`). I raise `OverflowError`, which is not a normative code.
- **§6, SLIP-0010.** `CLEAR`. The `0x00`-prefix warning and the fixed `m/1054'/role'/index'` path
  convention removed the two interoperability traps before I hit them. 11/11.

## 02-envelope.md

Implemented: full structural validation. **76/76 shape + 6/6 hash, after 2 corrections.**

- **§2.1, the per-kind "MAY additionally carry" table.** `CLEAR`, and the most valuable table in
  the specification. Thirty-plus of the 76 shape vectors are `<kind>-with-<member>` cases and this
  table decides every one. The text even records that the two reference implementations disagreed
  about all of it and that the corpus never asked — that candour is what made it implementable.
- **§2.1 vs §9.1, code precedence.** `AMBIGUOUS`, adjudicated by vectors. §2.1 says flatly that a
  member outside its kind's row is `schema-unknown-member` ("even though §1 lists it, and even
  though another kind requires it"). §9.1 says `execution`/`evidence`/`classification`/
  `authorization`/`commitment-ref` on a `cognition` envelope is
  `cognition-envelope-has-effect-fields`. Both are normative, both cover the identical input, and
  **no precedence is stated anywhere.** I followed §2.1's emphasis and was wrong on 4 vectors.
- **§9, order of checks within schema validation.** `SILENT`. §9.2 fixes the coarse order
  (parse → verify signature → schema → mandate → authorization) and is explicit about why. It says
  nothing about the order among `schema-missing-member`, `schema-unknown-member`,
  `schema-type-mismatch` and the encoding codes *inside* the schema step. I chose
  version → kind → kind-specific → unknown → missing → per-member. The corpus never builds a
  doubly-defective envelope, so this passed untested.
- **§3, `identity.subject` format.** `SILENT`. `<class>:<name>` with `class` ∈ {human, agent} is a
  MUST with no error code attached. I invented `schema-type-mismatch`. Untested.
- **§5, `payload-media-type-not-allowed`.** `SILENT` in the operative sense: the condition is
  "a media type the kernel will not serve back over the origin its console runs on", which is a
  deployment property, not a rule a validator can evaluate. No conformant implementation can be
  written against it.
- **§7 + §9.1, aggregation.** `CLEAR`. Count arithmetic, sample bounds, the 1024-action
  cardinality cap, negative counts and window inversion each have a named code, and §7.7 states
  the narrow-`resources` limitation rather than leaving it to be discovered.

## 03-mandate.md

Implemented: the §5 walk, scope matching, subset, budget, revocation. **26/26 after 1 input-shape
correction.**

- **§5, the verification pseudocode.** `CLEAR`, and the single most implementable artefact in the
  specification. Transcribing it line by line produced 24/26 on the first run; both misses were
  the harness input shape, not semantics. Giving the checks *in order* also resolves error
  precedence for this whole area — which is exactly what §02 does not do.
- **§4.3, monetary comparison.** `CLEAR` on the algorithm (grammar, 32-character cap, digit-wise
  comparison, an explicit "MUST NOT convert to a binary floating-point number", and the
  `9007199254740993` rationale). `WRONG` on the outcome vocabulary — three incompatible spellings
  of one contract: spec §4.3 names `schema-type-mismatch` for a refusal; `vectors/README.md` §3
  says `expected` is "`-1`, `0`, `1`, or an error code"; `money-compare.json` uses
  `less`/`equal`/`greater`/`refused`. A harness written from either document fails all 31 vectors.
- **§5, `scope_subset` pattern-vs-pattern coverage.** `AMBIGUOUS`. "every pattern in the child is
  matched by (i.e. is equal to, or is covered by) at least one pattern in the parent" does not
  define *covered* for two patterns. I had to decide unaided whether child `github.sub.*` under
  parent `github.*` is covered (I said yes) and whether child `*` under parent `github.*` is
  (I said no). The corpus tests neither, so both are guesses that happen not to be graded.
- **§6, the root set.** `WRONG` against the corpus. §6 states "The root set is `(key, subject)`
  pairs, and the subject is what §06 §5's self-approval prohibition is evaluated over". In
  `mandate-chain.json`, `roots` is a flat array of key identifiers, and §5's algorithm only ever
  evaluates `m.grantor.key in roots`. The pair-ness the spec calls load-bearing is unrepresentable
  in the one place the corpus models a root set — which is why the `parity` kind had to invent a
  different approver shape to test the same MUST (see §06 below).
- **§7, who may revoke.** `SILENT` in the walk. §7 gives a three-way standing test — grantor, any
  ancestor's grantor, or an enrolled root — but §5's loop says only "require id(m) not revoked at
  or before at", with no signer check at all. I verify the revocation object's own signature and
  nothing else. No vector exercises standing, so an implementation that honours revocations from
  arbitrary signers passes the corpus.

## 04-chain-and-checkpoints.md

Implemented: chain verification and payload binding. **8/8 + 7/7 first run.**

- **§2.1, the four-step verification.** `CLEAR`. Steps, error codes and the `anchored` obligation
  are all named, and "MUST NOT read any payload" is stated as a property of the algorithm.
- **`failed-at-seq`.** `SILENT`. Asserted by both the `chain` and `parity` kinds and defined in
  neither the spec nor `vectors/README.md`. I guessed "the `seq` of the offending record" and it
  matched — a guess that happened to be right is still a gap.
- **`anchored` for a range starting at `seq` 0.** `AMBIGUOUS`. §2.1 defines the anchor obligation
  only for ranges that do *not* start at 0. Whether a genesis-rooted range reports `anchored: true`
  is left to inference (I inferred yes, genesis being self-anchoring).
- **`chain-seq-duplicate` vs `chain-seq-gap` for a decreasing `seq`.** `SILENT`. §2 names both for
  their obvious cases; a `seq` that goes *backwards* is neither. I mapped it to duplicate.
- **§5.2, payloads.** `CLEAR`, including the explicit "MUST accept a request with `payloads: []`"
  — which is the whole decay property, and is the kind of thing usually left implicit.
- **§7.2, resuming a wedged stream.** Thorough and unusually well-reasoned, but entirely
  `kernel`-role; no primitive vector reaches it, so I implemented none of it.

## 05-policy-distribution.md

Implemented: classification, gate rule, and the §7.1 outcome predicate. **14/14 + 16/16 first
run — but one value in it is not derivable from the text at all.**

- **§3.1, reclassification specificity.** `CLEAR`, and exemplary. The scoring table (exact 2,
  segment-prefix 1, `*`/absent 0), the sum-across-dimensions rule and the document-order tie-break
  make 14 vectors mechanical. The paragraph recording that this clause previously said only "most
  specific first", and what that cost, is the best-written passage in the specification.
- **`policy-stale-offline`.** `VECTORS-ONLY`, and the worst gap I found. `sync-outcome.json`
  requires this exact string as the verbatim `reason-code` for `unreachable` + offline `block`.
  **The string occurs in none of the eleven spec files and not in `vectors/README.md`.** I
  confirmed by grep over the whole sandbox. There is no path from the prose to this value; I read
  it off the expected output. It decides 4 of 16 `sync-outcome` vectors.
- **§3 step 4, no matching gate rule.** `SILENT`. "The first matching `gate-rules` entry decides"
  says nothing about zero matching entries. I guessed `deny` (fail-closed); the vector
  `a-class-no-gate-rule-names-is-denied` confirms it. A fail-open implementation would be equally
  faithful to the text.
- **§1 `wedge-grace` vs the corpus's `wedge-grace-seconds`.** Minor `WRONG`. §1 defines the member
  as an ISO 8601 duration with default `PT5M`; `sync-outcome.json` supplies
  `policy.wedge-grace-seconds` as an integer. A component reading §1 looks for the wrong member.
- **§7.1 rule 4, the grace boundary.** `AMBIGUOUS` but inferable: "MAY serve until `wedge-grace`
  has elapsed" plus "once elapsed, every class MUST be refused" makes the bound exclusive. The
  vector `refused-other-reason-read-at-grace-expiry-refuses` confirms.
- **§7.1 generally.** `CLEAR` and genuinely good: the three-outcome table, the reason-gated /
  class-bound grace window, and the explicit statement of *both* failure directions (wedging on an
  unreachable kernel is a DoS; unbounded grace is an unaudited fleet) made the predicate
  implementable in one pass — apart from the one string above.

## 06-gates.md

Implemented: the §2 algorithm, §4.4 submission checks, §4.2 resubmission. **19/19 authorization,
16/16 parity (after 3 corrections), 11/11 gate-arguments, 12/12 gate-resubmission.**

- **§2, the eleven steps.** `CLEAR` as far as they go, and the per-step "what it prevents" table
  is excellent. All 19 `authorization` vectors passed first run.
- **§2 is incomplete and states that it is complete.** `VECTORS-ONLY`, and the second-worst gap.
  §2 says "An implementation MUST perform all eleven checks at ingest" and gives an algorithm that
  simply dereferences the gate objects' members. The `parity` file requires three behaviours no
  step can produce:
  1. `decision-not-after-is-not-a-timestamp` / `request-not-after-is-not-a-timestamp` — the four
     gate timestamps must be validated against §01 §2.3 and rejected `encoding-bad-timestamp`.
     Steps (8) and (9) are string comparisons; the string `"z"` passes them and yields an approval
     that never expires.
  2. `decision-decided-at-absent` — a missing REQUIRED member must be `schema-missing-member`.
     Derivable from §1.2, but not from the algorithm the spec calls normative.
  3. `single-use-zero-*` — see below.
- **A non-boolean `single-use` must be treated as `true`.** `VECTORS-ONLY`, the single sharpest
  item in this audit. The spec never says what a malformed `single-use` means. The two readings
  available from the text are "reject it, §02 §9 says a member of the wrong JSON type is
  `schema-type-mismatch`" and "it is falsy, so the approval is reusable" — and the corpus requires
  neither. It requires a *fail-safe coercion to `true`* that still yields a **valid** verdict, with
  the verifier reporting `single-use: true` back to the caller. The vector's own `divergence` note
  records that the two reference implementations split exactly here, one each way. No amount of
  careful reading produces this; it is read off the expected output.
- **§1.2, `reason`.** `AMBIGUOUS`, self-contradictory. "All members are REQUIRED and the set is
  closed" and `reason` "MUST be `null` or absent" for an approval cannot both hold. I treated
  `reason` as optional.
- **§5, self-approval over the subject.** `AMBIGUOUS`. "the approver subject MUST NOT be the
  subject that requested the action" is a MUST that is **unevaluable** in the input shape the
  `authorization` kind supplies (bare key strings). `vectors/README.md` §3.1 explains this at
  length and says a verifier "MUST NOT infer a subject it was not given" — the specification
  itself says none of that. The rule for the case the spec does not cover lives only in the
  corpus's README.
- **§4.2, resubmission.** `SILENT` on the two decisions that actually determine the output:
  1. *Which* of several matching pending rows wins. §4.2 says only "where one exists it MUST
     resolve to that request". `the-oldest-outstanding-copy-wins` requires the oldest by
     `requested-at`; newest-wins or first-in-list would be equally faithful readings.
  2. Whether the lookup returns a row that already carries a decision. Rule 4 says such a row "is
     governed by §3 and by §2, **not by this rule**", which reads as "ignore it here" — but
     `the-same-call-has-been-answered` requires returning it for the caller to consume. A literal
     implementation of rule 4 mints a new request and asks a human a second question.
  The `pending | decided | consumed` state vocabulary the vectors use appears nowhere in §06.
- **§3, cross-reference error.** Minor `WRONG`: §3 says a retry is permitted where no accepted
  envelope carries that `request-hash` — "that is exactly what step (9) tests". Replay is step
  (11); step (9) is approval expiry.
- **§4.4, the arguments an approver reads.** `CLEAR`. The 16384-**byte** canonical bound, the
  `object-hash(arguments) == args-hash` check, the ordering of the two refusals, and the "measure
  bytes, not characters" trap are all explicit. 11/11 first run.

## 07-streams.md

No primitive vectors (`trigger` is `kernel` role); read in full, one substantive finding.

- **§2 rule 6 contradicts §02 §2.** `WRONG`, internal. Rule 6 permits aggregating signals "with
  `kind: "signal-aggregate"`". That kind is not among §02 §2's nine; §02 requires an unknown
  `kind` to be rejected `envelope-unknown-kind`, and §04 §7.1 states the vocabulary "is closed at
  nine" and builds the whole rejection-record design on that closure. A validator built from §02 —
  mine does this — rejects an envelope §07 explicitly permits. No vector covers it, so both
  behaviours pass the corpus.
- **§4, triggers.** `CLEAR` as written; the three MUSTs and their codes are unambiguous. Not
  attempted (kernel role).
- **§1 and §3.** Normative and correct, but not mechanically testable: they constrain what an
  implementation must *not* infer from signal content. No vector could check them, and none does.
  Worth stating that this is a limit of the corpus, not of the text.

## 08-extension-manifest.md

Read in full. `manifest.json` is `role: "kernel"` (17 vectors) — **declined, per
`vectors/README.md` §1, which requires declining to be stated rather than silent.** I implement no
kernel, so manifest validation, registration conditions and the harness are out of scope for this
run.

- **§4.8, the driver protocol.** `CLEAR` and unusually complete for a wire protocol: transport,
  statelessness, the case table, and rule 3's requirement that the harness strip expected values
  before sending them (a component that received them could pass by echoing).
- **§4.4 vs §4.8 rule 7, naming.** Minor trap: §4.4 names the rejection
  `mandate-root-grantor-not-human`; §4.8 rule 7 names the *case* `mandate-root-not-human`. Rule 7
  does say it names cases rather than codes, so this is legal — but two near-identical identifiers
  differing by one word, in adjacent subsections, is a defect waiting to be typed.
- **§1.1, `manifest-malformed` as the catch-all** for anything §1 rejects without a more specific
  code is a good pattern the rest of the spec would benefit from (see the precedence gap below).

## 09-threat-model.md

Read in full. **Nothing to report as a sufficiency gap**, and that is the honest entry rather than
an absence of effort.

Its normative requirements are runtime or ingest-time — the `PT5M` future bound
(`envelope-emitted-in-future`), `key-file-permissions`, `gate-rate-limited`,
`emitter-must-persist-before-apply`, TLS — and `vectors/README.md` §7 explicitly places all of
them outside the corpus as not reproducible in a static file. `stream-status.json` (§4.2's
predicate) is `kernel` role and declined. Nothing here was implementable, and nothing in it
contradicted what I built. §3's statement that the audit is trustworthy about authority but is
*not* a completeness proof against a compromised emitter is the kind of thing most threat models
omit.

## 10-gateway-protocol.md

Read in full. No primitive vectors. Two findings.

- **The structured refusal object has no defined member set.** `SILENT`, and it is the gateway's
  wire format. §06 §4.1 shows nine members (including `decided-by`, `decided-at`, `envelope-id`);
  §10 §6 shows a different set that adds `classification-tier` and `hint` and drops
  `decided-by`/`decided-at`. Neither says which members are REQUIRED, whether the set is closed,
  or that the two are the same object — though §10 §6 asserts they are ("the §06 §4.1 refusal
  object"). Two implementations cannot produce interoperable refusals from this, and §05 §7.1
  rule 5 makes the refusal object load-bearing for the wedged state.
- **`gate-parked` is undefined.** §10 §6 says `reason-code` "is a normative code from this
  specification (§00 §1)" and then uses `gate-parked` in its own example. The identifier appears
  exactly once in the entire spec set — in that example — and in no error-code table and no vector.
- **§2 step 2, pinning `target` to `mcp:<server>`.** `CLEAR` and well-argued: it names why a finer
  target cannot be honestly derived, and says the extraction rule is deferred rather than
  forgotten. This is how a known gap should be written up.

---

# Verdict

**Yes, but for four things** — and one of them is fatal on its own.

A competent engineer can build an interoperable component from `spec/` alone for §01, §03, §04 and
most of §02 and §05. Those sections are better than most published protocol specs: §01 §3.4 gives
the number-serialization procedure instead of a reference, §03 §5 gives executable pseudocode, and
§05 §3.1 gives a scoring table with an explicit tie-break. My §01 implementation passed 65/65 and
§04 passed 15/15 with no corrections at all, which is the strongest evidence I can offer that those
parts are sufficient.

They could not build a conformant one, because:

1. `policy-stale-offline` is required on the wire and is defined nowhere. Not inferable, not
   guessable, not a judgement call — a missing string.
2. §06 §2 declares its eleven steps complete and they are not. A verifier built exactly to the
   algorithm accepts an approval whose `not-after` is `"z"` and never expires.
3. A non-boolean `single-use` requires a behaviour that neither available reading of the text
   produces, and the corpus's own note records both reference implementations getting it wrong in
   opposite directions.
4. There is no error-code precedence rule anywhere, and with ~90 normative codes that is not a
   detail: §02 §2.1 and §02 §9.1 give different codes for the same input, and the specification
   never says which wins.

A useful way to read this: **every area where the specification records its own past failure is
excellent** (§02 §2.1, §05 §3.1, §04 §7.2, §10 §2). The gaps are all in places nobody has yet been
bitten — which is precisely what a blind reader is for.

# The three worst gaps

### 1. `policy-stale-offline` — a required wire value that appears in no document

`sync-outcome.json` requires it verbatim; grep across all eleven spec files and
`vectors/README.md` returns zero hits. Any implementation built from the text fails 4 of 16
vectors on this one string, and — worse — two deployments would emit different reason codes for
the same refusal, which §05 §7.1 rule 5 makes visible to the calling agent.

**Add to §05 §7.1**, as a table beside the existing three-outcome table:

| Outcome | Class disposition | `reason-code` carried |
|---|---|---|
| `unreachable` | `offline[class]` is `allow` | — (serve) |
| `unreachable` | `offline[class]` is `block` | `policy-stale-offline` |
| `refused` | any | the kernel's reason code, verbatim |

### 2. §06 §2 claims completeness it does not have

Three behaviours the corpus requires cannot be produced by any of the eleven steps.

**Add a step (0) to the algorithm**, before step (1):

> (0) Validate `A.request` against §1.1's closed member set and `A.decision` against §1.2's,
> rejecting `schema-missing-member` / `schema-unknown-member`; and validate
> `request.requested-at`, `request.not-after`, `decision.decided-at` and `decision.not-after`
> as §01 §2.3 timestamps, rejecting `encoding-bad-timestamp`. Steps (8) and (9) compare
> timestamps as strings and are sound only over values of that form.

**And add to §1.2**, beside the `single-use` bullet:

> A `single-use` that is not a JSON boolean MUST be treated as `true`. It is not a rejection:
> the malformed value is a defect in the approver's tooling, and the safe reading of a defect
> here is the restrictive one. A verifier MUST report `single-use: true` to its caller so the
> `request-hash` is recorded in the seen-set.

And correct §3's cross-reference from "step (9)" to "step (11)".

### 3. No error-code precedence rule exists

The specification defines roughly ninety normative codes and never says which one an object
carrying two defects gets. §02 §2.1 (`schema-unknown-member` for any member outside the kind's
row) and §02 §9.1 (`cognition-envelope-has-effect-fields` for five specific such members) are the
concrete collision — it cost me four vectors — but the problem is general, and two implementations
that disagree here disagree on the wire, since §00 §1 makes codes part of the contract.

**Add to §00 §1:**

> Where more than one condition of this specification applies to one object, the **most specific**
> code wins: a code naming a particular member on a particular kind takes precedence over a code
> naming a class of members, which takes precedence over a generic structural code. Where two
> codes are equally specific, the earlier section's applies. An implementation MUST NOT report a
> generic code for a condition this specification names specifically.

Then state the §2.1/§9.1 case explicitly in §02 §2.1, since it is the one that has already bitten.

**Runner-up, cheap to fix:** monetary comparison has three incompatible spellings of its outcome
(§03 §4.3 `schema-type-mismatch`; `vectors/README.md` §3 `-1|0|1`; `money-compare.json`
`less|equal|greater|refused`). A harness written from either document fails all 31 vectors.

# Conformance table

All 18 files with `role: "primitive"`. Attempted = every vector in the file; nothing skipped.

| File | Kind | Attempted | Passed | Failed |
|---|---|---:|---:|---:|
| jcs-canonicalization.json | jcs | 22 | 22 | 0 |
| jcs-invalid.json | jcs-invalid | 13 | 13 | 0 |
| sha256.json | sha256 | 8 | 8 | 0 |
| ed25519.json | ed25519 | 8 | 8 | 0 |
| slip10-ed25519.json | slip10-ed25519 | 11 | 11 | 0 |
| object-hash.json | object-hash | 3 | 3 | 0 |
| envelope.json | envelope | 6 | 6 | 0 |
| envelope-shape.json | envelope-shape | 76 | 76 | 0 |
| chain.json | chain | 8 | 8 | 0 |
| mandate-chain.json | mandate-chain | 26 | 26 | 0 |
| authorization.json | authorization | 19 | 19 | 0 |
| payload-binding.json | payload-binding | 7 | 7 | 0 |
| money-compare.json | money-compare | 31 | 31 | 0 |
| parity.json | parity | 16 | 16 | 0 |
| policy-evaluation.json | policy-evaluation | 14 | 14 | 0 |
| gate-arguments.json | gate-arguments | 11 | 11 | 0 |
| gate-resubmission.json | gate-resubmission | 12 | 12 | 0 |
| sync-outcome.json | sync-outcome | 16 | 16 | 0 |
| **Total** | | **307** | **307** | **0** |

**Declined** (`role: "kernel"`, per `vectors/README.md` §1, which requires declining to be stated):
`checkpoint.json` (6), `trigger.json` (6), `manifest.json` (17), `gate-admission.json` (11),
`root-change.json` (7), `stream-status.json` (9), `stream-recovery.json` (7) — 63 vectors. I
implement no kernel. These are declined, not skipped, and not counted above.

Reproduce: `./.venv/bin/python impl/harness.py` (venv with `pynacl`). The harness reads
`index.json`, dispatches on `kind`, and raises `KeyError` on an unrecognised kind rather than
skipping it, as README §1 requires — verified by running it before the last two handlers existed.

# Did I read anything outside the sandbox?

**No.** Every file I opened is under
`…/scratchpad/blind-2/`: the eleven `spec/*.md`, `spec/vectors/*.json`, `spec/vectors/README.md`,
and files I wrote myself in `impl/`. I did not open, list, grep or search
`/Users/katsarov/projects/stozher`. `generate_vectors.py` is referenced by `README.md` §1 and §6
but is not present in the directory; I did not look for it elsewhere.
