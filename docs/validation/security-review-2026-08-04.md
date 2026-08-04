# Stozher — external cryptographic and security review

**Reviewer:** independent external reviewer (engaged as an adversarial third party; no prior
involvement with this codebase).
**Date of engagement:** 2026-08-04.
**Subject:** Stozher, git worktree of `main` @ `96b9811` ("spec: pay B2, B3 and B4 — the rest of what
a blind reader found"). Kernel (Rust) and gateway (Python) as committed; no deployed instance was
touched.
**Method:** source review guided by `SECURITY.md` §"Where a reviewer should look first", followed by
differential and adversarial testing. **Every finding below was reproduced against this code.**
Reproductions are listed with each finding and the probe sources are in `./repro/`.

---

## 0. Verdict

> Over the scope stated in §1, this review found **three reproducible defects that break stated
> security properties of the product**, one of them critical: the root-approval floor that
> `spec/03 §6`, `spec/05 §5.2`, `spec/08 §3.1` and `spec/04 §7.2` place over the kernel's own
> privileged actions can be bypassed entirely, with no approval signature of any kind, by an
> envelope that reports its `execution.outcome` as anything other than `applied` or `failed` — the
> kernel writes the privileged state change regardless of the outcome it just read. The previous
> attestation of "no findings" is not consistent with this scope; a review that covered
> `kernel/stozher-kernel/src/ingest.rs` and `kernel/stozher-kernel/src/store.rs` together would have
> had to find it, so whatever that attestation covered, it was not this.

The three defects are independent of one another and each has a small, local fix. The parts of the
system this review attacked and could **not** break are listed in §4, and they are substantial: the
chain, the replay set, the mandate walk, the signature primitives and the kernel's own timestamp
parser all held under everything thrown at them.

---

## 1. Scope

### 1.1 What was reviewed

Reviewed by reading in full, and attacked:

| Area | Files |
|---|---|
| Timestamp parsing and calendar arithmetic | `kernel/stozher-kernel/src/clock.rs` (all 771 lines), `kernel/stozher-core/src/envelope.rs` `is_timestamp`/`days_in_month`/`is_leap_year` |
| JCS canonicalization, both implementations | `kernel/stozher-core/src/jcs.rs`, `gateway/src/stozher_gateway/canonical.py` |
| Signed-object pattern, key ids, crypto primitives | `kernel/stozher-core/src/signed.rs`, `kernel/stozher-core/src/crypto.rs` (primitives + hex decoding) |
| Gate authorization (the eleven steps) | `kernel/stozher-core/src/gate.rs`, `gateway/src/stozher_gateway/gate.py` |
| Mandate chain walk, grant validation, revocation | `kernel/stozher-core/src/mandate.rs` (all 948 lines) |
| Ingest pipeline and validation order | `kernel/stozher-kernel/src/ingest.rs` (all 2002 lines) |
| Envelope schema validation | `kernel/stozher-core/src/envelope.rs` (all 786 lines) |
| Payload binding | `kernel/stozher-core/src/payload.rs` |
| Append path, projections, append-only triggers | `kernel/stozher-kernel/src/store.rs` `append`/`write_projections` and `src/sql/append_only.sqlite.sql` (all triggers) |
| Offline policy bundle | `gateway/src/stozher_gateway/bundle.py` (all 191 lines) |
| Proxy chokepoint ordering | `gateway/src/stozher_gateway/enforce.py` (control-flow map; the `call` path and its refusal branches read in detail, not the full 1397 lines) |

Tests actually run:

* `cargo test --manifest-path kernel/Cargo.toml` — **green, exit 0**, before any probe was added.
* Five purpose-built probe suites (see `./repro/`), each of which **failed against this code**.
* A 3,087-document differential between the two JCS implementations.
* A 3,573-candidate differential between the three timestamp validators.

Mechanical claims from `SECURITY.md` that were re-verified rather than trusted: `Store::append` is
`pub(crate)` with exactly one caller (§4.3); the conformance harness is not referenced from the
service (§4.4).

### 1.2 What was NOT reviewed — read this before weighing "no findings" anywhere below

This review makes **no statement at all** about the following. They were not read, not tested, and
are not covered by the verdict in §0.

* **`kernel/stozher-kernel/src/console.rs` (2,145 lines) and `src/http.rs` (1,245 lines).** The web
  console and the HTTP surface — route authorization, the caller-token scheme, session handling,
  CSRF, XSS, template escaping, and the console's own decision route — were **not** reviewed. This
  is the largest single gap in this engagement and, for a product whose approvals are given through
  a browser, plausibly the highest-value remaining target.
* **`deploy/` — the key ceremony and file modes.** Item 6 on the project's own map. Not opened.
* `notify.rs`, `migrate.rs`, `conformance.rs`, `driver.rs`, `harness.rs`, `genesis.rs`, `policy.rs`,
  `config.rs`, `manifest.rs`, `gatequeue.rs`, `budget.rs`, `checkpoint.rs`, `operator.rs`,
  `console`-adjacent code — read only where a trace from ingest led into them.
* **Gateway beyond the modules named in §1.1**: `proxy.py`, `store.py`, `runtime.py`, `config.py`,
  `classify.py`, `budget.py`, `money.py`, `revocation.py`, `conformance.py`, `emitter.py`,
  `governed.py`, `plugin.py`, `kernel_client.py`.
* **The Python test suite was not run.** There is no `.venv` in this worktree and one was not built;
  `pytest gateway/tests` was **not** executed. Every Python claim below comes from direct
  interpreter probes of the module under test, not from the project's suite.
* **No dependency audit.** `cargo audit` and `pip-audit` were not run. The RUSTSEC-2026-0009
  rationale in `clock.rs` was read but the current dependency set was not checked for advisories.
* **No deployed instance was touched**, per the engagement's instruction. No TLS, no container, no
  network posture, no operational key handling, no `docker compose` project.
* **The 306-vector corpus was not audited for completeness**, except for the one question in
  Finding 2 (float coverage), where it was found wanting.
* **No side-channel or timing analysis.** No fuzzing of the HTTP parsers. No review of `ed25519-dalek`
  or `ryu-js` internals — only their call sites.
* **No review of the specification itself** as a document. Findings are stated against the code's own
  claims and the spec clauses the code cites.

---

## 2. Findings

| # | Severity | Title | Location |
|---|---|---|---|
| 1 | **Critical** | Root-approval floor bypassed by an envelope reporting a non-applied outcome | `kernel/stozher-kernel/src/ingest.rs:735-737, 819-833`; `kernel/stozher-kernel/src/store.rs:2283-2389` |
| 2 | **High** | JCS number parsing is not correctly rounded: `object-hash` collisions, and the two implementations disagree on 5.3% of a random corpus | `kernel/Cargo.toml:14`; `kernel/stozher-core/src/jcs.rs:197-210` |
| 3 | **Medium** | Gateway accepts confusable non-ASCII-digit timestamps the kernel refuses; six of them never expire | `gateway/src/stozher_gateway/envelope.py:28, 368-381` |
| 4 | **Low** | JSON nesting-depth acceptance divergence between the two implementations | `kernel/stozher-core/src/jcs.rs:30-47` vs `gateway/src/stozher_gateway/canonical.py:100-122` |
| 5 | **Informational** | Doc comment on the highest-risk parser contradicts the code it documents | `kernel/stozher-kernel/src/clock.rs:334-336` |
| 6 | **Informational** | Python canonicalizer coerces non-string member names, which can emit a duplicate member | `gateway/src/stozher_gateway/canonical.py:209-214` |

No findings at **critical** severity other than Finding 1. Over the scope in §1.1 the review found
nothing in the mandate chain walk, the append-only triggers, the chain position logic, the replay
set, or the signature primitives — see §4.

---

### Finding 1 — Critical — The root-approval floor is bypassed by reporting a non-applied outcome

**Location.**
`kernel/stozher-kernel/src/ingest.rs:735-737`:

```rust
let outcome = env["execution"]["outcome"].as_str().unwrap_or("applied");
let applied = matches!(outcome, "applied" | "failed") || kind == "aggregate";
```

`kernel/stozher-kernel/src/ingest.rs:819-833`:

```rust
let root_approved = ROOT_APPROVED_ACTIONS.contains(&action) || kind == "policy-change";
let requires_gate = match &decision {
    Decision::Gate { .. } => applied,
    Decision::Allow => root_approved && applied,
    Decision::Deny => { /* … */ root_approved && applied }
};
```

`kernel/stozher-kernel/src/store.rs:2283`, `2296`, `2341` — `write_projections` applies
`enroll_root`, `retire_root` and `stream_resume` with **no reference whatever to
`plan.envelope["execution"]["outcome"]`**.

**The defect.** `requires_gate` is gated on `applied`. `applied` is computed from a field the
*emitter* writes. But the projections — the actual privileged state changes — are computed in
`validate_effect_kind` (`ingest.rs:798-812`) and written unconditionally. So the kernel reads
"this action did not apply", waives the approval on that basis, and then applies it.

The comment at `ingest.rs:821-823` states the intent correctly for ordinary effects: *"A gated action
that was never applied — parked, denied, timed out — legitimately has no approval to carry."* That is
sound when the effect is something a component did in the outside world. It is unsound for
`ROOT_APPROVED_ACTIONS`, because for those the effect **is** the row the kernel writes, and the
kernel writes it whatever the envelope claims happened.

**The exact attack.** Emit an ordinary `kind: "effect"` envelope, correctly signed and chained, with:

* `execution.action` set to one of `kernel.resume_stream`, `kernel.enroll_root`,
  `kernel.retire_root`, `kernel.register_component`;
* `execution.outcome` set to `"denied"`, `"blocked"` or `"attempted"` (all three are in
  `envelope::OUTCOMES`, so the schema accepts them);
* **no `authorization` member at all.**

`requires_gate` evaluates false, `gate::verify_authorization` returns `Ok(None)` because there is
nothing to verify, and `write_projections` performs the privileged change.

**Preconditions and what the attacker gains — three reproduced cases:**

1. **`kernel.resume_stream` — no root key needed.** `validate_effect_kind` has no signer check for
   this action; the only requirement is a mandate whose scope covers it. In the reproduction the
   envelope is signed by `agent:gateway/dev`, an ordinary agent. Result:

   ```
   PROBE resume outcome: Accepted(Appended { id: "c46c2a44…", stream: "kernel:core", seq: 5 })
   PROBE stream_resumes row: Some("1304f34cb3f3d68b05d5e1862095ded2a3ad8232274ab272e60c908d90f0892e")
   PROBE continuation: Accepted(Appended { id: "d47a8548…", stream: "gw:dev:0001", seq: 2 })
   ```

   The wedged emitter's envelope, refused `chain-seq-gap` moments earlier, is now appended. The
   attacker gains the one act `store.rs:1941-1951` calls *"not reachable without a human root's
   signature"* and `spec/05 §5.6` places beside publishing policy: the ability to change what
   `Store::append` will accept at a chain position, self-service. `def2_mandate_swap.rs`
   (`def2_a_wedged_stream_is_resumed_only_by_a_root_signed_operator_act`) asserts exactly this is
   impossible; it passes only because its negative fixture sets `outcome: "applied"`.

2. **`kernel.enroll_root`.** Precondition: one enrolled root key plus a mandate to it (which
   `spec/03 §6` anticipates — it is why root changes are supposed to need *two* humans). Result: the
   root set gained `human:third` with no approval signature:

   ```
   PROBE enroll outcome: Accepted(Appended { id: "7355d899…", stream: "kernel:core", seq: 6 })
   PROBE root set now: [ … "human:mira", … "human:ivan", (…f95c6a5d…, "human:third")]
   ```

3. **`kernel.retire_root`.** Same precondition. Result: the root set was reduced to the attacker
   alone:

   ```
   PROBE retire outcome: Accepted(Appended { id: "0febbd34…", stream: "kernel:core", seq: 6 })
   PROBE root set now: [(…d04ab232…, "human:ivan")]
   ```

   Combined with case 2, **a single compromised root key takes sole and permanent control of the
   deployment's trust anchor in two envelopes**, with no second human's signature at any point.
   `spec/03 §6`'s two-human requirement is the property this defeats.

`kernel.publish_policy` is **not** reachable this way: policy publication travels as
`kind: "policy-change"`, for which `envelope.rs:134-145` makes `authorization` a *required* member,
so an authorization is always present and always fully verified. `kernel.register_component` is
reachable by the same bypass but is additionally gated on a genuinely approved
`kernel.conformance_run` (`store.rs:998` requires `outcome = 'applied'`), which narrows it.

**Why the tests did not catch it.** Every negative fixture for these actions sets
`outcome: "applied"`, which is the one value that makes the gate fire. The property is tested; the
axis along which it fails is not varied.

**Smallest fix.** In `store.rs::write_projections`, refuse to write a privileged projection carried
by an envelope that reports it did not happen — or, equivalently and more cheaply, in
`ingest.rs::validate_effect_kind` compute

```rust
let requires_gate = match &decision {
    Decision::Gate { .. } => applied || root_approved,
    Decision::Allow => root_approved,
    Decision::Deny => { /* … */ root_approved }
};
```

so that a root-approved action needs its approval regardless of the outcome it reports. Either fix
is a few lines. The second is preferable because it keeps the decision in the one function that
already owns "what does this envelope need in order to be accepted", and because a
`kernel.enroll_root` that genuinely did not apply has nothing to record anyway. Add the outcome axis
to the negative fixtures in `def2_mandate_swap.rs` and `root_enrollment.rs`.

**Reproduction:** `repro/zz_review_probe.rs`, tests `probe_unapproved_resume_reporting_denied`,
`probe_unapproved_enroll_root_reporting_denied`, `probe_unapproved_retire_root_reporting_blocked`.
Place in `kernel/stozher-kernel/tests/` and run
`cargo test --manifest-path kernel/Cargo.toml --test zz_review_probe -- --nocapture`.

---

### Finding 2 — High — JCS number parsing is not correctly rounded

**Location.** `kernel/Cargo.toml:14` declares `serde_json = "1"` with no features. `serde_json`'s
default float parser is fast and **not correctly rounded**; correct rounding requires the
`float_roundtrip` feature. `kernel/stozher-core/src/jcs.rs:197-210` then formats whatever `f64`
`serde_json` produced.

**The defect.** `spec/01 §3.4`, as the module's own doc comment restates it
(`jcs.rs:194-196`), requires that *"Every JSON number is canonicalized as the binary64 value obtained
by parsing it."* The kernel obtains the wrong binary64 value — off by one ULP — for a large class of
literals. Verified directly:

```
1049841890.8179493: serde=0x41cf49a87168b28f  std=0x41cf49a87168b290  canonical={"n":1049841890.8179492}
```

`std=` is Rust's own correctly-rounded `str::parse::<f64>()` on the identical literal. The two differ.

**Three consequences, each reproduced.**

1. **`object-hash` collision.** Two documents denoting different binary64 values share one hash in
   the kernel:

   ```
   {"n":1049841890.8179492} → b9f3a2f75f854854f38d015e274e66c28895a0b23b6d1ad97c1008d148d70788
   {"n":1049841890.8179493} → b9f3a2f75f854854f38d015e274e66c28895a0b23b6d1ad97c1008d148d70788
   ```

   The Python gateway hashes the same two documents to `b9f3a2f7…` and `71dfd2b4…` — distinct, as
   they must be. `object-hash` is the substrate of `args-hash`, `payload-hash`, `request-hash`,
   `mandate-ref`, `prev-hash` and `id()`; a collision in it is a collision in every commitment the
   protocol makes.

2. **The two implementations disagree on 163 of 3,087 documents (5.3%)** — both accept, both return
   "success", and the canonical bytes differ. This is precisely the condition `SECURITY.md` ranks
   third on its own risk map: *"A canonicalization disagreement between implementations is a
   signature-validity disagreement."* Examples:

   | input | kernel | gateway |
   |---|---|---|
   | `123456789012345678901` | `123456789012345670000` | `123456789012345680000` |
   | `2.2250738585072011e-308` | `2.2250738585072014e-308` | `2.225073858507201e-308` |
   | `-1596336818.4097385` | `-1596336818.4097383` | `-1596336818.4097385` |

   The second row crosses the subnormal/normal boundary (`0x000fffffffffffff` vs
   `0x0010000000000000`).

3. **Reachable in the protocol, end to end.** `envelope::validate` step (8) (`check_numbers`) keeps
   non-integer numbers out of *envelope* bodies, but **payload bodies are not covered**:
   `payload::verify_ingest` (`payload.rs:103`) computes `jcs::object_hash(body)` over arbitrary JSON
   with no numeric restriction. Because the kernel's parse is not the inverse of its own
   serialization, a document that survives one wire round-trip denotes a different number. In the
   reproduction, an envelope commits to `payload-hash = c8f55c03…` — the hash the **gateway**
   computes for `{"amount":1049841890.8179492}` — and a payload body of
   `{"amount":1049841890.8179493}` is submitted, which the gateway hashes to `463ba65b…`. The kernel
   **accepted it**:

   ```
   PROBE substituted-payload outcome: Accepted(Appended { id: "651a6805…", stream: "gw:dev:0001", seq: 0 })
   ```

   A payload was admitted under the hash of a different payload. The direct consequence in normal
   operation is the mirror image and is an availability defect: a legitimate gateway-emitted envelope
   whose evidence payload carries any 17-significant-digit number will be refused
   `payload-hash-mismatch`, because signer and verifier compute different hashes for the same bytes.

**Why the corpus did not catch it.** `spec/vectors/jcs-canonicalization.json` contains six
long-precision numeric literals in total (`1.7976931348623157e308` and near neighbours,
`2.220446049250313e-16`, `100000000000000000000`). All six are values `serde_json`'s fast path
happens to get right. The corpus does not exercise the general 17-digit case.

**Preconditions and what the attacker gains.** No special position: any party that can supply a JSON
payload. The realistic gain today is the collision — two payload documents satisfying one committed
`args-hash`, on a path (`kernel.publish_policy`, `kernel.enroll_root`, `kernel.resume_stream`) where
the committed hash is what a human approved. **I did not demonstrate a full signature forgery**, and
should be explicit about why: every currently signed object is schema-restricted to integers and
strings, so the divergence is fail-closed for signatures as the schema stands today. The finding is
rated High on the strength of the demonstrated hash collision, the demonstrated cross-implementation
divergence, and the fact that the defect is silent — the kernel returns a well-formed wrong hash
rather than an error.

**Smallest fix.** One line in `kernel/Cargo.toml`:

```toml
serde_json = { version = "1", features = ["float_roundtrip"] }
```

Then re-run the differential in `repro/` and add 17-significant-digit floats and the subnormal
boundary to `spec/vectors/jcs-canonicalization.json`. Consider also extending `check_numbers` to
payload bodies, so the protocol's "integers only" rule is enforced where the hashes are actually
computed and not only on the envelope.

**Reproduction:** `repro/zz_review_float.rs`, `repro/zz_review_collision.rs` (unit-level, in
`kernel/stozher-core/tests/`); `repro/zz_review_probe.rs::probe_float_payload_collision_end_to_end`
(end to end); `repro/zz_review_jcs_dump.rs` + `gen_jcs.py` / `py_jcs.py` / `diff_jcs.py` (the 3,087
document differential).

---

### Finding 3 — Medium — The gateway accepts confusable timestamps the kernel refuses, and six of them never expire

**Location.** `gateway/src/stozher_gateway/envelope.py:28`:

```python
_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")
```

and `envelope.py:368-381`, whose docstring promises *"§01 §2.3's fixed 24-byte form"*.

**The defect.** Python's `\d` matches any Unicode decimal digit, and `datetime.strptime` and `int()`
accept them too. The function counts characters, never bytes, so it is not checking a 24-byte form
at all. **750 distinct non-ASCII code points** pass as a digit in the year position. The kernel's
`envelope::is_timestamp` and `clock::parse_timestamp` both start with `if b.len() != 24` over
*bytes* and use `is_ascii_digit`, so they refuse every one of them.

Over a 3,573-candidate adversarial corpus: **51 candidates the gateway accepts and the kernel
refuses, and 0 in the other direction.** The gateway is strictly the more permissive validator.

**Why that direction matters.** `enforce.py:10` states the pipeline order:

```
resolve → normalize → classify → prohibited? → mandate → gate → forward → emit
```

`forward` — the actual downstream call — happens **before** `emit`, so the gateway is the component
that decides whether the effect occurs and the kernel is the component that records it. A divergence
in which the gateway is more permissive therefore produces a real-world effect whose envelope the
kernel then refuses: the action happens, the audit record does not.

**The exact attack.** Both implementations' gate steps (8) and (9) compare timestamps as strings —
correct for a fixed-width ASCII form, and the code says so at `gate.py:161-165` and `gate.rs:201-205`,
warning that a value that is *not* one of these makes step (9) vacuous. Six of the 51 accepted
candidates sort **above every representable real timestamp**:

```
'２026-07-26T09:15:01.300Z'   (U+FF12 FULLWIDTH DIGIT TWO)
'٢026-07-26T09:15:01.300Z'   (U+0662 ARABIC-INDIC DIGIT TWO)
'๒026-07-26T09:15:01.300Z'   (U+0E52 THAI DIGIT TWO)
'𝟚026-07-26T09:15:01.300Z'   (U+1D7DA MATHEMATICAL DOUBLE-STRUCK TWO)
'٢026-07-26T09:13:01.300Z'
'２026-07-28T09:15:01.300Z'
```

Verified: `'２026-07-26T09:15:01.300Z' > '9999-12-31T23:59:59.999Z'` is `True`, and
`is_timestamp('２026-07-26T09:15:01.300Z')` is `True`.

The requester-controlled path needs no collusion: the agent writes its own
`authorization.request.not-after`. With a fullwidth digit there, step (8)
(`if decided_at > request_not_after`) can never fire — **the agent's action request never times
out**, and it can be approved and used arbitrarily far in the future. The same substitution in
`decision.not-after` makes step (9) vacuous — an approval that never expires — though that half
requires an approver signature over the malformed decision.

The homoglyph is the point. `２026-07-26T09:15:01.300Z` is visually indistinguishable from the real
thing in most fonts. `ADR-0011` and `ADR-0029` make the case that the approver must be able to read
what they are approving; this defeats that for the one field that bounds how long the approval lives.

**What the attacker gains.** A gate approval or action request with no effective expiry, in the
component that decides whether the call is forwarded, presented to the human approver as an ordinary
near-term expiry. Bounded by: the kernel refuses the resulting envelope, so the wedge logic in
`enforce.py` will eventually notice — but the first effects have already been forwarded, and the
grace-window path (`enforce.py:539-556`) keeps serving during it.

**Smallest fix.** Two lines. Anchor the regex to ASCII and check the byte length:

```python
_TIMESTAMP = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z", re.ASCII)
```

plus `if len(value.encode()) != 24: return False`. Add the six strings above to
`spec/vectors/` so the property is a corpus obligation and not one implementation's habit.

**Reproduction:** `repro/zz_review_ts.rs` + `ts_gen.py` / `ts_cmp.py`.

---

### Finding 4 — Low — Nesting-depth acceptance divergence

`jcs::parse` inherits `serde_json`'s recursion limit of 128 and reports `jcs-malformed-json` past it.
`canonical.parse` inherits CPython's recursion limit, roughly an order of magnitude higher.
Documents nested 130, 200 and 400 deep were accepted by the gateway and refused by the kernel in the
differential (3 of 3,087). Same direction as Finding 3 — the gateway is the permissive one — but
without an expiry-comparison consequence, so the impact is a legitimate emitter's envelope being
refused rather than an unauthorized effect. Fix: state a depth limit normatively in `spec/01` and
enforce the same number on both sides.

### Finding 5 — Informational — Doc comment contradicts the code, on the file the project names its highest-value target

`kernel/stozher-kernel/src/clock.rs:334-336` still reads:

> *A leap second (`:60`) is accepted — the specification's own validator allows it — and is treated
> as the first instant of the following minute, so ordering and arithmetic stay monotone.*

The code at line 383 refuses it (`second > 59`), and the test at line 631
(`a_leap_second_is_refused_rather_than_folded_into_the_next_minute`) asserts the refusal and its own
comment explains at length why the doc comment's reasoning was wrong. ADR-0020 records the fix; the
`# Errors` prose above the function was not updated with it. On the one file `SECURITY.md` calls
*"the single highest-value target in the codebase"*, a doc comment that describes the pre-fix
behaviour is a live hazard for the next reader — including the next reviewer. Delete the paragraph.

### Finding 6 — Informational — Python canonicalizer coerces non-string member names

`gateway/src/stozher_gateway/canonical.py:209-214` sorts and emits member names through `str(k)` /
`str(name)`. Text input can never produce a non-string key, so this is unreachable from `parse`; but
the in-memory entry point is public, and an in-memory dict such as `{1: "a", "1": "b"}` canonicalizes
to `{"1":"a","1":"b"}` — a document with a duplicate member, which the same module's `parse` would
reject as `jcs-duplicate-key`. The Rust side cannot express this (its `Map` is `String`-keyed). Raise
`jcs-malformed-json` on a non-string key instead of coercing.

---

## 3. What I would fix first

1. **Finding 1**, immediately and before anything else. It is the only one that hands an attacker the
   deployment's trust anchor, it needs no cryptographic sophistication, and the fix is a few lines in
   `ingest.rs`. Until it is fixed, the statement *"policy cannot lower the bar on the mechanism that
   enforces policy"* is not true of this build. Any deployment that has been running should have its
   root set and its `stream_resumes` table enumerated and confirmed out of band, exactly as
   `SECURITY.md` already advises for the separate `config.json` issue.
2. **Finding 2.** One line in `Cargo.toml`, then extend the vector corpus so the property is
   defended rather than accidentally held. This is the finding that most directly falsifies the
   project's own #3 risk-map entry.
3. **Finding 3.** Two lines in `envelope.py`. Cheap, and it closes the only place found where the
   component that decides whether an effect happens is more permissive than the component that
   records it.

---

## 4. What held

These are results, not omissions. Each was attacked and did not break, over the scope in §1.1.

* **The kernel's timestamp parser and calendar.** Over 3,573 adversarial candidates — structural
  mutations at every one of the 24 positions, insertions, Unicode confusables, leap seconds, year
  zero, February 30, hour 24, minute 60, embedded NUL and newline, and 4,000 random byte-level
  mutations — `envelope::is_timestamp` and `clock::parse_timestamp` **agreed on every single
  candidate (0 divergences)**. ADR-0020's unification of the two calendars holds under attack. Every
  timestamp `parse_timestamp` accepted **round-tripped exactly** through `format_millis` (0
  exceptions): one instant, one spelling, as the design requires. This is the file the project called
  its highest-value target, and on the rejection side — the side its own `SECURITY.md` says
  exhaustive round-tripping proves nothing about — it held.
* **The single append path.** `Store::append` is `pub(crate)` (`store.rs:1883`) and has exactly one
  caller in the entire crate, `ingest.rs:281`. Verified mechanically, as `SECURITY.md` §4 asks.
* **The gate replay set / single-use.** The pre-check at `ingest.rs:859-864` races, but it does not
  have to be correct: the authority is a `PRIMARY KEY` insert inside the same `BEGIN IMMEDIATE`
  transaction as the append (`store.rs:2031-2065`), with an explicit re-read of the stored
  `single_use` flag and a rollback on conflict. Two concurrent submissions of one approval cannot
  both succeed regardless of how their pre-checks interleave. This is the right construction.
* **Signature primitives.** `verify_strict` (`crypto.rs:49-63`) uses `VerifyingKey::from_bytes`,
  rejects weak/small-order keys explicitly via `is_weak()`, and calls `verify_strict` rather than
  `verify` — so malleable and non-canonical signatures are refused. `decode_hex` and `is_digest_hex`
  reject uppercase and non-hex strictly. `signing_input` removes only `sig`
  (`signed.rs:76-92`), and `object_id` covers `sig` — the two are correctly distinct.
* **Ingest ordering.** Parse strictly → verify signature over the received bytes → validate schema →
  mandate → authorization → append is implemented in that order (`ingest.rs:341-419`), with
  idempotency-by-`id()` placed before the replay check so a retry is not read as a reuse.
* **The mandate chain walk.** Termination at an enrolled human root is structural — the only `Ok`
  return is in the `interactive`/`standing` arm, which requires `parent` null, `grantor.role ==
  "human"` and membership in the enrolled root set. Cycles cannot reach acceptance; the hop budget
  bounds the walk. Scope narrowing (`covers_pattern`) is conservative in the right direction: it
  refuses to treat an exact parent pattern as covering a child wildcard. Segment matching requires a
  real segment after the dot (`value.len() > prefix.len() + 1`). Budget comparison is exact —
  decimal strings via `decimal::at_most`, integers via `as_i64` with a type refusal rather than an
  `f64` coercion. Revocation propagates to descendants and takes the earliest authorized instant.
  I found no way through it.
* **Append-only enforcement.** Seven tables carry `BEFORE UPDATE` and `BEFORE DELETE` triggers:
  `envelopes`, `rejections`, `checkpoints`, `policies`, `manifests`, `gate_requests`,
  `gate_decisions`, `gate_notifications`, `gate_request_hashes`. The one exemption the stream-resume
  needs is not a trigger exemption at all — it is a narrowly-scoped condition in `append`
  (`store.rs:1952-1969`) permitting exactly one envelope at `head + 2` whose `prev-hash` equals the
  `object-hash` the operator's document named, single-use because the head then moves. The
  construction is correct. **What is wrong is who can authorize it — see Finding 1.**
* **Self-approval over subjects.** In the kernel every `Approver` is constructed via
  `Approver::named` (`ingest.rs:1452-1459`, `1598-1642`), so `subject` is never `None` on the kernel
  path and `gate.rs`'s subject comparison is never silently skipped. The gate-decision path checks
  the same property independently (`ingest.rs:1417-1422`), resolving the approver's subject through
  both the root set and held mandates.
* **The offline policy bundle** (`bundle.py`). The signature is checked against the enrolled roots,
  the policy inside is independently re-verified against the organization's policy key so a root
  cannot mint a policy by wrapping one, `max-age` is inside the signed body so staleness is the
  root's declaration, an expired bundle refuses rather than warns, and **nothing is written to the
  store until every check has passed** — the two `cache_*` calls are the last statements in the
  function. Revocations in a bundle are refused as a set if any one fails to verify, unlike the live
  feed, and the reasoning for the asymmetry is stated and correct.
* **Envelope schema validation.** Closed member sets per kind, unknown members rejected, aggregate
  arithmetic accumulated in `i128` with a negative-count refusal and a cardinality bound, payload
  media types on an allowlist rather than a denylist with the reasoning stated.
* **The conformance harness** is referenced only from `main.rs:2924-2929` — not from `http.rs` and
  not from `console.rs`. Consistent with the claim that it is not reachable from the service.

---

## 5. Unverified concerns

Stated separately because they were **not** reproduced. Each is a lead, not a finding.

* **`bundle.py::_revocations` verifies each revocation's signature but not the revoker's
  authority.** `mandate.rs::revoker_is_authorized` requires the signer to be an enrolled root or the
  grantor of the target or an ancestor; the bundle path checks only that *some* valid Ed25519
  signature covers the object. The stated defence is that a root signed the set as a whole. That is
  probably sufficient, but it means a root who exports a bundle vouches for revocations they may not
  have examined. I did not trace what the gateway does with a cached revocation whose signer is
  unauthorized.
* **`gate.rs` step (10) compares members via `Value::as_str`, so two absent members compare equal**
  (`approved == performed == None`). For `effect` and `policy-change` every one of the nine bound
  members is schema-required, so I could not construct a case where this matters. It would matter for
  any future kind that made one of them optional.
* **`Approver.subject = None` is reachable on the gateway path** (`gate.py:52-57` documents it as
  intentional), where the subject half of the self-approval prohibition is then unevaluable. I did
  not determine whether any gateway configuration actually produces an approver with an unknown
  subject.
* **`AdvancedClock::now` saturates at `9999-12-31T23:59:59.999Z`** rather than erroring
  (`clock.rs:206`). Correct for the stated invariant, and unreachable for a bounded advance this side
  of the year 9989. Not attacked further.
* **`last_declared_instant`** (`clock.rs:309-318`) returns `None` if the most recent
  `clock-advance-in-force` rejection record's `detail` does not parse or lacks `effective`, which
  silently disables the ratchet. I did not find a way for an attacker to write such a record — the
  rejection stream is append-only and kernel-written — but the failure mode is open rather than
  closed, and a fail-closed reading would be safer.
* **`FixedClock::advance_seconds`** multiplies without checking (`clock.rs:70`), so it panics in
  debug on a large input. Test-only type; not reachable from the service.

---

## 6. On the attestation this report replaces

`SECURITY.md` currently records that an external review was performed and produced no findings, with
no reviewer, date, scope or report. This report is offered as the thing that can be weighed instead.
It found one critical and two substantive defects in roughly two thirds of the surface the project
itself ranks highest, and did not look at the console, the HTTP layer or the deployment scripts at
all. A reader should conclude that the remaining unreviewed surface — item 6 on the project's own
map especially — has not been cleared by anyone, and should not read §4's clean results as extending
one line past §1.2.

The project's own habit of naming its gaps rather than hiding them is, on the evidence of this
review, accurate and unusually well calibrated. Two of the three findings here sit exactly where
`SECURITY.md` said to look. The third sits in the one place it did not think to point at: the
boundary between the two implementations' *validators*, rather than their canonicalizers.
