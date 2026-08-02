# Test plan — the six changes

House rule this plan is written against (`testing-strategy`): **prove every new test fires** by
reverting the change and watching the right assertion fail. A test that has never failed is a
measurement wearing a test's name. Every case below names what it must fail on.

## A. First-call park states the catalog seed

| Case | Must fail when |
|---|---|
| A1 · a first-call park's hint names the classification consequence | the clause is removed |
| A2 · a **non**-first-call park's hint does **not** name it | the clause is emitted unconditionally — the paired negative, without which A1 passes on a constant string |
| A3 · the refusal still carries no route around the gate (§06 §4.1) | the clause is phrased as instructions to an approver rather than as a consequence |

A2 is the load-bearing one. A1 alone passes against a hint that always says it, which would be the
product lying about a genuinely consequential action.

## B. Export points at the retained arguments

| Case | Must fail when |
|---|---|
| B1 · the exported NDJSON body is **byte-identical** to the body before this change | anything is added to the record bytes |
| B2 · the response advertises the payload route | the header is dropped |
| B3 · following the advertised route for an exported envelope's `evidence.payload-hash` returns the arguments | the route or the hash linkage breaks |

B1 is the guard, not B2. The risk in this item is not failing to advertise; it is helpfully
corrupting a signed file.

## C. Human-readable export

| Case | Must fail when |
|---|---|
| C1 · no `format` → NDJSON, unchanged content-type and body | the default flips |
| C2 · `format=html` → a document whose rendered text contains the record count and the filters used | the filters are dropped, i.e. the document stops saying which question it answers |
| C3 · the document states it is a rendering and names the NDJSON as the record | the disclaimer is dropped |
| C4 · an unknown `format` is refused, not silently defaulted | it falls back — the same failure mode the existing unknown-filter guard exists to prevent |

C4 mirrors the export's own precedent: an unrecognised filter is refused because a silently ignored
one returns "a file that looks like the answer to the question you asked."

## D. Off-box anchor

| Case | Must fail when |
|---|---|
| D1 · the heads route returns the checkpoint head of every stream that has one | a stream is omitted |
| D2 · a deployment that has taken **no** anchor reports exactly that, and does not render a blank as reassurance | the console shows an empty/blank anchor state |
| D3 · an anchor taken, then a record appended, then the anchor re-taken → the heads move | the route serves a cached or genesis-only view (the compliance evaluator's real finding was heads covering only seq 0…1) |
| D4 · the exported anchor is verifiable against the store by an independent reader | it carries a claim with nothing to check it against |

D2 is the honesty case and the one most likely to be skipped: the failure this whole sprint is about
is a surface that stays quiet when it has nothing good to say.

## E. Bootstrap validation ordering

| Case | Must fail when |
|---|---|
| E1 · `--second-root` without `--second-root-key` exits non-zero **without** invoking docker build | validation moves back behind the build |

Assert on the absence of the build, not on the message — a test that only checks the error text
passes with the four-minute wait still in front of it.

## F. Park notification hook

| Case | Must fail when |
|---|---|
| F1 · with a hook configured, a park invokes it with the request-hash | the hook is not called |
| F2 · a hook that exits non-zero does not change the refusal the agent receives | a failing notifier is allowed to fail the call |
| F3 · a hook that hangs does not delay the refusal beyond its bound | it is awaited synchronously |
| F4 · the payload contains no argument values | arguments leak into the notification |
| F5 · a hook failure is logged/recorded, not swallowed | the failure path is silent, making "nothing pinged me" and "the ping failed" identical |

F2 and F3 are the availability pair: a governance control whose notifier can break the gate is worse
than no notifier.

## Regression floor

These must not move (`testing-strategy`): kernel **334**, gateway **134**, vectors **313 / 20
files**, conformance gate green. Counts are taken from a single non-interleaved run; two concurrent
`cargo test` invocations block on the package-cache lock and produce garbage totals.

Release-profile run (`cargo test --all --release`) is required for anything touching arithmetic or
parsing — D touches sequence numbers.

## Result

| | Before | After |
|---|---|---|
| Kernel, debug | 334 | **343** |
| Kernel, release | 334 | **343** |
| Gateway | 134 | **145** |
| Vectors | 313 / 20 files | unchanged — no vector was added or altered |
| Conformance gate | green, 7 groups / 131 | green, 7 groups / 131 |
| `cargo clippy --all-targets`, `cargo fmt --check`, `ruff`, `mypy` | clean | clean |

Every new guard was mutation-proven: the change reverted, the *named* test watched to fail, the
change restored. Three of those mutations are worth recording because they were not formalities.

**The synchronous-notifier mutation passed the first time.** `F3` bounded the caller's wait at 5s
while the harness's notifier timeout was 2s, so a fully synchronous notifier satisfied it — the test
measured something adjacent to the question it asked. The bound is now tighter than the timeout,
and the mutation kills it.

**`D2` failed on first run and was right to.** It asserted a fresh store reports no attestation; the
page said it was anchored. The cause was not the new code: `verify.html` branched on the chain
range's `anchored` — `first_seq == 0` — under the caption "Anchored to a signed checkpoint", so
every stream verified from its origin reported yes with no checkpoint in existence. The two facts
are now rendered separately, and re-conflating them fails exactly that test.

**The bootstrap fixture copied a live deployment.** `shutil.copytree(deploy/)` pulled in the
developer's running install — `secrets/`, `var/`, `config/` are gitignored, not absent — putting a
real root seed in `/tmp` and handing the script a store it refused as already bootstrapped. The
fixture now copies tracked files only, via `git ls-files`.
