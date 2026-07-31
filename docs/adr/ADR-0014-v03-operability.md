# ADR-0014: v0.3 operability — the schema gets a version, the timer gets an owner, and paging gets a cursor

**Status:** Accepted · **Date:** 2026-07-31 · **Arises from** `docs/product-completion-design.md`
§3 (v0.3) and §4.1 · **Follows** ADR-0013 · **Extends** ADR-0010 (where a knob lives)

v0.3 is the gap between a demo and something an operator runs for a year. Five decisions in it were
not mechanical, and this records those. Per ADR-0013's rule, every claim below about what the code
does names the test that fails if it stops being true; nothing here is asserted on this document's
own authority except the decisions themselves.

---

## 1. The migration runner refuses rather than heals

`PRAGMA user_version`, a forward-only registry, additive-only on chain-bearing tables. The parts
that took a decision:

**The whole run is one transaction, and the append-only enforcement is asserted inside it, before
the commit.** A step that dropped a chain-bearing table or one of its triggers is rolled back, so a
failed upgrade leaves the store the operator started with rather than a half-migrated one.
→ `a_migration_that_disarms_the_append_only_triggers_is_rolled_back`

**When a trigger is missing after a step, the runner refuses. It does not re-run the trigger DDL to
put it back.** Healing was the first implementation and it is the wrong answer twice over: it lets a
migration that disarms the store report success, and — the reason it was changed — it makes the
check *unfireable*, since `CREATE TRIGGER IF NOT EXISTS` restores whatever the step dropped. By this
repository's own standard that is not a check, it is a comment. Chain-bearing tables are
additive-only, so a migration that loses one of their triggers is a bug in the migration, and saying
so before the commit is the safe direction.

**The chain is re-verified after applying and before the store is reported open**, and only when
something was applied. Verifying on every start would turn a restart into a full scan of the audit
trail; verifying on none would leave a corrupting upgrade to be discovered by an auditor, which is
the one party who must not be the one to find it.
→ `an_upgrade_over_a_tampered_chain_is_refused` is the counterfactual that shows this is load-bearing
rather than decorative. Note what it costs an attacker: the test has to **drop a trigger** to do its
damage, because there is no way to corrupt this store through the engine without first disabling the
engine's own refusal.

**Version 1 is the v0.2 schema, adopted rather than rebuilt.** A fresh file and an existing v0.2
store both report `user_version = 0`, and the baseline is idempotent, so the first v0.3 boot over a
v0.2 store stamps it and re-verifies it. The upgrade gate is therefore the ordinary path, not a
special case of it.

**`sql/schema.sql` is frozen, and that was not the first design.** Step 1 embeds that file, and step
1 runs only against a store that has never been stamped — so an edit there reaches new installs and
*nothing else*, and the two shapes diverge with nothing to notice. The first cut of this release put
the new index in both `schema.sql` and step 2 on the theory that the file should stay a description
of the current schema; the drift test written to protect that arrangement turned out to be vacuous,
because both stores in it run the same registry and therefore agree however wrong they are. That is
what surfaced the real hazard. The file is now frozen at v0.2 with its digest pinned, and every later
change is a numbered step, which every store reaches exactly once whatever version it starts from.
→ `the_baseline_schema_is_frozen` (an edit fails a test, and the failure names the fix) and
`a_store_stamped_by_an_earlier_binary_reaches_the_same_schema_as_a_fresh_one` (which asserts the
index is *present*, not merely that two stores match — equality alone is satisfied by two stores that
are equally wrong, and the mutation that made step 2 a no-op proved it).

**The chain/projection distinction is data, not folklore** — `CHAIN_BEARING_TABLES`,
`REBUILDABLE_TABLES`, `CONTENT_TABLES` in `migrate.rs`, bound to the tables the database actually
holds by `the_classification_covers_every_table_the_database_holds`. Add a table and that test fails
until it has been classified. `payloads` is its own class deliberately: it is neither chained nor
rebuildable — erasing a row changes no signed byte, and nothing in the chain can put the content
back — and folding it into "projections" would have implied a recomputation that does not exist.

All four guards were mutation-tested in a detached worktree; each kills exactly one test.

## 2. Downgrade is refused, not attempted

An older kernel over a newer store exits with `x-schema-version-ahead` and touches nothing. There is
no downward migration and there will not be one: it would have to discard records, and the records
are the product. Rolling the binary back is therefore not a rollback — the store has already moved —
so the documented recovery is the backup, and `deploy/README.md` §5a says so rather than leaving an
operator to discover it during an incident.
→ `a_store_written_by_a_newer_kernel_is_refused`, which also asserts the refusal did not rewrite the
version it refused.

## 3. Decay is a kernel-owned timer, and cannot be switched off

The endpoint worked, was authenticated, and **nothing called it**. `deploy/README.md` §5 had already
documented that as an interim measure and named the kernel-owned timer as the right fix; this is it.

**The interval lives in `kernel-config.json`, not in policy.** ADR-0010's reasoning transfers
unchanged: `spec/05 §1`'s member set is closed and every member is required, so a new policy member
is a breaking wire change that invalidates every existing document and every vector at once. It is
also the wrong home — a sweep frequency authorizes nothing and changes nobody's rights.

**There is no way to disable it, and that is the decision.** Retention is policy's: `evidence-ttl`
decides how long a payload may be kept. A kernel that never swept would not retain anything longer —
it would only stop enforcing the retention its own policy promises, which is exactly the failure
this closes. So `decay-interval` must be a positive duration and its absence means daily.
→ `a_deployment_that_says_nothing_about_decay_still_gets_it`,
`a_decay_interval_is_a_duration_and_must_be_positive`,
`the_kernel_decays_expired_payloads_without_anyone_calling_the_endpoint`, and its paired negative
`the_sweep_leaves_a_payload_that_is_still_within_its_retention` — without which the positive is
satisfiable by a sweep that deletes whatever it finds.

**And the wiring is bound too, which it was not at first.** Those tests spawn the loop directly,
which a loop nobody started would still satisfy — the exact defect being closed. The two `spawn`
calls therefore moved out of `main` into `Kernel::spawn_maintenance`, so a test can start precisely
what the service starts, with the interval coming from the configuration rather than from an argument
the test chose. → `starting_the_service_starts_the_sweep`; replacing the spawn with a no-op fails it
and nothing else. What remains unbound is the single call inside `serve`, which
`deploy/gate/clean-install.sh` runs for real. The checkpointer inherited the same seam.

## 4. An unreachable downstream is a record, and does not refuse startup

A declared MCP server that cannot be enumerated used to produce exactly one observable: some tools
missing from `tools/list`. An agent cannot distinguish that from a server nobody configured, and the
audit said nothing at all, so a window in which a governed capability was simply absent left no
trace. It now emits `gateway.downstream_unavailable` with `outcome: "failed"` — the outcome is what
files it in the console's failed view rather than among the successes — and `config check` reports
it as a finding before an agent has to discover it as a missing capability.

**Two deliberate asymmetries with `gateway.session_open`:**

*It does not refuse startup.* Session establishment refuses, because an unrecorded session is an
unattributable one. This path is already the degraded one, and refusing here would trade a partial
proxy for no proxy at all over a fault the record exists to report.

*A policy that gates the report costs the record, not the gateway.* If an org classifies the action
as something requiring approval, the gateway logs loudly and continues. The baseline profile
classifies it `benign` so a stock install never meets that.
→ `test_an_unreachable_downstream_is_recorded_as_a_failed_effect`,
`test_the_record_commits_to_the_server_and_not_to_the_error_text` (`args-hash` commits to the server
name, because an error message carries paths, ports and sometimes a token),
`test_a_policy_that_gates_the_report_costs_the_record_and_not_the_gateway`,
`test_config_check_names_a_downstream_it_cannot_reach`, and
`the_baseline_profile_classifies_the_gateway_s_own_bookkeeping`.

## 5. Paging is keyset, and a bad cursor is refused

The audit explorer drew the first `limit` rows, said so honestly, and offered no way to reach the
second page — `offset` was hard-coded to zero, so "raise the limit" was the whole of the answer for a
log larger than any limit an operator would type. The export *did* page, by `OFFSET`.

**`OFFSET` is wrong here, and it is worth being exact about why**, because the obvious accusation is
the one that does not apply. `OFFSET n` is stable only while nothing sorts into the region already
discarded, and `emitted-at` is the *emitter's* clock rather than arrival order — so a concurrent
append lands ahead of rows a reader has passed, every later row shifts down, and the next page begins
one row early. **Nothing is lost.** The store is append-only and enforced so by triggers, so no row
can vanish from under an offset; the defect is duplication. It still matters: a regulator's export
holding one signed envelope twice is a file somebody has to reconcile, and neither they nor the
operator who sent it can tell a paging artefact from a genuine repeat without re-deriving `id()`
across the whole file. The test asserts both halves, because one that only looked for loss would have
passed against the defect that was actually there.

**The cursor is `(emitted_at, stream, seq)` and the triple is deliberate.** `PRIMARY KEY (stream,
seq)` makes the last two unique, so the triple is a *total* order — a cursor over a non-unique key
either skips the rest of a tie or repeats it, and there is no third option. The testkit's clock is
fixed, so every envelope in these tests shares one `emitted-at` and the whole cursor rests on the
tie-break: the hard case is the default case. Dropping the tie-break in a mutation fails
`paging_visits_every_record_exactly_once`.

**A cursor that does not parse is refused, not ignored.** Falling back to "no cursor" answers a
request for page four with page one and looks like success. The mutation that removed the timestamp
check demonstrated it exactly: a hand-edited `after` returned page one with a `200`.

`offset` is gone rather than left beside the cursor — including from `GET /v1/envelopes`, which now
returns `next` for a caller to echo back. A second paging mechanism with the weaker guarantee is a
thing someone reaches for later.

## 6. What v0.3 did not do, and why

| Item | State |
|---|---|
| Resource limits, log rotation, read-only rootfs | **Already satisfied at v0.2.** `deploy/docker-compose.yml` carries `mem_limit`, `pids_limit`, json-file rotation, a read-only rootfs with a named tmpfs, `cap_drop: ALL` and `no-new-privileges` on both services. The gateway's writable rootfs is deliberate and documented: a Python runtime writes bytecode caches, and a read-only rootfs the interpreter works around is a claim rather than a control. Verified, not changed |
| Export streaming | **Deferred on evidence, as the design intended.** §3 makes it conditional — "only if a design partner's log makes the in-memory body impractical". No design partner, no log, no evidence. The bound is recorded and this is the revisit |

The export still builds its body in memory; keyset paging changed how it *walks* the log, not where
it puts the result. That remains the one v0.3 line item deliberately left undone, and the condition
for revisiting it is unchanged: a real log that makes it impractical.

## Related

`docs/product-completion-design.md` §3, §4.1 · ADR-0010 (a knob that authorizes nothing lives in
kernel config) · ADR-0013 (an ADR points at a test; it does not assert about code) · ADR-0003 (two
compose services, which is why a cron sidecar was never available) · `deploy/README.md` §5, §5a
