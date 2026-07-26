-- Append-only, enforced by the storage engine — spec/04-chain-and-checkpoints.md §3.
--
-- "The store is append-only: no UPDATE and no DELETE on envelope rows, enforced at the storage
-- layer (SQLite triggers / Postgres rules), not merely in application code."
--
-- This is the one SQLite-specific file. The Postgres equivalent of each trigger is a BEFORE
-- trigger raising an exception, or a `CREATE RULE ... DO INSTEAD NOTHING`; the guarantee is the
-- same and the seam is confined here. Application code cannot suppress these: there is no
-- application-level flag they consult, and dropping them requires DDL, which the kernel never
-- issues after migration.

CREATE TRIGGER IF NOT EXISTS envelopes_are_append_only_no_update
BEFORE UPDATE ON envelopes
BEGIN
    SELECT RAISE(ABORT, 'envelopes are append-only: UPDATE is not a supported operation');
END;

CREATE TRIGGER IF NOT EXISTS envelopes_are_append_only_no_delete
BEFORE DELETE ON envelopes
BEGIN
    SELECT RAISE(ABORT, 'envelopes are append-only: DELETE is not a supported operation');
END;

-- The rejection stream is a chain too, so it gets the same treatment (§04 §7).
CREATE TRIGGER IF NOT EXISTS rejections_are_append_only_no_update
BEFORE UPDATE ON rejections
BEGIN
    SELECT RAISE(ABORT, 'rejection records are append-only: UPDATE is not a supported operation');
END;

CREATE TRIGGER IF NOT EXISTS rejections_are_append_only_no_delete
BEFORE DELETE ON rejections
BEGIN
    SELECT RAISE(ABORT, 'rejection records are append-only: DELETE is not a supported operation');
END;

-- A checkpoint is an attestation that a head existed; rewriting one would defeat its purpose.
CREATE TRIGGER IF NOT EXISTS checkpoints_are_append_only_no_update
BEFORE UPDATE ON checkpoints
BEGIN
    SELECT RAISE(ABORT, 'checkpoints are append-only: UPDATE is not a supported operation');
END;

CREATE TRIGGER IF NOT EXISTS checkpoints_are_append_only_no_delete
BEFORE DELETE ON checkpoints
BEGIN
    SELECT RAISE(ABORT, 'checkpoints are append-only: DELETE is not a supported operation');
END;

-- A policy version resolves forever (§05 §2.2); a manifest version is retained forever (§08 §3.5).
CREATE TRIGGER IF NOT EXISTS policies_are_immutable_no_update
BEFORE UPDATE ON policies
BEGIN
    SELECT RAISE(ABORT, 'a published policy version is immutable');
END;

CREATE TRIGGER IF NOT EXISTS policies_are_immutable_no_delete
BEFORE DELETE ON policies
BEGIN
    SELECT RAISE(ABORT, 'a published policy version is retained forever');
END;

CREATE TRIGGER IF NOT EXISTS manifests_are_immutable_no_update
BEFORE UPDATE ON manifests
BEGIN
    SELECT RAISE(ABORT, 'a registered manifest version is immutable');
END;

CREATE TRIGGER IF NOT EXISTS manifests_are_immutable_no_delete
BEFORE DELETE ON manifests
BEGIN
    SELECT RAISE(ABORT, 'a registered manifest version is retained forever');
END;

-- The pending queue is append-only too. A parked request that could be edited after an approver
-- read it is a request the approver did not actually approve, and a decision that could be rewritten
-- is not a decision — so both tables get the same treatment as the chain (§06 §4.3, §06 §5).
CREATE TRIGGER IF NOT EXISTS gate_requests_no_update
BEFORE UPDATE ON gate_requests
BEGIN
    SELECT RAISE(ABORT, 'a parked request is immutable: an edited request is not the one approved');
END;

CREATE TRIGGER IF NOT EXISTS gate_requests_no_delete
BEFORE DELETE ON gate_requests
BEGIN
    SELECT RAISE(ABORT, 'the pending queue is append-only');
END;

CREATE TRIGGER IF NOT EXISTS gate_decisions_no_update
BEFORE UPDATE ON gate_decisions
BEGIN
    SELECT RAISE(ABORT, 'a recorded decision is immutable: a human said this, once');
END;

CREATE TRIGGER IF NOT EXISTS gate_decisions_no_delete
BEFORE DELETE ON gate_decisions
BEGIN
    SELECT RAISE(ABORT, 'a recorded decision is retained forever');
END;

-- "Failure to notify must not silently drop a park" means the attempt log cannot be edited either.
CREATE TRIGGER IF NOT EXISTS gate_notifications_no_update
BEFORE UPDATE ON gate_notifications
BEGIN
    SELECT RAISE(ABORT, 'notification attempts are append-only');
END;

CREATE TRIGGER IF NOT EXISTS gate_notifications_no_delete
BEFORE DELETE ON gate_notifications
BEGIN
    SELECT RAISE(ABORT, 'notification attempts are append-only');
END;

-- An approval may be consumed once (§06 §3); forgetting that it was used is how it gets reused.
CREATE TRIGGER IF NOT EXISTS gate_request_hashes_no_update
BEFORE UPDATE ON gate_request_hashes
BEGIN
    SELECT RAISE(ABORT, 'the gate replay set is append-only');
END;

CREATE TRIGGER IF NOT EXISTS gate_request_hashes_no_delete
BEFORE DELETE ON gate_request_hashes
BEGIN
    SELECT RAISE(ABORT, 'the gate replay set is append-only');
END;
