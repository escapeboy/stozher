//! DEF-7 — one envelope arriving twice is not one approval spent twice.
//!
//! # What five fixes were looking for, and where it actually was
//!
//! CI failed 13 of 34 runs on `gate-authorization-replayed at gw:…:claude-code seq 7`, on Linux,
//! never on the author's macOS in eight days. Four fixes went into the *emitter*, on the theory
//! that it had handed one approval to two envelopes — three real check-then-act sites and one
//! non-atomic recovery, all genuine defects, none of them this one. CI stayed red.
//!
//! Then the emitter was asked instead of theorised about: on a `gate-authorization-replayed` it now
//! logs every locally chained envelope citing the spent approval. It reported **one**. There only
//! ever was one. The second spender was the same envelope.
//!
//! # The window
//!
//! `submit` is idempotent by `object_id`, and its comment names this exact case: *"re-submitting a
//! byte-identical envelope — a retry after a lost response — succeeds instead of being read as an
//! approval being used twice"*. That check reads the store. The single-use check reads the store
//! too, later, and `gate_request_hashes` is written by the append at the end. So two concurrent
//! submissions of one envelope both pass the idempotency check — neither has committed — and the
//! loser then reaches step 11 after the winner committed, finds the hash present, and is refused.
//!
//! The refusal is a verdict on the bytes, so the emitter wedges the stream permanently
//! (§05 §7.1 clause 3) over an envelope the kernel *has*, on a chain that was never divergent.
//!
//! `gate_request_hashes` has recorded `envelope_id` since the table existed. The seen-set was built
//! from a `bool`, which cannot tell "another envelope spent this" from "**this** envelope spent it"
//! — and only the first is a replay.
//!
//! # What is tested here, and what is deliberately not
//!
//! **The race is not reproduced, and no test here pretends to.** One was written — one envelope
//! submitted from 64 tasks at once — and then mutation-tested: it passed with the defect restored,
//! three times, at every concurrency tried. It could not discriminate, because this harness's store
//! serialises submissions and the window needs two of them genuinely in flight. A green test that
//! passes under its own mutation is not evidence, and this repository has now written that lesson
//! down twice; it is not shipping a third instance of it as DEF-7's proof.
//!
//! What IS bound below is the fact the fix rests on: **the ledger identifies its spender.** That is
//! the whole difference between a `bool` and an id, and it is the half a future edit is most likely
//! to undo — `gate_request_spent_by` reverting to "is it present" would restore the defect exactly
//! and pass every other test in the tree.
//!
//! The closing evidence for DEF-7 is CI on Linux, where the race actually happens, and
//! `docs/open-defects.md` keeps the row open until it says so.

use serde_json::json;
use stozher_testkit::world;

#[tokio::test]
async fn the_replay_ledger_says_which_envelope_spent_the_approval() {
    let world = world().await;
    let envelope = world.gated_effect("github.create_issue", json!({})).await;
    let hash = envelope["authorization"]["decision"]["request-hash"]
        .as_str()
        .expect("the approval's request hash")
        .to_owned();

    // Nothing has spent it yet, so nothing may be named.
    assert_eq!(
        world
            .ingest()
            .store()
            .gate_request_spent_by(&hash)
            .await
            .expect("reading the replay ledger"),
        None,
        "an unspent approval reads as spent"
    );

    let id = world.accept(&envelope, &[]).await;

    assert_eq!(
        world
            .ingest()
            .store()
            .gate_request_spent_by(&hash)
            .await
            .expect("reading the replay ledger"),
        Some(id),
        "the ledger cannot name the envelope that spent this approval, so the ingest path cannot \
         tell \"another envelope spent it\" — a replay — from \"this envelope spent it\", which is \
         one envelope arriving twice and is idempotent success (§06 §3). That is DEF-7."
    );
}
