//! The clock advance — ADR-0023, `spec/04 §7.1`, `spec/09 §5.1`.
//!
//! # What this facility is for
//!
//! An external reviewer reported that a deployment "offers no facility to advance or simulate time,
//! and no payload had reached its retention ceiling, so we did not observe retention enforcement at
//! all". Mandate expiry, payload decay and the checkpoint interval are all judged by comparing the
//! kernel's clock against a deadline, and every deadline this system can express outlives an
//! engagement. The advance makes those four behaviours observable in an afternoon.
//!
//! # What the tests here are actually claiming
//!
//! Not "the advance works" — that is one assertion and it is the least interesting one. The claims
//! are the four properties that make a time-moving facility in a production binary something other
//! than a vulnerability:
//!
//! 1. **It only moves forward**, so it can never lengthen anybody's authority. Asserted against the
//!    thing it would break: a mandate that has expired, and the store query the kernel really uses
//!    to decide who holds one.
//! 2. **It cannot run undeclared.** The declaration is chained, signed and append-only, and if it
//!    cannot be written the kernel does not start.
//! 3. **It ratchets.** A deployment that has run ahead cannot be returned to the host's clock, so a
//!    trip into the future cannot be taken and then covered up.
//! 4. **A deployment that does not ask for it is untouched** — no record, no refusal, no cost.

use std::sync::Arc;

use serde_json::json;
use stozher_kernel::clock::{
    self, AdvancedClock, CLOCK_ADVANCE_ACKNOWLEDGEMENT, CLOCK_ADVANCE_DECLARED,
    CLOCK_ADVANCE_REFUSED, Clock, ClockAdvance, FixedClock, SharedClock,
};
use stozher_kernel::keys::{ROLE_KERNEL_CHECKPOINT, Seed, SigningKey};
use stozher_kernel::store::{Store, verify_rejection_chain};

const REJECTIONS: &str = "kernel:rejections";
const HOST_NOW: &str = "2026-08-01T09:00:00.000Z";

fn advance(duration: &str) -> ClockAdvance {
    ClockAdvance {
        seconds: clock::parse_duration_seconds(duration).expect("a duration"),
        duration: duration.to_owned(),
    }
}

fn kernel_key() -> SigningKey {
    Seed::generate()
        .expect("entropy")
        .derive(ROLE_KERNEL_CHECKPOINT, 0)
        .expect("derivation")
}

/// A clock reading `HOST_NOW`, and the same clock advanced.
fn clocks(duration: &str) -> (SharedClock, SharedClock) {
    let host: SharedClock = Arc::new(FixedClock::new(HOST_NOW).expect("a host clock"));
    let advanced: SharedClock = Arc::new(
        AdvancedClock::new(Arc::clone(&host), advance(duration)).expect("a legal advance"),
    );
    (host, advanced)
}

#[tokio::test]
async fn the_advance_is_declared_into_a_signed_chained_record_before_anything_is_served() {
    let store = Store::open_memory(REJECTIONS).await.expect("a store");
    let key = kernel_key();
    let (host, advanced) = clocks("P400D");

    let id = clock::declare_advance(&store, &key, &advanced, Some(&advance("P400D")))
        .await
        .expect("the declaration")
        .expect("an id, because an advance was configured");

    let records = store
        .rejections(Some(CLOCK_ADVANCE_DECLARED), 10)
        .await
        .expect("the record stream");
    assert_eq!(records.len(), 1, "the advance was not declared");
    let record = &records[0];
    assert_eq!(record["id"], id);
    assert_eq!(record["submitted-by"], "agent:kernel");

    // The one field in the store that still says when this actually happened. Everything the
    // process goes on to emit is stamped 400 days later, and the difference between these two
    // numbers is how a reader recovers the truth from the records.
    assert_eq!(record["received-at"], host.now());
    let detail: serde_json::Value =
        serde_json::from_str(record["detail"].as_str().expect("detail")).expect("canonical JSON");
    assert_eq!(detail["real"], HOST_NOW);
    assert_eq!(detail["effective"], advanced.now());
    assert_eq!(detail["advance"], "P400D");
    assert_eq!(detail["advance-seconds"], 400 * 86_400);
    assert_eq!(detail["acknowledged"], CLOCK_ADVANCE_ACKNOWLEDGEMENT);
    assert_ne!(
        detail["real"], detail["effective"],
        "a declaration that says the clock is where it already was declares nothing"
    );

    // It is a real member of the kernel's record chain, not a note beside it: it verifies with
    // everything else in that stream, and the storage engine's append-only triggers cover it.
    let chain = store.rejection_chain().await.expect("the chain");
    assert!(
        verify_rejection_chain(&chain, REJECTIONS)
            .expect("a verifiable chain")
            .is_some()
    );
}

#[tokio::test]
async fn a_deployment_that_has_run_ahead_will_not_go_back() {
    let store = Store::open_memory(REJECTIONS).await.expect("a store");
    let key = kernel_key();
    let (host, advanced) = clocks("P400D");

    clock::declare_advance(&store, &key, &advanced, Some(&advance("P400D")))
        .await
        .expect("the first declaration");

    // The trip cannot be covered up. Returning to the host's own clock is refused, and so is any
    // smaller advance: both would put new records behind ones already written.
    let back_to_reality = clock::declare_advance(&store, &key, &host, None)
        .await
        .unwrap_err();
    assert_eq!(back_to_reality.code(), CLOCK_ADVANCE_REFUSED);
    assert!(
        back_to_reality.detail().contains(&advanced.now()),
        "the refusal must name the instant the deployment has already reached"
    );

    let (_, smaller) = clocks("P399D");
    assert_eq!(
        clock::declare_advance(&store, &key, &smaller, Some(&advance("P399D")))
            .await
            .unwrap_err()
            .code(),
        CLOCK_ADVANCE_REFUSED
    );

    // Staying put, or going further, is fine — and each process that runs this way leaves its own
    // record, so the audit shows how many times and how far.
    let (_, further) = clocks("P401D");
    clock::declare_advance(&store, &key, &further, Some(&advance("P401D")))
        .await
        .expect("a larger advance is allowed");
    assert_eq!(
        store
            .rejections(Some(CLOCK_ADVANCE_DECLARED), 10)
            .await
            .expect("the record stream")
            .len(),
        2
    );
}

#[tokio::test]
async fn a_deployment_that_never_asks_for_an_advance_pays_nothing_for_it() {
    let store = Store::open_memory(REJECTIONS).await.expect("a store");
    let key = kernel_key();
    let host: SharedClock = Arc::new(FixedClock::new(HOST_NOW).expect("a host clock"));

    assert!(
        clock::declare_advance(&store, &key, &host, None)
            .await
            .expect("an ordinary start")
            .is_none()
    );
    assert!(
        store
            .rejections(None, 10)
            .await
            .expect("the record stream")
            .is_empty(),
        "an ordinary deployment must not write a clock record at all"
    );
}

/// The attack: use the facility to make an expired mandate work again.
///
/// The first half establishes that the resurrection is real and reachable *if* a clock could be
/// moved backwards — `mandates_held_by` is the query the kernel itself uses to decide who holds a
/// live mandate, and at an earlier instant it hands the expired one straight back. The second half
/// is the refusal: every clock the shipped binary can be configured to run reads at or ahead of the
/// host's, so the instant that would resurrect it is one no configuration can produce.
#[tokio::test]
async fn the_advance_cannot_bring_an_expired_mandate_back() {
    const NONCE: &str = "0000000000000000000000000000c10c";
    let world = stozher_testkit::world().await;
    let agent = world.agent.subject.clone();
    world
        .grant_standing(NONCE, json!({ "not-after": "2026-08-01T00:00:00.000Z" }))
        .await;
    let store = world.kernel.ingest.store();
    // The bootstrap grants this subject other mandates, so the question is about *this* one.
    let live_at = async |at: String| {
        store
            .mandates_held_by(&agent, &at)
            .await
            .expect("the registry")
            .iter()
            .any(|mandate| mandate["nonce"] == NONCE)
    };

    // Alive while the clock is inside the window.
    assert!(live_at(stozher_testkit::NOW.to_owned()).await);

    // The host's clock passes `not-after`. The mandate is gone.
    let host: SharedClock = Arc::new(FixedClock::new("2026-08-02T00:00:00.000Z").expect("a clock"));
    assert!(
        !live_at(host.now()).await,
        "the mandate did not expire, so this test is not testing what it says"
    );

    // The resurrection is real: one hour before it expired, the kernel's own query hands it back.
    // This is exactly the instant the attack needs, and exactly the one the facility cannot reach.
    assert!(
        live_at("2026-07-31T23:00:00.000Z".to_owned()).await,
        "a backwards clock would resurrect this mandate — that is the thing being refused"
    );

    // Every advance the kernel accepts, from the smallest to the bound. None of them reaches back
    // into the window; each one only pushes the mandate further past its deadline.
    for duration in ["PT1S", "PT1H", "P1D", "P400D", "P3650D"] {
        let clock = AdvancedClock::new(Arc::clone(&host), advance(duration)).expect("an advance");
        assert!(
            clock.now() >= host.now(),
            "{duration} produced a clock behind the host"
        );
        assert!(
            !live_at(clock.now()).await,
            "{duration} brought an expired mandate back"
        );
    }

    // And the ways of asking for the clock that would: refused at the grammar, refused at the
    // constructor. There is no third way in — the advance is the only member of the configuration
    // that touches time, and it is a duration, which has no sign.
    for spelling in ["-PT1H", "-P1D", "P-1D"] {
        assert_eq!(
            clock::parse_duration_seconds(spelling).unwrap_err().code(),
            "encoding-bad-duration",
            "{spelling:?} parsed as a duration"
        );
    }
    let forged = ClockAdvance {
        seconds: -3_600,
        duration: "PT1H".to_owned(),
    };
    assert_eq!(
        AdvancedClock::new(Arc::clone(&host), forged)
            .unwrap_err()
            .code(),
        CLOCK_ADVANCE_REFUSED,
        "a hand-built negative advance was accepted"
    );
}

/// An advance applied near the top of the representable range must answer, not unwind.
///
/// `shift` refuses to leave the four-digit year form of `spec/01 §2.3`, so a base close to that
/// ceiling plus a ten-year advance walks off the end. `now()` is on the ingest path, and a panic
/// there is an availability failure with no envelope to show for it — the same reason
/// `tests/timestamp_adversarial.rs` exists.
#[test]
fn an_advance_near_the_representable_ceiling_does_not_panic_or_go_backwards() {
    for base in [
        "9999-12-31T23:59:59.998Z",
        "9995-01-01T00:00:00.000Z",
        "2026-08-01T00:00:00.000Z",
    ] {
        let advance = ClockAdvance {
            seconds: 3650 * 86_400,
            duration: "P3650D".to_owned(),
        };
        let Ok(clock) =
            AdvancedClock::new(Arc::new(FixedClock::new(base).expect("a base")), advance)
        else {
            continue;
        };
        let now = clock.now();
        assert!(!now.is_empty(), "the clock returned nothing at base {base}");
        assert!(
            now.as_str() >= base,
            "the clock went backwards at the ceiling: {base} -> {now}"
        );
    }
}
