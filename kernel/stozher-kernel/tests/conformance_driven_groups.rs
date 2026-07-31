//! The four groups of `spec/08 §4` that need the component to act, driven through §4.8's protocol.
//!
//! # Why the component is a double here
//!
//! These groups are the harness's judgement, and judgement is only demonstrated by a case it gets
//! *wrong* being caught. A real component conforms — that is what makes it useless as a test of a
//! conformance checker. So each group is run against a scripted component built to fail exactly the
//! property under test, and against one that satisfies it, and the pair is the assertion.
//!
//! `tests/conformance_live_component.rs` covers the other half: the protocol itself, against a real
//! subprocess. A double that answered a protocol nobody speaks would certify nothing.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Value, json};
use stozher_core::error::{Error, Result};
use stozher_kernel::clock::Clock;
use stozher_kernel::conformance::{
    GroupResult, NEGATIVE_CASES, VECTOR_KINDS, check_aggregation, check_negative_cases,
    check_offline_behaviour, check_vectors,
};
use stozher_kernel::driver::ComponentDriver;
use stozher_kernel::manifest::Manifest;
use stozher_testkit::{TestKey, World, manifest_object};

// -- Doubles --------------------------------------------------------------------------------------

/// A component whose every answer the test decides.
///
/// Keyed by case, and by action or negative-case name where one case is asked more than once — a
/// double that answered every `negative` request identically could not express "conformant except
/// for the replay case", which is the shape most of these tests need.
#[derive(Default)]
struct Scripted(HashMap<String, Value>);

impl Scripted {
    fn with(mut self, key: &str, answer: Value) -> Self {
        self.0.insert(key.to_owned(), answer);
        self
    }
}

fn key_of(request: &Value) -> String {
    match request["case"].as_str().unwrap_or("?") {
        "negative" => format!("negative/{}", request["negative"].as_str().unwrap_or("?")),
        "emit" => format!("emit/{}", request["action"].as_str().unwrap_or("?")),
        other => other.to_owned(),
    }
}

impl ComponentDriver for Scripted {
    async fn ask(&self, request: Value) -> Result<Value> {
        let key = key_of(&request);
        self.0.get(&key).cloned().ok_or_else(|| {
            Error::new(
                "x-conformance-driver-failed",
                format!("the scripted component has no answer for {key}"),
            )
        })
    }
}

/// A component that never answers.
struct Unreachable;

impl ComponentDriver for Unreachable {
    async fn ask(&self, _request: Value) -> Result<Value> {
        Err(Error::new(
            "x-conformance-driver-failed",
            "the component closed its output without answering",
        ))
    }
}

/// A component that answers §4.1 by echoing back what it was sent.
///
/// The whole point of stripping expected values: this component computes nothing and would pass a
/// harness that let it see the answers.
struct Echo;

impl ComponentDriver for Echo {
    async fn ask(&self, request: Value) -> Result<Value> {
        let mut answers = serde_json::Map::new();
        for vector in request["vectors"].as_array().into_iter().flatten() {
            let id = vector["id"].as_str().unwrap_or_default().to_owned();
            answers.insert(id, vector.clone());
        }
        Ok(json!({ "answers": answers }))
    }
}

// -- §4.1, the vector corpus ----------------------------------------------------------------------

/// The real corpus files for the kinds §4.1 names.
fn corpus() -> Vec<Value> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    let files = [
        "jcs-canonicalization.json",
        "sha256.json",
        "ed25519.json",
        "object-hash.json",
        "chain.json",
    ];
    files
        .iter()
        .map(|file| {
            let text = std::fs::read_to_string(root.join(file))
                .unwrap_or_else(|e| panic!("reading {file}: {e}"));
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {file}: {e}"))
        })
        .collect()
}

/// A component that reproduces the corpus, standing in for one with a correct implementation.
fn conformant_on_vectors(documents: &[Value], corrupt: Option<&str>) -> Scripted {
    let mut answers = serde_json::Map::new();
    for document in documents {
        let kind = document["kind"].as_str().expect("a corpus file names its kind");
        let Some((_, members)) = VECTOR_KINDS.iter().find(|(k, _)| *k == kind) else {
            continue;
        };
        for vector in document["vectors"].as_array().into_iter().flatten() {
            let name = vector["name"].as_str().expect("a vector is named");
            let id = format!("{kind}/{name}");
            let mut answer = serde_json::Map::new();
            for member in *members {
                if let Some(value) = vector.get(*member) {
                    let value = if corrupt == Some(id.as_str()) {
                        json!("0000000000000000000000000000000000000000000000000000000000000000")
                    } else {
                        value.clone()
                    };
                    answer.insert((*member).to_owned(), value);
                }
            }
            if !answer.is_empty() {
                answers.insert(id, Value::Object(answer));
            }
        }
    }
    Scripted::default().with("vectors", json!({ "answers": answers }))
}

#[tokio::test]
async fn a_component_that_reproduces_the_corpus_passes_and_says_how_many_values_it_matched() {
    let documents = corpus();
    let component = conformant_on_vectors(&documents, None);
    match check_vectors(&component, &documents).await {
        GroupResult::Passed { checks } => assert!(
            checks > 50,
            "the corpus has hundreds of expected values and only {checks} were compared"
        ),
        other => panic!("a conformant component failed §4.1: {other:?}"),
    }
}

#[tokio::test]
async fn a_component_that_echoes_the_request_fails_because_the_answers_were_stripped() {
    // The property the whole group rests on. If §4.8's "inputs only" rule were ever relaxed — one
    // convenient `vector.clone()` in the request builder — this component would pass §4.1 while
    // implementing no canonicalizer, no hash and no signature at all.
    let documents = corpus();
    match check_vectors(&Echo, &documents).await {
        GroupResult::Failed { detail } => assert!(
            detail.contains("did not answer") || detail.contains("was null"),
            "the echo was refused for the wrong reason: {detail}"
        ),
        other => panic!("a component that computed nothing passed §4.1: {other:?}"),
    }
}

#[tokio::test]
async fn one_wrong_value_fails_the_group_and_names_the_vector() {
    let documents = corpus();
    let component = conformant_on_vectors(&documents, Some("sha256/empty"));
    match check_vectors(&component, &documents).await {
        GroupResult::Failed { detail } => {
            assert!(detail.contains("sha256/empty"), "{detail}");
            assert!(detail.contains("the corpus says"), "{detail}");
        }
        other => panic!("a wrong digest passed §4.1: {other:?}"),
    }
}

#[tokio::test]
async fn a_corpus_missing_a_required_kind_fails_rather_than_asking_fewer_questions() {
    // The quiet failure: a harness shipped with three of the five vector files would pass every
    // component on the primitives it still had, and nobody would see which questions stopped being
    // asked.
    let documents: Vec<Value> = corpus()
        .into_iter()
        .filter(|d| d["kind"].as_str() != Some("ed25519"))
        .collect();
    let component = conformant_on_vectors(&documents, None);
    match check_vectors(&component, &documents).await {
        GroupResult::Failed { detail } => assert!(detail.contains("ed25519"), "{detail}"),
        other => panic!("a truncated corpus passed §4.1: {other:?}"),
    }
}

#[tokio::test]
async fn a_component_that_cannot_be_driven_fails_the_group_rather_than_the_run() {
    // A component that will not speak the protocol has not been certified, and the run must say so
    // as a conformance failure rather than as a harness error an operator might dismiss.
    match check_vectors(&Unreachable, &corpus()).await {
        GroupResult::Failed { detail } => assert!(detail.contains("could not be driven"), "{detail}"),
        other => panic!("an unreachable component did not fail §4.1: {other:?}"),
    }
}

// -- §4.3, aggregation ----------------------------------------------------------------------------

fn fixture_manifest(overrides: Value) -> Manifest {
    let mut document = manifest_object("github", "1.0.0", json!({}));
    stozher_testkit::merge(&mut document, overrides);
    let component = TestKey::new(0x16, "agent:github-proxy");
    Manifest::parse(&component.sign(&document)).expect("the fixture manifest parses")
}

fn context(world: &World) -> Value {
    json!({
        "at": world.clock.now(),
        "mandate-ref": world.standing_mandate,
        "policy-version": world.policy_version
    })
}

/// One aggregation record folding `total` calls to `github.get_file`, with `samples` samples.
///
/// `counts` is replaced rather than merged: the testkit's overrides deep-merge, so folding nine
/// calls over a fixture that already names two actions would leave the other action's thirty-two
/// behind and the record would describe a window nobody drove.
async fn aggregate_over(world: &World, total: u64, samples: usize) -> Value {
    let hashes: Vec<String> = (0..samples)
        .map(|i| stozher_core::crypto::sha256_hex(format!("sample-{i}").as_bytes()))
        .collect();
    let mut body = world
        .aggregate(json!({ "sample-hashes": hashes }))
        .await;
    body.as_object_mut().expect("an object").remove("sig");
    body["counts"] = json!({ "total": total, "by-action": { "github.get_file": total } });
    json!({ "envelope": world.agent.sign(&body), "payloads": [] })
}

#[tokio::test]
async fn a_component_that_folds_the_window_it_declared_passes() {
    let world = stozher_testkit::world().await;
    let manifest = fixture_manifest(json!({}));
    // The fixture declares max-samples 8, so the harness drives 9 — one past the ceiling, which is
    // the boundary §4.3 names.
    let component = Scripted::default().with(
        "emit/github.get_file",
        json!({ "submissions": [aggregate_over(&world, 9, 2).await] }),
    );

    match check_aggregation(&component, world.ingest(), &manifest, &context(&world)).await {
        Ok(GroupResult::Passed { checks }) => assert!(checks >= 3, "only {checks} assertions"),
        other => panic!("a conformant component failed §4.3: {other:?}"),
    }
}

#[tokio::test]
async fn a_component_that_itemizes_instead_of_aggregating_fails() {
    // Every rule in §02 §7 is satisfied vacuously by a component that never emits an aggregation
    // record — while doing precisely what §02 §7 exists to prevent, which is burying the day's two
    // consequential actions under a firehose of reads.
    let world = stozher_testkit::world().await;
    let manifest = fixture_manifest(json!({}));
    let mut itemized = Vec::new();
    for _ in 0..9 {
        let envelope = world.effect("github.get_file", "read", json!({})).await;
        itemized.push(json!({ "envelope": envelope, "payloads": [] }));
    }
    let component =
        Scripted::default().with("emit/github.get_file", json!({ "submissions": itemized }));

    match check_aggregation(&component, world.ingest(), &manifest, &context(&world)).await {
        Ok(GroupResult::Failed { detail }) => assert!(detail.contains("itemized"), "{detail}"),
        other => panic!("an itemizing component passed §4.3: {other:?}"),
    }
}

#[tokio::test]
async fn sampling_beyond_the_declared_maximum_fails_even_though_the_kernel_allows_it() {
    // §02 §7.4's ceiling is sixteen and the kernel enforces that. The manifest declared eight, and
    // the manifest is what an auditor was told to expect — so twelve samples is a component that
    // broke its own promise, and only something holding both documents can notice.
    let world = stozher_testkit::world().await;
    let manifest = fixture_manifest(json!({}));
    let component = Scripted::default().with(
        "emit/github.get_file",
        json!({ "submissions": [aggregate_over(&world, 9, 12).await] }),
    );

    match check_aggregation(&component, world.ingest(), &manifest, &context(&world)).await {
        Ok(GroupResult::Failed { detail }) => {
            assert!(detail.contains("max-samples of 8"), "{detail}");
        }
        other => panic!("over-sampling passed §4.3: {other:?}"),
    }
}

#[tokio::test]
async fn counts_that_do_not_account_for_the_calls_driven_fail() {
    // The kernel checks that `total` equals the sum of `by-action`. It cannot check that either
    // number describes reality, because it never saw the calls. The harness did.
    let world = stozher_testkit::world().await;
    let manifest = fixture_manifest(json!({}));
    let component = Scripted::default().with(
        "emit/github.get_file",
        json!({ "submissions": [aggregate_over(&world, 4, 2).await] }),
    );

    match check_aggregation(&component, world.ingest(), &manifest, &context(&world)).await {
        Ok(GroupResult::Failed { detail }) => {
            assert!(detail.contains("account for 4"), "{detail}");
        }
        other => panic!("an aggregate that lost five calls passed §4.3: {other:?}"),
    }
}

#[tokio::test]
async fn a_manifest_with_no_read_action_satisfies_the_group_by_having_none() {
    // Not `NotApplicable` — §4.3 applies to every component, and the assertion is about the
    // manifest rather than about nothing.
    let world = stozher_testkit::world().await;
    let manifest = fixture_manifest(json!({
        "actions": [{
            "action": "github.create_issue",
            "class": "consequential",
            "evidence-schema": "github.create_issue.v1",
            "idempotent": false,
            "target-kind": "repo",
            "degrade": Value::Null
        }]
    }));
    assert!(matches!(
        check_aggregation(
            &Scripted::default(),
            world.ingest(),
            &manifest,
            &context(&world)
        )
        .await,
        Ok(GroupResult::Passed { .. })
    ));
}

// -- §4.4, the negative cases ---------------------------------------------------------------------

/// Where an accepted attempt leaves the effect stream, so the cases that follow can be positioned.
///
/// Chain position is checked before the mandate walk — a fixture at an occupied seq is refused
/// `chain-seq-duplicate` however expired its mandate — so the order the cases run in is part of how
/// they have to be built.
struct Anchor {
    seq: u64,
    first_id: String,
}

/// A component that attempts all seven of its cases correctly.
async fn conformant_on_negatives(world: &World) -> (Scripted, Anchor) {
    let one = |envelope: Value| json!({ "submissions": [{ "envelope": envelope, "payloads": [] }] });

    // A gated action with no approval at all.
    let missing = world
        .effect("github.create_issue", "consequential", json!({}))
        .await;

    // A gated action whose approval was signed over a different target.
    let mismatch = world
        .gated_effect(
            "github.create_issue",
            json!({ "execution": { "target": "repo:acme/elsewhere" } }),
        )
        .await;

    // The same approval twice: the first lands, the second must not. The second has to be a
    // *different* envelope carrying the same authorization — resubmitting identical bytes is a
    // retry, which §04 §3 makes idempotent, and a fixture that did that would be testing the retry
    // path while claiming to test replay.
    let first = world.gated_effect("github.create_issue", json!({})).await;
    let seq = first["seq"].as_u64().expect("a seq");
    let first_id = stozher_core::signed::object_id(&first).expect("an id");
    let mut body = first.clone();
    body.as_object_mut().expect("an object").remove("sig");
    body["seq"] = json!(seq + 1);
    body["prev-hash"] = json!(&first_id);
    let replay = world.agent.sign(&body);

    // A prohibited action, recorded as an attempt. Positioned after the approval that lands, since
    // this one is accepted too and two accepted envelopes cannot share a chain position.
    let prohibited = world
        .effect(
            "github.delete_repo",
            "prohibited",
            json!({
                "seq": seq + 1,
                "prev-hash": &first_id,
                "execution": { "outcome": "attempted" }
            }),
        )
        .await;

    // A cognition envelope carrying effect fields.
    let cognition = world
        .cognition(json!({ "evidence": [{ "media-type": "text/plain", "payload-hash": "a".repeat(64) }] }))
        .await;

    // A standing mandate whose grantor is an agent: a chain that does not reach a human root. This
    // kernel refuses to *store* such a chain, so the refusal lands one step earlier than §4.4
    // describes — which is stronger, and carries the code §4.4 names.
    let rootless = world
        .core_envelope(
            "mandate",
            json!({ "mandate": world.agent.sign(&stozher_testkit::mandate_object(
                &world.agent,
                &world.component,
                "0000000000000000000000000000bbbb",
                json!({
                    "grantor": { "subject": world.agent.subject, "key": world.agent.id.as_str(), "role": "agent" }
                }),
            )) }),
        )
        .await;

    // An effect under a mandate that has run out. Expiry is a clock move rather than a fixture: a
    // mandate expired at the moment it was granted would never have been appended to grant from,
    // and validity is judged against the envelope's own `emitted-at`, so the envelope has to be
    // signed *after* the move. Four hours, because the approvals every other case here carries are
    // good until 17:00 — a bigger jump would expire them and the cases would fail for a reason that
    // has nothing to do with what they test.
    let brief = world
        .grant_standing(
            "00000000000000000000000000000005",
            json!({
                "not-after": "2026-07-26T12:00:00.000Z",
                "scope": {
                    "components": ["gateway"],
                    "actions": ["github.get_file"],
                    "classes": ["read"],
                    "resources": ["*"]
                }
            }),
        )
        .await;
    world.clock.advance_seconds(60 * 60 * 4);
    let expired = world
        .effect(
            "github.get_file",
            "read",
            json!({
                "seq": seq + 1,
                "prev-hash": &first_id,
                "mandate-ref": brief
            }),
        )
        .await;

    let component = Scripted::default()
        .with("negative/gate-authorization-missing", one(missing))
        .with("negative/gate-authorization-action-mismatch", one(mismatch))
        .with(
            "negative/gate-authorization-replayed",
            json!({ "submissions": [
                { "envelope": first, "payloads": [] },
                { "envelope": replay, "payloads": [] }
            ] }),
        )
        .with("negative/mandate-expired", one(expired))
        .with("negative/mandate-root-not-human", one(rootless))
        .with("negative/prohibited-attempted", one(prohibited))
        .with("negative/cognition-with-evidence", one(cognition));
    (component, Anchor { seq, first_id })
}

#[tokio::test]
async fn a_component_that_attempts_every_negative_case_passes() {
    let world = stozher_testkit::world().await;
    let (component, _) = conformant_on_negatives(&world).await;

    match check_negative_cases(
        &component,
        world.ingest(),
        &context(&world),
        &BTreeMap::new(),
    )
    .await
    {
        Ok(GroupResult::Passed { checks }) => assert_eq!(
            checks as usize,
            NEGATIVE_CASES.len(),
            "one assertion per case of §08 §4.4"
        ),
        other => panic!("a conformant component failed §4.4: {other:?}"),
    }
}

#[tokio::test]
async fn a_component_that_declines_to_attempt_a_case_fails_it() {
    // Declining to emit an envelope one knows to be invalid is good engineering and a conformance
    // failure: the subject of the group is what the *kernel* does with such an envelope, and a
    // component that never sends one has left that question unanswered.
    let world = stozher_testkit::world().await;
    let component = Scripted::default().with(
        "negative/gate-authorization-missing",
        json!({ "submissions": [] }),
    );

    match check_negative_cases(
        &component,
        world.ingest(),
        &context(&world),
        &BTreeMap::new(),
    )
    .await
    {
        Ok(GroupResult::Failed { detail }) => {
            assert!(detail.contains("refused to attempt"), "{detail}");
        }
        other => panic!("a declined case passed §4.4: {other:?}"),
    }
}

#[tokio::test]
async fn an_attempt_the_kernel_accepts_fails_the_group() {
    // The failure §4.4's preamble is written against: "these MUST fail, and the harness MUST fail
    // the component if they succeed". A component that sent a perfectly valid gated effect for the
    // authorization-missing case would otherwise look like it had attempted something.
    let world = stozher_testkit::world().await;
    let valid = world.gated_effect("github.create_issue", json!({})).await;
    let component = Scripted::default().with(
        "negative/gate-authorization-missing",
        json!({ "submissions": [{ "envelope": valid, "payloads": [] }] }),
    );

    match check_negative_cases(
        &component,
        world.ingest(),
        &context(&world),
        &BTreeMap::new(),
    )
    .await
    {
        Ok(GroupResult::Failed { detail }) => assert!(detail.contains("was accepted"), "{detail}"),
        other => panic!("an accepted attempt passed §4.4: {other:?}"),
    }
}

#[tokio::test]
async fn a_refusal_for_the_wrong_reason_fails_and_names_both_codes() {
    // A component that sent an unsigned envelope for every case would be refused every time, and a
    // harness checking only "was it refused" would certify it. The reason code is the check.
    let world = stozher_testkit::world().await;
    let wrong = stozher_testkit::tamper(
        &world
            .effect("github.create_issue", "consequential", json!({}))
            .await,
        json!({ "policy-version": "2026.07.99" }),
    );
    let component = Scripted::default().with(
        "negative/gate-authorization-missing",
        json!({ "submissions": [{ "envelope": wrong, "payloads": [] }] }),
    );

    match check_negative_cases(
        &component,
        world.ingest(),
        &context(&world),
        &BTreeMap::new(),
    )
    .await
    {
        Ok(GroupResult::Failed { detail }) => {
            assert!(detail.contains("sig-invalid"), "{detail}");
            assert!(detail.contains("gate-authorization-missing"), "{detail}");
        }
        other => panic!("a refusal for the wrong reason passed §4.4: {other:?}"),
    }
}

#[tokio::test]
async fn a_prohibited_action_reported_as_applied_fails() {
    // §4.4 requires the attempt to be *recorded*, not refused — deleting the evidence of an attempt
    // to punish the attempt is how an audit log becomes a record of what nobody minded. But it must
    // be recorded as an attempt: a component claiming it applied a prohibited action has confessed
    // to something the group must not pass.
    let world = stozher_testkit::world().await;
    let (component, anchor) = conformant_on_negatives(&world).await;
    let applied = world
        .effect(
            "github.delete_repo",
            "prohibited",
            json!({ "seq": anchor.seq + 1, "prev-hash": anchor.first_id }),
        )
        .await;
    let component = component.with(
        "negative/prohibited-attempted",
        json!({ "submissions": [{ "envelope": applied, "payloads": [] }] }),
    );
    world.clock.advance_seconds(60 * 60 * 24 * 400);

    match check_negative_cases(
        &component,
        world.ingest(),
        &context(&world),
        &BTreeMap::new(),
    )
    .await
    {
        Ok(GroupResult::Failed { detail }) => assert!(detail.contains("attempted"), "{detail}"),
        other => panic!("a prohibited action claimed as applied passed §4.4: {other:?}"),
    }
}

// -- §4.5, offline behaviour ----------------------------------------------------------------------

/// Two envelopes chained locally onto the component's own stream, as a queue would be.
async fn queued(world: &World, blocked_outcome: &str) -> Vec<Value> {
    let read = world.effect("github.get_file", "read", json!({})).await;
    let previous = stozher_core::signed::object_id(&read).expect("an id");
    let gated = world
        .effect(
            "github.create_issue",
            "consequential",
            json!({
                "seq": read["seq"].as_u64().expect("a seq") + 1,
                "prev-hash": previous,
                "execution": { "outcome": blocked_outcome }
            }),
        )
        .await;
    vec![
        json!({ "envelope": read, "payloads": [] }),
        json!({ "envelope": gated, "payloads": [] }),
    ]
}

#[tokio::test]
async fn a_component_that_queues_and_blocks_offline_passes() {
    let world = stozher_testkit::world().await;
    let component = Scripted::default().with(
        "offline",
        json!({
            "submissions": queued(&world, "blocked").await,
            "blocked": ["github.create_issue"]
        }),
    );

    match check_offline_behaviour(
        &component,
        world.ingest(),
        &context(&world),
        &["github.get_file".to_owned(), "github.create_issue".to_owned()],
        "github.create_issue",
    )
    .await
    {
        Ok(GroupResult::Passed { checks }) => assert!(checks >= 5, "only {checks} assertions"),
        other => panic!("a conformant component failed §4.5: {other:?}"),
    }
}

#[tokio::test]
async fn a_component_that_applied_a_gated_action_offline_fails() {
    // The whole point of the offline profile: an approval nobody could have given cannot be
    // presumed. A component that applied it anyway and queued a tidy record of having done so is
    // the failure §05 §7 exists to prevent, and it queues and chains perfectly while doing it.
    let world = stozher_testkit::world().await;
    let component = Scripted::default().with(
        "offline",
        json!({
            "submissions": queued(&world, "applied").await,
            "blocked": ["github.create_issue"]
        }),
    );

    match check_offline_behaviour(
        &component,
        world.ingest(),
        &context(&world),
        &["github.create_issue".to_owned()],
        "github.create_issue",
    )
    .await
    {
        Ok(GroupResult::Failed { detail }) => assert!(detail.contains("was applied offline"), "{detail}"),
        other => panic!("an action applied offline passed §4.5: {other:?}"),
    }
}

#[tokio::test]
async fn a_queue_that_does_not_chain_locally_fails() {
    // Envelopes that each verify on their own but do not link are not a chain; they are a pile. The
    // property §04 §3 buys is that an offline period is as ordered and as tamper-evident as an
    // online one.
    let world = stozher_testkit::world().await;
    let mut submissions = queued(&world, "blocked").await;
    submissions[1]["envelope"]["prev-hash"] = json!("b".repeat(64));
    let component = Scripted::default().with(
        "offline",
        json!({ "submissions": submissions, "blocked": ["github.create_issue"] }),
    );

    match check_offline_behaviour(
        &component,
        world.ingest(),
        &context(&world),
        &["github.create_issue".to_owned()],
        "github.create_issue",
    )
    .await
    {
        Ok(GroupResult::Failed { detail }) => assert!(detail.contains("does not link"), "{detail}"),
        other => panic!("an unchained queue passed §4.5: {other:?}"),
    }
}

#[tokio::test]
async fn a_component_that_reports_no_blocking_fails_however_well_it_queued() {
    let world = stozher_testkit::world().await;
    let component = Scripted::default().with(
        "offline",
        json!({ "submissions": queued(&world, "blocked").await, "blocked": [] }),
    );

    match check_offline_behaviour(
        &component,
        world.ingest(),
        &context(&world),
        &["github.create_issue".to_owned()],
        "github.create_issue",
    )
    .await
    {
        Ok(GroupResult::Failed { detail }) => assert!(detail.contains("did not report blocking"), "{detail}"),
        other => panic!("a component that blocked nothing passed §4.5: {other:?}"),
    }
}

#[tokio::test]
async fn a_component_that_queued_nothing_fails_rather_than_passing_vacuously() {
    // "The kernel went away and I did nothing" satisfies every assertion about a queue that exists.
    let world = stozher_testkit::world().await;
    let component = Scripted::default().with("offline", json!({ "submissions": [], "blocked": [] }));

    match check_offline_behaviour(
        &component,
        world.ingest(),
        &context(&world),
        &["github.create_issue".to_owned()],
        "github.create_issue",
    )
    .await
    {
        Ok(GroupResult::Failed { detail }) => assert!(detail.contains("queued nothing"), "{detail}"),
        other => panic!("an empty queue passed §4.5: {other:?}"),
    }
}
