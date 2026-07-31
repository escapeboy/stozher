//! Conformance run results — `spec/08 §4`, `docs/product-completion-design.md` §4.3.
//!
//! # Why this exists before the checks do
//!
//! `spec/08 §3.3` is "no green conformance run, no registration", and the kernel enforces it by
//! looking for an applied `kernel.conformance_run` envelope committing to the manifest's hash
//! ([`crate::store::Store::conformance_run_is_green`]). **The existence of that envelope is the whole
//! gate.** Nothing downstream re-derives what the run actually checked.
//!
//! That makes a partially-built harness worse than no harness. One that ran two of §08 §4's seven
//! groups and emitted its result would unlock registration on the strength of five checks that never
//! happened — and it would look exactly like a harness that ran them all. The failure would surface
//! as a third-party component in production that nobody had actually certified.
//!
//! So this module is the result document and the rule about it, written **first**: a run is green
//! only when every group §08 §4 requires has an outcome, and a group nobody implemented is
//! [`GroupResult::NotRun`], which is not an outcome. Adding a check later can only move a group from
//! red to green; it can never be forgotten into looking green, because the default is red and the
//! list of groups is fixed here rather than assembled from whatever ran.
//!
//! # What is not here yet
//!
//! Every group's implementation. Several need a live component and a kernel that can be made
//! unreachable — §08 §4.5's offline behaviour, §4.3's "driving N > max-samples calls", §4.4's eight
//! negative cases. ADR-0015 §7 records that as the open item; this module is what stops the gap being
//! silently bridged in the meantime.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// The check groups `spec/08 §4` requires, in its order.
///
/// Fixed here rather than derived from what a run happened to execute. A list assembled from
/// completed checks would make "every group passed" true of a run that skipped six of them, which is
/// the whole failure this module exists to prevent.
pub const REQUIRED_GROUPS: [&str; 7] = [
    "vectors",
    "per-action-emission",
    "aggregation",
    "negative-cases",
    "offline-behaviour",
    "durable-objects",
    "decay-independence",
];

/// What one group of §08 §4 concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupResult {
    /// Every check in the group ran and held. `checks` is how many, so a group that asserted
    /// nothing is visible as such rather than reading like a pass.
    Passed {
        /// How many individual assertions the group made.
        checks: u32,
    },
    /// The group ran and the component failed it.
    Failed {
        /// What went wrong, for the operator reading the run.
        detail: String,
    },
    /// The group genuinely does not apply to this component — §08 §4.6's durable objects, for a
    /// manifest that declares none.
    ///
    /// Deliberately distinct from [`Self::Passed`]: "there was nothing to check" and "it was checked
    /// and held" are different claims, and a reader of the run must be able to tell them apart. It
    /// is accepted as satisfying the group only for the groups that can be inapplicable at all.
    NotApplicable {
        /// Why nothing applied.
        why: String,
    },
    /// The group was not executed. **Not an outcome**, and never green.
    NotRun {
        /// Why not — an unimplemented check says so here rather than being absent.
        why: String,
    },
}

impl GroupResult {
    /// Whether this result satisfies its group.
    #[must_use]
    pub fn satisfied(&self) -> bool {
        matches!(self, Self::Passed { .. } | Self::NotApplicable { .. })
    }

    fn as_json(&self) -> Value {
        match self {
            Self::Passed { checks } => json!({ "result": "passed", "checks": checks }),
            Self::Failed { detail } => json!({ "result": "failed", "detail": detail }),
            Self::NotApplicable { why } => json!({ "result": "not-applicable", "why": why }),
            Self::NotRun { why } => json!({ "result": "not-run", "why": why }),
        }
    }
}

/// Groups that may legitimately not apply to a component.
///
/// Only §08 §4.6, and only for a manifest declaring no durable objects. Every other group applies to
/// every component — a component with no `read` action still has to satisfy §4.3 by having none, and
/// saying "not applicable" to the negative cases would be saying the trust boundary is optional.
const MAY_NOT_APPLY: [&str; 1] = ["durable-objects"];

/// The result of one conformance run against one manifest.
#[derive(Debug, Clone)]
pub struct Run {
    /// `object-hash` of the manifest under test — what the envelope commits to.
    pub manifest_hash: String,
    /// The component's name, for the operator reading the run.
    pub component: String,
    /// When the run finished.
    pub at: String,
    /// The outcome per group. Groups absent from this map are [`GroupResult::NotRun`] by default.
    pub groups: BTreeMap<String, GroupResult>,
}

impl Run {
    /// A run in which nothing has been checked yet: every required group is `NotRun`.
    ///
    /// The starting point is red, and a check moves a group out of it. The reverse — starting green
    /// and marking failures — would make a harness that crashed halfway emit a pass.
    #[must_use]
    pub fn new(manifest_hash: &str, component: &str, at: &str) -> Self {
        Self {
            manifest_hash: manifest_hash.to_owned(),
            component: component.to_owned(),
            at: at.to_owned(),
            groups: BTreeMap::new(),
        }
    }

    /// Record a group's outcome.
    ///
    /// # Panics
    ///
    /// If `group` is not one of [`REQUIRED_GROUPS`]. A harness reporting a group nobody asked for is
    /// a harness whose author and this module disagree about what §08 §4 says, and the disagreement
    /// must be loud rather than silently ignored.
    pub fn record(&mut self, group: &str, result: GroupResult) {
        assert!(
            REQUIRED_GROUPS.contains(&group),
            "{group} is not a group spec/08 section 4 defines"
        );
        if let GroupResult::NotApplicable { .. } = result {
            assert!(
                MAY_NOT_APPLY.contains(&group),
                "{group} applies to every component; it cannot be reported as not-applicable"
            );
        }
        self.groups.insert(group.to_owned(), result);
    }

    /// The groups that are not satisfied, in `REQUIRED_GROUPS` order.
    ///
    /// A group nobody recorded counts as unsatisfied, which is the point: silence is not a pass.
    #[must_use]
    pub fn outstanding(&self) -> Vec<&'static str> {
        REQUIRED_GROUPS
            .into_iter()
            .filter(|group| !self.groups.get(*group).is_some_and(GroupResult::satisfied))
            .collect()
    }

    /// Whether this run may be emitted as a green one.
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.outstanding().is_empty()
    }

    /// The run as evidence for a `kernel.conformance_run` envelope (§08 §4).
    ///
    /// Every required group appears whatever happened to it, so "it passed conformance" is an
    /// audited claim a reader can take apart — with a date, a manifest hash, and the outcome of each
    /// group — rather than a sentence in a README.
    #[must_use]
    pub fn evidence(&self) -> Value {
        let absent = GroupResult::NotRun {
            why: "the harness did not execute this group".to_owned(),
        };
        let groups: serde_json::Map<String, Value> = REQUIRED_GROUPS
            .into_iter()
            .map(|group| {
                let result = self.groups.get(group).unwrap_or(&absent);
                (group.to_owned(), result.as_json())
            })
            .collect();
        json!({
            "schema": "kernel.conformance_run.v1",
            "manifest-hash": self.manifest_hash,
            "component": self.component,
            "at": self.at,
            "green": self.is_green(),
            "outstanding": self.outstanding(),
            "groups": groups
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{GroupResult, REQUIRED_GROUPS, Run};

    fn run() -> Run {
        Run::new("a".repeat(64).as_str(), "notes", "2026-07-31T09:00:00.000Z")
    }

    fn pass_everything(run: &mut Run) {
        for group in REQUIRED_GROUPS {
            run.record(group, GroupResult::Passed { checks: 1 });
        }
    }

    #[test]
    fn a_new_run_is_red_and_names_every_group_it_has_not_done() {
        let run = run();
        assert!(!run.is_green());
        assert_eq!(run.outstanding(), REQUIRED_GROUPS.to_vec());
    }

    #[test]
    fn a_run_is_green_only_when_every_group_is_satisfied() {
        let mut run = run();
        pass_everything(&mut run);
        assert!(run.is_green(), "{:?}", run.outstanding());

        // Take any single group away and it is red again. This is the property that makes a
        // half-built harness harmless: it cannot emit the envelope that unlocks registration.
        for group in REQUIRED_GROUPS {
            let mut partial = run.clone();
            partial.record(
                group,
                GroupResult::NotRun {
                    why: "not implemented yet".to_owned(),
                },
            );
            assert!(
                !partial.is_green(),
                "a run with {group} unexecuted reported itself green"
            );
            assert_eq!(partial.outstanding(), vec![group]);
        }
    }

    #[test]
    fn a_failed_group_is_not_satisfied_and_neither_is_an_absent_one() {
        let mut run = run();
        pass_everything(&mut run);
        run.record(
            "negative-cases",
            GroupResult::Failed {
                detail: "a gated action applied with no authorization was accepted".to_owned(),
            },
        );
        assert!(!run.is_green());

        // Absence is the case a harness reaches by crashing, and it must read the same as failure.
        let mut crashed = run.clone();
        crashed.groups.remove("offline-behaviour");
        assert!(crashed.outstanding().contains(&"offline-behaviour"));
    }

    #[test]
    fn only_durable_objects_may_be_reported_as_not_applicable() {
        let mut run = run();
        pass_everything(&mut run);
        run.record(
            "durable-objects",
            GroupResult::NotApplicable {
                why: "the manifest declares none".to_owned(),
            },
        );
        assert!(
            run.is_green(),
            "a component with no durable objects cannot pass"
        );
    }

    #[test]
    #[should_panic(expected = "applies to every component")]
    fn the_negative_cases_cannot_be_declared_inapplicable() {
        // §08 §4.4 is the trust boundary for third-party code. A harness that could opt out of it
        // would certify a component precisely where certification matters most.
        run().record(
            "negative-cases",
            GroupResult::NotApplicable {
                why: "we would rather not".to_owned(),
            },
        );
    }

    #[test]
    #[should_panic(expected = "is not a group")]
    fn a_group_the_specification_does_not_define_is_refused() {
        run().record("vibes", GroupResult::Passed { checks: 1 });
    }

    #[test]
    fn the_evidence_names_every_group_including_the_ones_that_did_not_run() {
        // An operator reading a red run has to be able to see *which* checks are missing. Evidence
        // that listed only what ran would make a two-group run look like a two-group specification.
        let mut run = run();
        run.record("vectors", GroupResult::Passed { checks: 208 });
        let evidence = run.evidence();

        assert_eq!(evidence["green"].as_bool(), Some(false));
        for group in REQUIRED_GROUPS {
            assert!(
                evidence["groups"].get(group).is_some(),
                "the evidence omits {group}"
            );
        }
        assert_eq!(
            evidence["groups"]["vectors"]["result"].as_str(),
            Some("passed")
        );
        assert_eq!(
            evidence["groups"]["offline-behaviour"]["result"].as_str(),
            Some("not-run")
        );
        assert_eq!(
            evidence["outstanding"].as_array().map(Vec::len),
            Some(REQUIRED_GROUPS.len() - 1)
        );
    }

    #[test]
    fn the_group_list_is_the_one_the_specification_fixes() {
        // spec/08 §4 enumerates seven groups. If that list changes, this fails and the harness has
        // to be brought back into line rather than quietly certifying against an older reading.
        assert_eq!(REQUIRED_GROUPS.len(), 7);
        assert!(REQUIRED_GROUPS.contains(&"negative-cases"));
        assert!(REQUIRED_GROUPS.contains(&"offline-behaviour"));
    }
}
