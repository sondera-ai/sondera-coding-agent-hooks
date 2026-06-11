//! Runtime-verification monitors for multi-hop temporal security properties.
//!
//! A [`Monitor`] is a pure, deterministic state machine that observes
//! trajectory events and reports a three-valued [`Verdict`]. Monitors take no
//! clock, RNG, LLM, network, disk, or cross-trajectory input: every predicate
//! evaluates intrinsic fields of the [`Event`] it is given, so a JSONL-order
//! replay of the same event list yields an identical verdict.

use crate::types::Event;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sondera_information_flow_control::Label;

pub mod backstop;
pub mod config;
pub mod predicates;
pub mod untrusted_then_protected_write;

pub use config::MonitorConfig;
pub use untrusted_then_protected_write::{MonitorState, UntrustedThenProtectedWrite};

/// Three-valued monitor verdict.
///
/// `Pending` is deliberately distinct from a bool: an outstanding obligation
/// (e.g. an untrusted read with no approval yet) is neither satisfied nor
/// violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The property holds with no outstanding obligation.
    Satisfied,
    /// The property has been violated; latching/terminal.
    Violated,
    /// An obligation is outstanding but not yet violated.
    Pending,
}

/// Witness data exposed by a monitor.
///
/// Each field carries the id of the event that caused the corresponding
/// transition, letting downstream consumers (Adjudicated mirroring, dashboard)
/// reconstruct the witness prefix from the full event list without copying
/// sub-sequences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MonitorAttributes {
    /// Id of the event that armed the monitor (untrusted read).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub armed_event_id: Option<String>,
    /// Id of the approval event that last cleared the armed obligation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleared_event_id: Option<String>,
    /// Id of the protected write that tripped the monitor into `Violated`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tripped_event_id: Option<String>,
}

/// Denormalized monitor-derived state mirrored into the trajectory log.
///
/// This struct IS the wire contract the dashboard DTOs deserialize: it is
/// serde-serialized as the `"monitor"` key inside every Cedar-path Adjudicated
/// record's `raw_json` and inside the synthetic Started/Resumed snapshot
/// records — never hand-assembled `json!` keys. A separate OS process can
/// therefore read verdict, FSM state, witness ids, `untrusted_pending`,
/// taints, and label from Turso/JSONL alone — never Fjall.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitorSnapshot {
    /// Three-valued monitor verdict at the time the record was written.
    pub verdict: Verdict,
    /// FSM state name (`"clean"` / `"armed"` / `"violated"`) — a `String`
    /// produced inside the monitors module so `pub(crate) FsmState` is never
    /// exposed.
    pub state: String,
    /// Witness event ids for the transitions taken so far.
    pub attributes: MonitorAttributes,
    /// The Armed-or-Violated Cedar fact. Passed in from the single derivation
    /// site in `adjudicate` — never re-derived here.
    pub untrusted_pending: bool,
    /// Trajectory taints. Deliberately NOT skip-if-empty: a uniform shape with
    /// no absent-field special cases (an empty `taints: []` is informative).
    pub taints: Vec<String>,
    /// Max sensitivity label accumulated by the trajectory.
    pub label: Label,
}

impl MonitorSnapshot {
    /// Build a snapshot from the in-scope monitor binding plus the
    /// trajectory-derived facts.
    ///
    /// `untrusted_pending` must be the bool from the ONE derivation site in
    /// `adjudicate` — a second `matches!` site can drift from the Cedar
    /// attribute.
    pub fn from_monitor(
        monitor: &UntrustedThenProtectedWrite,
        untrusted_pending: bool,
        taints: Vec<String>,
        label: Label,
    ) -> Self {
        Self {
            verdict: monitor.verdict(),
            state: monitor.state_name().to_string(),
            attributes: monitor.attributes(),
            untrusted_pending,
            taints,
            label,
        }
    }
}

/// A deterministic, synchronous runtime-verification monitor.
///
/// Synchronous by design: no async, no clock, no I/O. `observe` mutates
/// internal FSM state; `verdict` and `attributes` are pure reads.
pub trait Monitor: Send + Sync {
    /// Feed one trajectory event to the monitor, advancing its state machine.
    ///
    /// Irrelevant events (e.g. `Observation::Think`, `State::Snapshot`,
    /// `Control::Adjudicated`) must no-op gracefully.
    fn observe(&mut self, event: &Event) -> Result<()>;

    /// Current three-valued verdict for the observed trajectory.
    fn verdict(&self) -> Verdict;

    /// Witness data for the transitions taken so far.
    fn attributes(&self) -> MonitorAttributes;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_variants_distinct() {
        assert_ne!(Verdict::Satisfied, Verdict::Pending);
        assert_ne!(Verdict::Pending, Verdict::Violated);
        assert_ne!(Verdict::Violated, Verdict::Satisfied);
    }

    #[test]
    fn verdict_serde_roundtrip() {
        assert_eq!(
            serde_json::to_string(&Verdict::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Satisfied).unwrap(),
            "\"satisfied\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Violated).unwrap(),
            "\"violated\""
        );

        assert_eq!(
            serde_json::from_str::<Verdict>("\"pending\"").unwrap(),
            Verdict::Pending
        );
        assert_eq!(
            serde_json::from_str::<Verdict>("\"satisfied\"").unwrap(),
            Verdict::Satisfied
        );
        assert_eq!(
            serde_json::from_str::<Verdict>("\"violated\"").unwrap(),
            Verdict::Violated
        );
    }

    #[test]
    fn monitor_attributes_default_is_all_none() {
        let attrs = MonitorAttributes::default();
        assert!(attrs.armed_event_id.is_none());
        assert!(attrs.cleared_event_id.is_none());
        assert!(attrs.tripped_event_id.is_none());
    }

    /// Arming WebFetchOutput fixture for snapshot coherence tests.
    fn arming_event() -> Event {
        use crate::types::{Agent, Observation, TrajectoryEvent, WebFetchOutput};
        let agent = Agent {
            id: "agent-1".to_string(),
            provider_id: "test".to_string(),
        };
        Event::new(
            agent,
            "traj-1",
            TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
                "call-1",
                "https://example.com",
                200,
                "body",
            ))),
        )
    }

    /// The typed struct round-trips through serde with the exact snake_case
    /// wire shape the dashboard depends on.
    #[test]
    fn monitor_snapshot_serde_roundtrip() {
        let snapshot = MonitorSnapshot {
            verdict: Verdict::Violated,
            state: "violated".to_string(),
            attributes: MonitorAttributes {
                armed_event_id: Some("evt-armed".to_string()),
                cleared_event_id: Some("evt-cleared".to_string()),
                tripped_event_id: Some("evt-tripped".to_string()),
            },
            untrusted_pending: true,
            taints: vec!["web".to_string()],
            label: Label::Confidential,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(
            json.contains("\"verdict\":\"violated\""),
            "verdict must serialize snake_case, got: {json}"
        );
        assert!(
            json.contains("\"state\":\"violated\""),
            "state must carry the FsmState serde name, got: {json}"
        );

        let back: MonitorSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, snapshot, "round-trip must be Eq-equal (D-32)");
    }

    /// Uniform shape on Clean: absent witness ids are skipped
    /// (MonitorAttributes' skip_serializing_if rides along) but `taints`
    /// is always present, even when empty.
    #[test]
    fn clean_snapshot_skips_absent_witness_ids() {
        let snapshot = MonitorSnapshot {
            verdict: Verdict::Satisfied,
            state: "clean".to_string(),
            attributes: MonitorAttributes::default(),
            untrusted_pending: false,
            taints: Vec::new(),
            label: Label::Public,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.contains("armed_event_id"), "got: {json}");
        assert!(!json.contains("cleared_event_id"), "got: {json}");
        assert!(!json.contains("tripped_event_id"), "got: {json}");
        assert!(
            json.contains("\"taints\":[]"),
            "taints must serialize even when empty (D-34 uniform shape), got: {json}"
        );
    }

    /// from_monitor coherence: the snapshot mirrors the monitor's own
    /// verdict/state/attributes plus the passed-in trajectory facts.
    #[test]
    fn from_monitor_snapshot_coheres_with_monitor() {
        let mut monitor = UntrustedThenProtectedWrite::new(MonitorConfig::default()).unwrap();
        monitor.observe(&arming_event()).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Pending);

        let snapshot =
            MonitorSnapshot::from_monitor(&monitor, true, vec!["web".to_string()], Label::Internal);
        assert_eq!(snapshot.verdict, monitor.verdict());
        assert_eq!(snapshot.state, monitor.state_name());
        assert_eq!(snapshot.attributes, monitor.attributes());
        assert!(snapshot.untrusted_pending);
        assert_eq!(snapshot.taints, vec!["web".to_string()]);
        assert_eq!(snapshot.label, Label::Internal);
    }
}
