//! Console domain ↔ proto conversions.
//!
//! The `sondera.console.v1` wire shapes are projections of the domain types in
//! `sondera_types`: an [`AgentActivity`] becomes an `AgentSummary`, a
//! [`Trajectory`] a `TrajectorySummary`, an [`Event`] a `TrajectoryEvent`. There
//! is no intermediate read model — the resource names the wire needs are built
//! here, from bare domain ids, via [`crate::names`].
//!
//! Encoding is infallible (`From<&Domain> for pb::Message`); this whole surface
//! is OUTPUT_ONLY, so nothing on it decodes.
//!
//! Two things deliberately do not live here. The event payload, adjudication,
//! and scan messages are not re-modelled: the console proto reuses the
//! `sondera.harness.v1` messages, so those conversions come from
//! [`crate::trajectory`] unchanged. And the sparkline messages are converted in
//! `sondera-console`, which is where the strip itself is defined — it is a UI
//! composite, not a domain type this crate can see.

use crate::console_v1 as pb;
use crate::harness_v1 as hb;
use crate::names::{agent_name, trajectory_event_name, trajectory_name};
use crate::wire::datetime_to_timestamp;
use sondera_types::{
    AgentActivity, AgentStats, AgentStatus, Decision, Event, EventDetail, Trajectory,
    TrajectoryEvent, TranscriptScan,
};

// ============================================================================
// Enums
// ============================================================================

fn status_to_proto(value: AgentStatus) -> i32 {
    match value {
        AgentStatus::Unspecified => pb::AgentStatus::Unspecified.into(),
        AgentStatus::Healthy => pb::AgentStatus::Healthy.into(),
        AgentStatus::Degraded => pb::AgentStatus::Degraded.into(),
        AgentStatus::Offline => pb::AgentStatus::Offline.into(),
    }
}

/// Encode an optional decision. `None` — nothing was adjudicated — is the
/// proto's `UNSPECIFIED`.
///
/// Shared with the sparkline conversions in `sondera-console`, which face the
/// same "absent verdict must not read as allow" problem.
pub fn decision_to_proto(value: Option<Decision>) -> i32 {
    match value {
        Some(Decision::Allow) => hb::Decision::Allow.into(),
        Some(Decision::Deny) => hb::Decision::Deny.into(),
        Some(Decision::Escalate) => hb::Decision::Escalate.into(),
        None => hb::Decision::Unspecified.into(),
    }
}

fn event_category_to_proto(value: &TrajectoryEvent) -> i32 {
    match value {
        TrajectoryEvent::Action(_) => pb::TrajectoryEventCategory::Action.into(),
        TrajectoryEvent::Observation(_) => pb::TrajectoryEventCategory::Observation.into(),
        TrajectoryEvent::Control(_) => pb::TrajectoryEventCategory::Control.into(),
        TrajectoryEvent::State(_) => pb::TrajectoryEventCategory::State.into(),
    }
}

// ============================================================================
// Agents
// ============================================================================

/// Encode an agent rollup.
///
/// `sparkline` is left unset: the strip is a console composite this crate cannot
/// see, so the console attaches it after calling this.
impl From<&AgentActivity> for pb::AgentSummary {
    fn from(value: &AgentActivity) -> Self {
        Self {
            name: agent_name(&value.agent.id),
            // The id is the display name — there is no separate stored label.
            display_name: value.agent.id.clone(),
            provider: value.agent.provider.clone(),
            platform: value.agent.platform.clone(),
            status: status_to_proto(value.status),
            health_score: value.health_score,
            last_seen: value.last_active_time.as_ref().map(datetime_to_timestamp),
            runs_today: value.runs_today,
            deny_rate: value.deny_rate,
            sparkline: None,
        }
    }
}

impl From<&AgentStats> for pb::AgentStats {
    fn from(value: &AgentStats) -> Self {
        Self {
            total: value.total,
            healthy: value.healthy,
            degraded: value.degraded,
            offline: value.offline,
        }
    }
}

// ============================================================================
// Trajectories
// ============================================================================

impl From<&Trajectory> for pb::TrajectorySummary {
    fn from(value: &Trajectory) -> Self {
        Self {
            name: trajectory_name(&value.id),
            agent: agent_name(&value.agent_id),
            started_at: value.started_at.as_ref().map(datetime_to_timestamp),
            duration_ms: value.duration_ms,
            decision: decision_to_proto(value.decision),
            event_count: value.event_count,
            policy_hits: value.policy_hits.clone(),
            score: value.score.unwrap_or(0.0),
            summary: value.summary.clone(),
            status: value.status.to_string(),
            update_time: value.update_time.as_ref().map(datetime_to_timestamp),
            digest: value.digest.as_ref().map(hb::TranscriptDigest::from),
            scan: value.scan.as_ref().map(hb::TranscriptScan::from),
        }
    }
}

impl From<&TranscriptScan> for hb::TranscriptScan {
    fn from(value: &TranscriptScan) -> Self {
        Self {
            source_event_id: value.source_event_id.clone(),
            result: Some(hb::TranscriptScanResult::from(&value.result)),
        }
    }
}

impl From<&Event> for pb::TrajectoryEvent {
    fn from(value: &Event) -> Self {
        Self {
            name: trajectory_event_name(&value.trajectory_id, &value.event_id),
            trajectory: trajectory_name(&value.trajectory_id),
            event_id: value.event_id.clone(),
            agent: agent_name(&value.agent.id),
            timestamp: Some(datetime_to_timestamp(&value.timestamp)),
            category: event_category_to_proto(&value.event),
            payload: Some(hb::TrajectoryEvent::from(&value.event)),
            actor: value.actor.id.clone(),
            correlation_id: value.causality.correlation_id.clone(),
            causation_id: value.causality.causation_id.clone().unwrap_or_default(),
            parent_id: value.causality.parent_id.clone().unwrap_or_default(),
        }
    }
}

impl From<&EventDetail> for pb::TrajectoryEventDetail {
    fn from(value: &EventDetail) -> Self {
        Self {
            event: Some(pb::TrajectoryEvent::from(&value.event)),
            adjudication: value.adjudication.as_ref().map(hb::Adjudicated::from),
            summary: value.summary.as_ref().map(hb::EventScanResult::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use sondera_types::{
        Actor, Adjudicated, Agent, Causality, Control, Observation, ShellCommand, Thought,
        TrajectoryStatus,
    };

    fn activity() -> AgentActivity {
        AgentActivity {
            status: AgentStatus::Degraded,
            health_score: 42,
            last_active_time: Some(Utc.timestamp_millis_opt(1_700_000_000_000).unwrap()),
            runs_today: 7,
            deny_rate: 0.58,
            ..Agent::new("a1", "anthropic", "claude-code").into()
        }
    }

    fn event(id: &str, payload: TrajectoryEvent) -> Event {
        Event {
            event_id: id.to_string(),
            trajectory_id: "run-1".to_string(),
            agent: Agent::new("a1", "anthropic", "claude-code"),
            timestamp: Utc.timestamp_millis_opt(0).unwrap(),
            event: payload,
            actor: Actor::agent("a1"),
            causality: Causality::default(),
        }
    }

    #[test]
    fn an_agent_rollup_encodes_its_id_as_a_resource_name_and_display_name() {
        let wire = pb::AgentSummary::from(&activity());
        assert_eq!(wire.name, "agents/a1");
        assert_eq!(wire.display_name, "a1");
        assert_eq!(wire.status, pb::AgentStatus::Degraded as i32);
        assert_eq!(wire.provider, "anthropic");
        // The strip is the console's to attach.
        assert!(wire.sparkline.is_none());
    }

    #[test]
    fn a_compound_agent_id_survives_the_resource_name_round_trip() {
        let activity: AgentActivity = Agent::new(
            "claude-code-developer/rs-engineer",
            "anthropic",
            "claude-code",
        )
        .into();
        let wire = pb::AgentSummary::from(&activity);
        assert_eq!(wire.name, "agents/claude-code-developer/rs-engineer");
        assert_eq!(
            crate::names::agent_id_from_name(&wire.name).unwrap(),
            "claude-code-developer/rs-engineer"
        );
    }

    #[test]
    fn an_unadjudicated_run_encodes_as_decision_unspecified() {
        // `None` must not collapse onto ALLOW: "nothing was checked" and
        // "everything was permitted" are different audit claims.
        assert_eq!(
            decision_to_proto(None),
            hb::Decision::Unspecified as i32,
            "absent decision must not read as allow"
        );
        assert_eq!(
            decision_to_proto(Some(Decision::Deny)),
            hb::Decision::Deny as i32
        );
    }

    #[test]
    fn trajectory_summary_encodes_names_and_the_canonical_status_string() {
        let domain = Trajectory {
            id: "run-1".to_string(),
            agent_id: "a1".to_string(),
            started_at: None,
            duration_ms: 1_500,
            decision: Some(Decision::Escalate),
            event_count: 3,
            policy_hits: vec!["policies/review".to_string()],
            score: None,
            summary: "did a thing".to_string(),
            // `terminated` is exactly the status the older core Decision enum
            // cannot express, which is why this field is string-shaped.
            status: TrajectoryStatus::Terminated,
            update_time: None,
            digest: None,
            scan: None,
        };

        let wire = pb::TrajectorySummary::from(&domain);
        assert_eq!(wire.name, "trajectories/run-1");
        assert_eq!(wire.agent, "agents/a1");
        assert_eq!(wire.status, "terminated");
        assert_eq!(wire.decision, hb::Decision::Escalate as i32);
        assert_eq!(wire.score, 0.0);
        assert!(wire.digest.is_none());
    }

    #[test]
    fn event_detail_carries_the_payload_category_and_folded_adjudication() {
        let mut source = event(
            "e1",
            TrajectoryEvent::Action(sondera_types::Action::ShellCommand(ShellCommand::new("ls"))),
        );
        source.causality = source.causality.caused_by("e0");
        let detail = EventDetail {
            event: source,
            adjudication: Some(Adjudicated::deny()),
            summary: None,
        };

        let wire = pb::TrajectoryEventDetail::from(&detail);
        let event = wire.event.expect("event present");
        assert_eq!(event.name, "trajectories/run-1/events/e1");
        assert_eq!(event.trajectory, "trajectories/run-1");
        assert_eq!(event.agent, "agents/a1");
        assert_eq!(event.category, pb::TrajectoryEventCategory::Action as i32);
        assert_eq!(event.causation_id, "e0");
        assert!(event.payload.is_some());
        assert_eq!(
            wire.adjudication.expect("adjudication").decision,
            hb::Decision::Deny as i32
        );
    }

    #[test]
    fn absent_causality_encodes_as_empty_rather_than_a_placeholder() {
        let wire = pb::TrajectoryEvent::from(&event(
            "e1",
            TrajectoryEvent::Observation(Observation::Thought(Thought::new("hm"))),
        ));
        assert!(wire.causation_id.is_empty());
        assert!(wire.parent_id.is_empty());
        assert_eq!(
            wire.category,
            pb::TrajectoryEventCategory::Observation as i32
        );
    }

    #[test]
    fn control_events_keep_their_category() {
        let wire = pb::TrajectoryEvent::from(&event(
            "e2",
            TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
        ));
        assert_eq!(wire.category, pb::TrajectoryEventCategory::Control as i32);
    }
}
