//! The run-level [`Trajectory`] aggregate, the governance fold over a run's
//! events, and the trajectory store surface.
//!
//! [`Event`](super::Event) is the grain the harness writes; [`Trajectory`] is
//! the grain a reader asks about — one run, rolled up from its events. Both the
//! rollup and the fold that hides governance events ([`fold_event_details`]) are
//! pure functions over `&[Event]`, so a store computes them without inventing a
//! parallel event shape, and any caller can recompute them from a raw event
//! list.
//!
//! Nothing here speaks AIP: ids are bare, and `trajectories/{id}` resource names
//! are built and parsed at the wire edge (see `sondera_schema::names`).

use super::{
    Adjudicated, Control, Event, EventScanResult, TrajectoryEvent, TrajectoryStatus,
    TranscriptDigest, TranscriptScan,
};
use crate::error::StoreError;
use crate::page::Page;
use crate::policy::Decision;
use chrono::{DateTime, Utc};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

type Result<T> = std::result::Result<T, StoreError>;

/// One agent run, rolled up from the events recorded against it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trajectory {
    /// Bare trajectory id.
    pub id: String,
    /// Bare id of the agent that produced the run.
    pub agent_id: String,
    pub started_at: Option<DateTime<Utc>>,
    pub duration_ms: i64,
    /// The run-level verdict: the most severe adjudication recorded on the run.
    pub decision: Option<Decision>,
    /// How many events a caller can page through — the visible (folded) count,
    /// not the raw row count.
    pub event_count: i32,
    pub policy_hits: Vec<String>,
    /// Run quality score, when something produced one. Nothing here scores runs
    /// yet, so this stays `None`.
    pub score: Option<f64>,
    /// A one-line description of the run.
    pub summary: String,
    pub status: TrajectoryStatus,
    pub update_time: Option<DateTime<Utc>>,
    /// Latest hierarchical transcript digest, projected from the run's `Scanned`
    /// control events. Absent until the scanner has produced one, and only
    /// populated by [`Trajectory::detail`].
    pub digest: Option<TranscriptDigest>,
    /// Latest transcript-level behavioral scan. [`Trajectory::detail`] only,
    /// like `digest`.
    pub scan: Option<TranscriptScan>,
}

impl Trajectory {
    /// List-grained rollup: everything except the digest and transcript scan,
    /// which are left unset because a list view does not render them and
    /// projecting them costs a scan of every run's control events.
    pub fn summarize(id: &str, events: &[Event]) -> Self {
        let started_at = events.first().map(|event| event.timestamp);
        let update_time = events.last().map(|event| event.timestamp);
        let duration_ms = match (started_at, update_time) {
            (Some(first), Some(last)) => (last - first).num_milliseconds().max(0),
            _ => 0,
        };

        Self {
            id: id.to_string(),
            agent_id: events
                .first()
                .map(|event| event.agent.id.clone())
                .unwrap_or_default(),
            started_at,
            duration_ms,
            decision: run_decision(events),
            event_count: fold_event_details(events).len() as i32,
            policy_hits: run_policy_hits(events),
            score: None,
            summary: run_summary(events, None),
            status: run_status(events),
            update_time,
            digest: None,
            scan: None,
        }
    }

    /// Detail-grained rollup: [`Trajectory::summarize`] plus the latest
    /// transcript digest and behavioral scan.
    pub fn detail(id: &str, events: &[Event]) -> Self {
        let digest = latest_digest(events);
        let summary = run_summary(events, digest.as_ref());
        Self {
            summary,
            digest,
            scan: latest_scan(events),
            ..Self::summarize(id, events)
        }
    }
}

/// The lifecycle status implied by a run's last lifecycle control event.
fn run_status(events: &[Event]) -> TrajectoryStatus {
    events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            // Adjudications and scans are governance bookkeeping, not lifecycle:
            // they must not pin a finished run back to `Running`.
            TrajectoryEvent::Control(Control::Adjudicated(_) | Control::Scanned(_)) => None,
            TrajectoryEvent::Control(control) => Some(TrajectoryStatus::from_control(control)),
            _ => None,
        })
        .unwrap_or_default()
}

fn latest_digest(events: &[Event]) -> Option<TranscriptDigest> {
    events.iter().rev().find_map(|event| match &event.event {
        TrajectoryEvent::Control(Control::Scanned(scanned)) => {
            scanned.transcript_digest_result().cloned()
        }
        _ => None,
    })
}

fn latest_scan(events: &[Event]) -> Option<TranscriptScan> {
    events.iter().rev().find_map(|event| match &event.event {
        TrajectoryEvent::Control(Control::Scanned(scanned)) => scanned
            .transcript_scan_result()
            .cloned()
            .map(|result| TranscriptScan {
                source_event_id: scanned.source_event_id().to_string(),
                result,
            }),
        _ => None,
    })
}

/// A one-line description of the run: the scanner's title if it produced one,
/// otherwise whatever the terminal control event recorded.
fn run_summary(events: &[Event], digest: Option<&TranscriptDigest>) -> String {
    if let Some(digest) = digest {
        return digest.title.clone();
    }
    events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            TrajectoryEvent::Control(Control::Completed(completed)) => {
                completed.summary.clone().or_else(|| Some(String::new()))
            }
            TrajectoryEvent::Control(Control::Failed(failed)) => Some(failed.reason.clone()),
            TrajectoryEvent::Control(Control::Terminated(terminated)) => {
                Some(terminated.reason.clone())
            }
            _ => None,
        })
        .unwrap_or_default()
}

/// A trajectory event paired with the adjudication and scanner summary it
/// produced.
///
/// The harness records `Adjudicated` and `Scanned` control events causally
/// linked to their source event (`causation_id == source event_id`). A reader
/// hides those control events and folds them back onto the source event as this
/// record, so a detail table renders the decision and summary inline instead of
/// as bare governance rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventDetail {
    pub event: Event,
    pub adjudication: Option<Adjudicated>,
    pub summary: Option<EventScanResult>,
}

/// Fold a run's raw events into detail records: hide the causally linked
/// `Adjudicated` / `Scanned` control events and attach them to the source event
/// they describe.
///
/// Adjudications and scans that name no source (or name one outside `events`)
/// stay hidden — [`Trajectory::decision`] still reflects them — so a detail
/// table never renders a governance event as a bare row.
pub fn fold_event_details(events: &[Event]) -> Vec<EventDetail> {
    let mut adjudications: HashMap<&str, &Adjudicated> = HashMap::new();
    let mut summaries: HashMap<&str, &EventScanResult> = HashMap::new();

    for event in events {
        let TrajectoryEvent::Control(control) = &event.event else {
            continue;
        };
        let Some(source) = event.causality.causation_id.as_deref() else {
            continue;
        };
        match control {
            // Later adjudications win: the last verdict recorded for an event is
            // the one that governed it.
            Control::Adjudicated(adjudicated) => {
                adjudications.insert(source, adjudicated);
            }
            Control::Scanned(scanned) => {
                if let Some(result) = scanned.event_scan_result() {
                    summaries.insert(source, result);
                }
            }
            _ => {}
        }
    }

    events
        .iter()
        .filter(|event| !is_folded_control(event))
        .map(|event| EventDetail {
            event: event.clone(),
            adjudication: adjudications
                .get(event.event_id.as_str())
                .map(|a| (*a).clone()),
            summary: summaries.get(event.event_id.as_str()).map(|s| (*s).clone()),
        })
        .collect()
}

/// Whether an event is a governance control event folded onto its source, and
/// therefore hidden from the detail list.
fn is_folded_control(event: &Event) -> bool {
    matches!(
        &event.event,
        TrajectoryEvent::Control(Control::Adjudicated(_) | Control::Scanned(_))
    )
}

/// The run-level verdict for a trajectory: the most severe adjudication recorded
/// on it, or `None` when nothing was adjudicated.
pub fn run_decision(events: &[Event]) -> Option<Decision> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            TrajectoryEvent::Control(Control::Adjudicated(a)) => Some(a.decision),
            _ => None,
        })
        .max_by_key(|decision| decision_severity(*decision))
}

/// Distinct policy ids named by the firing (deny/escalate) adjudications on a
/// run, in first-seen order.
pub fn run_policy_hits(events: &[Event]) -> Vec<String> {
    let mut hits = Vec::new();
    for event in events {
        let TrajectoryEvent::Control(Control::Adjudicated(adjudicated)) = &event.event else {
            continue;
        };
        if adjudicated.decision == Decision::Allow {
            continue;
        }
        if let Some(hit) = adjudication_policy_hit(adjudicated)
            && !hits.contains(&hit)
        {
            hits.push(hit);
        }
    }
    hits
}

/// The policy id (or description) named by a firing adjudication, if any.
pub fn adjudication_policy_hit(adjudicated: &Adjudicated) -> Option<String> {
    adjudicated.metadata.iter().find_map(|metadata| {
        metadata
            .policy_id
            .clone()
            .or_else(|| metadata.description.clone())
    })
}

/// Severity ordering for folding and summarising: deny outranks escalate.
/// `Allow` maps to the natural `0` floor.
pub fn decision_severity(decision: Decision) -> u8 {
    match decision {
        Decision::Deny => 2,
        Decision::Escalate => 1,
        Decision::Allow => 0,
    }
}

/// Which runs a list or stream read should consider.
///
/// Every field is a narrowing clause; `None` means "do not narrow on this", so a
/// default filter matches every run. Parsing the wire filter grammar into this
/// shape is the service edge's job.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrajectoryFilter {
    /// Narrows to one agent. Unlike the other two clauses this is a stored
    /// column, so a store can push it into its query rather than applying it to
    /// built rollups.
    pub agent_id: Option<String>,
    pub status: Option<TrajectoryStatus>,
    pub decision: Option<Decision>,
}

impl TrajectoryFilter {
    /// Whether a built rollup satisfies the derived (non-column) clauses.
    ///
    /// [`Self::agent_id`] is deliberately not checked here: it is a stored
    /// column a store narrows on before rolling anything up.
    pub fn matches(&self, trajectory: &Trajectory) -> bool {
        if let Some(status) = self.status
            && trajectory.status != status
        {
            return false;
        }
        if let Some(decision) = self.decision
            && trajectory.decision != Some(decision)
        {
            return false;
        }
        true
    }
}

/// The orderings a store can sort a run list by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrajectoryOrderBy {
    /// Newest-first by default, because the primary view is a live activity feed.
    #[default]
    StartTime,
    UpdateTime,
    EventCount,
}

/// A complete trajectory list read: which runs, in what order, and which window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrajectoryQuery {
    pub filter: TrajectoryFilter,
    pub order_by: TrajectoryOrderBy,
    pub descending: bool,
    pub offset: usize,
    pub limit: usize,
}

impl Default for TrajectoryQuery {
    fn default() -> Self {
        Self {
            filter: TrajectoryFilter::default(),
            order_by: TrajectoryOrderBy::default(),
            // Newest-first is the useful default for an activity feed.
            descending: true,
            offset: 0,
            // Unbounded: a domain query has no opinion about page sizes, so an
            // unset limit reads every match. Service edges clamp before calling.
            limit: usize::MAX,
        }
    }
}

/// A live feed of run rollups.
pub type TrajectoryStream = Pin<Box<dyn Stream<Item = Result<Trajectory>> + Send + 'static>>;

/// A live feed of raw trajectory events.
pub type TrajectoryEventStream = Pin<Box<dyn Stream<Item = Result<Event>> + Send + 'static>>;

/// The trajectory store surface, shared by the harness (writes) and readers such
/// as the console gRPC service.
///
/// The harness owns the write side: it appends each adjudicated event as it
/// arrives. Everything else is a projection — the run rollup, the folded event
/// detail, and the two live streams that tail in-flight runs. Every method takes
/// bare ids; resource names are parsed at the service edge.
pub trait TrajectoryReaderWriter: Send + Sync {
    // ── Writes (harness ingest path) ─────────────────────────────────────────

    /// Persist a single trajectory event.
    fn insert_event(&self, event: &Event) -> impl Future<Output = Result<()>> + Send;

    /// Persist multiple events in a single transaction.
    fn insert_events(&self, events: &[Event]) -> impl Future<Output = Result<()>> + Send;

    /// Delete all events for a trajectory, returning the count deleted.
    fn delete_trajectory(&self, id: &str) -> impl Future<Output = Result<u64>> + Send;

    // ── Reads ────────────────────────────────────────────────────────────────

    /// The detail-grained rollup for one run, with `digest` and `scan`
    /// populated, or `None` when the run has no events.
    fn get_trajectory(&self, id: &str) -> impl Future<Output = Result<Option<Trajectory>>> + Send;

    /// A window of list-grained run rollups matching `query`.
    fn list_trajectories(
        &self,
        query: &TrajectoryQuery,
    ) -> impl Future<Output = Result<Page<Trajectory>>> + Send;

    /// A window of one run's visible events, each folded together with the
    /// adjudication and scanner summary it caused.
    fn list_trajectory_events(
        &self,
        trajectory_id: &str,
        offset: usize,
        limit: usize,
    ) -> impl Future<Output = Result<Page<EventDetail>>> + Send;

    /// One run's stored events, in causal order — the raw grain, unfolded.
    ///
    /// This is what lets a caller derive its own projections (a UI strip, a
    /// report) without the store having to know about them.
    fn trajectory_events(
        &self,
        trajectory_id: &str,
    ) -> impl Future<Output = Result<Vec<Event>>> + Send;

    /// Live feed of new and updated run rollups, honoring the same clauses as
    /// [`Self::list_trajectories`].
    fn stream_trajectories(
        &self,
        filter: &TrajectoryFilter,
    ) -> impl Future<Output = Result<TrajectoryStream>> + Send;

    /// One run's stored event backlog followed by a tail of newly inserted
    /// events.
    fn stream_trajectory(
        &self,
        trajectory_id: &str,
    ) -> impl Future<Output = Result<TrajectoryEventStream>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trajectory::{
        Action, AgentIntent, Completed, MessageType, Observation, Scanned, ShellCommand, Started,
        Terminated,
    };
    use crate::{Actor, Agent, Causality, PolicyMetadata, Thought};
    use chrono::TimeZone;

    fn event_scan_result() -> EventScanResult {
        EventScanResult {
            explanation: String::new(),
            message_type: MessageType::ToolResult,
            intent: AgentIntent::Investigate,
            description: String::new(),
            key_entities: Vec::new(),
            is_side_effecting: false,
            signals: Vec::new(),
            confidence: 0.0,
            embedding: None,
        }
    }

    fn event(index: i64, payload: TrajectoryEvent) -> Event {
        Event {
            event_id: format!("event-{index}"),
            trajectory_id: "run-1".to_string(),
            agent: Agent::new("agent-1", "test", ""),
            timestamp: Utc.timestamp_millis_opt(index * 1_000).unwrap(),
            event: payload,
            actor: Actor::agent("agent-1"),
            causality: Causality::default(),
        }
    }

    /// An adjudication causally linked to the source event at `source_index`.
    fn adjudication(index: i64, source_index: i64, adjudicated: Adjudicated) -> Event {
        let mut event = event(
            index,
            TrajectoryEvent::Control(Control::Adjudicated(adjudicated)),
        );
        event.causality = event.causality.caused_by(format!("event-{source_index}"));
        event
    }

    fn shell(command: &str) -> TrajectoryEvent {
        TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new(command)))
    }

    #[test]
    fn a_rollup_carries_the_agent_duration_and_verdict_of_its_events() {
        let events = vec![
            event(0, shell("rm -rf /")),
            adjudication(
                2,
                0,
                Adjudicated::deny()
                    .with_metadata(PolicyMetadata::new().with_id("policies/no-shell".into())),
            ),
            event(
                3,
                TrajectoryEvent::Control(Control::Completed(Completed::new())),
            ),
        ];

        let trajectory = Trajectory::summarize("run-1", &events);
        assert_eq!(trajectory.id, "run-1");
        assert_eq!(trajectory.agent_id, "agent-1");
        assert_eq!(trajectory.duration_ms, 3_000);
        assert_eq!(trajectory.decision, Some(Decision::Deny));
        assert_eq!(
            trajectory.policy_hits,
            vec!["policies/no-shell".to_string()]
        );
        assert_eq!(trajectory.status, TrajectoryStatus::Completed);
        // The adjudication folds onto the action, so it is not its own row.
        assert_eq!(trajectory.event_count, 2);
    }

    #[test]
    fn a_terminal_run_is_not_pinned_to_running_by_a_trailing_adjudication() {
        // The harness appends the adjudication *after* the control event it
        // cleared, so a status derived from "last control event" would read the
        // finished run as still running.
        let events = vec![
            event(
                0,
                TrajectoryEvent::Control(Control::Completed(Completed::new())),
            ),
            event(
                1,
                TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
            ),
        ];
        assert_eq!(
            Trajectory::summarize("run-1", &events).status,
            TrajectoryStatus::Completed
        );
    }

    #[test]
    fn digest_and_scan_are_detail_only() {
        let events = vec![
            event(0, shell("x")),
            event(
                1,
                TrajectoryEvent::Control(Control::Scanned(Scanned::message(
                    "event-0",
                    event_scan_result(),
                ))),
            ),
        ];
        let listed = Trajectory::summarize("run-1", &events);
        assert!(listed.digest.is_none() && listed.scan.is_none());
    }

    #[test]
    fn the_terminal_events_reason_becomes_the_run_summary() {
        let events = vec![
            event(0, shell("boom")),
            event(
                1,
                TrajectoryEvent::Control(Control::Terminated(Terminated::new("timeout", "system"))),
            ),
        ];
        assert_eq!(Trajectory::summarize("run-1", &events).summary, "timeout");
    }

    #[test]
    fn a_run_with_no_events_rolls_up_to_an_empty_shell() {
        let trajectory = Trajectory::summarize("run-1", &[]);
        assert_eq!(trajectory.agent_id, "");
        assert_eq!(trajectory.duration_ms, 0);
        assert_eq!(trajectory.event_count, 0);
        assert_eq!(trajectory.status, TrajectoryStatus::Pending);
    }

    #[test]
    fn deny_outranks_escalate_for_the_run_verdict() {
        let events = vec![
            event(0, shell("curl evil.sh")),
            adjudication(
                1,
                0,
                Adjudicated::escalate()
                    .with_metadata(PolicyMetadata::new().with_id("policies/review".into())),
            ),
            adjudication(
                2,
                0,
                Adjudicated::deny()
                    .with_metadata(PolicyMetadata::new().with_id("policies/no-net".into())),
            ),
        ];
        assert_eq!(run_decision(&events), Some(Decision::Deny));
        assert_eq!(
            run_policy_hits(&events),
            vec!["policies/review".to_string(), "policies/no-net".to_string()]
        );
    }

    #[test]
    fn detail_fold_hides_governance_events_and_attaches_them_to_their_source() {
        let events = vec![
            event(0, shell("rm -rf /")),
            adjudication(1, 0, Adjudicated::deny()),
            {
                let mut scanned = event(
                    2,
                    TrajectoryEvent::Control(Control::Scanned(Scanned::message(
                        "event-0",
                        event_scan_result(),
                    ))),
                );
                scanned.causality = scanned.causality.caused_by("event-0");
                scanned
            },
            event(
                3,
                TrajectoryEvent::Control(Control::Completed(Completed::new())),
            ),
        ];

        let details = fold_event_details(&events);
        // Only the shell action and the lifecycle bookend remain as rows.
        assert_eq!(details.len(), 2);
        assert_eq!(details[0].event.event_id, "event-0");
        assert_eq!(
            details[0].adjudication.as_ref().map(|a| a.decision),
            Some(Decision::Deny)
        );
        assert!(details[0].summary.is_some());
        assert_eq!(details[1].event.event_id, "event-3");
        assert!(details[1].adjudication.is_none());
    }

    #[test]
    fn orphan_adjudications_are_hidden_without_attaching_anywhere() {
        // No causation_id: the verdict still counts toward the run decision, but
        // it must not surface as a bare detail row.
        let events = vec![
            event(0, shell("x")),
            event(
                1,
                TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::deny())),
            ),
        ];
        let details = fold_event_details(&events);
        assert_eq!(details.len(), 1);
        assert!(details[0].adjudication.is_none());
        assert_eq!(run_decision(&events), Some(Decision::Deny));
    }

    #[test]
    fn a_filter_checks_derived_clauses_but_leaves_the_agent_column_alone() {
        let trajectory = Trajectory::summarize(
            "run-1",
            &[event(
                0,
                TrajectoryEvent::Control(Control::Started(Started::new(Agent::new(
                    "agent-1", "test", "",
                )))),
            )],
        );

        assert!(TrajectoryFilter::default().matches(&trajectory));
        assert!(
            TrajectoryFilter {
                status: Some(TrajectoryStatus::Running),
                ..Default::default()
            }
            .matches(&trajectory)
        );
        assert!(
            !TrajectoryFilter {
                decision: Some(Decision::Deny),
                ..Default::default()
            }
            .matches(&trajectory)
        );
        // The agent clause is a stored column, applied before the rollup exists.
        assert!(
            TrajectoryFilter {
                agent_id: Some("somebody-else".to_string()),
                ..Default::default()
            }
            .matches(&trajectory)
        );
    }

    #[test]
    fn a_thought_only_run_reports_no_verdict_rather_than_allow() {
        // "nothing was checked" and "everything was permitted" are different
        // audit claims.
        let events = vec![event(
            0,
            TrajectoryEvent::Observation(Observation::Thought(Thought::new("hm"))),
        )];
        assert_eq!(Trajectory::summarize("run-1", &events).decision, None);
    }
}
