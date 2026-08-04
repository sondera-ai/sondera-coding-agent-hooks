//! [`TrajectoryReaderWriter`] over the Turso ledger.
//!
//! Writes append to `trajectory_events` (upserting agent identity so the agent
//! surface sees every agent that has acted). Reads project the domain shapes: a
//! [`Trajectory`] rolled up from a run's events, and the folded [`EventDetail`]
//! list.
//!
//! The rollups themselves are not computed here — they are pure folds over
//! `&[Event]` that live in `sondera_types` ([`Trajectory::summarize`],
//! [`fold_event_details`]), so this module only decides *which* events to load.
//! Deriving a run's decision, policy hits, digest, and scan means interpreting
//! the serialized `TrajectoryEvent` JSON, and this is a single-machine local
//! database where reading a run's events is cheap. SQL still does the work it is
//! good at: filtering, aggregating counts, and bounding what gets loaded.
//!
//! Every method takes bare ids and pre-parsed filter clauses; resource names and
//! the wire filter grammar belong to the service edge.

use super::scan;
use super::{StoreResult, TrajectoryStore, events, store_err};
use chrono::{DateTime, Utc};
use sondera_types::{
    Event, EventDetail, EventScanResult, Page, Trajectory, TrajectoryEventStream, TrajectoryFilter,
    TrajectoryOrderBy, TrajectoryQuery, TrajectoryReaderWriter, TrajectoryScans, TrajectoryStream,
    fold_event_details,
};
use std::collections::HashMap;
use tracing::debug;
use turso::Connection;

/// The `INSERT` both write paths share. Column list and placeholders are kept
/// together so they cannot drift apart.
const INSERT_EVENT: &str = r#"
    INSERT INTO trajectory_events (
        event_id, trajectory_id, agent_id, agent_provider,
        timestamp, event_category, event_type, event_json,
        actor_id, actor_type, correlation_id, causation_id, parent_id
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
"#;

/// The bound parameters for [`INSERT_EVENT`], owned so they outlive the borrow
/// of `event` inside a transaction loop.
fn insert_params(event: &Event) -> StoreResult<[String; 13]> {
    let (category, event_type) = TrajectoryStore::extract_event_info(&event.event);
    let event_json = serde_json::to_string(&event.event)
        .map_err(|e| store_err("Failed to serialize event", e))?;

    Ok([
        event.event_id.clone(),
        event.trajectory_id.clone(),
        event.agent.id.clone(),
        event.agent.provider.clone(),
        event.timestamp.to_rfc3339(),
        category.to_string(),
        event_type.unwrap_or("").to_string(),
        event_json,
        event.actor.id.clone(),
        format!("{:?}", event.actor.actor_type),
        event.causality.correlation_id.clone(),
        event.causality.causation_id.clone().unwrap_or_default(),
        event.causality.parent_id.clone().unwrap_or_default(),
    ])
}

impl TrajectoryReaderWriter for TrajectoryStore {
    async fn insert_event(&self, event: &Event) -> StoreResult<()> {
        // Register the agent first: an agent read must never miss an agent that
        // has produced events, and the two writes are ordered so a crash between
        // them leaves an extra agent row rather than an orphaned event.
        self.register_agent(&event.agent).await?;

        self.connection()?
            .execute(INSERT_EVENT, insert_params(event)?)
            .await
            .map_err(|e| store_err("Failed to insert event", e))?;

        debug!(
            "Inserted event: {} for trajectory: {}",
            event.event_id, event.trajectory_id
        );
        Ok(())
    }

    async fn insert_events(&self, batch: &[Event]) -> StoreResult<()> {
        for agent in batch.iter().map(|event| &event.agent) {
            self.register_agent(agent).await?;
        }

        // Bound rather than used inline: the transaction borrows its
        // connection, and every statement in the batch has to run on that one.
        let conn = self.connection()?;
        let tx = conn
            .unchecked_transaction()
            .await
            .map_err(|e| store_err("Failed to begin transaction", e))?;

        for event in batch {
            if let Err(error) = tx.execute(INSERT_EVENT, insert_params(event)?).await {
                tx.rollback()
                    .await
                    .map_err(|e| store_err("Failed to roll back event batch", e))?;
                return Err(store_err("Failed to insert event", error));
            }
        }

        tx.commit()
            .await
            .map_err(|e| store_err("Failed to commit event batch", e))?;
        debug!("Inserted {} events in batch", batch.len());
        Ok(())
    }

    async fn delete_trajectory(&self, id: &str) -> StoreResult<u64> {
        let deleted = self
            .connection()?
            .execute(
                "DELETE FROM trajectory_events WHERE trajectory_id = ?1",
                [id],
            )
            .await
            .map_err(|e| store_err("Failed to delete trajectory", e))?;

        // The scan tables are keyed by trajectory, not joined by a live foreign
        // key, so they have to be told. Deleted after the events: a crash
        // between the two leaves orphaned enrichment, which reads ignore,
        // rather than events whose summaries have silently vanished.
        scan::delete_scans(&self.connection()?, id).await?;

        debug!("Deleted {deleted} events for trajectory: {id}");
        Ok(deleted)
    }

    async fn get_trajectory(&self, id: &str) -> StoreResult<Option<Trajectory>> {
        let conn = self.connection()?;
        let Some(mut trajectory) = rollup(&conn, id, Trajectory::detail).await? else {
            return Ok(None);
        };
        attach_scans(&mut trajectory, scan::transcript_scans(&conn, id).await?);
        Ok(Some(trajectory))
    }

    async fn list_trajectories(&self, query: &TrajectoryQuery) -> StoreResult<Page<Trajectory>> {
        let conn = self.connection()?;
        let mut trajectories = trajectories_matching(&conn, &query.filter).await?;
        sort_trajectories(&mut trajectories, query.order_by, query.descending);

        // Enrich the whole matched set before windowing. Two grouped queries
        // cover every run, so this does not scale with the page size, and
        // sorting already required the full set in memory.
        let mut scans = scan::latest_transcript_scans(&conn).await?;
        for trajectory in &mut trajectories {
            if let Some(found) = scans.remove(&trajectory.id) {
                attach_scans(trajectory, found);
            }
        }

        Ok(Page::slice(trajectories, query.offset, query.limit))
    }

    async fn list_trajectory_events(
        &self,
        trajectory_id: &str,
        offset: usize,
        limit: usize,
    ) -> StoreResult<Page<EventDetail>> {
        // The fold hides the causally linked adjudication/scan control events, so
        // paging must run over the folded list — paging the raw rows would leave
        // short pages wherever governance events were removed.
        let mut details = fold_event_details(&self.trajectory_events(trajectory_id).await?);
        attach_event_scans(
            &mut details,
            scan::event_scans(&self.connection()?, trajectory_id).await?,
        );
        Ok(Page::slice(details, offset, limit))
    }

    async fn trajectory_events(&self, trajectory_id: &str) -> StoreResult<Vec<Event>> {
        events(&self.connection()?, trajectory_id).await
    }

    async fn stream_trajectories(
        &self,
        filter: &TrajectoryFilter,
    ) -> StoreResult<TrajectoryStream> {
        self.spawn_trajectory_stream(filter.clone())
    }

    async fn stream_trajectory(&self, trajectory_id: &str) -> StoreResult<TrajectoryEventStream> {
        self.spawn_trajectory_event_stream(trajectory_id.to_string())
    }
}

/// Overlay a run's stored transcript digest and behavioral scan onto its rollup.
///
/// The rollup already projects both from the run's `Scanned` control events, and
/// that projection stays as the fallback — a store written by an older harness,
/// or one whose table write failed after the control event landed, still renders.
/// The table wins when it has a row: it is what the scanner committed, it is the
/// only place an *interim* digest survives being superseded, and it is not
/// subject to a control event being trimmed from the ledger.
fn attach_scans(trajectory: &mut Trajectory, scans: TrajectoryScans) {
    if let Some(digest) = scans.digest {
        // The run summary is the digest title when there is one, so it has to
        // follow the digest rather than keep the value the fold derived.
        trajectory.summary = digest.title.clone();
        trajectory.digest = Some(digest);
    }
    if let Some(scan) = scans.scan {
        trajectory.scan = Some(scan);
    }
}

/// Overlay stored message-level scans onto the folded event details.
///
/// Same precedence as [`attach_scans`], for the same reason: the folded
/// `Scanned` control event is the log record, the table row is what the scanner
/// committed.
fn attach_event_scans(details: &mut [EventDetail], mut scans: HashMap<String, EventScanResult>) {
    for detail in details {
        if let Some(summary) = scans.remove(&detail.event.event_id) {
            detail.summary = Some(summary);
        }
    }
}

/// Ordering for `list_trajectories`.
fn sort_trajectories(
    trajectories: &mut [Trajectory],
    order_by: TrajectoryOrderBy,
    descending: bool,
) {
    match order_by {
        TrajectoryOrderBy::EventCount => {
            trajectories.sort_by_key(|trajectory| trajectory.event_count)
        }
        TrajectoryOrderBy::UpdateTime => {
            trajectories.sort_by_key(|trajectory| trajectory.update_time)
        }
        TrajectoryOrderBy::StartTime => {
            trajectories.sort_by_key(|trajectory| trajectory.started_at)
        }
    }
    if descending {
        trajectories.reverse();
    }
}

/// A per-run change fingerprint: how many events the run has and when the last
/// one landed.
///
/// The live tail compares this before rebuilding anything, so an idle poll costs
/// one grouped aggregate over the ledger rather than a full re-read of every
/// run's events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunFingerprint {
    pub event_count: i64,
    pub last_event_at: Option<DateTime<Utc>>,
}

/// Fingerprints for every trajectory, optionally narrowed to one agent.
pub(crate) async fn fingerprints(
    conn: &Connection,
    agent_id: Option<&str>,
) -> StoreResult<Vec<(String, RunFingerprint)>> {
    const PROJECTION: &str =
        "SELECT trajectory_id, COUNT(*), MAX(timestamp) FROM trajectory_events";

    let mut rows = match agent_id {
        Some(agent_id) => {
            conn.query(
                &format!("{PROJECTION} WHERE agent_id = ?1 GROUP BY trajectory_id"),
                [agent_id],
            )
            .await
        }
        None => {
            conn.query(&format!("{PROJECTION} GROUP BY trajectory_id"), ())
                .await
        }
    }
    .map_err(|e| store_err("Failed to list trajectories", e))?;

    let mut runs = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| store_err("Failed to read trajectory row", e))?
    {
        let id = row
            .get_value(0)
            .map_err(|e| store_err("Failed to read trajectory id", e))?
            .as_text()
            .cloned();
        let Some(id) = id else { continue };
        let event_count = row
            .get_value(1)
            .map_err(|e| store_err("Failed to read event count", e))?
            .as_integer()
            .copied()
            .unwrap_or_default();
        runs.push((
            id,
            RunFingerprint {
                event_count,
                last_event_at: super::optional_timestamp(&row, 2)?,
            },
        ));
    }
    Ok(runs)
}

/// Every trajectory matching `filter`, as list-grained rollups.
///
/// The agent clause is pushed into SQL (it is a stored column); status and
/// decision are derived rollups, so they are applied to the built summaries.
///
/// Takes a bare `&Connection` rather than `&TrajectoryStore` so the live tail —
/// which owns its own connection and outlives the borrow that spawned it — runs
/// the same projection as `list_trajectories` instead of a parallel copy.
pub(crate) async fn trajectories_matching(
    conn: &Connection,
    filter: &TrajectoryFilter,
) -> StoreResult<Vec<Trajectory>> {
    let runs = fingerprints(conn, filter.agent_id.as_deref()).await?;

    let mut trajectories = Vec::with_capacity(runs.len());
    for (id, _) in runs {
        if let Some(trajectory) = rollup(conn, &id, Trajectory::summarize).await?
            && filter.matches(&trajectory)
        {
            trajectories.push(trajectory);
        }
    }
    Ok(trajectories)
}

/// Roll one run up at the grain `fold` implies, or `None` when it has no events.
///
/// Parameterized by the fold rather than by a flag so the two grains
/// ([`Trajectory::summarize`] and [`Trajectory::detail`]) stay the domain's to
/// define and this layer only decides which one a given read wants.
pub(crate) async fn rollup(
    conn: &Connection,
    trajectory_id: &str,
    fold: fn(&str, &[Event]) -> Trajectory,
) -> StoreResult<Option<Trajectory>> {
    let events = events(conn, trajectory_id).await?;
    if events.is_empty() {
        return Ok(None);
    }
    Ok(Some(fold(trajectory_id, &events)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::turso::tests::{test_agent, test_event};
    use sondera_types::{
        Action, Adjudicated, AgentIntent, AgentReaderWriter, Completed, Control, Decision,
        EventScanResult, MessageType, Observation, PolicyMetadata, ScanReaderWriter, ScanSource,
        ShellCommand, SignalSeverity, Started, Thought, TrajectoryEvent, TrajectoryStatus,
        TranscriptDigest, TranscriptOutcome, TranscriptScanResult,
    };

    async fn store_with(events: Vec<Event>) -> TrajectoryStore {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store.insert_events(&events).await.unwrap();
        store
    }

    /// A shell action followed by the deny that governed it, then a completion.
    fn denied_run(trajectory_id: &str) -> Vec<Event> {
        let action = test_event(
            trajectory_id,
            TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("rm -rf /"))),
        );
        let mut adjudication = test_event(
            trajectory_id,
            TrajectoryEvent::Control(Control::Adjudicated(
                Adjudicated::deny()
                    .with_metadata(PolicyMetadata::new().with_id("policies/no-shell".into())),
            )),
        );
        adjudication.causality = adjudication.causality.caused_by(action.event_id.clone());
        let completed = test_event(
            trajectory_id,
            TrajectoryEvent::Control(Control::Completed(Completed::new())),
        );
        vec![action, adjudication, completed]
    }

    #[tokio::test]
    async fn get_trajectory_rolls_up_decision_hits_and_status() {
        let store = store_with(denied_run("run-1")).await;

        let trajectory = store
            .get_trajectory("run-1")
            .await
            .unwrap()
            .expect("run exists");
        assert_eq!(trajectory.id, "run-1");
        assert_eq!(trajectory.agent_id, "test-agent");
        assert_eq!(trajectory.decision, Some(Decision::Deny));
        assert_eq!(
            trajectory.policy_hits,
            vec!["policies/no-shell".to_string()]
        );
        assert_eq!(trajectory.status, TrajectoryStatus::Completed);
        // The adjudication folds onto the action, so it is not its own row.
        assert_eq!(trajectory.event_count, 2);
    }

    #[tokio::test]
    async fn get_trajectory_reports_unknown_runs_as_absent() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        assert!(store.get_trajectory("nope").await.unwrap().is_none());
        // The surface takes bare ids, so a resource name simply names no run.
        assert!(
            store
                .get_trajectory("trajectories/run-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn list_trajectory_events_folds_governance_onto_its_source() {
        let store = store_with(denied_run("run-1")).await;

        let page = store
            .list_trajectory_events("run-1", 0, usize::MAX)
            .await
            .unwrap();

        assert_eq!(page.total, 2);
        assert_eq!(page.items.len(), 2);
        assert_eq!(
            page.items[0].adjudication.as_ref().map(|a| a.decision),
            Some(Decision::Deny)
        );
    }

    #[tokio::test]
    async fn trajectory_events_returns_the_raw_unfolded_grain() {
        // The fold is the caller's to apply: this read hands back every stored
        // row, governance events included, so a caller can build its own
        // projection.
        let store = store_with(denied_run("run-1")).await;
        assert_eq!(store.trajectory_events("run-1").await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn list_trajectories_filters_by_agent_status_and_decision() {
        let mut events = denied_run("denied");
        events.extend([
            test_event(
                "clean",
                TrajectoryEvent::Observation(Observation::Thought(Thought::new("thinking"))),
            ),
            test_event(
                "clean",
                TrajectoryEvent::Control(Control::Started(Started::new(test_agent()))),
            ),
        ]);
        let store = store_with(events).await;

        let query = |filter: TrajectoryFilter| TrajectoryQuery {
            filter,
            ..Default::default()
        };

        let all = store
            .list_trajectories(&query(TrajectoryFilter::default()))
            .await
            .unwrap();
        assert_eq!(all.total, 2);

        let denied = store
            .list_trajectories(&query(TrajectoryFilter {
                decision: Some(Decision::Deny),
                ..Default::default()
            }))
            .await
            .unwrap();
        assert_eq!(denied.total, 1);
        assert_eq!(denied.items[0].id, "denied");

        let running = store
            .list_trajectories(&query(TrajectoryFilter {
                status: Some(TrajectoryStatus::Running),
                ..Default::default()
            }))
            .await
            .unwrap();
        assert_eq!(running.total, 1);
        assert_eq!(running.items[0].id, "clean");

        let by_agent = store
            .list_trajectories(&query(TrajectoryFilter {
                agent_id: Some("test-agent".to_string()),
                ..Default::default()
            }))
            .await
            .unwrap();
        assert_eq!(by_agent.total, 2);

        let other_agent = store
            .list_trajectories(&query(TrajectoryFilter {
                agent_id: Some("nobody".to_string()),
                ..Default::default()
            }))
            .await
            .unwrap();
        assert_eq!(other_agent.total, 0);
    }

    #[tokio::test]
    async fn list_trajectories_windows_the_filtered_set() {
        let mut events = Vec::new();
        for index in 0..5 {
            events.push(test_event(
                &format!("run-{index}"),
                TrajectoryEvent::Observation(Observation::Thought(Thought::new("t"))),
            ));
        }
        let store = store_with(events).await;

        let first = store
            .list_trajectories(&TrajectoryQuery {
                limit: 2,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(first.items.len(), 2);
        assert_eq!(first.total, 5);

        let last = store
            .list_trajectories(&TrajectoryQuery {
                offset: 4,
                limit: 2,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(last.items.len(), 1);
        assert_eq!(last.total, 5);
    }

    fn digest(title: &str) -> TranscriptDigest {
        TranscriptDigest {
            trajectory_id: "run-1".to_string(),
            title: title.to_string(),
            summary: "Investigated, then implemented.".to_string(),
            interim: false,
            phases: Vec::new(),
            files_modified: vec!["src/auth.rs".to_string()],
            tools_used: vec!["Write".to_string()],
            total_events: 2,
            side_effecting_count: 1,
        }
    }

    fn behavioral_scan() -> TranscriptScanResult {
        TranscriptScanResult {
            explanation: "One denial, otherwise clean.".to_string(),
            outcome: TranscriptOutcome::Partial,
            outcome_description: "Blocked once.".to_string(),
            aggregate_severity: SignalSeverity::High,
            signals: Vec::new(),
            adjudication_summary: "1 deny.".to_string(),
            behavioral_notes: Vec::new(),
            confidence: 0.9,
        }
    }

    #[tokio::test]
    async fn a_detail_read_joins_the_stored_digest_and_behavioral_scan() {
        let store = store_with(denied_run("run-1")).await;
        let source = ScanSource {
            event_id: "scan-trigger",
            trajectory_id: "run-1",
            agent_id: "test-agent",
        };
        store
            .insert_transcript_digest(source, &digest("Implemented JWT auth"))
            .await
            .unwrap();
        store
            .insert_transcript_scan(source, &behavioral_scan())
            .await
            .unwrap();

        let trajectory = store.get_trajectory("run-1").await.unwrap().expect("run");

        assert_eq!(
            trajectory.digest.as_ref().map(|d| d.title.as_str()),
            Some("Implemented JWT auth")
        );
        assert_eq!(
            trajectory.scan.as_ref().map(|s| s.result.outcome),
            Some(TranscriptOutcome::Partial)
        );
        assert_eq!(
            trajectory.scan.as_ref().map(|s| s.source_event_id.as_str()),
            Some("scan-trigger"),
            "the scan must name the event that triggered it"
        );
        // The one-line run summary follows the digest title once there is one.
        assert_eq!(trajectory.summary, "Implemented JWT auth");
    }

    #[tokio::test]
    async fn a_list_read_carries_the_semantic_summary_too() {
        // The list is the console's activity feed: it renders the scanner's
        // title, so leaving the digest to detail reads would make every row
        // fall back to the terminal event's reason.
        let mut events = denied_run("run-1");
        events.push(test_event(
            "run-2",
            TrajectoryEvent::Observation(Observation::Thought(Thought::new("thinking"))),
        ));
        let store = store_with(events).await;
        store
            .insert_transcript_digest(
                ScanSource {
                    event_id: "scan-trigger",
                    trajectory_id: "run-1",
                    agent_id: "test-agent",
                },
                &digest("Implemented JWT auth"),
            )
            .await
            .unwrap();

        let page = store
            .list_trajectories(&TrajectoryQuery::default())
            .await
            .unwrap();

        let scanned = page.items.iter().find(|t| t.id == "run-1").expect("run-1");
        assert_eq!(
            scanned.digest.as_ref().map(|d| d.title.as_str()),
            Some("Implemented JWT auth")
        );
        // A run the scanner has not reached stays unenriched rather than
        // borrowing another run's digest.
        let unscanned = page.items.iter().find(|t| t.id == "run-2").expect("run-2");
        assert!(unscanned.digest.is_none());
        assert!(unscanned.scan.is_none());
    }

    #[tokio::test]
    async fn event_details_carry_the_stored_per_event_summary() {
        let events = denied_run("run-1");
        let scanned_event_id = events[0].event_id.clone();
        let store = store_with(events).await;
        store
            .insert_event_scan(
                ScanSource {
                    event_id: &scanned_event_id,
                    trajectory_id: "run-1",
                    agent_id: "test-agent",
                },
                &EventScanResult {
                    explanation: "Destructive shell command.".to_string(),
                    message_type: MessageType::ToolCall,
                    intent: AgentIntent::Implement,
                    description: "Attempted 'rm -rf /'".to_string(),
                    key_entities: Vec::new(),
                    is_side_effecting: true,
                    signals: Vec::new(),
                    confidence: 0.95,
                    embedding: None,
                },
            )
            .await
            .unwrap();

        let page = store
            .list_trajectory_events("run-1", 0, usize::MAX)
            .await
            .unwrap();

        let detail = page
            .items
            .iter()
            .find(|d| d.event.event_id == scanned_event_id)
            .expect("the scanned event is still a visible row");
        assert_eq!(
            detail.summary.as_ref().map(|s| s.description.as_str()),
            Some("Attempted 'rm -rf /'")
        );
        // The adjudication fold is untouched by the scan join.
        assert_eq!(
            detail.adjudication.as_ref().map(|a| a.decision),
            Some(Decision::Deny)
        );
        // The lifecycle bookend has no scan, and gets none.
        assert!(
            page.items
                .iter()
                .any(|d| d.event.event_id != scanned_event_id && d.summary.is_none())
        );
    }

    #[tokio::test]
    async fn delete_trajectory_removes_events_but_keeps_the_agent() {
        let store = store_with(denied_run("run-1")).await;

        assert_eq!(store.delete_trajectory("run-1").await.unwrap(), 3);
        assert!(store.get_trajectory("run-1").await.unwrap().is_none());
        // The agent registered on the ingest path outlives its events.
        assert!(store.get_agent("test-agent").await.unwrap().is_some());
    }
}
