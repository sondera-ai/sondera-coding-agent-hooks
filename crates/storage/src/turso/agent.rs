//! [`AgentReaderWriter`] over the Turso ledger.
//!
//! Agent identity lives in its own `agents` table, written by the harness on the
//! ingest path. Everything else on [`AgentActivity`] — liveness, today's run
//! count, and the deny rate — is a rollup derived from that agent's
//! `trajectory_events` rows.
//!
//! This module deals in bare agent ids and pre-parsed [`AgentFilter`] clauses.
//! Resource names and the wire filter grammar belong to the service edge.

use super::{StoreResult, TrajectoryStore, optional_timestamp, store_err};
use chrono::{DateTime, Duration, NaiveTime, Utc};
use sondera_types::{
    Agent, AgentActivity, AgentFilter, AgentOrderBy, AgentQuery, AgentReaderWriter, AgentStats,
    AgentStatus, Control, Decision, Page, TrajectoryEvent,
};
use tracing::debug;

/// How long an agent may be silent before it reads as offline.
const OFFLINE_AFTER: Duration = Duration::hours(24);

/// The window the deny rate is computed over. A rate over all recorded history
/// would never recover from an old block, which is the opposite of what a
/// liveness signal is for.
const DENY_RATE_WINDOW: Duration = Duration::hours(24);

/// Deny rate above which an agent reads as degraded rather than healthy.
const DEGRADED_DENY_RATE: f64 = 0.3;

impl AgentReaderWriter for TrajectoryStore {
    async fn upsert_agent(&self, agent: &Agent) -> StoreResult<()> {
        self.register_agent(agent).await
    }

    async fn list_agents(&self, query: &AgentQuery) -> StoreResult<Page<AgentActivity>> {
        let mut agents = self.agents_matching(&query.filter).await?;
        sort_agents(&mut agents, query.order_by, query.descending);
        Ok(Page::slice(agents, query.offset, query.limit))
    }

    async fn get_agent(&self, id: &str) -> StoreResult<Option<AgentActivity>> {
        let Some(identity) = self.agent_identity(id).await? else {
            return Ok(None);
        };
        Ok(Some(self.project_agent(identity).await?))
    }

    async fn analyze_agents(&self, filter: &AgentFilter) -> StoreResult<AgentStats> {
        Ok(AgentStats::tally(&self.agents_matching(filter).await?))
    }

    async fn delete_agent(&self, id: &str) -> StoreResult<bool> {
        let conn = self.connection()?;
        let tx = conn
            .unchecked_transaction()
            .await
            .map_err(|e| store_err("Failed to begin agent deletion", e))?;
        // CONTEXT: Turso transactions roll back on drop, so any `?` below
        // preserves every table when the complete hard delete cannot commit.
        for table in [
            "event_scan_results",
            "transcript_digest_results",
            "transcript_scan_results",
        ] {
            tx.execute(&format!("DELETE FROM {table} WHERE agent_id = ?1"), [id])
                .await
                .map_err(|e| store_err("Failed to delete agent scans", e))?;
        }
        let events = tx
            .execute("DELETE FROM trajectory_events WHERE agent_id = ?1", [id])
            .await
            .map_err(|e| store_err("Failed to delete agent events", e))?;
        let agents = tx
            .execute("DELETE FROM agents WHERE id = ?1", [id])
            .await
            .map_err(|e| store_err("Failed to delete agent", e))?;
        tx.commit()
            .await
            .map_err(|e| store_err("Failed to commit agent deletion", e))?;

        debug!("Deleted agent {id}: {agents} identity rows, {events} events");
        Ok(agents > 0 || events > 0)
    }

    async fn latest_trajectory_id(&self, agent_id: &str) -> StoreResult<Option<String>> {
        // Phrased as "the newest timestamp, then the last row at it" rather
        // than the equivalent `ORDER BY timestamp DESC, id DESC LIMIT 1`.
        // Both name the same row — the greatest `(timestamp, id)` pair — but
        // the planner only serves this one from an index. Given the ORDER BY
        // form it picks `idx_timestamp` and scans the whole table, ignoring the
        // `agent_id` predicate entirely; the MAX form searches
        // `idx_agent_timestamp`. On 20 agents / 6k events that is 270ms against
        // 3ms, and the gap widens with the ledger.
        //
        // `a_tie_within_one_millisecond_resolves_by_insertion_order` pins the
        // equivalence, since the rewrite is only safe while it holds.
        let mut rows = self
            .connection()?
            .query(
                "SELECT trajectory_id FROM trajectory_events \
                 WHERE agent_id = ?1 AND timestamp = ( \
                     SELECT MAX(timestamp) FROM trajectory_events WHERE agent_id = ?1) \
                 ORDER BY id DESC LIMIT 1",
                [agent_id],
            )
            .await
            .map_err(|e| store_err("Failed to read agent trajectories", e))?;

        let row = rows
            .next()
            .await
            .map_err(|e| store_err("Failed to read agent trajectory row", e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(row
            .get_value(0)
            .map_err(|e| store_err("Failed to read trajectory id", e))?
            .as_text()
            .cloned())
    }
}

impl TrajectoryStore {
    /// Register (or refresh) an agent's identity.
    ///
    /// Idempotent: re-reporting an agent only advances `last_seen_at` and
    /// refreshes the harness-owned provider/platform, so a hook that reports on
    /// every event costs one upsert rather than churning identity.
    pub(crate) async fn register_agent(&self, agent: &Agent) -> StoreResult<()> {
        let now = Utc::now().to_rfc3339();
        self.connection()?
            .execute(
                r#"
                INSERT INTO agents (id, provider, platform, first_seen_at, last_seen_at)
                VALUES (?1, ?2, ?3, ?4, ?4)
                ON CONFLICT(id) DO UPDATE SET
                    provider     = excluded.provider,
                    platform     = excluded.platform,
                    last_seen_at = excluded.last_seen_at
                "#,
                [
                    agent.id.clone(),
                    agent.provider.clone(),
                    agent.platform.clone(),
                    now,
                ],
            )
            .await
            .map_err(|e| store_err("Failed to register agent", e))?;
        Ok(())
    }

    /// Stored identity for one agent, if it has ever reported in.
    async fn agent_identity(&self, id: &str) -> StoreResult<Option<Agent>> {
        let mut rows = self
            .connection()?
            .query(
                "SELECT id, provider, platform FROM agents WHERE id = ?1",
                [id],
            )
            .await
            .map_err(|e| store_err("Failed to read agent", e))?;

        let row = rows
            .next()
            .await
            .map_err(|e| store_err("Failed to read agent row", e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(row_to_agent(&row)?))
    }

    /// Every agent matching `filter`, fully projected.
    async fn agents_matching(&self, filter: &AgentFilter) -> StoreResult<Vec<AgentActivity>> {
        let mut rows = self
            .connection()?
            .query("SELECT id, provider, platform FROM agents", ())
            .await
            .map_err(|e| store_err("Failed to list agents", e))?;

        let mut identities = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| store_err("Failed to read agent row", e))?
        {
            let agent = row_to_agent(&row)?;
            if filter.matches(&agent) {
                identities.push(agent);
            }
        }

        let mut agents = Vec::with_capacity(identities.len());
        for identity in identities {
            agents.push(self.project_agent(identity).await?);
        }
        Ok(agents)
    }

    /// Build the rollup for one agent: identity plus the activity derived from
    /// its events.
    async fn project_agent(&self, identity: Agent) -> StoreResult<AgentActivity> {
        let last_active_time = self.agent_last_active(&identity.id).await?;
        let deny_rate = self.agent_deny_rate(&identity.id).await?;

        Ok(AgentActivity {
            runs_today: self.agent_runs_today(&identity.id).await?,
            health_score: health_score(deny_rate),
            status: status(last_active_time, deny_rate),
            last_active_time,
            deny_rate,
            ..identity.into()
        })
    }

    /// Timestamp of the agent's most recent event, if it has produced any.
    async fn agent_last_active(&self, id: &str) -> StoreResult<Option<DateTime<Utc>>> {
        let mut rows = self
            .connection()?
            .query(
                "SELECT MAX(timestamp) FROM trajectory_events WHERE agent_id = ?1",
                [id],
            )
            .await
            .map_err(|e| store_err("Failed to read agent activity", e))?;

        match rows
            .next()
            .await
            .map_err(|e| store_err("Failed to read agent activity row", e))?
        {
            Some(row) => optional_timestamp(&row, 0),
            None => Ok(None),
        }
    }

    /// Distinct trajectories the agent has touched since UTC midnight.
    async fn agent_runs_today(&self, id: &str) -> StoreResult<i32> {
        let midnight = Utc::now()
            .date_naive()
            .and_time(NaiveTime::MIN)
            .and_utc()
            .to_rfc3339();

        let mut rows = self
            .connection()?
            .query(
                "SELECT COUNT(DISTINCT trajectory_id) FROM trajectory_events \
                 WHERE agent_id = ?1 AND timestamp >= ?2",
                [id.to_string(), midnight],
            )
            .await
            .map_err(|e| store_err("Failed to count agent runs", e))?;

        match rows
            .next()
            .await
            .map_err(|e| store_err("Failed to read agent run count", e))?
        {
            Some(row) => Ok(row
                .get_value(0)
                .map_err(|e| store_err("Failed to read agent run count", e))?
                .as_integer()
                .copied()
                .unwrap_or(0) as i32),
            None => Ok(0),
        }
    }

    /// Share of the agent's recent adjudications that did not clear.
    ///
    /// `0.0` when nothing has been adjudicated in the window — an idle agent is
    /// not a blocked one.
    async fn agent_deny_rate(&self, id: &str) -> StoreResult<f64> {
        let cutoff = (Utc::now() - DENY_RATE_WINDOW).to_rfc3339();

        let mut rows = self
            .connection()?
            .query(
                "SELECT event_json FROM trajectory_events \
                 WHERE agent_id = ?1 AND event_category = 'Control' \
                   AND event_type = 'Adjudicated' AND timestamp >= ?2",
                [id.to_string(), cutoff],
            )
            .await
            .map_err(|e| store_err("Failed to read agent adjudications", e))?;

        let (mut total, mut fired) = (0_u32, 0_u32);
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| store_err("Failed to read adjudication row", e))?
        {
            let Ok(value) = row.get_value(0) else {
                continue;
            };
            let Some(json) = value.as_text() else {
                continue;
            };
            // A row that fails to decode is skipped rather than failing the whole
            // projection: one unreadable event must not blank an agent's rollup.
            let Ok(TrajectoryEvent::Control(Control::Adjudicated(adjudicated))) =
                serde_json::from_str::<TrajectoryEvent>(json)
            else {
                continue;
            };
            total += 1;
            if adjudicated.decision != Decision::Allow {
                fired += 1;
            }
        }

        Ok(if total == 0 {
            0.0
        } else {
            f64::from(fired) / f64::from(total)
        })
    }
}

fn row_to_agent(row: &turso::Row) -> StoreResult<Agent> {
    let text = |index: usize| -> StoreResult<String> {
        Ok(row
            .get_value(index)
            .map_err(|e| store_err("Failed to read agent column", e))?
            .as_text()
            .cloned()
            .unwrap_or_default())
    };
    Ok(Agent {
        id: text(0)?,
        provider: text(1)?,
        platform: text(2)?,
    })
}

/// A simple inverse of the deny rate, clamped to 0–100.
fn health_score(deny_rate: f64) -> i32 {
    let score = ((1.0 - deny_rate) * 100.0).round();
    score.clamp(0.0, 100.0) as i32
}

/// The liveness dot: silence past [`OFFLINE_AFTER`] reads as offline regardless
/// of how clean the agent's record is, since a stale rate says nothing about
/// what the agent is doing now.
fn status(last_active: Option<DateTime<Utc>>, deny_rate: f64) -> AgentStatus {
    let Some(last_active) = last_active else {
        return AgentStatus::Offline;
    };
    if Utc::now() - last_active > OFFLINE_AFTER {
        return AgentStatus::Offline;
    }
    if deny_rate > DEGRADED_DENY_RATE {
        AgentStatus::Degraded
    } else {
        AgentStatus::Healthy
    }
}

fn sort_agents(agents: &mut [AgentActivity], order_by: AgentOrderBy, descending: bool) {
    match order_by {
        AgentOrderBy::Id => agents.sort_by(|a, b| a.agent.id.cmp(&b.agent.id)),
        AgentOrderBy::RunsToday => agents.sort_by_key(|agent| agent.runs_today),
        AgentOrderBy::LastActive => agents.sort_by_key(|agent| agent.last_active_time),
    }
    if descending {
        agents.reverse();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::turso::tests::{test_agent, test_event};
    use chrono::TimeZone;
    use sondera_types::{
        Action, Adjudicated, Event, Observation, ShellCommand, Thought, TrajectoryEvent,
        TrajectoryReaderWriter,
    };

    async fn store_with(events: Vec<Event>) -> TrajectoryStore {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store.insert_events(&events).await.unwrap();
        store
    }

    async fn rows_for_agent(store: &TrajectoryStore, table: &str, agent_id: &str) -> i64 {
        let conn = store.connection().unwrap();
        let mut rows = conn
            .query(
                &format!("SELECT COUNT(*) FROM {table} WHERE agent_id = ?1"),
                [agent_id],
            )
            .await
            .unwrap();
        rows.next()
            .await
            .unwrap()
            .unwrap()
            .get_value(0)
            .unwrap()
            .as_integer()
            .copied()
            .unwrap()
    }

    #[tokio::test]
    async fn inserting_an_event_registers_its_agent() {
        let store = store_with(vec![test_event(
            "run-1",
            TrajectoryEvent::Observation(Observation::Thought(Thought::new("t"))),
        )])
        .await;

        let agent = store
            .get_agent("test-agent")
            .await
            .unwrap()
            .expect("agent registered by the ingest path");
        assert_eq!(agent.agent.id, "test-agent");
        assert_eq!(agent.agent.provider, "test-provider");
        assert_eq!(agent.runs_today, 1);
        assert_eq!(agent.status, AgentStatus::Healthy);
    }

    #[tokio::test]
    async fn an_agent_with_no_events_lists_as_offline() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store.upsert_agent(&test_agent()).await.unwrap();

        let agent = store.get_agent("test-agent").await.unwrap().unwrap();
        assert_eq!(agent.status, AgentStatus::Offline);
        assert_eq!(agent.runs_today, 0);
        assert_eq!(agent.deny_rate, 0.0);
        // An idle agent is not a blocked one.
        assert_eq!(agent.health_score, 100);
        assert!(
            store
                .latest_trajectory_id("test-agent")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn upsert_is_idempotent_and_refreshes_identity() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store.upsert_agent(&test_agent()).await.unwrap();
        store
            .upsert_agent(&Agent::new("test-agent", "anthropic", "claude-code"))
            .await
            .unwrap();

        let page = store.list_agents(&AgentQuery::default()).await.unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].agent.provider, "anthropic");
        assert_eq!(page.items[0].agent.platform, "claude-code");
    }

    #[tokio::test]
    async fn deny_rate_drives_health_and_degraded_status() {
        let denied = |trajectory: &str| {
            test_event(
                trajectory,
                TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::deny())),
            )
        };
        let allowed = |trajectory: &str| {
            test_event(
                trajectory,
                TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
            )
        };
        let store = store_with(vec![denied("run-1"), allowed("run-1"), denied("run-2")]).await;

        let agent = store.get_agent("test-agent").await.unwrap().unwrap();
        assert!((agent.deny_rate - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(agent.health_score, 33);
        assert_eq!(agent.status, AgentStatus::Degraded);
        assert_eq!(agent.runs_today, 2);
    }

    #[tokio::test]
    async fn analyze_counts_the_filtered_roster() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store
            .upsert_agent(&Agent::new("a", "anthropic", "claude-code"))
            .await
            .unwrap();
        store
            .upsert_agent(&Agent::new("b", "openai", "codex"))
            .await
            .unwrap();
        store
            .insert_event(&Event::new(
                Agent::new("a", "anthropic", "claude-code"),
                "run-1",
                TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("ls"))),
            ))
            .await
            .unwrap();

        let all = store.analyze_agents(&AgentFilter::default()).await.unwrap();
        assert_eq!(all.total, 2);
        assert_eq!(all.healthy, 1);
        assert_eq!(all.offline, 1);

        let anthropic = store
            .analyze_agents(&AgentFilter {
                provider: Some("anthropic".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(anthropic.total, 1);
        assert_eq!(anthropic.healthy, 1);

        let one = store
            .analyze_agents(&AgentFilter {
                agent_id: Some("b".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(one.total, 1);
        assert_eq!(one.offline, 1);
    }

    #[tokio::test]
    async fn a_missing_agent_reads_as_absent_rather_than_an_error() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        assert!(store.get_agent("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_agent_removes_identity_events_and_scans_then_reports_missing() {
        let store = store_with(vec![test_event(
            "run-1",
            TrajectoryEvent::Observation(Observation::Thought(Thought::new("t"))),
        )])
        .await;
        store
            .connection()
            .unwrap()
            .execute_batch(
                r#"
                INSERT INTO event_scan_results (
                    event_id, trajectory_id, agent_id, message_type, intent,
                    description, confidence, scan_json, created_at
                ) VALUES (
                    'event-scan', 'run-1', 'test-agent', 'ToolCall', 'Investigate',
                    'summary', 0.9, '{}', '2026-01-01T00:00:00+00:00'
                );
                INSERT INTO transcript_digest_results (
                    event_id, trajectory_id, agent_id, title, interim, scan_json, created_at
                ) VALUES (
                    'digest', 'run-1', 'test-agent', 'title', 0, '{}',
                    '2026-01-01T00:00:00+00:00'
                );
                INSERT INTO transcript_scan_results (
                    event_id, trajectory_id, agent_id, outcome, aggregate_severity,
                    confidence, scan_json, created_at
                ) VALUES (
                    'scan', 'run-1', 'test-agent', 'Completed', 'Info', 0.8, '{}',
                    '2026-01-01T00:00:00+00:00'
                );
                "#,
            )
            .await
            .unwrap();

        assert!(store.delete_agent("test-agent").await.unwrap());
        assert!(store.get_agent("test-agent").await.unwrap().is_none());
        assert!(store.get_trajectory("run-1").await.unwrap().is_none());
        for table in [
            "event_scan_results",
            "transcript_digest_results",
            "transcript_scan_results",
        ] {
            assert_eq!(rows_for_agent(&store, table, "test-agent").await, 0);
        }
        // Idempotent: a repeat delete reports nothing was removed.
        assert!(!store.delete_agent("test-agent").await.unwrap());
    }

    #[tokio::test]
    async fn compound_agent_ids_are_stored_and_read_back_verbatim() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        let agent = Agent::new(
            "claude-code-developer/rs-engineer",
            "anthropic",
            "claude-code",
        );
        store.upsert_agent(&agent).await.unwrap();

        let fetched = store
            .get_agent("claude-code-developer/rs-engineer")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.agent.id, "claude-code-developer/rs-engineer");
    }

    #[tokio::test]
    async fn latest_trajectory_id_reports_the_most_recent_run() {
        let store = store_with(vec![
            test_event(
                "older",
                TrajectoryEvent::Observation(Observation::Thought(Thought::new("a"))),
            ),
            test_event(
                "newer",
                TrajectoryEvent::Observation(Observation::Thought(Thought::new("b"))),
            ),
        ])
        .await;

        assert_eq!(
            store.latest_trajectory_id("test-agent").await.unwrap(),
            Some("newer".to_string())
        );
    }

    #[tokio::test]
    async fn agents_page_and_sort_by_the_requested_field() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        for id in ["c", "a", "b"] {
            store
                .upsert_agent(&Agent::new(id, "anthropic", "claude-code"))
                .await
                .unwrap();
        }

        let ascending = store
            .list_agents(&AgentQuery {
                order_by: AgentOrderBy::Id,
                descending: false,
                ..Default::default()
            })
            .await
            .unwrap();
        let ids: Vec<_> = ascending
            .items
            .iter()
            .map(|agent| agent.agent.id.as_str())
            .collect();
        assert_eq!(ids, vec!["a", "b", "c"]);

        let windowed = store
            .list_agents(&AgentQuery {
                order_by: AgentOrderBy::Id,
                descending: false,
                offset: 1,
                limit: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(windowed.total, 3);
        assert_eq!(windowed.items.len(), 1);
        assert_eq!(windowed.items[0].agent.id, "b");
    }

    /// The store surface takes bare ids, so a caller that passes a resource name
    /// addresses an agent that does not exist rather than having it parsed.
    #[tokio::test]
    async fn store_reads_take_bare_ids_not_resource_names() {
        let store = store_with(vec![test_event(
            "run-1",
            TrajectoryEvent::Observation(Observation::Thought(Thought::new("t"))),
        )])
        .await;

        assert!(
            store
                .get_agent("agents/test-agent")
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.get_agent("test-agent").await.unwrap().is_some());
    }

    /// The row `latest_trajectory_id` names must be the greatest
    /// `(timestamp, id)` pair, not merely one of the rows at the newest
    /// timestamp.
    ///
    /// Hooks emit several events in the same millisecond, so ties are ordinary
    /// rather than exotic, and the insertion-order tiebreak is what keeps the
    /// answer stable. The query is phrased as a MAX subquery to stay on an
    /// index; this is the test that phrasing has to keep passing.
    #[tokio::test]
    async fn a_tie_within_one_millisecond_resolves_by_insertion_order() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        let at = chrono::Utc.timestamp_millis_opt(1_700_000_000_000).unwrap();

        // Same agent, same instant, three runs: the last one inserted wins.
        for run in ["run-a", "run-b", "run-c"] {
            let mut event = test_event(
                run,
                TrajectoryEvent::Observation(Observation::Thought(Thought::new(run))),
            );
            event.timestamp = at;
            store.insert_event(&event).await.unwrap();
        }
        // An older event inserted last must not win on insertion order alone.
        let mut stale = test_event(
            "run-old",
            TrajectoryEvent::Observation(Observation::Thought(Thought::new("old"))),
        );
        stale.timestamp = at - chrono::Duration::seconds(60);
        store.insert_event(&stale).await.unwrap();

        assert_eq!(
            store.latest_trajectory_id("test-agent").await.unwrap(),
            Some("run-c".to_string())
        );
    }

    #[tokio::test]
    async fn an_agent_with_no_events_has_no_latest_trajectory() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store.register_agent(&test_agent()).await.unwrap();

        assert_eq!(
            store.latest_trajectory_id("test-agent").await.unwrap(),
            None
        );
        assert_eq!(store.latest_trajectory_id("nobody").await.unwrap(), None);
    }

    /// The per-agent rollups must reach their rows through
    /// `idx_agent_timestamp` rather than scanning the ledger.
    ///
    /// This is a performance contract, asserted structurally because a timing
    /// assertion would be flaky. It has teeth: phrased with `ORDER BY timestamp
    /// DESC, id DESC` the planner ignores the `agent_id` predicate and picks a
    /// full `SCAN ... USING INDEX idx_timestamp`, which is a whole-table read
    /// per agent on every console roster refresh.
    #[tokio::test]
    async fn per_agent_reads_are_served_by_the_agent_timestamp_index() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store
            .insert_event(&test_event(
                "run-1",
                TrajectoryEvent::Observation(Observation::Thought(Thought::new("t"))),
            ))
            .await
            .unwrap();

        for sql in [
            "SELECT trajectory_id FROM trajectory_events \
             WHERE agent_id = 'test-agent' AND timestamp = ( \
                 SELECT MAX(timestamp) FROM trajectory_events WHERE agent_id = 'test-agent') \
             ORDER BY id DESC LIMIT 1",
            "SELECT MAX(timestamp) FROM trajectory_events WHERE agent_id = 'test-agent'",
        ] {
            let conn = store.connection().unwrap();
            let mut rows = conn
                .query(&format!("EXPLAIN QUERY PLAN {sql}"), ())
                .await
                .unwrap();

            let mut plan = String::new();
            while let Some(row) = rows.next().await.unwrap() {
                for column in 0..4 {
                    if let Ok(value) = row.get_value(column)
                        && let Some(text) = value.as_text()
                    {
                        plan.push_str(text);
                        plan.push(' ');
                    }
                }
            }

            assert!(
                plan.contains("idx_agent_timestamp"),
                "expected the agent composite to serve this read, got: {plan}"
            );
            assert!(
                !plan.contains("SCAN"),
                "a per-agent read must not scan the ledger, got: {plan}"
            );
        }
    }
}
