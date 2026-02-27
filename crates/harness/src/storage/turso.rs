//! Turso-based storage for trajectory events.
//!
//! Provides persistent storage with efficient querying capabilities for
//! trajectory events. Uses file-based Turso storage by default.
//!
//! This module uses async APIs and the Connection is Send + Sync,
//! eliminating the need for Mutex wrappers.

use super::file::get_storage_dir;
use crate::Event;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, warn};
use turso::{Builder, Connection, Database};

/// Statistics about a trajectory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryStats {
    pub trajectory_id: String,
    pub event_count: u64,
    pub first_event_at: Option<DateTime<Utc>>,
    pub last_event_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<i64>,
    pub agent_id: Option<String>,
    pub agent_provider: Option<String>,
    pub action_count: u64,
    pub observation_count: u64,
    pub control_count: u64,
    pub state_count: u64,
}

/// Turso (libsql)-based trajectory storage.
pub struct TrajectoryStore {
    _db: Database,
    conn: Connection,
}

impl TrajectoryStore {
    /// Open or create a trajectory store at the specified path.
    ///
    /// Creates the database file and schema if they don't exist.
    pub async fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy();
        let db = Builder::new_local(&path_str)
            .build()
            .await
            .context("Failed to open turso database")?;
        let conn = db.connect().context("Failed to connect to database")?;

        Self::init_schema(&conn).await?;
        debug!("TrajectoryStore opened at {:?}", path.as_ref());

        Ok(Self { _db: db, conn })
    }

    /// Create an in-memory trajectory store.
    ///
    /// Useful for testing or temporary storage.
    pub async fn open_in_memory() -> Result<Self> {
        let db = Builder::new_local(":memory:")
            .build()
            .await
            .context("Failed to create in-memory turso")?;
        let conn = db.connect().context("Failed to connect to database")?;

        Self::init_schema(&conn).await?;
        debug!("TrajectoryStore opened in-memory");

        Ok(Self { _db: db, conn })
    }

    async fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS trajectory_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                trajectory_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                agent_provider TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_category TEXT NOT NULL,
                event_type TEXT,
                event_json TEXT NOT NULL,
                actor_id TEXT,
                actor_type TEXT,
                correlation_id TEXT,
                causation_id TEXT,
                parent_id TEXT,
                raw_json TEXT,
                created_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_trajectory_id ON trajectory_events(trajectory_id);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON trajectory_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_agent_id ON trajectory_events(agent_id);
            CREATE INDEX IF NOT EXISTS idx_event_category ON trajectory_events(event_category);
            "#,
        )
        .await
        .context("Failed to initialize schema")?;

        debug!("Schema initialized");
        Ok(())
    }

    /// Insert a trajectory event into the store.
    pub async fn insert_event(&self, event: &Event) -> Result<()> {
        let (category, event_type) = Self::extract_event_info(&event.event);
        let event_json =
            serde_json::to_string(&event.event).context("Failed to serialize event")?;
        let raw_json = event.raw.as_ref().map(|v| v.to_string());

        self.conn
            .execute(
                r#"
            INSERT INTO trajectory_events (
                event_id, trajectory_id, agent_id, agent_provider,
                timestamp, event_category, event_type, event_json,
                actor_id, actor_type, correlation_id, causation_id, parent_id, raw_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
                [
                    event.event_id.as_str(),
                    event.trajectory_id.as_str(),
                    event.agent.id.as_str(),
                    event.agent.provider_id.as_str(),
                    &event.timestamp.to_rfc3339(),
                    category,
                    event_type.unwrap_or(""),
                    &event_json,
                    event.actor.id.as_str(),
                    &format!("{:?}", event.actor.actor_type),
                    event.causality.correlation_id.as_str(),
                    event.causality.causation_id.as_deref().unwrap_or(""),
                    event.causality.parent_id.as_deref().unwrap_or(""),
                    raw_json.as_deref().unwrap_or(""),
                ],
            )
            .await
            .context("Failed to insert event")?;

        debug!(
            "Inserted event: {} for trajectory: {}",
            event.event_id, event.trajectory_id
        );
        Ok(())
    }

    /// Insert multiple events in a single transaction.
    pub async fn insert_events(&self, events: &[Event]) -> Result<()> {
        let tx = self.conn.unchecked_transaction().await?;

        for event in events {
            let (category, event_type) = Self::extract_event_info(&event.event);
            let event_json =
                serde_json::to_string(&event.event).context("Failed to serialize event")?;
            let raw_json = event.raw.as_ref().map(|v| v.to_string());

            if let Err(e) = tx
                .execute(
                    r#"
                INSERT INTO trajectory_events (
                    event_id, trajectory_id, agent_id, agent_provider,
                    timestamp, event_category, event_type, event_json,
                    actor_id, actor_type, correlation_id, causation_id, parent_id, raw_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                "#,
                    [
                        event.event_id.as_str(),
                        event.trajectory_id.as_str(),
                        event.agent.id.as_str(),
                        event.agent.provider_id.as_str(),
                        &event.timestamp.to_rfc3339(),
                        category,
                        event_type.unwrap_or(""),
                        &event_json,
                        event.actor.id.as_str(),
                        &format!("{:?}", event.actor.actor_type),
                        event.causality.correlation_id.as_str(),
                        event.causality.causation_id.as_deref().unwrap_or(""),
                        event.causality.parent_id.as_deref().unwrap_or(""),
                        raw_json.as_deref().unwrap_or(""),
                    ],
                )
                .await
            {
                tx.rollback().await?;
                return Err(e).context("Failed to insert event");
            }
        }

        tx.commit().await?;
        debug!("Inserted {} events in batch", events.len());
        Ok(())
    }

    /// Get all events for a trajectory, ordered by timestamp.
    pub async fn get_trajectory(&self, trajectory_id: &str) -> Result<Vec<Event>> {
        let mut rows = self
            .conn
            .query(
                r#"
            SELECT event_id, trajectory_id, agent_id, agent_provider,
                   timestamp, event_json, actor_id, actor_type,
                   correlation_id, causation_id, parent_id, raw_json
            FROM trajectory_events
            WHERE trajectory_id = ?1
            ORDER BY timestamp ASC
            "#,
                [trajectory_id],
            )
            .await?;

        let mut result = Vec::new();
        while let Ok(Some(row)) = rows.next().await {
            result.push(Self::row_to_event(&row)?);
        }

        debug!(
            "Retrieved {} events for trajectory: {}",
            result.len(),
            trajectory_id
        );
        Ok(result)
    }

    /// List all trajectories with statistics.
    pub async fn list_trajectories(&self) -> Result<Vec<TrajectoryStats>> {
        let mut rows = self
            .conn
            .query(
                r#"
            SELECT
                trajectory_id,
                COUNT(*) as event_count,
                MIN(timestamp) as first_event_at,
                MAX(timestamp) as last_event_at,
                CAST((julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400 AS INTEGER) as duration_seconds,
                MIN(agent_id) as agent_id,
                MIN(agent_provider) as agent_provider,
                SUM(CASE WHEN event_category = 'Action' THEN 1 ELSE 0 END) as action_count,
                SUM(CASE WHEN event_category = 'Observation' THEN 1 ELSE 0 END) as observation_count,
                SUM(CASE WHEN event_category = 'Control' THEN 1 ELSE 0 END) as control_count,
                SUM(CASE WHEN event_category = 'State' THEN 1 ELSE 0 END) as state_count
            FROM trajectory_events
            GROUP BY trajectory_id
            ORDER BY first_event_at DESC
            "#,
                (),
            )
            .await?;

        let mut result = Vec::new();
        while let Ok(Some(row)) = rows.next().await {
            result.push(Self::row_to_stats(&row)?);
        }

        debug!("Listed {} trajectories", result.len());
        Ok(result)
    }

    /// List trajectories with optional filtering and pagination.
    pub async fn list_trajectories_filtered(
        &self,
        agent_id: Option<&str>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<TrajectoryStats>> {
        let mut query = String::from(
            r#"
            SELECT
                trajectory_id,
                COUNT(*) as event_count,
                MIN(timestamp) as first_event_at,
                MAX(timestamp) as last_event_at,
                CAST((julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400 AS INTEGER) as duration_seconds,
                MIN(agent_id) as agent_id,
                MIN(agent_provider) as agent_provider,
                SUM(CASE WHEN event_category = 'Action' THEN 1 ELSE 0 END) as action_count,
                SUM(CASE WHEN event_category = 'Observation' THEN 1 ELSE 0 END) as observation_count,
                SUM(CASE WHEN event_category = 'Control' THEN 1 ELSE 0 END) as control_count,
                SUM(CASE WHEN event_category = 'State' THEN 1 ELSE 0 END) as state_count
            FROM trajectory_events
            "#,
        );

        if agent_id.is_some() {
            query.push_str(" WHERE agent_id = ?1");
        }

        query.push_str(" GROUP BY trajectory_id ORDER BY first_event_at DESC");

        if let Some(l) = limit {
            query.push_str(&format!(" LIMIT {}", l));
        }
        if let Some(o) = offset {
            query.push_str(&format!(" OFFSET {}", o));
        }

        let mut result = Vec::new();
        let mut rows = if let Some(aid) = agent_id {
            self.conn.query(&query, [aid]).await?
        } else {
            self.conn.query(&query, ()).await?
        };

        while let Ok(Some(row)) = rows.next().await {
            result.push(Self::row_to_stats(&row)?);
        }

        debug!(
            "Listed {} trajectories (agent_id={:?}, limit={:?}, offset={:?})",
            result.len(),
            agent_id,
            limit,
            offset
        );
        Ok(result)
    }

    /// Get statistics for a specific trajectory.
    pub async fn get_trajectory_stats(
        &self,
        trajectory_id: &str,
    ) -> Result<Option<TrajectoryStats>> {
        let mut rows = self
            .conn
            .query(
                r#"
            SELECT
                trajectory_id,
                COUNT(*) as event_count,
                MIN(timestamp) as first_event_at,
                MAX(timestamp) as last_event_at,
                CAST((julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400 AS INTEGER) as duration_seconds,
                MIN(agent_id) as agent_id,
                MIN(agent_provider) as agent_provider,
                SUM(CASE WHEN event_category = 'Action' THEN 1 ELSE 0 END) as action_count,
                SUM(CASE WHEN event_category = 'Observation' THEN 1 ELSE 0 END) as observation_count,
                SUM(CASE WHEN event_category = 'Control' THEN 1 ELSE 0 END) as control_count,
                SUM(CASE WHEN event_category = 'State' THEN 1 ELSE 0 END) as state_count
            FROM trajectory_events
            WHERE trajectory_id = ?1
            GROUP BY trajectory_id
            "#,
                [trajectory_id],
            )
            .await?;

        if let Ok(Some(row)) = rows.next().await {
            Ok(Some(Self::row_to_stats(&row)?))
        } else {
            Ok(None)
        }
    }

    /// Delete all events for a trajectory.
    pub async fn delete_trajectory(&self, trajectory_id: &str) -> Result<u64> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM trajectory_events WHERE trajectory_id = ?1",
                [trajectory_id],
            )
            .await?;

        debug!(
            "Deleted {} events for trajectory: {}",
            deleted, trajectory_id
        );
        Ok(deleted)
    }

    /// Count total events in the store.
    pub async fn count_events(&self) -> Result<u64> {
        let mut rows = self
            .conn
            .query("SELECT COUNT(*) FROM trajectory_events", ())
            .await?;
        if let Ok(Some(row)) = rows.next().await {
            let count = row.get_value(0)?.as_integer().copied().unwrap_or(0);
            Ok(count as u64)
        } else {
            Ok(0)
        }
    }

    /// Count total trajectories in the store.
    pub async fn count_trajectories(&self) -> Result<u64> {
        let mut rows = self
            .conn
            .query(
                "SELECT COUNT(DISTINCT trajectory_id) FROM trajectory_events",
                (),
            )
            .await?;
        if let Ok(Some(row)) = rows.next().await {
            let count = row.get_value(0)?.as_integer().copied().unwrap_or(0);
            Ok(count as u64)
        } else {
            Ok(0)
        }
    }

    fn extract_event_info(event: &crate::TrajectoryEvent) -> (&'static str, Option<&'static str>) {
        use crate::TrajectoryEvent;

        match event {
            TrajectoryEvent::Action(action) => {
                let event_type = match action {
                    crate::Action::ToolCall(_) => Some("ToolCall"),
                    crate::Action::ShellCommand(_) => Some("ShellCommand"),
                    crate::Action::WebFetch(_) => Some("WebFetch"),
                    crate::Action::FileOperation(_) => Some("FileOperation"),
                };
                ("Action", event_type)
            }
            TrajectoryEvent::Observation(obs) => {
                let event_type = match obs {
                    crate::Observation::Prompt(_) => Some("Prompt"),
                    crate::Observation::Think(_) => Some("Think"),
                    crate::Observation::ToolOutput(_) => Some("ToolOutput"),
                    crate::Observation::ShellCommandOutput(_) => Some("ShellCommandOutput"),
                    crate::Observation::FileOperationResult(_) => Some("FileOperationResult"),
                    crate::Observation::WebFetchOutput(_) => Some("WebFetchOutput"),
                };
                ("Observation", event_type)
            }
            TrajectoryEvent::Control(ctrl) => {
                let event_type = match ctrl {
                    crate::Control::Started(_) => Some("Started"),
                    crate::Control::Completed(_) => Some("Completed"),
                    crate::Control::Failed(_) => Some("Failed"),
                    crate::Control::Suspended(_) => Some("Suspended"),
                    crate::Control::Resumed(_) => Some("Resumed"),
                    crate::Control::Terminated(_) => Some("Terminated"),
                    crate::Control::Adjudicated(_) => Some("Adjudicated"),
                };
                ("Control", event_type)
            }
            TrajectoryEvent::State(_) => ("State", Some("Snapshot")),
        }
    }

    fn row_to_event(row: &turso::Row) -> Result<Event> {
        let event_id = row.get_value(0)?.as_text().cloned().unwrap_or_default();
        let trajectory_id = row.get_value(1)?.as_text().cloned().unwrap_or_default();
        let agent_id = row.get_value(2)?.as_text().cloned().unwrap_or_default();
        let agent_provider = row.get_value(3)?.as_text().cloned().unwrap_or_default();
        let timestamp_str = row.get_value(4)?.as_text().cloned().unwrap_or_default();
        let event_json = row.get_value(5)?.as_text().cloned().unwrap_or_default();
        let actor_id = row.get_value(6)?.as_text().cloned().unwrap_or_default();
        let actor_type_str = row.get_value(7)?.as_text().cloned().unwrap_or_default();
        let correlation_id = row.get_value(8)?.as_text().cloned().unwrap_or_default();
        let causation_id_val = row.get_value(9)?;
        let causation_id = if causation_id_val.is_null() {
            None
        } else {
            causation_id_val.as_text().cloned()
        };
        let parent_id_val = row.get_value(10)?;
        let parent_id = if parent_id_val.is_null() {
            None
        } else {
            parent_id_val.as_text().cloned()
        };
        let raw_json_val = row.get_value(11)?;
        let raw_json = if raw_json_val.is_null() {
            None
        } else {
            raw_json_val.as_text().cloned()
        };

        let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|e| {
                warn!(event_id = %event_id, error = %e, "Failed to parse timestamp, using current time");
                Utc::now()
            });

        let event: crate::TrajectoryEvent = serde_json::from_str(&event_json).unwrap_or_else(|e| {
            warn!(event_id = %event_id, error = %e, "Failed to deserialize event JSON");
            crate::TrajectoryEvent::Observation(crate::Observation::Think(crate::Think::new(
                "Failed to deserialize event",
            )))
        });

        let actor_type = match actor_type_str.as_str() {
            "Human" => crate::ActorType::Human,
            "System" => crate::ActorType::System,
            "Policy" => crate::ActorType::Policy,
            _ => crate::ActorType::Agent,
        };

        let raw = raw_json.and_then(|s| serde_json::from_str(&s).ok());

        Ok(Event {
            event_id,
            trajectory_id,
            agent: crate::Agent {
                id: agent_id,
                provider_id: agent_provider,
            },
            timestamp,
            event,
            actor: crate::Actor {
                id: actor_id,
                actor_type,
            },
            causality: crate::Causality {
                correlation_id,
                causation_id,
                parent_id,
            },
            raw,
        })
    }

    fn row_to_stats(row: &turso::Row) -> Result<TrajectoryStats> {
        let first_event_val = row.get_value(2)?;
        let first_event_str = if first_event_val.is_null() {
            None
        } else {
            first_event_val.as_text().cloned()
        };
        let last_event_val = row.get_value(3)?;
        let last_event_str = if last_event_val.is_null() {
            None
        } else {
            last_event_val.as_text().cloned()
        };
        let duration_val = row.get_value(4)?;
        let duration_seconds = if duration_val.is_null() {
            None
        } else {
            duration_val.as_integer().copied()
        };
        let agent_id_val = row.get_value(5)?;
        let agent_id = if agent_id_val.is_null() {
            None
        } else {
            agent_id_val.as_text().cloned()
        };
        let agent_provider_val = row.get_value(6)?;
        let agent_provider = if agent_provider_val.is_null() {
            None
        } else {
            agent_provider_val.as_text().cloned()
        };

        Ok(TrajectoryStats {
            trajectory_id: row.get_value(0)?.as_text().cloned().unwrap_or_default(),
            event_count: row.get_value(1)?.as_integer().copied().unwrap_or(0) as u64,
            first_event_at: first_event_str.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            last_event_at: last_event_str.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
            duration_seconds,
            agent_id,
            agent_provider,
            action_count: row.get_value(7)?.as_integer().copied().unwrap_or(0) as u64,
            observation_count: row.get_value(8)?.as_integer().copied().unwrap_or(0) as u64,
            control_count: row.get_value(9)?.as_integer().copied().unwrap_or(0) as u64,
            state_count: row.get_value(10)?.as_integer().copied().unwrap_or(0) as u64,
        })
    }
}

/// Get the default database path, stored in the same directory as file storage.
///
/// Returns `~/.sondera/trajectories/trajectories.db`
pub fn get_default_db_path() -> Result<std::path::PathBuf> {
    let storage_dir = get_storage_dir()?;
    Ok(storage_dir.join("trajectories.db"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Action, Agent, Control, Event, Observation, Started, Think, ToolCall, TrajectoryEvent,
    };

    fn create_test_agent() -> Agent {
        Agent {
            id: "test-agent".to_string(),
            provider_id: "test-provider".to_string(),
        }
    }

    fn create_test_event(trajectory_id: &str, event: TrajectoryEvent) -> Event {
        Event::new(create_test_agent(), trajectory_id, event)
    }

    #[tokio::test]
    async fn test_open_in_memory() {
        let store = TrajectoryStore::open_in_memory()
            .await
            .expect("Failed to open in-memory store");
        assert_eq!(store.count_events().await.unwrap(), 0);
        assert_eq!(store.count_trajectories().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_insert_and_get_event() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        let trajectory_id = "test-traj-1";

        let event = create_test_event(
            trajectory_id,
            TrajectoryEvent::Observation(Observation::Think(Think::new("test thought"))),
        );

        store.insert_event(&event).await.unwrap();

        let events = store.get_trajectory(trajectory_id).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, event.event_id);
        assert_eq!(events[0].trajectory_id, trajectory_id);
    }

    #[tokio::test]
    async fn test_insert_multiple_events() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        let trajectory_id = "test-traj-2";

        let events = vec![
            create_test_event(
                trajectory_id,
                TrajectoryEvent::Control(Control::Started(Started::new("test-agent"))),
            ),
            create_test_event(
                trajectory_id,
                TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                    "search",
                    serde_json::json!({"q": "rust"}),
                ))),
            ),
            create_test_event(
                trajectory_id,
                TrajectoryEvent::Observation(Observation::Think(Think::new("thinking..."))),
            ),
        ];

        store.insert_events(&events).await.unwrap();

        let retrieved = store.get_trajectory(trajectory_id).await.unwrap();
        assert_eq!(retrieved.len(), 3);
    }

    #[tokio::test]
    async fn test_list_trajectories() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();

        // Create events for two trajectories
        let event1 = create_test_event(
            "traj-a",
            TrajectoryEvent::Control(Control::Started(Started::new("test-agent"))),
        );
        let event2 = create_test_event(
            "traj-a",
            TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                "tool",
                serde_json::json!({}),
            ))),
        );
        let event3 = create_test_event(
            "traj-b",
            TrajectoryEvent::Observation(Observation::Think(Think::new("test"))),
        );

        store.insert_event(&event1).await.unwrap();
        store.insert_event(&event2).await.unwrap();
        store.insert_event(&event3).await.unwrap();

        let stats = store.list_trajectories().await.unwrap();
        assert_eq!(stats.len(), 2);

        // Find traj-a stats
        let traj_a = stats.iter().find(|s| s.trajectory_id == "traj-a").unwrap();
        assert_eq!(traj_a.event_count, 2);
        assert_eq!(traj_a.control_count, 1);
        assert_eq!(traj_a.action_count, 1);
        assert_eq!(traj_a.agent_id, Some("test-agent".to_string()));

        // Find traj-b stats
        let traj_b = stats.iter().find(|s| s.trajectory_id == "traj-b").unwrap();
        assert_eq!(traj_b.event_count, 1);
        assert_eq!(traj_b.observation_count, 1);
    }

    #[tokio::test]
    async fn test_get_trajectory_stats() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        let trajectory_id = "stats-test";

        // No trajectory yet
        assert!(
            store
                .get_trajectory_stats(trajectory_id)
                .await
                .unwrap()
                .is_none()
        );

        let event = create_test_event(
            trajectory_id,
            TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                "test",
                serde_json::json!({}),
            ))),
        );
        store.insert_event(&event).await.unwrap();

        let stats = store
            .get_trajectory_stats(trajectory_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stats.trajectory_id, trajectory_id);
        assert_eq!(stats.event_count, 1);
        assert_eq!(stats.action_count, 1);
    }

    #[tokio::test]
    async fn test_delete_trajectory() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        let trajectory_id = "delete-test";

        let event = create_test_event(
            trajectory_id,
            TrajectoryEvent::Observation(Observation::Think(Think::new("test"))),
        );
        store.insert_event(&event).await.unwrap();

        assert_eq!(store.count_events().await.unwrap(), 1);

        let deleted = store.delete_trajectory(trajectory_id).await.unwrap();
        assert!(deleted >= 1, "should delete at least 1 row");
        assert_eq!(store.count_events().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_list_trajectories_filtered() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();

        // Create events for multiple trajectories
        for i in 0..5 {
            let event = create_test_event(
                &format!("traj-{}", i),
                TrajectoryEvent::Observation(Observation::Think(Think::new("test"))),
            );
            store.insert_event(&event).await.unwrap();
        }

        // Test limit
        let limited = store
            .list_trajectories_filtered(None, Some(2), None)
            .await
            .unwrap();
        assert_eq!(limited.len(), 2);

        // Test offset
        let offset = store
            .list_trajectories_filtered(None, Some(2), Some(2))
            .await
            .unwrap();
        assert_eq!(offset.len(), 2);

        // Test agent filter
        let filtered = store
            .list_trajectories_filtered(Some("test-agent"), None, None)
            .await
            .unwrap();
        assert_eq!(filtered.len(), 5);

        let filtered_none = store
            .list_trajectories_filtered(Some("nonexistent"), None, None)
            .await
            .unwrap();
        assert_eq!(filtered_none.len(), 0);
    }

    #[tokio::test]
    async fn test_event_categories_counted() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        let trajectory_id = "category-test";

        let events = vec![
            create_test_event(
                trajectory_id,
                TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                    "t1",
                    serde_json::json!({}),
                ))),
            ),
            create_test_event(
                trajectory_id,
                TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                    "t2",
                    serde_json::json!({}),
                ))),
            ),
            create_test_event(
                trajectory_id,
                TrajectoryEvent::Observation(Observation::Think(Think::new("test"))),
            ),
            create_test_event(
                trajectory_id,
                TrajectoryEvent::Control(Control::Started(Started::new("agent"))),
            ),
            create_test_event(
                trajectory_id,
                TrajectoryEvent::State(crate::State::Snapshot(crate::Snapshot::new())),
            ),
        ];

        store.insert_events(&events).await.unwrap();

        let stats = store
            .get_trajectory_stats(trajectory_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stats.action_count, 2);
        assert_eq!(stats.observation_count, 1);
        assert_eq!(stats.control_count, 1);
        assert_eq!(stats.state_count, 1);
        assert_eq!(stats.event_count, 5);
    }
}
