//! Turso-based storage for trajectory events, agent identity, and Cedar
//! entities.
//!
//! One database file backs the harness ingest path, the policy engine, and the
//! console read surface. [`TrajectoryStore`] implements every store trait over
//! it — [`sondera_types::TrajectoryReaderWriter`] (the `trajectory` submodule),
//! [`sondera_types::AgentReaderWriter`] (the `agent` submodule), and
//! [`sondera_types::EntityReaderWriter`] (the `entity` submodule, behind the
//! `cedar` feature) — so no side needs to know about the others, and an
//! adjudication that appends an event and raises a trajectory's sensitivity
//! label touches one database rather than two.
//!
//! # Connections
//!
//! Those three callers run as independent tokio tasks against one shared
//! `Arc<TrajectoryStore>`, so their operations overlap as a matter of course.
//! A `Connection` is `Send + Sync` but **not** concurrently usable: turso
//! guards each one with a single-use flag and fails the loser of a race with
//! `Misuse("concurrent use forbidden")`. Every operation therefore takes its
//! own connection from [`TrajectoryStore::connection`] and never shares one —
//! see that method for why an owned connection rather than a lock.
//!
//! Two things still serialize, for reasons a connection cannot address:
//! [`TrajectoryStore::update_entity`] holds
//! [`TrajectoryStore::update_lock`] across a read-modify-write sequence, and
//! competing writers wait out [`BUSY_TIMEOUT`] on turso's single-writer lock.

mod agent;
#[cfg(feature = "cedar")]
mod entity;
mod scan;
mod stream;
mod trajectory;

use super::file::get_storage_dir;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sondera_types::{Event, StoreError};
use std::path::Path;
use std::time::Duration;
use tracing::{debug, warn};
use turso::{Builder, Connection, Database};

pub(crate) type StoreResult<T> = std::result::Result<T, StoreError>;

/// Map an internal storage failure onto the store error surface.
///
/// Everything that reaches here is an infrastructure fault (I/O, SQL, decode),
/// never a caller mistake, so it lands on the opaque `Source` variant that the
/// gRPC layer reports as `internal`.
pub(crate) fn store_err(
    message: impl Into<String>,
    error: impl std::error::Error + Send + Sync + 'static,
) -> StoreError {
    StoreError::source(message, error)
}

/// The columns [`TrajectoryStore::row_to_event`] expects, in order.
pub(crate) const EVENT_COLUMNS: &str = "event_id, trajectory_id, agent_id, agent_provider, \
     timestamp, event_json, actor_id, actor_type, \
     correlation_id, causation_id, parent_id";

/// Deterministic event ordering: by wall-clock time, then by insertion order.
///
/// Hooks emit an action and its adjudication in the same millisecond, and the
/// console folds a verdict onto the action that caused it, so a timestamp-only
/// sort would let a tie reorder the two and break the fold. The autoincrement
/// id is the insertion sequence, which is the tiebreak that preserves causality.
pub(crate) const EVENT_ORDER: &str = "ORDER BY timestamp ASC, id ASC";

/// How long a statement waits out a competing writer before giving up.
///
/// turso admits one writer at a time. Without a timeout the loser of a race
/// fails immediately with `Busy`; with one it retries on a backoff. That is
/// what makes it safe for independent connections to write concurrently, so
/// this is a companion to [`TrajectoryStore::connection`], not a tuning knob.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Turso (libsql)-based trajectory, agent, and Cedar entity storage.
pub struct TrajectoryStore {
    db: Database,
    /// Serializes entity read-modify-write sequences. See
    /// [`TrajectoryStore::update_entity`] for why whole-entity writes cannot be
    /// composed safely from a separate read.
    #[cfg(feature = "cedar")]
    update_lock: tokio::sync::Mutex<()>,
}

impl TrajectoryStore {
    /// Assemble a store from an opened database.
    ///
    /// Exists so the `cedar`-gated field is initialized in one place rather
    /// than under a `cfg` in every constructor.
    fn from_parts(db: Database) -> Self {
        Self {
            db,
            #[cfg(feature = "cedar")]
            update_lock: tokio::sync::Mutex::new(()),
        }
    }

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

        Ok(Self::from_parts(db))
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

        Ok(Self::from_parts(db))
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
                -- RFC 3339, always written from a UTC `DateTime` so the offset
                -- is a constant `+00:00`. That is what lets ORDER BY / MIN /
                -- MAX compare these lexicographically and still be
                -- chronological; a mixed-offset writer would silently break
                -- event ordering and the change fingerprints built on it.
                timestamp TEXT NOT NULL,
                event_category TEXT NOT NULL,
                event_type TEXT,
                event_json TEXT NOT NULL,
                actor_id TEXT,
                actor_type TEXT,
                correlation_id TEXT,
                causation_id TEXT,
                parent_id TEXT,
                created_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_trajectory_id ON trajectory_events(trajectory_id);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON trajectory_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_agent_id ON trajectory_events(agent_id);
            CREATE INDEX IF NOT EXISTS idx_event_category ON trajectory_events(event_category);

            -- Every per-agent console rollup narrows by `agent_id` and then
            -- takes an extreme of `timestamp`. `idx_agent_id` alone finds the
            -- agent's rows and leaves the rest to a scan; this composite lets
            -- the planner answer from the index. Measured on 20 agents / 6k
            -- events, it takes the roster's MAX(timestamp) rollup from 289ms to
            -- 2.4ms, and is what makes `latest_trajectory_id`'s MAX form fast.
            --
            -- Deliberately not paired with a `(trajectory_id, timestamp, id)`
            -- index for the event page. It would remove that query's sorter,
            -- but the planner prefers `idx_trajectory_id` while both exist, and
            -- forcing the composite measured no faster (90.9ms against 90.3ms).
            -- An index that earns nothing on reads still costs every write.
            CREATE INDEX IF NOT EXISTS idx_agent_timestamp
                ON trajectory_events(agent_id, timestamp);

            -- Agent identity, registered by the harness the first time a hook
            -- reports in. Kept as its own table (rather than projected purely
            -- from `trajectory_events`) so an agent that has registered but not
            -- yet acted, or whose events have all been deleted, still lists.
            CREATE TABLE IF NOT EXISTS agents (
                id            TEXT NOT NULL PRIMARY KEY,
                provider      TEXT NOT NULL,
                platform      TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at  TEXT NOT NULL
            );

            -- Cedar entities in their JSON encoding, keyed by uid. Created
            -- unconditionally rather than behind the `cedar` feature: one
            -- database file is opened by both the harness (which writes
            -- entities) and the console (which is built without `cedar-policy`
            -- and never touches them), and the two must not disagree about the
            -- file's shape depending on which one created it first.
            CREATE TABLE IF NOT EXISTS entities (
                uid         TEXT NOT NULL PRIMARY KEY,
                entity_json TEXT NOT NULL
            );

            -- Trajectory scanner output. Each scan is also appended to
            -- `trajectory_events` as a `Control::Scanned` event, because the
            -- ledger is the complete record of what happened to a run. These
            -- tables are the *read* path: they answer "what is this run's
            -- digest" with an indexed lookup instead of replaying and
            -- interpreting every control event the run recorded.
            --
            -- Created unconditionally, like `entities`, so the harness and the
            -- console cannot disagree about the file's shape depending on which
            -- opened it first.
            --
            -- `scan_json` is the whole serialized result, and every read
            -- decodes it: the payload stays whole so a scanner that adds a
            -- field does not need a migration to keep round-tripping.
            --
            -- `created_at` is load-bearing — reads order on it to resolve the
            -- latest digest per run — and is written as a UTC RFC 3339 stamp so
            -- lexicographic comparison is chronological, exactly as
            -- `trajectory_events.timestamp` is.
            --
            -- The remaining lifted-out columns (message_type, intent, outcome,
            -- aggregate_severity, confidence, title, description, interim) have
            -- no reader yet. They are here so a governance query can filter on a
            -- classification without decoding every payload, and a test pins
            -- them to what `scan_json` says so the two cannot drift before that
            -- reader exists.

            -- Message-level scans, at most one per source event.
            CREATE TABLE IF NOT EXISTS event_scan_results (
                event_id      TEXT NOT NULL PRIMARY KEY,
                trajectory_id TEXT NOT NULL,
                agent_id      TEXT NOT NULL,
                message_type  TEXT NOT NULL,
                intent        TEXT NOT NULL,
                description   TEXT NOT NULL,
                confidence    REAL NOT NULL DEFAULT 0.0,
                scan_json     TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_event_scan_trajectory
                ON event_scan_results(trajectory_id);

            -- Hierarchical digests. Keyed by the triggering event rather than
            -- by run: a long session accumulates interim digests alongside its
            -- terminal one, and reads take the most recent.
            CREATE TABLE IF NOT EXISTS transcript_digest_results (
                event_id      TEXT NOT NULL PRIMARY KEY,
                trajectory_id TEXT NOT NULL,
                agent_id      TEXT NOT NULL,
                title         TEXT NOT NULL,
                interim       INTEGER NOT NULL DEFAULT 0,
                scan_json     TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_transcript_digest_trajectory
                ON transcript_digest_results(trajectory_id, created_at);

            -- Transcript-level behavioral scans.
            CREATE TABLE IF NOT EXISTS transcript_scan_results (
                event_id           TEXT NOT NULL PRIMARY KEY,
                trajectory_id      TEXT NOT NULL,
                agent_id           TEXT NOT NULL,
                outcome            TEXT NOT NULL,
                aggregate_severity TEXT NOT NULL,
                confidence         REAL NOT NULL DEFAULT 0.0,
                scan_json          TEXT NOT NULL,
                created_at         TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_transcript_scan_trajectory
                ON transcript_scan_results(trajectory_id, created_at);
            "#,
        )
        .await
        .context("Failed to initialize schema")?;

        debug!("Schema initialized");
        Ok(())
    }

    /// A connection for one store operation.
    ///
    /// **Every operation takes its own; connections are never shared.** turso
    /// guards each connection with a single-use flag, so two statements
    /// stepping on one connection at the same time fails the loser outright
    /// with `Misuse("concurrent use forbidden")`. This store is held as one
    /// `Arc` by the harness ingest path, the console read surface, and the
    /// trajectory scanner, each serving its own tokio task, so overlap is the
    /// normal case rather than an edge one.
    ///
    /// An owned connection makes exclusivity structural rather than a rule to
    /// remember: nothing else can reach it, and the cursors and transactions
    /// opened on it hold their own handle, so it stays alive exactly as long as
    /// they need it. Holding a *shared* connection under a lock would not be
    /// equivalent — [`turso::Rows`] owns its statement instead of borrowing the
    /// connection, so a guard could be dropped while a cursor was still
    /// draining and nothing would flag it.
    ///
    /// Concurrency moves down a level as a result: readers no longer contend at
    /// all, and competing writers wait out [`BUSY_TIMEOUT`] instead of failing.
    pub(crate) fn connection(&self) -> StoreResult<Connection> {
        let conn = self
            .db
            .connect()
            .map_err(|e| store_err("Failed to open a database connection", e))?;
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(|e| store_err("Failed to set the connection busy timeout", e))?;
        Ok(conn)
    }

    pub(crate) fn extract_event_info(
        event: &sondera_types::TrajectoryEvent,
    ) -> (&'static str, Option<&'static str>) {
        use sondera_types::{Action, Control, Observation, TrajectoryEvent};

        match event {
            TrajectoryEvent::Action(action) => {
                let event_type = match action {
                    Action::ToolCall(_) => Some("ToolCall"),
                    Action::ShellCommand(_) => Some("ShellCommand"),
                    Action::WebFetch(_) => Some("WebFetch"),
                    Action::FileOperation(_) => Some("FileOperation"),
                };
                ("Action", event_type)
            }
            TrajectoryEvent::Observation(obs) => {
                let event_type = match obs {
                    Observation::Prompt(_) => Some("Prompt"),
                    Observation::Thought(_) => Some("Thought"),
                    Observation::ToolOutput(_) => Some("ToolOutput"),
                    Observation::ShellCommandOutput(_) => Some("ShellCommandOutput"),
                    Observation::FileOperationResult(_) => Some("FileOperationResult"),
                    Observation::WebFetchOutput(_) => Some("WebFetchOutput"),
                };
                ("Observation", event_type)
            }
            TrajectoryEvent::Control(ctrl) => {
                let event_type = match ctrl {
                    Control::Started(_) => Some("Started"),
                    Control::Completed(_) => Some("Completed"),
                    Control::Failed(_) => Some("Failed"),
                    Control::Suspended(_) => Some("Suspended"),
                    Control::Resumed(_) => Some("Resumed"),
                    Control::Terminated(_) => Some("Terminated"),
                    Control::Adjudicated(_) => Some("Adjudicated"),
                    Control::Scanned(_) => Some("Scanned"),
                };
                ("Control", event_type)
            }
            TrajectoryEvent::State(_) => ("State", Some("Snapshot")),
        }
    }

    /// Decode an event from a row whose [`EVENT_COLUMNS`] start at index 0.
    pub(crate) fn row_to_event(row: &turso::Row) -> StoreResult<Event> {
        Self::row_to_event_at(row, 0)
    }

    /// Decode an event from a row whose [`EVENT_COLUMNS`] start at `base`.
    ///
    /// The live tail selects the autoincrement id ahead of the event columns to
    /// carry its cursor, so it reads at an offset.
    pub(crate) fn row_to_event_at(row: &turso::Row, base: usize) -> StoreResult<Event> {
        use sondera_types::{Actor, ActorType, Agent, Causality, Observation, Thought};

        let text = |offset: usize| -> StoreResult<String> {
            Ok(row
                .get_value(base + offset)
                .map_err(|e| store_err("Failed to read event column", e))?
                .as_text()
                .cloned()
                .unwrap_or_default())
        };

        let event_id = text(0)?;
        let trajectory_id = text(1)?;
        let agent_id = text(2)?;
        let agent_provider = text(3)?;
        let timestamp_str = text(4)?;
        let event_json = text(5)?;
        let actor_id = text(6)?;
        let actor_type_str = text(7)?;
        let correlation_id = text(8)?;
        let causation_id = optional_text(row, base + 9)?;
        let parent_id = optional_text(row, base + 10)?;

        let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|e| {
                warn!(event_id = %event_id, error = %e, "Failed to parse timestamp, using current time");
                Utc::now()
            });

        let event: sondera_types::TrajectoryEvent = serde_json::from_str(&event_json)
            .unwrap_or_else(|e| {
                warn!(event_id = %event_id, error = %e, "Failed to deserialize event JSON");
                sondera_types::TrajectoryEvent::Observation(Observation::Thought(Thought::new(
                    "Failed to deserialize event",
                )))
            });

        let actor_type = match actor_type_str.as_str() {
            "Human" => ActorType::Human,
            "System" => ActorType::System,
            "Policy" => ActorType::Policy,
            _ => ActorType::Agent,
        };

        Ok(Event {
            event_id,
            trajectory_id,
            agent: Agent {
                id: agent_id,
                provider: agent_provider,
                platform: String::new(),
            },
            timestamp,
            event,
            actor: Actor {
                id: actor_id,
                actor_type,
            },
            causality: Causality {
                correlation_id,
                causation_id,
                parent_id,
            },
        })
    }
}

// ── Connection-level reads ───────────────────────────────────────────────────
//
// Free functions rather than `TrajectoryStore` methods because the live tails
// own a connection of their own: a polling task outlives the `&self` borrow
// that spawned it, so anything both it and the store need has to be reachable
// from a bare `&Connection`.

/// Load one trajectory's stored events, in causal order.
pub(crate) async fn events(conn: &Connection, trajectory_id: &str) -> StoreResult<Vec<Event>> {
    let mut rows = conn
        .query(
            &format!(
                "SELECT {EVENT_COLUMNS} FROM trajectory_events \
                 WHERE trajectory_id = ?1 {EVENT_ORDER}"
            ),
            [trajectory_id],
        )
        .await
        .map_err(|e| store_err("Failed to read trajectory events", e))?;

    let mut result = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| store_err("Failed to read trajectory event row", e))?
    {
        result.push(TrajectoryStore::row_to_event(&row)?);
    }

    debug!(
        "Retrieved {} events for trajectory: {}",
        result.len(),
        trajectory_id
    );
    Ok(result)
}

/// A NULL-aware text column read.
///
/// Empty strings are how the event writer encodes "absent" for the nullable
/// causality columns, so they read back as `None` too.
pub(crate) fn optional_text(row: &turso::Row, index: usize) -> StoreResult<Option<String>> {
    let value = row
        .get_value(index)
        .map_err(|e| store_err("Failed to read column", e))?;
    if value.is_null() {
        return Ok(None);
    }
    Ok(value.as_text().cloned().filter(|text| !text.is_empty()))
}

/// A NULL-aware RFC 3339 timestamp column read. An unparsable stamp reads as
/// absent rather than failing the whole projection.
pub(crate) fn optional_timestamp(
    row: &turso::Row,
    index: usize,
) -> StoreResult<Option<DateTime<Utc>>> {
    Ok(optional_text(row, index)?.and_then(|text| {
        DateTime::parse_from_rfc3339(&text)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    }))
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
    use sondera_types::{
        Action, Adjudicated, Agent, Control, Observation, Snapshot, Started, State, Thought,
        ToolCall, TrajectoryEvent, TrajectoryQuery, TrajectoryReaderWriter,
    };

    pub(crate) fn test_agent() -> Agent {
        Agent::new("test-agent", "test-provider", "")
    }

    pub(crate) fn test_event(trajectory_id: &str, event: TrajectoryEvent) -> Event {
        Event::new(test_agent(), trajectory_id, event)
    }

    /// Read back the `(event_category, event_type)` pairs the writer persisted.
    async fn stored_categories(store: &TrajectoryStore) -> Vec<(String, String)> {
        let mut rows = store
            .connection()
            .unwrap()
            .query(
                "SELECT event_category, event_type FROM trajectory_events ORDER BY id",
                (),
            )
            .await
            .expect("query");
        let mut pairs = Vec::new();
        while let Some(row) = rows.next().await.expect("row") {
            pairs.push((
                row.get_value(0)
                    .unwrap()
                    .as_text()
                    .cloned()
                    .unwrap_or_default(),
                row.get_value(1)
                    .unwrap()
                    .as_text()
                    .cloned()
                    .unwrap_or_default(),
            ));
        }
        pairs
    }

    #[tokio::test]
    async fn a_fresh_store_has_no_trajectories() {
        let store = TrajectoryStore::open_in_memory()
            .await
            .expect("Failed to open in-memory store");
        let page = store
            .list_trajectories(&TrajectoryQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 0);
    }

    #[tokio::test]
    async fn every_event_category_is_persisted_with_its_variant_name() {
        // The agent deny-rate rollup selects on
        // `event_category = 'Control' AND event_type = 'Adjudicated'`, so these
        // denormalized columns are load-bearing, not just debugging aids.
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        let trajectory_id = "category-test";

        store
            .insert_events(&[
                test_event(
                    trajectory_id,
                    TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                        "t1",
                        serde_json::json!({}),
                    ))),
                ),
                test_event(
                    trajectory_id,
                    TrajectoryEvent::Observation(Observation::Thought(Thought::new("test"))),
                ),
                test_event(
                    trajectory_id,
                    TrajectoryEvent::Control(Control::Started(Started::new(test_agent()))),
                ),
                test_event(
                    trajectory_id,
                    TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::deny())),
                ),
                test_event(
                    trajectory_id,
                    TrajectoryEvent::State(State::Snapshot(Snapshot::new())),
                ),
            ])
            .await
            .unwrap();

        assert_eq!(
            stored_categories(&store).await,
            vec![
                ("Action".to_string(), "ToolCall".to_string()),
                ("Observation".to_string(), "Thought".to_string()),
                ("Control".to_string(), "Started".to_string()),
                ("Control".to_string(), "Adjudicated".to_string()),
                ("State".to_string(), "Snapshot".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn events_are_read_back_in_insertion_order_within_a_timestamp() {
        // Hooks stamp an action and the adjudication it caused in the same
        // millisecond; the console folds the verdict onto that action, so a
        // timestamp-only sort would be free to swap them and break the fold.
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        let mut batch: Vec<Event> = (0..5)
            .map(|i| {
                test_event(
                    "tie",
                    TrajectoryEvent::Observation(Observation::Thought(Thought::new(format!(
                        "step-{i}"
                    )))),
                )
            })
            .collect();
        let stamp = batch[0].timestamp;
        for event in &mut batch {
            event.timestamp = stamp;
        }
        let expected: Vec<String> = batch.iter().map(|e| e.event_id.clone()).collect();

        store.insert_events(&batch).await.unwrap();

        let read_back = events(&store.connection().unwrap(), "tie").await.unwrap();
        let actual: Vec<String> = read_back.into_iter().map(|e| e.event_id).collect();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn an_undecodable_event_payload_degrades_to_a_placeholder_row() {
        // One corrupt row must not fail the whole projection — the console
        // still needs to render the rest of the run.
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store
            .insert_event(&test_event(
                "corrupt",
                TrajectoryEvent::Observation(Observation::Thought(Thought::new("fine"))),
            ))
            .await
            .unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE trajectory_events SET event_json = '{not valid}'",
                (),
            )
            .await
            .unwrap();

        let read_back = events(&store.connection().unwrap(), "corrupt")
            .await
            .unwrap();
        assert_eq!(read_back.len(), 1);
        assert!(matches!(
            read_back[0].event,
            TrajectoryEvent::Observation(Observation::Thought(_))
        ));
    }
}

/// Concurrency regressions.
///
/// The store is held as one `Arc` by the harness ingest path, the console read
/// surface, and the trajectory scanner, all serving independent tokio tasks.
/// These drive that overlap directly.
#[cfg(test)]
mod concurrency {
    use super::tests::{test_agent, test_event};
    use super::*;
    use sondera_types::{
        AgentQuery, AgentReaderWriter, Observation, Thought, TrajectoryEvent,
        TrajectoryReaderWriter,
    };
    use std::sync::Arc;

    fn thought(trajectory: &str, n: usize) -> Event {
        test_event(
            trajectory,
            TrajectoryEvent::Observation(Observation::Thought(Thought::new(format!("t{n}")))),
        )
    }

    /// Reads issued while the ingest path is writing must not fail.
    ///
    /// Regression: every operation used to share one `Connection`, and turso
    /// rejects two statements stepping on one connection at the same time with
    /// `Misuse("concurrent use forbidden")`. That surfaced as an intermittent
    /// `internal` on console reads whenever a hook happened to be writing.
    // Multi-threaded on purpose. turso holds its per-connection guard only
    // across a synchronous `step()`, so on the single-threaded test runtime two
    // tasks interleave at await points and never overlap inside one — the fault
    // this guards against simply cannot occur there. `sondera serve` runs the
    // multi-threaded runtime, which is where it did.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reads_and_writes_overlap_without_a_concurrent_use_failure() {
        let store = Arc::new(TrajectoryStore::open_in_memory().await.unwrap());
        store.register_agent(&test_agent()).await.unwrap();

        let writer = {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                for n in 0..150 {
                    store.insert_event(&thought("run-1", n)).await?;
                }
                Ok::<_, StoreError>(())
            })
        };

        let reader = {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                for _ in 0..150 {
                    store.list_agents(&AgentQuery::default()).await?;
                    store.trajectory_events("run-1").await?;
                    tokio::task::yield_now().await;
                }
                Ok::<_, StoreError>(())
            })
        };

        writer.await.unwrap().expect("writes must not be refused");
        reader.await.unwrap().expect("reads must not be refused");
    }

    /// Two writers racing must both land, not fail the loser.
    ///
    /// Independent connections make turso's per-connection guard a non-issue,
    /// which moves the contention down to the single-writer lock; `BUSY_TIMEOUT`
    /// is what turns that into a wait instead of an error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writers_both_commit() {
        let store = Arc::new(TrajectoryStore::open_in_memory().await.unwrap());
        store.register_agent(&test_agent()).await.unwrap();

        let mut writers = Vec::new();
        for w in 0..4 {
            let store = Arc::clone(&store);
            writers.push(tokio::spawn(async move {
                for n in 0..40 {
                    store.insert_event(&thought(&format!("run-{w}"), n)).await?;
                }
                Ok::<_, StoreError>(())
            }));
        }
        for writer in writers {
            writer
                .await
                .unwrap()
                .expect("a losing writer must wait, not fail");
        }

        for w in 0..4 {
            assert_eq!(
                store
                    .trajectory_events(&format!("run-{w}"))
                    .await
                    .unwrap()
                    .len(),
                40
            );
        }
    }
}
