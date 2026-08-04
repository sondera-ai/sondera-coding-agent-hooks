//! [`ScanReaderWriter`] over the Turso scan tables.
//!
//! The background scanner writes here; the console read path joins from here.
//! Three tables, one per scan granularity, each keyed by the event that
//! triggered the scan and carrying the run id the scan describes.
//!
//! Writes upsert. Re-scanning an event replaces its row rather than
//! accumulating duplicates, so a scanner that runs twice over the same event —
//! after a restart, say — converges instead of leaving the read path to pick a
//! winner.
//!
//! Reads take the *latest* row per run for the transcript granularities: a long
//! session produces several digests over its lifetime (interim refreshes plus a
//! terminal one), and the newest is the current one. Ordering is by
//! `created_at`, which is written as a UTC RFC 3339 stamp for the same reason
//! `trajectory_events.timestamp` is — a constant `+00:00` offset is what makes
//! lexicographic comparison chronological.

use super::{StoreResult, TrajectoryStore, store_err};
use chrono::Utc;
use sondera_types::{
    EventScanResult, ScanReaderWriter, ScanSource, TrajectoryScans, TranscriptDigest,
    TranscriptScan, TranscriptScanResult,
};
use std::collections::HashMap;
use tracing::{debug, warn};
use turso::Connection;

const INSERT_EVENT_SCAN: &str = r#"
    INSERT INTO event_scan_results (
        event_id, trajectory_id, agent_id,
        message_type, intent, description, confidence, scan_json, created_at
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
    ON CONFLICT(event_id) DO UPDATE SET
        trajectory_id = excluded.trajectory_id,
        agent_id      = excluded.agent_id,
        message_type  = excluded.message_type,
        intent        = excluded.intent,
        description   = excluded.description,
        confidence    = excluded.confidence,
        scan_json     = excluded.scan_json,
        created_at    = excluded.created_at
"#;

const INSERT_TRANSCRIPT_DIGEST: &str = r#"
    INSERT INTO transcript_digest_results (
        event_id, trajectory_id, agent_id, title, interim, scan_json, created_at
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    ON CONFLICT(event_id) DO UPDATE SET
        trajectory_id = excluded.trajectory_id,
        agent_id      = excluded.agent_id,
        title         = excluded.title,
        interim       = excluded.interim,
        scan_json     = excluded.scan_json,
        created_at    = excluded.created_at
"#;

const INSERT_TRANSCRIPT_SCAN: &str = r#"
    INSERT INTO transcript_scan_results (
        event_id, trajectory_id, agent_id,
        outcome, aggregate_severity, confidence, scan_json, created_at
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
    ON CONFLICT(event_id) DO UPDATE SET
        trajectory_id      = excluded.trajectory_id,
        agent_id           = excluded.agent_id,
        outcome            = excluded.outcome,
        aggregate_severity = excluded.aggregate_severity,
        confidence         = excluded.confidence,
        scan_json          = excluded.scan_json,
        created_at         = excluded.created_at
"#;

impl ScanReaderWriter for TrajectoryStore {
    async fn insert_event_scan(
        &self,
        source: ScanSource<'_>,
        result: &EventScanResult,
    ) -> StoreResult<()> {
        let scan_json = serde_json::to_string(result)
            .map_err(|e| store_err("Failed to serialize event scan result", e))?;

        self.connection()?
            .execute(
                INSERT_EVENT_SCAN,
                turso::params![
                    source.event_id,
                    source.trajectory_id,
                    source.agent_id,
                    variant_name(&result.message_type),
                    variant_name(&result.intent),
                    result.description.clone(),
                    result.confidence,
                    scan_json,
                    Utc::now().to_rfc3339(),
                ],
            )
            .await
            .map_err(|e| store_err("Failed to insert event scan result", e))?;

        debug!(
            event_id = %source.event_id,
            trajectory_id = %source.trajectory_id,
            "Recorded event scan"
        );
        Ok(())
    }

    async fn insert_transcript_digest(
        &self,
        source: ScanSource<'_>,
        digest: &TranscriptDigest,
    ) -> StoreResult<()> {
        let scan_json = serde_json::to_string(digest)
            .map_err(|e| store_err("Failed to serialize transcript digest", e))?;

        self.connection()?
            .execute(
                INSERT_TRANSCRIPT_DIGEST,
                turso::params![
                    source.event_id,
                    source.trajectory_id,
                    source.agent_id,
                    digest.title.clone(),
                    i64::from(digest.interim),
                    scan_json,
                    Utc::now().to_rfc3339(),
                ],
            )
            .await
            .map_err(|e| store_err("Failed to insert transcript digest", e))?;

        debug!(
            event_id = %source.event_id,
            trajectory_id = %source.trajectory_id,
            interim = digest.interim,
            "Recorded transcript digest"
        );
        Ok(())
    }

    async fn insert_transcript_scan(
        &self,
        source: ScanSource<'_>,
        scan: &TranscriptScanResult,
    ) -> StoreResult<()> {
        let scan_json = serde_json::to_string(scan)
            .map_err(|e| store_err("Failed to serialize transcript scan", e))?;

        self.connection()?
            .execute(
                INSERT_TRANSCRIPT_SCAN,
                turso::params![
                    source.event_id,
                    source.trajectory_id,
                    source.agent_id,
                    variant_name(&scan.outcome),
                    variant_name(&scan.aggregate_severity),
                    scan.confidence,
                    scan_json,
                    Utc::now().to_rfc3339(),
                ],
            )
            .await
            .map_err(|e| store_err("Failed to insert transcript scan", e))?;

        debug!(
            event_id = %source.event_id,
            trajectory_id = %source.trajectory_id,
            "Recorded transcript scan"
        );
        Ok(())
    }

    async fn event_scans(
        &self,
        trajectory_id: &str,
    ) -> StoreResult<HashMap<String, EventScanResult>> {
        event_scans(&self.connection()?, trajectory_id).await
    }

    async fn transcript_scans(&self, trajectory_id: &str) -> StoreResult<TrajectoryScans> {
        transcript_scans(&self.connection()?, trajectory_id).await
    }

    async fn latest_transcript_scans(&self) -> StoreResult<HashMap<String, TrajectoryScans>> {
        latest_transcript_scans(&self.connection()?).await
    }
}

// ── Connection-level reads ───────────────────────────────────────────────────
//
// Free functions rather than methods for the same reason the event reads are:
// the live tails own a connection of their own and outlive the `&self` borrow
// that spawned them, so a projection both sides need has to be reachable from a
// bare `&Connection`.

/// Every message-level scan for one run, keyed by the event it describes.
pub(crate) async fn event_scans(
    conn: &Connection,
    trajectory_id: &str,
) -> StoreResult<HashMap<String, EventScanResult>> {
    let mut rows = conn
        .query(
            "SELECT event_id, scan_json FROM event_scan_results WHERE trajectory_id = ?1",
            [trajectory_id],
        )
        .await
        .map_err(|e| store_err("Failed to read event scans", e))?;

    let mut scans = HashMap::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| store_err("Failed to read event scan row", e))?
    {
        let (Some(event_id), Some(mut result)) = (
            text(&row, 0)?,
            decode::<EventScanResult>(&row, 1, "event scan")?,
        ) else {
            continue;
        };
        // Drop the description embedding on the way out. It is a dense float
        // vector, no console view reads it, and this projection is loaded for
        // every event of a run — so carrying it would put kilobytes per row on
        // a response that has no use for them. The field is `#[serde(default)]`,
        // so nothing downstream distinguishes this from "never embedded".
        result.embedding = None;
        scans.insert(event_id, result);
    }
    Ok(scans)
}

/// The latest digest and behavioral scan for one run.
pub(crate) async fn transcript_scans(
    conn: &Connection,
    trajectory_id: &str,
) -> StoreResult<TrajectoryScans> {
    let digest = latest_digest(conn, trajectory_id).await?;
    let scan = latest_scan(conn, trajectory_id).await?;
    Ok(TrajectoryScans { digest, scan })
}

async fn latest_digest(
    conn: &Connection,
    trajectory_id: &str,
) -> StoreResult<Option<TranscriptDigest>> {
    let mut rows = conn
        .query(
            "SELECT scan_json FROM transcript_digest_results \
             WHERE trajectory_id = ?1 ORDER BY created_at DESC, rowid DESC LIMIT 1",
            [trajectory_id],
        )
        .await
        .map_err(|e| store_err("Failed to read transcript digest", e))?;

    let Some(row) = rows
        .next()
        .await
        .map_err(|e| store_err("Failed to read transcript digest row", e))?
    else {
        return Ok(None);
    };
    decode(&row, 0, "transcript digest")
}

async fn latest_scan(
    conn: &Connection,
    trajectory_id: &str,
) -> StoreResult<Option<TranscriptScan>> {
    let mut rows = conn
        .query(
            "SELECT event_id, scan_json FROM transcript_scan_results \
             WHERE trajectory_id = ?1 ORDER BY created_at DESC, rowid DESC LIMIT 1",
            [trajectory_id],
        )
        .await
        .map_err(|e| store_err("Failed to read transcript scan", e))?;

    let Some(row) = rows
        .next()
        .await
        .map_err(|e| store_err("Failed to read transcript scan row", e))?
    else {
        return Ok(None);
    };
    transcript_scan_from_row(&row)
}

/// The latest digest and behavioral scan for every run that has one.
///
/// Two queries rather than one per run: a list read joins this against its whole
/// page, and a per-row lookup would put the query count on the number of runs.
///
/// "Latest" is resolved by reading each table newest-first and keeping the first
/// row seen per run, rather than by `GROUP BY` with a bare column beside
/// `MAX(created_at)`. SQLite defines that bare column to come from the maximizing
/// row, but Turso does not implement that special case — it returns an arbitrary
/// row of the group, in practice the first inserted. A run with an interim digest
/// followed by a terminal one would therefore list under the interim title
/// forever. See `the_batch_read_resolves_latest_the_same_way_a_single_run_read_does`.
pub(crate) async fn latest_transcript_scans(
    conn: &Connection,
) -> StoreResult<HashMap<String, TrajectoryScans>> {
    let mut scans: HashMap<String, TrajectoryScans> = HashMap::new();

    let mut rows = conn
        .query(
            "SELECT trajectory_id, scan_json FROM transcript_digest_results \
             ORDER BY created_at DESC, rowid DESC",
            (),
        )
        .await
        .map_err(|e| store_err("Failed to read transcript digests", e))?;
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| store_err("Failed to read transcript digest row", e))?
    {
        let (Some(trajectory_id), Some(digest)) =
            (text(&row, 0)?, decode(&row, 1, "transcript digest")?)
        else {
            continue;
        };
        // Newest-first, so the first row for a run is its current digest and
        // every later one is superseded.
        scans
            .entry(trajectory_id)
            .or_default()
            .digest
            .get_or_insert(digest);
    }

    let mut rows = conn
        .query(
            "SELECT trajectory_id, event_id, scan_json FROM transcript_scan_results \
             ORDER BY created_at DESC, rowid DESC",
            (),
        )
        .await
        .map_err(|e| store_err("Failed to read transcript scans", e))?;
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| store_err("Failed to read transcript scan row", e))?
    {
        let Some(trajectory_id) = text(&row, 0)? else {
            continue;
        };
        if let Some(scan) = transcript_scan_from_row_at(&row, 1)? {
            scans
                .entry(trajectory_id)
                .or_default()
                .scan
                .get_or_insert(scan);
        }
    }

    Ok(scans)
}

/// Delete every scan recorded against `trajectory_id`.
///
/// Called from the trajectory delete path rather than left to a foreign key:
/// nothing here enables SQLite's `PRAGMA foreign_keys`, so a declared `ON DELETE
/// CASCADE` would be inert and the rows would outlive the run they describe.
pub(crate) async fn delete_scans(conn: &Connection, trajectory_id: &str) -> StoreResult<()> {
    for table in [
        "event_scan_results",
        "transcript_digest_results",
        "transcript_scan_results",
    ] {
        conn.execute(
            &format!("DELETE FROM {table} WHERE trajectory_id = ?1"),
            [trajectory_id],
        )
        .await
        .map_err(|e| store_err("Failed to delete trajectory scans", e))?;
    }
    Ok(())
}

/// A [`TranscriptScan`] from a row whose `(event_id, scan_json)` start at 0.
fn transcript_scan_from_row(row: &turso::Row) -> StoreResult<Option<TranscriptScan>> {
    transcript_scan_from_row_at(row, 0)
}

/// A [`TranscriptScan`] from a row whose `(event_id, scan_json)` start at `base`.
fn transcript_scan_from_row_at(
    row: &turso::Row,
    base: usize,
) -> StoreResult<Option<TranscriptScan>> {
    let (Some(source_event_id), Some(result)) =
        (text(row, base)?, decode(row, base + 1, "transcript scan")?)
    else {
        return Ok(None);
    };
    Ok(Some(TranscriptScan {
        source_event_id,
        result,
    }))
}

/// A text column, or `None` when it is NULL or empty.
fn text(row: &turso::Row, index: usize) -> StoreResult<Option<String>> {
    Ok(row
        .get_value(index)
        .map_err(|e| store_err("Failed to read scan column", e))?
        .as_text()
        .cloned()
        .filter(|value| !value.is_empty()))
}

/// Decode a `scan_json` column.
///
/// A row that no longer deserializes — written by a newer scanner, or
/// corrupted — degrades to absent rather than failing the read. The scan is
/// enrichment: losing one summary must not take down the trajectory list that
/// happens to contain it.
fn decode<T: serde::de::DeserializeOwned>(
    row: &turso::Row,
    index: usize,
    what: &str,
) -> StoreResult<Option<T>> {
    let Some(json) = text(row, index)? else {
        return Ok(None);
    };
    match serde_json::from_str(&json) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            warn!(error = %error, "Failed to deserialize {what}; treating it as absent");
            Ok(None)
        }
    }
}

/// The serde name of a fieldless enum variant, for the denormalized columns.
///
/// Goes through the type's own `Serialize` so a column can never disagree with
/// what `scan_json` says — a hand-written `match` would be a second source of
/// truth that a new variant could silently skip.
fn variant_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::turso::tests::test_event;
    use sondera_types::{
        AgentIntent, MessageType, Observation, SignalSeverity, Thought, TrajectoryEvent,
        TrajectoryReaderWriter, TranscriptOutcome, TranscriptPhase,
    };

    async fn store() -> TrajectoryStore {
        TrajectoryStore::open_in_memory().await.unwrap()
    }

    fn source<'a>(event_id: &'a str, trajectory_id: &'a str) -> ScanSource<'a> {
        ScanSource {
            event_id,
            trajectory_id,
            agent_id: "test-agent",
        }
    }

    fn event_scan(description: &str) -> EventScanResult {
        EventScanResult {
            explanation: "reasoned about it".to_string(),
            message_type: MessageType::ToolCall,
            intent: AgentIntent::Investigate,
            description: description.to_string(),
            key_entities: vec!["src/main.rs".to_string()],
            is_side_effecting: false,
            signals: Vec::new(),
            confidence: 0.9,
            embedding: None,
        }
    }

    fn digest(title: &str, interim: bool) -> TranscriptDigest {
        TranscriptDigest {
            trajectory_id: "run-1".to_string(),
            title: title.to_string(),
            summary: "did some work".to_string(),
            interim,
            phases: vec![TranscriptPhase {
                name: "Investigation".to_string(),
                description: "read files".to_string(),
                event_indices: vec![0],
            }],
            files_modified: vec!["src/main.rs".to_string()],
            tools_used: vec!["Read".to_string()],
            total_events: 3,
            side_effecting_count: 1,
        }
    }

    fn transcript_scan(outcome: TranscriptOutcome) -> TranscriptScanResult {
        TranscriptScanResult {
            explanation: "the agent finished".to_string(),
            outcome,
            outcome_description: "done".to_string(),
            aggregate_severity: SignalSeverity::Info,
            signals: Vec::new(),
            adjudication_summary: "No adjudication events.".to_string(),
            behavioral_notes: Vec::new(),
            confidence: 0.8,
        }
    }

    #[tokio::test]
    async fn an_event_scan_round_trips_keyed_by_its_source_event() {
        let store = store().await;

        store
            .insert_event_scan(source("event-1", "run-1"), &event_scan("Read src/main.rs"))
            .await
            .unwrap();

        let scans = store.event_scans("run-1").await.unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans["event-1"].description, "Read src/main.rs");
        assert_eq!(scans["event-1"].intent, AgentIntent::Investigate);
        // Another run's scans are not visible from this one.
        assert!(store.event_scans("run-2").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn re_scanning_an_event_replaces_its_row_rather_than_duplicating_it() {
        // A scanner that runs twice over one event — after a restart, say —
        // must converge, not leave the read path to pick between two rows.
        let store = store().await;

        store
            .insert_event_scan(source("event-1", "run-1"), &event_scan("first pass"))
            .await
            .unwrap();
        store
            .insert_event_scan(source("event-1", "run-1"), &event_scan("second pass"))
            .await
            .unwrap();

        let scans = store.event_scans("run-1").await.unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans["event-1"].description, "second pass");
    }

    #[tokio::test]
    async fn the_latest_digest_wins_over_the_interim_ones_that_preceded_it() {
        // A long Codex session refreshes its digest per turn; the terminal one
        // is the current answer.
        let store = store().await;

        store
            .insert_transcript_digest(source("event-1", "run-1"), &digest("Turn one", true))
            .await
            .unwrap();
        store
            .insert_transcript_digest(source("event-2", "run-1"), &digest("Finished it", false))
            .await
            .unwrap();

        let scans = store.transcript_scans("run-1").await.unwrap();
        let found = scans.digest.expect("a digest was recorded");
        assert_eq!(found.title, "Finished it");
        assert!(!found.interim);
    }

    #[tokio::test]
    async fn a_transcript_scan_carries_the_event_that_triggered_it() {
        let store = store().await;

        store
            .insert_transcript_scan(
                source("event-9", "run-1"),
                &transcript_scan(TranscriptOutcome::Success),
            )
            .await
            .unwrap();

        let scans = store.transcript_scans("run-1").await.unwrap();
        let found = scans.scan.expect("a scan was recorded");
        assert_eq!(found.source_event_id, "event-9");
        assert_eq!(found.result.outcome, TranscriptOutcome::Success);
    }

    #[tokio::test]
    async fn an_unscanned_run_reports_absence_rather_than_an_empty_digest() {
        let store = store().await;
        assert!(store.transcript_scans("run-1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_batch_read_returns_the_latest_per_run() {
        let store = store().await;

        store
            .insert_transcript_digest(source("event-1", "run-1"), &digest("Run one", false))
            .await
            .unwrap();
        store
            .insert_transcript_digest(source("event-2", "run-2"), &digest("Run two", false))
            .await
            .unwrap();
        store
            .insert_transcript_scan(
                source("event-3", "run-2"),
                &transcript_scan(TranscriptOutcome::Failure),
            )
            .await
            .unwrap();

        let all = store.latest_transcript_scans().await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all["run-1"].digest.as_ref().unwrap().title, "Run one");
        assert!(all["run-1"].scan.is_none());
        assert_eq!(all["run-2"].digest.as_ref().unwrap().title, "Run two");
        assert_eq!(
            all["run-2"].scan.as_ref().unwrap().result.outcome,
            TranscriptOutcome::Failure
        );
    }

    #[tokio::test]
    async fn deleting_a_trajectory_takes_its_scans_with_it() {
        // Nothing enables SQLite foreign keys here, so this is the only thing
        // stopping scan rows from outliving the run they describe.
        let store = store().await;
        store
            .insert_event(&test_event(
                "run-1",
                TrajectoryEvent::Observation(Observation::Thought(Thought::new("hm"))),
            ))
            .await
            .unwrap();
        store
            .insert_event_scan(source("event-1", "run-1"), &event_scan("Read"))
            .await
            .unwrap();
        store
            .insert_transcript_digest(source("event-1", "run-1"), &digest("Done", false))
            .await
            .unwrap();
        store
            .insert_transcript_scan(
                source("event-1", "run-1"),
                &transcript_scan(TranscriptOutcome::Success),
            )
            .await
            .unwrap();

        store.delete_trajectory("run-1").await.unwrap();

        assert!(store.event_scans("run-1").await.unwrap().is_empty());
        assert!(store.transcript_scans("run-1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_batch_read_resolves_latest_the_same_way_a_single_run_read_does() {
        // Regression: this was a `GROUP BY trajectory_id` with a bare
        // `scan_json` beside `MAX(created_at)`. SQLite defines that column to
        // come from the maximizing row; Turso does not implement the special
        // case and returned the *first inserted* row instead. Every long Codex
        // session — interim digests then a terminal one — would have listed
        // under its first interim title forever, while opening the same run
        // showed the terminal one. The two paths must agree.
        let store = store().await;
        store
            .insert_transcript_digest(source("event-1", "run-1"), &digest("Turn one", true))
            .await
            .unwrap();
        store
            .insert_transcript_digest(source("event-2", "run-1"), &digest("Finished it", false))
            .await
            .unwrap();
        store
            .insert_transcript_scan(
                source("event-1", "run-1"),
                &transcript_scan(TranscriptOutcome::InProgress),
            )
            .await
            .unwrap();
        store
            .insert_transcript_scan(
                source("event-2", "run-1"),
                &transcript_scan(TranscriptOutcome::Success),
            )
            .await
            .unwrap();

        let batched = store.latest_transcript_scans().await.unwrap();
        let single = store.transcript_scans("run-1").await.unwrap();

        assert_eq!(batched["run-1"], single);
        assert_eq!(
            batched["run-1"].digest.as_ref().unwrap().title,
            "Finished it"
        );
        assert_eq!(
            batched["run-1"].scan.as_ref().unwrap().result.outcome,
            TranscriptOutcome::Success
        );
    }

    #[tokio::test]
    async fn the_read_path_drops_the_description_embedding() {
        // A dense float vector per event, on a projection loaded for every
        // event of a run, that no console view reads.
        let store = store().await;
        let mut with_embedding = event_scan("Read src/main.rs");
        with_embedding.embedding = Some(vec![0.1, 0.2, 0.3]);
        store
            .insert_event_scan(source("event-1", "run-1"), &with_embedding)
            .await
            .unwrap();

        let scans = store.event_scans("run-1").await.unwrap();
        assert!(scans["event-1"].embedding.is_none());
        // Everything else survives the trip.
        assert_eq!(scans["event-1"].description, "Read src/main.rs");
    }

    #[tokio::test]
    async fn an_undecodable_scan_payload_degrades_to_absent() {
        // Enrichment must never take down the list that contains it.
        let store = store().await;
        store
            .insert_event_scan(source("event-1", "run-1"), &event_scan("Read"))
            .await
            .unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE event_scan_results SET scan_json = '{not valid}'",
                (),
            )
            .await
            .unwrap();

        assert!(store.event_scans("run-1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_denormalized_columns_agree_with_the_stored_payload() {
        // They are filter/order columns, so a drift between them and
        // `scan_json` would make a query answer a different question than the
        // payload it returns.
        let store = store().await;
        store
            .insert_transcript_scan(
                source("event-1", "run-1"),
                &transcript_scan(TranscriptOutcome::Interrupted),
            )
            .await
            .unwrap();

        let mut rows = store
            .connection()
            .unwrap()
            .query(
                "SELECT outcome, aggregate_severity FROM transcript_scan_results",
                (),
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().expect("one row");
        assert_eq!(text(&row, 0).unwrap().as_deref(), Some("Interrupted"));
        assert_eq!(text(&row, 1).unwrap().as_deref(), Some("Info"));
    }
}
