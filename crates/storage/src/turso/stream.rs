//! Polling live tails over the Turso ledger.
//!
//! Turso has no push channel, so the two live tails poll: a task per subscriber
//! re-reads the ledger on an interval, emits only what changed since its last
//! pass, and stops as soon as the receiver is dropped.
//!
//! Both tails detect change rather than re-reading everything each tick. The
//! trajectory tail compares a cheap per-run fingerprint (event count plus last
//! timestamp — one grouped aggregate) and rebuilds a rollup only for runs that
//! moved; the event tail pages forward from the last row id it sent. An idle
//! subscriber therefore costs one small query per tick, not a full scan of every
//! event in the database.
//!
//! Each stream takes its own database connection because it outlives the
//! `&self` borrow that created it. The spawned task's lifetime is bounded by
//! the returned stream: once the consumer drops the receiver, the next send
//! fails and the task returns.

use super::trajectory::{RunFingerprint, fingerprints, rollup};
use super::{EVENT_COLUMNS, EVENT_ORDER, StoreResult, TrajectoryStore, store_err};
use futures_core::Stream;
use sondera_types::{
    Event, StoreError, Trajectory, TrajectoryEventStream, TrajectoryFilter, TrajectoryStream,
};
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc;
use turso::Connection;

/// How often a live tail re-reads the ledger.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How many items a slow consumer may fall behind before the producer parks.
const CHANNEL_CAPACITY: usize = 64;

/// A [`Stream`] over an mpsc receiver.
///
/// The producer is a spawned polling task, so the stream ends when that task
/// drops its sender — either because it finished or because this receiver was
/// dropped and its sends started failing.
struct ChannelStream<T>(mpsc::Receiver<T>);

impl<T> Stream for ChannelStream<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.0.poll_recv(cx)
    }
}

impl TrajectoryStore {
    /// Live feed of new and updated run rollups matching `filter`.
    ///
    /// A rollup is emitted when the run first appears and again whenever its
    /// fingerprint moves, so a caller sees each change once rather than the
    /// whole roster on every tick.
    pub(crate) fn spawn_trajectory_stream(
        &self,
        filter: TrajectoryFilter,
    ) -> StoreResult<TrajectoryStream> {
        let conn = self.connection()?;
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);

        tokio::spawn(async move {
            let mut seen: HashMap<String, RunFingerprint> = HashMap::new();

            loop {
                match changed_trajectories(&conn, &filter, &mut seen).await {
                    Ok(trajectories) => {
                        for trajectory in trajectories {
                            if tx.send(Ok(trajectory)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        // A read failure terminates the stream: the consumer
                        // sees the status rather than a silently stalled tail.
                        let _ = tx.send(Err(error)).await;
                        return;
                    }
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        });

        Ok(Box::pin(ChannelStream(rx)))
    }

    /// One trajectory's stored backlog followed by a tail of new events.
    ///
    /// The cursor is the autoincrement row id, so the tail never re-emits an
    /// event and never misses one that landed with an earlier timestamp than a
    /// row already sent.
    pub(crate) fn spawn_trajectory_event_stream(
        &self,
        trajectory_id: String,
    ) -> StoreResult<TrajectoryEventStream> {
        let conn = self.connection()?;
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);

        tokio::spawn(async move {
            let mut cursor = 0_i64;
            loop {
                match events_after(&conn, &trajectory_id, cursor).await {
                    Ok(batch) => {
                        for (row_id, event) in batch {
                            cursor = row_id;
                            if tx.send(Ok(event)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(Err(error)).await;
                        return;
                    }
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        });

        Ok(Box::pin(ChannelStream(rx)))
    }
}

/// One polling pass: the rollups of runs whose fingerprint changed since the
/// last pass, oldest change first so a consumer rendering a feed appends in
/// order. `seen` is advanced in place.
///
/// A run that filters out is still recorded in `seen`, so it costs one
/// projection per change rather than one per tick.
async fn changed_trajectories(
    conn: &Connection,
    filter: &TrajectoryFilter,
    seen: &mut HashMap<String, RunFingerprint>,
) -> Result<Vec<Trajectory>, StoreError> {
    let mut changed = Vec::new();
    for (id, fingerprint) in fingerprints(conn, filter.agent_id.as_deref()).await? {
        if seen.get(&id) == Some(&fingerprint) {
            continue;
        }
        seen.insert(id.clone(), fingerprint);
        if let Some(trajectory) = rollup(conn, &id, Trajectory::summarize).await?
            && filter.matches(&trajectory)
        {
            changed.push(trajectory);
        }
    }
    changed.sort_by_key(|trajectory| trajectory.update_time);
    Ok(changed)
}

/// Events for `trajectory_id` with a row id strictly greater than `cursor`,
/// paired with that row id.
async fn events_after(
    conn: &Connection,
    trajectory_id: &str,
    cursor: i64,
) -> Result<Vec<(i64, Event)>, StoreError> {
    let mut rows = conn
        .query(
            &format!(
                "SELECT id, {EVENT_COLUMNS} FROM trajectory_events \
                 WHERE trajectory_id = ?1 AND id > ?2 {EVENT_ORDER}"
            ),
            (trajectory_id.to_string(), cursor),
        )
        .await
        .map_err(|e| store_err("Failed to read trajectory events", e))?;

    let mut batch = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| store_err("Failed to read trajectory event row", e))?
    {
        let row_id = row
            .get_value(0)
            .map_err(|e| store_err("Failed to read event row id", e))?
            .as_integer()
            .copied()
            .unwrap_or_default();
        // `row_to_event_at` reads the columns after the leading cursor id.
        batch.push((row_id, TrajectoryStore::row_to_event_at(&row, 1)?));
    }
    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::turso::tests::test_event;
    use sondera_types::{Observation, Thought, TrajectoryEvent, TrajectoryReaderWriter};
    use std::future::poll_fn;

    /// Pull the next item, giving the polling task time to produce it.
    async fn next<S, T>(stream: &mut Pin<Box<S>>) -> Option<T>
    where
        S: Stream<Item = T> + ?Sized,
    {
        tokio::time::timeout(
            Duration::from_secs(5),
            poll_fn(|cx| stream.as_mut().poll_next(cx)),
        )
        .await
        .expect("stream produced an item before the timeout")
    }

    fn thought(trajectory_id: &str, text: &str) -> Event {
        test_event(
            trajectory_id,
            TrajectoryEvent::Observation(Observation::Thought(Thought::new(text))),
        )
    }

    #[tokio::test]
    async fn trajectory_event_stream_emits_backlog_then_tails_new_events() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        let backlog = thought("run-1", "first");
        store.insert_event(&backlog).await.unwrap();

        let mut stream = store.stream_trajectory("run-1").await.unwrap();

        let first = next(&mut stream).await.unwrap().unwrap();
        assert_eq!(first.event_id, backlog.event_id);
        assert_eq!(first.trajectory_id, "run-1");

        let appended = thought("run-1", "second");
        store.insert_event(&appended).await.unwrap();

        let second = next(&mut stream).await.unwrap().unwrap();
        assert_eq!(second.event_id, appended.event_id);
    }

    #[tokio::test]
    async fn trajectory_stream_emits_a_run_once_then_again_on_change() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store
            .insert_event(&thought("run-1", "first"))
            .await
            .unwrap();

        let mut stream = store
            .stream_trajectories(&TrajectoryFilter::default())
            .await
            .unwrap();

        let first = next(&mut stream).await.unwrap().unwrap();
        assert_eq!(first.id, "run-1");
        assert_eq!(first.event_count, 1);

        store
            .insert_event(&thought("run-1", "second"))
            .await
            .unwrap();

        // The unchanged passes in between are suppressed, so the next item is
        // the updated rollup rather than a repeat of the first.
        let updated = next(&mut stream).await.unwrap().unwrap();
        assert_eq!(updated.id, "run-1");
        assert_eq!(updated.event_count, 2);
    }

    #[tokio::test]
    async fn an_unchanged_ledger_produces_no_further_rollups() {
        // The fingerprint pass is what keeps an idle subscriber cheap: a run
        // that has not moved must be neither re-projected nor re-emitted.
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store.insert_event(&thought("run-1", "only")).await.unwrap();

        let mut stream = store
            .stream_trajectories(&TrajectoryFilter::default())
            .await
            .unwrap();
        next(&mut stream).await.unwrap().unwrap();

        let idle = tokio::time::timeout(
            Duration::from_millis(1_200),
            poll_fn(|cx| stream.as_mut().poll_next(cx)),
        )
        .await;
        assert!(idle.is_err(), "an unchanged run must not be re-emitted");
    }

    #[tokio::test]
    async fn trajectory_stream_honors_the_filter() {
        let store = TrajectoryStore::open_in_memory().await.unwrap();
        store.insert_event(&thought("run-1", "x")).await.unwrap();

        let mut stream = store
            .stream_trajectories(&TrajectoryFilter {
                agent_id: Some("nobody".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();

        // Nothing matches, so the tail stays quiet rather than leaking the run.
        let idle = tokio::time::timeout(
            Duration::from_millis(1_200),
            poll_fn(|cx| stream.as_mut().poll_next(cx)),
        )
        .await;
        assert!(idle.is_err(), "filtered-out run must not be emitted");
    }
}
