//! Turso-poll fallback: the live-feed source when the notify watcher
//! cannot start.
//!
//! Startup-decided: `bin/server.rs` spawns this ONLY when
//! [`super::tail::spawn_tail`] errs — there is no mid-flight switching.
//! The task runs an id-cursor SELECT loop through [`ReadOnlyStore`] (the
//! snapshot-copy path — the live `trajectories.db` is never opened),
//! initializing the cursor at `MAX(id)` so a new dashboard process never
//! replays history. The init RETRIES until `MAX(id)` reads successfully: a
//! failed first snapshot (the torn-copy window at startup, exactly when the
//! harness is busiest) must never default the cursor to 0 and flood the
//! broadcast ring with the entire history.

use crate::storage::ReadOnlyStore;
use axum::extract::ws::Utf8Bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

/// Poll cadence. Coexists with the 1 s snapshot-copy debounce: each tick's
/// `refresh_if_stale` re-copies at most once per debounce window.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Spawn the poll fallback task: initialize the cursor at `MAX(id)` —
/// retrying on a [`POLL_INTERVAL`] cadence until the read succeeds — then
/// publish every newer row through [`super::publish`] on the same cadence.
/// Query errors warn + retry — the task never exits: init failure retries
/// forever rather than degrading. It never opens anything but the
/// `ReadOnlyStore`.
pub fn spawn_poll(store: Arc<ReadOnlyStore>, tx: broadcast::Sender<Utf8Bytes>) {
    tokio::spawn(async move {
        // Cursor at MAX(id): rows that already exist are history — REST
        // serves them; the feed is deltas only. The loop sits BEFORE the
        // ticker so `events_after_id` structurally cannot run with a
        // defaulted-0 cursor.
        let mut last_seen = loop {
            match store.max_event_row_id().await {
                Ok(id) => break id,
                Err(err) => {
                    tracing::warn!(error = %err, "poll fallback cursor init failed; retrying");
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
        };
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        loop {
            ticker.tick().await;
            match store.events_after_id(last_seen).await {
                Ok(batch) => {
                    for (id, event) in batch {
                        super::publish(&tx, &event);
                        last_seen = last_seen.max(id);
                    }
                }
                Err(err) => {
                    // warn + continue: the task never dies.
                    tracing::warn!(
                        error = %err,
                        "poll fallback query failed; retrying next tick"
                    );
                }
            }
        }
    });
}
