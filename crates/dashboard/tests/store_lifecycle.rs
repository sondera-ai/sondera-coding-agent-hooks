//! Snapshot-copy lifecycle tests: the dashboard's disk footprint in its copy
//! dir is BOUNDED — replaced snapshots delete their files and dropping the
//! store removes the last pair.
//!
//! Why this matters: the copy dir shares a filesystem with the live
//! `trajectories.db`. Unbounded copy accumulation under sustained refresh
//! (the poll fallback alone refreshes every 2 s against an active harness)
//! would eventually fill the volume and break the HARNESS's writes.
//!
//! The harness import rule: `TrajectoryStore` is allowed HERE (dev/test
//! seeding context) and FORBIDDEN in `crates/dashboard/src`. Seeding stores
//! live in inner scopes, DROPPED before the dashboard reads (turso dedupes
//! same-process opens by canonical path).

use sondera_dashboard::storage::ReadOnlyStore;
use sondera_harness::{Action, Agent, Event, ToolCall, TrajectoryEvent, TrajectoryStore};
use std::time::Duration;

fn test_agent() -> Agent {
    Agent {
        id: "test-agent".to_string(),
        provider_id: "test-provider".to_string(),
    }
}

/// Unique trajectory ids keep runs independent.
fn new_trajectory_id() -> String {
    format!("test-lifecycle-{}", uuid::Uuid::new_v4())
}

fn action_event(traj: &str) -> Event {
    Event::new(
        test_agent(),
        traj,
        TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
            "search",
            serde_json::json!({"q": "rust"}),
        ))),
    )
}

/// Count `snapshot-*` copy files in the dir: `(db_count, wal_count)`.
fn snapshot_files(dir: &std::path::Path) -> (usize, usize) {
    let (mut db, mut wal) = (0, 0);
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("snapshot-") {
                continue;
            }
            if name.ends_with(".db-wal") {
                wal += 1;
            } else if name.ends_with(".db") {
                db += 1;
            }
        }
    }
    (db, wal)
}

/// Seed one more event on the live path in an inner scope (changes the
/// live (mtime, len) stat so the next refresh re-copies).
async fn seed_one(db_path: &std::path::Path, traj: &str) {
    let store = TrajectoryStore::open(db_path).await.unwrap();
    store.insert_event(&action_event(traj)).await.unwrap();
} // DROP before the dashboard reads.

/// Replace path: repeated refreshes against a changing live file keep at
/// most ONE snapshot pair on disk — each replaced `Snapshot` deletes its
/// copy files.
#[tokio::test]
async fn refresh_replaces_copy_without_leaking() {
    let tmp = tempfile::tempdir().unwrap();
    let copy_dir = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();

    seed_one(&db_path, &traj).await;

    let store = ReadOnlyStore::new(db_path.clone(), copy_dir.path().to_path_buf())
        .with_refresh_debounce(Duration::ZERO);

    // First read takes the first copy.
    assert_eq!(store.events_for_trajectory(&traj).await.unwrap().len(), 1);

    // Three refresh cycles, each against a CHANGED live file (new row =>
    // new (mtime, len) stat => a genuinely new copy, not a freshness
    // short-circuit).
    for i in 2..=4u64 {
        seed_one(&db_path, &traj).await;
        store.force_refresh().await.unwrap();
        assert_eq!(
            store.events_for_trajectory(&traj).await.unwrap().len() as u64,
            i,
            "each cycle must see its newly seeded row"
        );
    }

    let (db_count, wal_count) = snapshot_files(copy_dir.path());
    assert_eq!(
        db_count, 1,
        "exactly one snapshot-*.db may remain after repeated refreshes \
         (CR-01: replaced snapshots delete their copies), found {db_count}"
    );
    assert!(
        wal_count <= 1,
        "at most one *.db-wal sidecar may remain, found {wal_count}"
    );
}

/// Drop path: dropping the store removes the LAST snapshot pair — the copy
/// dir is empty of snapshot files afterwards.
#[tokio::test]
async fn drop_removes_last_snapshot_pair() {
    let tmp = tempfile::tempdir().unwrap();
    let copy_dir = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();

    seed_one(&db_path, &traj).await;

    let store = ReadOnlyStore::new(db_path.clone(), copy_dir.path().to_path_buf())
        .with_refresh_debounce(Duration::ZERO);
    assert_eq!(store.events_for_trajectory(&traj).await.unwrap().len(), 1);

    let (db_count, _) = snapshot_files(copy_dir.path());
    assert!(
        db_count >= 1,
        "a successful read must have produced a snapshot copy"
    );

    drop(store);

    let (db_count, wal_count) = snapshot_files(copy_dir.path());
    assert_eq!(
        (db_count, wal_count),
        (0, 0),
        "dropping the store must remove the last snapshot pair (CR-01)"
    );
}
