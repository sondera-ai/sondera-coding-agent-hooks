//! Schema contract tests: rows written by the harness `TrajectoryStore` are
//! readable through the dashboard `ReadOnlyStore`'s own SELECTs and
//! deserialize into harness `Event` structs.
//!
//! Proves from outside the crate boundary that:
//! - the dashboard's column-explicit SELECTs match the live
//!   `trajectory_events` schema (a harness schema change breaks THIS suite,
//!   not production),
//! - the snapshot-copy path actually runs: the seeding store is DROPPED
//!   before the dashboard reads (turso dedupes same-process opens by
//!   canonical path — without the drop+copy this test would prove nothing),
//! - new rows written after the first read are visible on the next read
//!   (stat-on-access staleness refresh),
//! - a missing live DB serves empty results, reports `Absent`, and is
//!   NEVER created (turso's default open mode would silently create it).
//!
//! The harness import rule: `TrajectoryStore` is allowed HERE (dev/test
//! seeding context) and FORBIDDEN in `crates/dashboard/src`.

use sondera_dashboard::dto::AdjudicationDto;
use sondera_dashboard::storage::{DbState, ReadOnlyStore};
use sondera_harness::{
    Action, Actor, Adjudicated, Agent, Completed, Control, Event, Label, MonitorAttributes,
    MonitorSnapshot, Observation, Snapshot, Started, State, Think, ToolCall, TrajectoryEvent,
    TrajectoryStore, Verdict,
};

fn test_agent() -> Agent {
    Agent {
        id: "test-agent".to_string(),
        provider_id: "test-provider".to_string(),
    }
}

/// Unique trajectory ids keep runs independent.
fn new_trajectory_id() -> String {
    format!("test-contract-{}", uuid::Uuid::new_v4())
}

/// An agent-originated Action event (default actor, no raw payload).
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

/// A Clean monitor snapshot in the exact wire shape the harness writes.
fn clean_snapshot() -> MonitorSnapshot {
    MonitorSnapshot {
        verdict: Verdict::Satisfied,
        state: "clean".to_string(),
        attributes: MonitorAttributes::default(),
        untrusted_pending: false,
        taints: Vec::new(),
        label: Label::Public,
    }
}

/// A Cedar-path Adjudicated record: `Actor::policy("cedar")` with the
/// raw `{request, response, monitor}` sibling structure, where `monitor`
/// is the serde-serialized typed `MonitorSnapshot`. The request context is
/// caller-chosen so both the empty-context (ToolCall) and the full
/// ShellCommand carrier shapes stay pinned.
fn adjudicated_event_with_context(traj: &str, context: serde_json::Value) -> Event {
    let raw = serde_json::json!({
        "request": {
            "principal": "Agent::\"test-agent\"",
            "action": "Action::\"ToolCall\"",
            "resource": "Trajectory::\"test\"",
            "context": context,
        },
        "response": {
            "decision": "Allow",
            "reason": [],
            "errors": [],
        },
        "monitor": serde_json::to_value(clean_snapshot()).unwrap(),
    });
    Event::new(
        test_agent(),
        traj,
        TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
    )
    .with_actor(Actor::policy("cedar"))
    .with_raw(raw)
}

/// The empty-context (ToolCall-shape) Cedar-path record.
fn adjudicated_event(traj: &str) -> Event {
    adjudicated_event_with_context(traj, serde_json::json!({}))
}

/// The canonical production ShellCommand request context as the harness
/// writes it, with SENTINEL values on every content-bearing key.
fn shell_command_context() -> serde_json::Value {
    serde_json::json!({
        "workspace": "SENTINEL-context-workspace",
        "command": "cat /etc/SENTINEL-context-command",
        "working_dir": "/tmp/SENTINEL-context-wd",
        "protected_path": true,
        "label": {"__entity": {"type": "Label", "id": "Confidential"}},
        "policy": {
            "compliant": false,
            "violations": ["SC2: OS Command Injection"],
        },
        "signature": {
            "matches": 2,
            "categories": ["credential_access"],
            "severity": 3,
        },
    })
}

/// Seed via the harness store, drop it, read everything back through the
/// dashboard's own SELECTs and the snapshot-copy path.
#[tokio::test]
async fn contract_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();

    let action = action_event(&traj);
    let adjudicated = adjudicated_event(&traj);
    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        store.insert_event(&action).await.unwrap();
        store.insert_event(&adjudicated).await.unwrap();
    } // DROP before reading: same-process opens dedupe by canonical path —
    // the copy path must actually run for this to mean anything.

    let ro = ReadOnlyStore::new(db_path.clone(), tmp.path().join("cache"));
    let events = ro.events_for_trajectory(&traj).await.unwrap();
    assert_eq!(events.len(), 2, "both seeded events must round-trip");

    // Ordered timestamp ASC, id ASC: the Action event was created and
    // inserted first.
    assert_eq!(events[0].event_id, action.event_id);
    assert!(
        matches!(
            events[0].event,
            TrajectoryEvent::Action(Action::ToolCall(_))
        ),
        "Action event category must round-trip through event_json"
    );

    let adj = &events[1];
    assert_eq!(adj.event_id, adjudicated.event_id);
    assert!(
        matches!(adj.event, TrajectoryEvent::Control(Control::Adjudicated(_))),
        "Adjudicated payload must round-trip"
    );
    let raw = adj.raw.as_ref().expect("Adjudicated record must carry raw");
    assert!(
        raw.get("request").is_some() && raw.get("response").is_some(),
        "request/response siblings must survive the round-trip"
    );
    let snapshot: MonitorSnapshot = serde_json::from_value(raw["monitor"].clone())
        .expect("raw[\"monitor\"] must deserialize into MonitorSnapshot (D-32)");
    assert_eq!(snapshot.verdict, Verdict::Satisfied);
    assert_eq!(snapshot.state, "clean");

    // The empty-context (ToolCall-shape) record projects NO guardrails.
    let dto = AdjudicationDto::project(adj).expect("Adjudicated record must project");
    assert!(
        dto.guardrails.is_none(),
        "empty context yields no guardrails block"
    );

    assert_eq!(ro.count_events().await.unwrap(), 2);
}

/// Pin the harness-written `raw_json.request.context` carrier shape through
/// REAL `TrajectoryStore` writes. The three guardrail signals must
/// round-trip into `AdjudicationDto.guardrails` while every content-bearing
/// context sentinel stays behind the boundary.
#[tokio::test]
async fn guardrail_context_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();

    let seeded = adjudicated_event_with_context(&traj, shell_command_context());
    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        store.insert_event(&seeded).await.unwrap();
    } // DROP before reading.

    let ro = ReadOnlyStore::new(db_path, tmp.path().join("cache"));
    let events = ro.events_for_trajectory(&traj).await.unwrap();
    assert_eq!(events.len(), 1, "the seeded record must round-trip");
    assert_eq!(events[0].event_id, seeded.event_id);

    let dto = AdjudicationDto::project(&events[0]).expect("Adjudicated record must project");
    let guardrails = dto
        .guardrails
        .as_ref()
        .expect("guardrails projected from the harness-written context");

    let signature = guardrails.signature.as_ref().expect("signature signal");
    assert_eq!(signature.matches, 2);
    assert_eq!(signature.categories, vec!["credential_access"]);
    assert_eq!(signature.severity, 3);

    let policy = guardrails.policy.as_ref().expect("policy signal");
    assert!(!policy.compliant);
    assert_eq!(policy.violations, vec!["SC2: OS Command Injection"]);

    assert_eq!(
        guardrails.label.as_deref(),
        Some("confidential"),
        "label crosses as the Label::from_str-validated snake_case form"
    );

    let serialized = serde_json::to_string(&dto).unwrap();
    assert!(
        !serialized.contains("SENTINEL-context"),
        "content-bearing context keys must never cross the boundary (T-06-17)"
    );
}

/// Rows written AFTER the first read are visible on the next read
/// (stat-on-access mtime+len refresh). Built with a ZERO debounce so it
/// proves the raw stat-on-access refresh independently of the debounce.
#[tokio::test]
async fn staleness_refresh() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();

    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        store.insert_event(&action_event(&traj)).await.unwrap();
        store.insert_event(&adjudicated_event(&traj)).await.unwrap();
    }

    let ro = ReadOnlyStore::new(db_path.clone(), tmp.path().join("cache"))
        .with_refresh_debounce(std::time::Duration::ZERO);
    assert_eq!(
        ro.events_for_trajectory(&traj).await.unwrap().len(),
        2,
        "first read sees the initial seed"
    );

    // Re-seed on the same path in another inner scope (harness writes more
    // rows while the dashboard is running).
    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        store.insert_event(&action_event(&traj)).await.unwrap();
    }

    assert_eq!(
        ro.events_for_trajectory(&traj).await.unwrap().len(),
        3,
        "next read must see the new row (stat-on-access refresh)"
    );
}

/// A changed live file inside the debounce window serves the STALE
/// snapshot, while `force_refresh` bypasses the debounce and picks up the
/// new row. A second `force_refresh` against an UNCHANGED live file does NOT
/// re-copy — only the debounce is bypassed, the (mtime, len) freshness check
/// still holds.
#[tokio::test]
async fn debounce_serves_stale_then_force_sees_new_row() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();

    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        store.insert_event(&action_event(&traj)).await.unwrap();
    }

    let ro = ReadOnlyStore::new(db_path.clone(), tmp.path().join("cache"))
        .with_refresh_debounce(std::time::Duration::from_secs(3600));
    assert_eq!(
        ro.events_for_trajectory(&traj).await.unwrap().len(),
        1,
        "first read takes the initial snapshot copy"
    );

    // The harness writes a second row while the dashboard is running.
    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        store.insert_event(&action_event(&traj)).await.unwrap();
    }

    assert_eq!(
        ro.events_for_trajectory(&traj).await.unwrap().len(),
        1,
        "inside the debounce window the stale snapshot is served (D-64)"
    );

    ro.force_refresh().await.unwrap();
    assert_eq!(
        ro.events_for_trajectory(&traj).await.unwrap().len(),
        2,
        "force_refresh bypasses the debounce and sees the new row (Pitfall 8)"
    );

    // force_refresh on an UNCHANGED live file must NOT re-copy: the
    // (mtime, len) equality check still short-circuits.
    let taken_before = ro
        .snapshot_taken_at()
        .await
        .expect("snapshot exists after a successful read");
    ro.force_refresh().await.unwrap();
    let taken_after = ro.snapshot_taken_at().await.expect("snapshot still exists");
    assert_eq!(
        taken_before, taken_after,
        "no write happened — force_refresh must not take a new copy"
    );
}

/// `snapshot_taken_at` is `None` before any read and for an absent live DB,
/// and reports a sane copy time after a successful read.
#[tokio::test]
async fn snapshot_taken_at_reports_copy_time() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();

    // Absent DB: None before AND after a read (no snapshot ever taken).
    let absent = ReadOnlyStore::new(
        tmp.path().join("nonexistent.db"),
        tmp.path().join("cache-absent"),
    );
    assert_eq!(absent.snapshot_taken_at().await, None);
    absent.events_for_trajectory(&traj).await.unwrap();
    assert_eq!(
        absent.snapshot_taken_at().await,
        None,
        "an absent live DB never yields a snapshot time"
    );

    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        store.insert_event(&action_event(&traj)).await.unwrap();
    }

    let ro = ReadOnlyStore::new(db_path.clone(), tmp.path().join("cache"));
    assert_eq!(
        ro.snapshot_taken_at().await,
        None,
        "no snapshot before the first read (construction does no I/O)"
    );

    let before = chrono::Utc::now() - chrono::Duration::seconds(60);
    ro.events_for_trajectory(&traj).await.unwrap();
    let taken = ro
        .snapshot_taken_at()
        .await
        .expect("Some(ts) after a successful read");
    let after = chrono::Utc::now() + chrono::Duration::seconds(60);
    assert!(
        before < taken && taken < after,
        "copy time must be within a sane window of now, got {taken}"
    );
}

/// Parse a fixed RFC 3339 instant for deterministic seeding.
fn at(ts: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

/// Set the envelope timestamp explicitly (deterministic MIN/MAX asserts).
fn with_ts(mut event: Event, ts: &str) -> Event {
    event.timestamp = at(ts);
    event
}

/// Seed one event of each category plus two extra Control events (Started
/// lifecycle, cedar Adjudicated, Completed lifecycle = 3 Control total)
/// with explicit increasing timestamps. Returns (first_ts, last_ts) in the
/// stored `to_rfc3339()` form.
async fn seed_aggregate_fixture(db_path: &std::path::Path, traj: &str) -> (String, String) {
    let events = vec![
        with_ts(action_event(traj), "2026-06-01T10:00:00Z"),
        with_ts(
            Event::new(
                test_agent(),
                traj,
                TrajectoryEvent::Observation(Observation::Think(Think::new("hmm"))),
            ),
            "2026-06-01T10:01:00Z",
        ),
        with_ts(
            Event::new(
                test_agent(),
                traj,
                TrajectoryEvent::Control(Control::Started(Started::new("test-agent"))),
            ),
            "2026-06-01T10:02:00Z",
        ),
        with_ts(
            Event::new(
                test_agent(),
                traj,
                TrajectoryEvent::State(State::Snapshot(Snapshot::new())),
            ),
            "2026-06-01T10:03:00Z",
        ),
        with_ts(adjudicated_event(traj), "2026-06-01T10:04:00Z"),
        with_ts(
            Event::new(
                test_agent(),
                traj,
                TrajectoryEvent::Control(Control::Completed(Completed::new())),
            ),
            "2026-06-01T10:05:00Z",
        ),
    ];
    {
        let store = TrajectoryStore::open(db_path).await.unwrap();
        for event in &events {
            store.insert_event(event).await.unwrap();
        }
    } // DROP before reading.
    (
        at("2026-06-01T10:00:00Z").to_rfc3339(),
        at("2026-06-01T10:05:00Z").to_rfc3339(),
    )
}

/// The aggregate SELECT is pinned to the live harness schema — event_count,
/// per-category counts, MIN/MAX timestamps.
#[tokio::test]
async fn aggregate_select_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();
    let (first_ts, last_ts) = seed_aggregate_fixture(&db_path, &traj).await;

    let ro = ReadOnlyStore::new(db_path, tmp.path().join("cache"));
    let rows = ro.trajectory_aggregates(None, None, 50).await.unwrap();
    assert_eq!(rows.len(), 1, "one trajectory -> one aggregate row");

    let row = &rows[0];
    assert_eq!(row.trajectory_id, traj);
    assert_eq!(row.event_count, 6);
    assert_eq!(row.action_count, 1);
    assert_eq!(row.observation_count, 1);
    assert_eq!(row.control_count, 3);
    assert_eq!(row.state_count, 1);
    assert_eq!(
        row.first_event_at, first_ts,
        "first_event_at == MIN(timestamp) in the stored rfc3339 form"
    );
    assert_eq!(
        row.last_activity, last_ts,
        "last_activity == MAX(timestamp) in the stored rfc3339 form"
    );
    assert_eq!(row.agent_id, "test-agent");
    assert_eq!(row.agent_provider, "test-provider");
}

/// The page-scoped Control-row SELECT returns ONLY Control-category rows,
/// ordered timestamp ASC id ASC, with event_type and actor_id populated.
#[tokio::test]
async fn control_rows_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();
    seed_aggregate_fixture(&db_path, &traj).await;

    let ro = ReadOnlyStore::new(db_path, tmp.path().join("cache"));
    let rows = ro.control_rows(std::slice::from_ref(&traj)).await.unwrap();
    assert_eq!(
        rows.len(),
        3,
        "only the Control-category rows come back (Action/Observation/State excluded)"
    );

    // Ordered timestamp ASC: Started -> Adjudicated -> Completed.
    let types: Vec<&str> = rows.iter().map(|r| r.event_type.as_str()).collect();
    assert_eq!(types, vec!["Started", "Adjudicated", "Completed"]);

    for row in &rows {
        assert_eq!(row.trajectory_id, traj);
        assert!(!row.event_type.is_empty(), "event_type populated");
        assert!(!row.actor_id.is_empty(), "actor_id populated");
        assert!(!row.event_json.is_empty(), "event_json populated");
    }
    // The cedar Adjudicated row carries the policy-actor discriminator.
    assert_eq!(rows[1].actor_id, "cedar");

    // Empty id list short-circuits — never emits IN ().
    assert!(ro.control_rows(&[]).await.unwrap().is_empty());
}

/// The prefilter SELECT returns ONLY `event_category = 'Control' AND
/// event_type = 'Adjudicated'` rows with raw_json populated; the
/// time-bounded variant respects from/to.
#[tokio::test]
async fn adjudicated_rows_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();
    // The fixture's single Adjudicated row sits at 10:04 among five other
    // non-Adjudicated rows.
    seed_aggregate_fixture(&db_path, &traj).await;

    let ro = ReadOnlyStore::new(db_path, tmp.path().join("cache"));
    let rows = ro.adjudicated_rows(None, None).await.unwrap();
    assert_eq!(
        rows.len(),
        1,
        "only the Adjudicated row comes back (lifecycle Control rows excluded)"
    );
    let row = &rows[0];
    assert_eq!(row.trajectory_id, traj);
    assert_eq!(row.actor_id, "cedar");
    assert!(
        row.raw_json.is_some(),
        "raw_json populated on the cedar Adjudicated record"
    );
    let event: TrajectoryEvent = serde_json::from_str(&row.event_json).unwrap();
    assert!(matches!(
        event,
        TrajectoryEvent::Control(Control::Adjudicated(_))
    ));

    // Time-bounded variants (stored +00:00 TEXT form).
    let ts = |s: &str| at(s).to_rfc3339();
    let in_window = ro
        .adjudicated_rows(Some(&ts("2026-06-01T10:04:00Z")), None)
        .await
        .unwrap();
    assert_eq!(in_window.len(), 1, "from == row timestamp is inclusive");
    let after = ro
        .adjudicated_rows(Some(&ts("2026-06-01T10:05:00Z")), None)
        .await
        .unwrap();
    assert!(after.is_empty(), "from after the row excludes it");
    let before = ro
        .adjudicated_rows(None, Some(&ts("2026-06-01T10:03:00Z")))
        .await
        .unwrap();
    assert!(before.is_empty(), "to before the row excludes it");
}

/// `trajectory_ids_in_range` returns DISTINCT trajectory ids with any
/// activity in the window.
#[tokio::test]
async fn trajectory_ids_in_range_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let (traj_early, traj_late) = (new_trajectory_id(), new_trajectory_id());
    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        // Two rows for the early trajectory prove DISTINCT.
        store
            .insert_event(&with_ts(action_event(&traj_early), "2026-06-01T10:00:00Z"))
            .await
            .unwrap();
        store
            .insert_event(&with_ts(action_event(&traj_early), "2026-06-01T10:01:00Z"))
            .await
            .unwrap();
        store
            .insert_event(&with_ts(action_event(&traj_late), "2026-06-05T10:00:00Z"))
            .await
            .unwrap();
    } // DROP before reading.

    let ro = ReadOnlyStore::new(db_path, tmp.path().join("cache"));
    let ts = |s: &str| at(s).to_rfc3339();

    let mut all = ro.trajectory_ids_in_range(None, None).await.unwrap();
    all.sort();
    let mut expected = vec![traj_early.clone(), traj_late.clone()];
    expected.sort();
    assert_eq!(all, expected, "unbounded scan returns DISTINCT ids");

    let windowed = ro
        .trajectory_ids_in_range(
            Some(&ts("2026-06-01T00:00:00Z")),
            Some(&ts("2026-06-02T00:00:00Z")),
        )
        .await
        .unwrap();
    assert_eq!(
        windowed,
        vec![traj_early],
        "window covers only the early trajectory, exactly once (DISTINCT)"
    );
}

/// The poll fallback's id-cursor SELECTs are pinned to the live harness
/// schema — `max_event_row_id` returns the highest rowid and
/// `events_after_id` returns exactly the rows past the cursor, in id order,
/// with full `Event` deserialization. Absent live DB -> `Ok(0)` / empty.
#[tokio::test]
async fn id_cursor_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();

    let events = vec![
        with_ts(action_event(&traj), "2026-06-01T10:00:00Z"),
        with_ts(action_event(&traj), "2026-06-01T10:01:00Z"),
        with_ts(adjudicated_event(&traj), "2026-06-01T10:02:00Z"),
    ];
    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        for event in &events {
            store.insert_event(event).await.unwrap();
        }
    } // DROP before reading.

    let ro = ReadOnlyStore::new(db_path, tmp.path().join("cache"));

    let max_id = ro.max_event_row_id().await.unwrap();
    assert!(
        max_id >= 3,
        "3 seeded rows -> highest rowid must be at least 3, got {max_id}"
    );

    // Cursor two before the max: exactly the last 2 rows, in id order,
    // fully deserialized.
    let after = ro.events_after_id(max_id - 2).await.unwrap();
    assert_eq!(after.len(), 2, "cursor at max-2 yields exactly the last 2");
    assert!(
        after[0].0 < after[1].0,
        "rows come back in ascending id order"
    );
    assert_eq!(after[1].0, max_id, "the last row carries the max rowid");
    assert_eq!(
        after[0].1.event_id, events[1].event_id,
        "second seeded event deserializes at the cursor boundary"
    );
    assert_eq!(after[1].1.event_id, events[2].event_id);
    assert!(
        matches!(
            after[1].1.event,
            TrajectoryEvent::Control(Control::Adjudicated(_))
        ),
        "Adjudicated payload must round-trip through events_after_id"
    );

    // Cursor at the max: empty (nothing newer).
    assert!(
        ro.events_after_id(max_id).await.unwrap().is_empty(),
        "cursor at MAX(id) yields nothing"
    );

    // Absent live DB: Ok(0) / empty, file never created.
    let absent = ReadOnlyStore::new(
        tmp.path().join("nonexistent.db"),
        tmp.path().join("cache-absent"),
    );
    assert_eq!(absent.max_event_row_id().await.unwrap(), 0);
    assert!(absent.events_after_id(0).await.unwrap().is_empty());
    assert!(!tmp.path().join("nonexistent.db").exists());
}

/// A missing live DB serves empty, reports `Absent`, and is NEVER created
/// (turso's default open mode would silently create the file).
#[tokio::test]
async fn absent_db_serves_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("nonexistent.db");

    let ro = ReadOnlyStore::new(db_path.clone(), tmp.path().join("cache"));

    let health = ro.health().await;
    assert_eq!(health.db_state, DbState::Absent);
    assert_eq!(health.event_count, None);

    let events = ro.events_for_trajectory("any-trajectory").await.unwrap();
    assert!(events.is_empty(), "absent DB serves empty results");
    assert_eq!(ro.count_events().await.unwrap(), 0);

    // CRITICAL: the store must never have created the live file.
    assert!(
        !tmp.path().join("nonexistent.db").exists(),
        "the dashboard must NEVER create the live DB (D-50)"
    );
}
