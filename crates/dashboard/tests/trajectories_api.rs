//! Integration tests for `GET /trajectories/{id}/events` and
//! `GET /trajectories/{id}/adjudications` — plus the list suite for
//! `GET /trajectories` (ordering, status, counts, limit clamp, keyset cursor
//! with tie-break, four-dimension filtering, strict 400s, monitor-record
//! exclusion).
//!
//! Seeds real harness-written rows via `TrajectoryStore` (the dev/test
//! exception — the write-capable store stays FORBIDDEN in
//! `crates/dashboard/src`), drops the seeding store before the dashboard
//! reads (turso dedupes same-process opens by canonical path — the
//! snapshot-copy path must actually run), then exercises the production
//! router end to end:
//!
//! - the ordered event sequence round-trips as `EventDto` JSON with NO raw
//!   agent payload crossing the boundary (sentinel assertion),
//! - adjudication records surface cedar AND monitor actors (the mirrored
//!   monitor verdict is data, not noise),
//! - an existing trajectory with zero adjudications is 200 `[]`, not 404,
//! - an unknown id is 404 with the pinned `{"error": "..."}` body,
//! - store-backed 200s carry the `x-sondera-snapshot-at` header,
//! - the detail routes inherit `secure()` — no token means 401.

use axum::http::HeaderValue;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use sondera_dashboard::storage::ReadOnlyStore;
use sondera_dashboard::{AppState, build_router, cors::cors_layer};
use sondera_harness::{
    Action, Actor, Adjudicated, Agent, Annotation, Completed, Control, Event, Failed, Label,
    MonitorAttributes, MonitorSnapshot, Suspended, Terminated, ToolCall, TrajectoryEvent,
    TrajectoryStore, Verdict,
};
use std::path::{Path, PathBuf};
use tower::ServiceExt;
use tower_http::cors::CorsLayer;

const TOKEN: &str = "sondera-test-token-0001";

fn test_agent() -> Agent {
    Agent {
        id: "test-agent".to_string(),
        provider_id: "test-provider".to_string(),
    }
}

/// Unique trajectory ids keep runs independent.
fn new_trajectory_id() -> String {
    format!("test-detail-{}", uuid::Uuid::new_v4())
}

fn default_cors() -> CorsLayer {
    cors_layer(&[
        HeaderValue::from_static("http://localhost:5173"),
        HeaderValue::from_static("http://127.0.0.1:5173"),
    ])
}

/// Production router whose store points at a real seeded tempdir DB —
/// the auth_gate.rs `test_state` shape, but with live data behind it.
fn app_with_db(db_path: PathBuf, trajectories_dir: PathBuf, token: &str) -> Router {
    let cache = db_path
        .parent()
        .expect("db path has a parent dir")
        .join("dashboard-cache");
    let state = AppState {
        token: token.to_string(),
        db_path: db_path.clone(),
        trajectories_dir,
        store: std::sync::Arc::new(ReadOnlyStore::new(db_path, cache)),
        stream_tx: tokio::sync::broadcast::channel(sondera_dashboard::stream::BROADCAST_CAPACITY).0,
    };
    build_router(state, default_cors())
}

/// An Armed monitor snapshot in the wire shape the harness writes.
fn armed_snapshot() -> MonitorSnapshot {
    MonitorSnapshot {
        verdict: Verdict::Pending,
        state: "armed".to_string(),
        attributes: MonitorAttributes {
            armed_event_id: Some("evt-armed-1".to_string()),
            cleared_event_id: None,
            tripped_event_id: None,
        },
        untrusted_pending: true,
        taints: vec!["untrusted_read".to_string()],
        label: Label::Confidential,
    }
}

/// Agent Action event carrying a raw agent-native payload that must NEVER
/// cross the DTO boundary.
fn action_event(traj: &str) -> Event {
    Event::new(
        test_agent(),
        traj,
        TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
            "search",
            serde_json::json!({"q": "rust"}),
        ))),
    )
    .with_raw(serde_json::json!({"agent_native": "SENTINEL-raw-must-not-cross"}))
}

/// The canonical production ShellCommand request context with SENTINEL
/// values on every content-bearing key — those sentinels must NEVER cross
/// the DTO boundary, while the guardrail sub-blocks
/// (signature/policy/label) must.
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

/// Cedar-path Adjudicated record: `Actor::policy("cedar")` with the full
/// `{request, response, monitor}` raw sibling structure.
fn cedar_adjudicated_event(traj: &str) -> Event {
    let raw = serde_json::json!({
        "request": {
            "principal": "Agent::\"test-agent\"",
            "action": "Action::\"FileWrite\"",
            "resource": "File::\"/repo/.github/workflows/ci.yml\"",
            "context": shell_command_context(),
        },
        "response": {
            "decision": "Deny",
            "reason": ["multi-hop-001"],
            "errors": [],
        },
        "monitor": serde_json::to_value(armed_snapshot()).unwrap(),
    });
    Event::new(
        test_agent(),
        traj,
        TrajectoryEvent::Control(Control::Adjudicated(
            Adjudicated::deny()
                .with_reason("multi-hop forbid")
                .with_annotation(Annotation::new().with_id("multi-hop-001".to_string())),
        )),
    )
    .with_actor(Actor::policy("cedar"))
    .with_raw(raw)
}

/// Synthetic monitor-mirror record: `Actor::policy("monitor")`, Allow,
/// raw = monitor block only (the Started/Resumed snapshot shape).
fn monitor_adjudicated_event(traj: &str) -> Event {
    Event::new(
        test_agent(),
        traj,
        TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
    )
    .with_actor(Actor::policy("monitor"))
    .with_raw(serde_json::json!({
        "monitor": serde_json::to_value(armed_snapshot()).unwrap(),
    }))
}

/// Seed the canonical three-event trajectory (Action + cedar Adjudicated +
/// monitor Adjudicated) with strictly increasing timestamps, dropping the
/// seeding store before returning. Returns the event ids in timestamp order.
async fn seed_full_trajectory(db_path: &Path, traj: &str) -> (String, String, String) {
    let base = chrono::Utc::now();
    let mut action = action_event(traj);
    action.timestamp = base;
    let mut cedar = cedar_adjudicated_event(traj);
    cedar.timestamp = base + chrono::Duration::seconds(1);
    let mut monitor = monitor_adjudicated_event(traj);
    monitor.timestamp = base + chrono::Duration::seconds(2);

    {
        let store = TrajectoryStore::open(db_path).await.unwrap();
        store.insert_event(&action).await.unwrap();
        store.insert_event(&cedar).await.unwrap();
        store.insert_event(&monitor).await.unwrap();
    } // DROP before reading: the snapshot-copy path must actually run.

    (action.event_id, cedar.event_id, monitor.event_id)
}

/// Authenticated GET returning the raw response.
async fn authed_get(app: Router, path: &str) -> axum::response::Response {
    app.oneshot(
        Request::get(path)
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn body_string(res: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn events_happy_path() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();
    let (action_id, cedar_id, monitor_id) = seed_full_trajectory(&db_path, &traj).await;

    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let res = authed_get(app, &format!("/trajectories/{traj}/events")).await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = body_string(res).await;
    assert!(
        !body.contains("SENTINEL-raw-must-not-cross"),
        "raw agent payload must never cross the DTO boundary (D-44)"
    );
    assert!(
        !body.contains("SENTINEL-context"),
        "EventDto never reads raw — context sentinels must not leak through /events"
    );

    let value: serde_json::Value = serde_json::from_str(&body).expect("body is JSON");
    let arr = value.as_array().expect("body is a bare JSON array");
    assert_eq!(arr.len(), 3, "all three seeded events round-trip");

    // Ordered timestamp ASC — the seed used strictly increasing timestamps.
    assert_eq!(arr[0]["eventId"], action_id);
    assert_eq!(arr[1]["eventId"], cedar_id);
    assert_eq!(arr[2]["eventId"], monitor_id);

    // camelCase EventDto wire shape on the first element.
    let first = arr[0].as_object().unwrap();
    assert!(first.contains_key("eventId"));
    assert!(first.contains_key("trajectoryId"));
    assert!(first.contains_key("event"));
    assert_eq!(arr[0]["trajectoryId"], traj.as_str());
}

#[tokio::test]
async fn adjudications_happy_path() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();
    seed_full_trajectory(&db_path, &traj).await;

    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let res = authed_get(app, &format!("/trajectories/{traj}/adjudications")).await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = body_string(res).await;
    let value: serde_json::Value = serde_json::from_str(&body).expect("body is JSON");
    let arr = value.as_array().expect("body is a bare JSON array");
    assert_eq!(
        arr.len(),
        2,
        "cedar AND monitor adjudication records are both included (API-04)"
    );

    let cedar = arr
        .iter()
        .find(|record| record["actorId"] == "cedar")
        .expect("cedar-actor record present");
    assert_eq!(cedar["decision"], "Deny");
    assert!(cedar["annotations"].is_array());
    assert!(
        cedar.get("monitor").is_some(),
        "cedar record carries the monitor block"
    );
    assert!(
        cedar.get("request").is_some(),
        "cedar record carries the cedar request block"
    );
    assert!(
        cedar.get("response").is_some(),
        "cedar record carries the cedar response block"
    );

    // The three guardrail signals surface on the cedar record exactly as
    // seeded.
    assert_eq!(cedar["guardrails"]["signature"]["matches"], 2);
    assert_eq!(cedar["guardrails"]["signature"]["severity"], 3);
    assert_eq!(
        cedar["guardrails"]["signature"]["categories"],
        serde_json::json!(["credential_access"])
    );
    assert_eq!(cedar["guardrails"]["policy"]["compliant"], false);
    assert_eq!(
        cedar["guardrails"]["policy"]["violations"],
        serde_json::json!(["SC2: OS Command Injection"])
    );
    assert_eq!(cedar["guardrails"]["label"], "confidential");

    let monitor = arr
        .iter()
        .find(|record| record["actorId"] == "monitor")
        .expect("monitor-actor record present (the mirrored monitor verdict)");
    assert!(monitor.get("monitor").is_some());
    assert!(
        monitor.get("request").is_none(),
        "monitor record has no cedar request block"
    );
    assert!(
        monitor.get("response").is_none(),
        "monitor record has no cedar response block"
    );
    assert!(
        monitor.get("guardrails").is_none(),
        "monitor record (raw = monitor only) has no guardrails block"
    );

    // The content-bearing context sentinels never cross the boundary.
    assert!(
        !body.contains("SENTINEL-context"),
        "sensitive context keys must never cross the DTO boundary (T-06-17)"
    );
}

#[tokio::test]
async fn adjudications_empty_is_200() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();

    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        store.insert_event(&action_event(&traj)).await.unwrap();
    } // DROP before reading.

    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let res = authed_get(app, &format!("/trajectories/{traj}/adjudications")).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "trajectory exists; zero adjudications is data, not 404"
    );

    let body = body_string(res).await;
    let value: serde_json::Value = serde_json::from_str(&body).expect("body is JSON");
    assert_eq!(value, serde_json::json!([]));
}

#[tokio::test]
async fn unknown_id_is_404_with_error_body() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    // A real DB exists, but with a DIFFERENT trajectory in it.
    seed_full_trajectory(&db_path, &new_trajectory_id()).await;

    for route in ["events", "adjudications"] {
        let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
        let res = authed_get(app, &format!("/trajectories/no-such-id/{route}")).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "/{route} must 404");

        let body = body_string(res).await;
        let value: serde_json::Value =
            serde_json::from_str(&body).expect("404 must carry a JSON error body");
        assert_eq!(
            value,
            serde_json::json!({"error": "trajectory not found"}),
            "/{route} 404 body is the pinned ErrorBody shape"
        );
    }
}

#[tokio::test]
async fn snapshot_header_present() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();
    seed_full_trajectory(&db_path, &traj).await;

    for route in ["events", "adjudications"] {
        let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
        let res = authed_get(app, &format!("/trajectories/{traj}/{route}")).await;
        assert_eq!(res.status(), StatusCode::OK);

        let header = res
            .headers()
            .get("x-sondera-snapshot-at")
            .unwrap_or_else(|| panic!("/{route} 200 must carry x-sondera-snapshot-at (D-66)"));
        let header_str = header.to_str().expect("header is valid UTF-8");
        chrono::DateTime::parse_from_rfc3339(header_str)
            .expect("x-sondera-snapshot-at must be RFC 3339");
    }
}

#[tokio::test]
async fn detail_routes_require_auth() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);

    let res = app
        .oneshot(
            Request::get("/trajectories/x/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "detail routes inherit secure() — no token means 401"
    );
}

// ============================================================================
// List-endpoint fixtures
// ============================================================================

/// Parse a fixed RFC 3339 instant — the list fixtures set `event.timestamp`
/// explicitly so ordering, the shared-timestamp tie-break, and the
/// `from`/`to` window are deterministic.
fn at(ts: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

/// Set the envelope timestamp explicitly (the `Event.timestamp` field is
/// pub) for deterministic last-activity ordering.
fn with_ts(mut event: Event, ts: &str) -> Event {
    event.timestamp = at(ts);
    event
}

/// A lifecycle Control event (Started/Completed/Failed/Terminated/Suspended
/// fixtures for the status mapping).
fn lifecycle_event(traj: &str, control: Control) -> Event {
    Event::new(test_agent(), traj, TrajectoryEvent::Control(control))
}

/// Cedar-path Adjudicated record with a chosen decision payload and a
/// chosen sensitivity label inside the raw monitor block (the label source).
/// Carries the known `multi-hop-001` policy id when the payload has
/// annotations.
fn cedar_decision_event(traj: &str, adjudicated: Adjudicated, label: Label) -> Event {
    let mut snap = armed_snapshot();
    snap.label = label;
    let raw = serde_json::json!({
        "request": {
            "principal": "Agent::\"test-agent\"",
            "action": "Action::\"FileWrite\"",
            "resource": "File::\"/repo/.github/workflows/ci.yml\"",
            "context": shell_command_context(),
        },
        "response": {
            "decision": "Deny",
            "reason": ["multi-hop-001"],
            "errors": [],
        },
        "monitor": serde_json::to_value(snap).unwrap(),
    });
    Event::new(
        test_agent(),
        traj,
        TrajectoryEvent::Control(Control::Adjudicated(adjudicated)),
    )
    .with_actor(Actor::policy("cedar"))
    .with_raw(raw)
}

/// Deny adjudication carrying the known `multi-hop-001` policy id.
fn deny_adjudicated(traj: &str, label: Label) -> Event {
    cedar_decision_event(
        traj,
        Adjudicated::deny()
            .with_reason("multi-hop forbid")
            .with_annotation(Annotation::new().with_id("multi-hop-001".to_string())),
        label,
    )
}

/// Escalate adjudication.
fn escalate_adjudicated(traj: &str, label: Label) -> Event {
    cedar_decision_event(
        traj,
        Adjudicated::escalate().with_reason("needs review"),
        label,
    )
}

/// Seed a batch of events, dropping the seeding store before reading (the
/// snapshot-copy path must actually run).
async fn seed_events(db_path: &Path, events: &[Event]) {
    let store = TrajectoryStore::open(db_path).await.unwrap();
    for event in events {
        store.insert_event(event).await.unwrap();
    }
} // store dropped here

/// Authenticated GET returning (status, parsed JSON body).
async fn get_json(app: Router, path: &str) -> (StatusCode, serde_json::Value) {
    let res = authed_get(app, path).await;
    let status = res.status();
    let body = body_string(res).await;
    let value: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("body is JSON ({e}): {body}"));
    (status, value)
}

/// The trajectory ids in a list response, in response order.
fn page_ids(body: &serde_json::Value) -> Vec<String> {
    body["trajectories"]
        .as_array()
        .expect("body has a trajectories array")
        .iter()
        .map(|item| item["trajectoryId"].as_str().unwrap().to_string())
        .collect()
}

// ============================================================================
// Ordering, counts, status, clamp, keyset cursor
// ============================================================================

#[tokio::test]
async fn list_recent_first_with_counts_and_status() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let (traj_deny, traj_escalate, traj_done) = (
        new_trajectory_id(),
        new_trajectory_id(),
        new_trajectory_id(),
    );

    seed_events(
        &db_path,
        &[
            // Oldest last-activity: a Deny adjudication.
            with_ts(action_event(&traj_deny), "2026-06-01T10:00:00Z"),
            with_ts(
                deny_adjudicated(&traj_deny, Label::Confidential),
                "2026-06-01T10:01:00Z",
            ),
            // Middle: an Escalate adjudication.
            with_ts(action_event(&traj_escalate), "2026-06-01T11:00:00Z"),
            with_ts(
                escalate_adjudicated(&traj_escalate, Label::Public),
                "2026-06-01T11:01:00Z",
            ),
            // Newest: a Completed lifecycle event.
            with_ts(action_event(&traj_done), "2026-06-01T12:00:00Z"),
            with_ts(
                lifecycle_event(&traj_done, Control::Completed(Completed::new())),
                "2026-06-01T12:01:00Z",
            ),
        ],
    )
    .await;

    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories").await;
    assert_eq!(status, StatusCode::OK);

    let ids = page_ids(&body);
    assert_eq!(
        ids,
        vec![traj_done.clone(), traj_escalate.clone(), traj_deny.clone()],
        "newest-last-activity-first ordering (D-57)"
    );

    let items = body["trajectories"].as_array().unwrap();
    for item in items {
        let obj = item.as_object().unwrap();
        assert!(obj.contains_key("trajectoryId"));
        assert!(obj.contains_key("eventCount"));
        assert!(obj.contains_key("denyCount"));
        assert!(obj.contains_key("escalateCount"));
        assert!(obj.contains_key("status"));
        assert_eq!(item["eventCount"], 2);
    }

    let by_id = |id: &str| items.iter().find(|i| i["trajectoryId"] == id).unwrap();
    let done = by_id(&traj_done);
    assert_eq!(done["status"], "completed", "Completed -> completed (D-58)");
    assert_eq!(done["denyCount"], 0);
    assert_eq!(done["escalateCount"], 0);

    let deny = by_id(&traj_deny);
    assert_eq!(
        deny["status"], "active",
        "no terminal Control yet -> active"
    );
    assert_eq!(deny["denyCount"], 1);
    assert_eq!(deny["escalateCount"], 0);

    let escalate = by_id(&traj_escalate);
    assert_eq!(escalate["status"], "active");
    assert_eq!(escalate["denyCount"], 0);
    assert_eq!(escalate["escalateCount"], 1);
}

#[tokio::test]
async fn limit_clamp() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let (traj_a, traj_b) = (new_trajectory_id(), new_trajectory_id());
    seed_events(
        &db_path,
        &[
            with_ts(action_event(&traj_a), "2026-06-01T10:00:00Z"),
            with_ts(action_event(&traj_b), "2026-06-01T11:00:00Z"),
        ],
    )
    .await;

    // ?limit=999 is server-clamped: still a valid 200, never a 500.
    let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?limit=999").await;
    assert_eq!(status, StatusCode::OK, "clamped limit must not error");
    assert_eq!(page_ids(&body).len(), 2);

    // ?limit=1 caps the page at exactly one item.
    let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page_ids(&body).len(), 1, "limit=1 page has exactly 1 item");

    // Non-numeric limit -> 400 naming the offender.
    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?limit=abc").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("limit"),
        "400 body must name 'limit', got: {body}"
    );
}

#[tokio::test]
async fn keyset_pagination_with_tiebreak() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    // Four trajectories; two share the SAME last-activity timestamp so the
    // cursor must tie-break on trajectory_id.
    let trajs: Vec<String> = (0..4).map(|_| new_trajectory_id()).collect();
    seed_events(
        &db_path,
        &[
            with_ts(action_event(&trajs[0]), "2026-06-01T10:00:00Z"),
            with_ts(action_event(&trajs[1]), "2026-06-01T11:00:00Z"),
            // The shared-timestamp pair: identical DateTime values.
            with_ts(action_event(&trajs[2]), "2026-06-01T12:00:00Z"),
            with_ts(action_event(&trajs[3]), "2026-06-01T12:00:00Z"),
        ],
    )
    .await;

    let mut collected: Vec<String> = Vec::new();
    let mut query = "/trajectories?limit=2".to_string();
    for _page in 0..4 {
        let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
        let (status, body) = get_json(app, &query).await;
        assert_eq!(status, StatusCode::OK, "page fetch failed for {query}");
        let ids = page_ids(&body);
        if ids.is_empty() {
            break;
        }
        collected.extend(ids);
        match (body.get("nextBefore"), body.get("nextBeforeId")) {
            (Some(before), Some(before_id)) if before.is_string() => {
                // '+' must not be reinterpreted as a space — %XX-encode it.
                let before = before.as_str().unwrap().replace('+', "%2B");
                let before_id = before_id.as_str().unwrap();
                query = format!("/trajectories?limit=2&before={before}&before_id={before_id}");
            }
            _ => break,
        }
    }

    let mut expected: Vec<String> = trajs.clone();
    expected.sort();
    let mut got = collected.clone();
    got.sort();
    assert_eq!(
        got, expected,
        "union of pages covers all 4 trajectories with no duplicates and no skips"
    );
    assert_eq!(collected.len(), 4, "no trajectory appears twice");
}

// ============================================================================
// Filter dimensions, error shapes, monitor exclusion
// ============================================================================

#[tokio::test]
async fn filter_decision_any_match() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let (traj_deny, traj_escalate, traj_allow) = (
        new_trajectory_id(),
        new_trajectory_id(),
        new_trajectory_id(),
    );
    seed_events(
        &db_path,
        &[
            with_ts(
                deny_adjudicated(&traj_deny, Label::Public),
                "2026-06-01T10:00:00Z",
            ),
            with_ts(
                escalate_adjudicated(&traj_escalate, Label::Public),
                "2026-06-01T11:00:00Z",
            ),
            with_ts(
                cedar_decision_event(&traj_allow, Adjudicated::allow(), Label::Public),
                "2026-06-01T12:00:00Z",
            ),
        ],
    )
    .await;

    // Single value: only the denying trajectory (any-match within).
    let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?decision=deny").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page_ids(&body), vec![traj_deny.clone()]);

    // Repeated key ORs within the dimension.
    let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?decision=deny&decision=escalate").await;
    assert_eq!(status, StatusCode::OK);
    let mut ids = page_ids(&body);
    ids.sort();
    let mut expected = vec![traj_deny.clone(), traj_escalate.clone()];
    expected.sort();
    assert_eq!(ids, expected, "deny OR escalate returns both");

    // Case-insensitive input canonicalizes.
    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?decision=DENY").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page_ids(&body), vec![traj_deny]);
}

#[tokio::test]
async fn filter_and_across_dimensions() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let (traj_both, traj_deny_public, traj_allow_confidential) = (
        new_trajectory_id(),
        new_trajectory_id(),
        new_trajectory_id(),
    );
    seed_events(
        &db_path,
        &[
            // Deny AND confidential label: the only survivor.
            with_ts(
                deny_adjudicated(&traj_both, Label::Confidential),
                "2026-06-01T10:00:00Z",
            ),
            // Deny but public label: decision matches, label does not.
            with_ts(
                deny_adjudicated(&traj_deny_public, Label::Public),
                "2026-06-01T11:00:00Z",
            ),
            // Allow with confidential label: label matches, decision does not.
            with_ts(
                cedar_decision_event(
                    &traj_allow_confidential,
                    Adjudicated::allow(),
                    Label::Confidential,
                ),
                "2026-06-01T12:00:00Z",
            ),
        ],
    )
    .await;

    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?decision=deny&label=confidential").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        page_ids(&body),
        vec![traj_both],
        "AND across dimensions (D-61): deny AND confidential only"
    );
}

#[tokio::test]
async fn filter_policy_id() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let (traj_hit, traj_miss) = (new_trajectory_id(), new_trajectory_id());
    seed_events(
        &db_path,
        &[
            // Carries the multi-hop-001 annotation.
            with_ts(
                deny_adjudicated(&traj_hit, Label::Public),
                "2026-06-01T10:00:00Z",
            ),
            // Adjudicated, but no annotations at all.
            with_ts(
                cedar_decision_event(&traj_miss, Adjudicated::allow(), Label::Public),
                "2026-06-01T11:00:00Z",
            ),
        ],
    )
    .await;

    let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?policy_id=multi-hop-001").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page_ids(&body), vec![traj_hit]);

    // An unknown policy id is a valid filter with an empty result page.
    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?policy_id=no-such-policy").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page_ids(&body).is_empty(),
        "unknown policy id returns an empty page, not an error"
    );
}

#[tokio::test]
async fn filter_time_range() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let (traj_in, traj_out) = (new_trajectory_id(), new_trajectory_id());
    seed_events(
        &db_path,
        &[
            with_ts(action_event(&traj_in), "2026-06-01T10:00:00Z"),
            with_ts(action_event(&traj_out), "2026-06-05T10:00:00Z"),
        ],
    )
    .await;

    // Z-suffixed RFC 3339 window around the first trajectory only.
    let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(
        app,
        "/trajectories?from=2026-06-01T00:00:00Z&to=2026-06-02T00:00:00Z",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        page_ids(&body),
        vec![traj_in],
        "from/to restrict to trajectories with activity in range"
    );

    // Malformed from -> 400.
    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?from=yesterday").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("from")
            || body["error"].as_str().unwrap().contains("yesterday"),
        "400 body must name the offending param, got: {body}"
    );
}

#[tokio::test]
async fn unknown_key_and_bad_value_400() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();
    seed_events(
        &db_path,
        &[with_ts(action_event(&traj), "2026-06-01T10:00:00Z")],
    )
    .await;

    // Typo key -> 400 naming the key.
    let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?decison=deny").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("decison"),
        "400 body must name the unknown key, got: {body}"
    );

    // Unrecognized label value -> 400 naming the value.
    let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?label=secret").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("secret"),
        "400 body must name the bad value, got: {body}"
    );

    // The token key is auth's domain — silently ignored here.
    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let (status, _body) = get_json(app, "/trajectories?token=anything").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "?token= must be IGNORED by the filter parser"
    );
}

#[tokio::test]
async fn monitor_records_never_match_decision_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let traj = new_trajectory_id();
    // The ONLY Adjudicated rows are synthetic monitor-actor Allow records
    // (the Started/Resumed snapshot shape).
    seed_events(
        &db_path,
        &[
            with_ts(action_event(&traj), "2026-06-01T10:00:00Z"),
            with_ts(monitor_adjudicated_event(&traj), "2026-06-01T10:01:00Z"),
        ],
    )
    .await;

    // It must NOT match ?decision=allow.
    let app = app_with_db(db_path.clone(), tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories?decision=allow").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page_ids(&body).is_empty(),
        "synthetic monitor-actor Allow records never match ?decision= (Pitfall 5)"
    );

    // And its deny/escalate counts stay 0 in the unfiltered list.
    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories").await;
    assert_eq!(status, StatusCode::OK);
    let items = body["trajectories"].as_array().unwrap();
    let item = items
        .iter()
        .find(|i| i["trajectoryId"] == traj.as_str())
        .expect("trajectory present in the unfiltered list");
    assert_eq!(item["denyCount"], 0);
    assert_eq!(item["escalateCount"], 0);
}

#[tokio::test]
async fn status_lifecycle_mapping() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let (traj_failed, traj_terminated, traj_suspended) = (
        new_trajectory_id(),
        new_trajectory_id(),
        new_trajectory_id(),
    );
    seed_events(
        &db_path,
        &[
            with_ts(
                lifecycle_event(&traj_failed, Control::Failed(Failed::new("oops"))),
                "2026-06-01T10:00:00Z",
            ),
            with_ts(
                lifecycle_event(
                    &traj_terminated,
                    Control::Terminated(Terminated::new("timeout", "system")),
                ),
                "2026-06-01T11:00:00Z",
            ),
            // Suspended is NOT a terminal state -> active.
            with_ts(
                lifecycle_event(
                    &traj_suspended,
                    Control::Suspended(Suspended::new("waiting")),
                ),
                "2026-06-01T12:00:00Z",
            ),
        ],
    )
    .await;

    let app = app_with_db(db_path, tmp.path().join("trajectories"), TOKEN);
    let (status, body) = get_json(app, "/trajectories").await;
    assert_eq!(status, StatusCode::OK);
    let items = body["trajectories"].as_array().unwrap();
    let status_of = |id: &str| {
        items
            .iter()
            .find(|i| i["trajectoryId"] == id)
            .unwrap_or_else(|| panic!("{id} missing from list"))["status"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(status_of(&traj_failed), "failed");
    assert_eq!(status_of(&traj_terminated), "terminated");
    assert_eq!(
        status_of(&traj_suspended),
        "active",
        "Suspended is not terminal (D-58)"
    );
}
