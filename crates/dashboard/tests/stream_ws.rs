//! Integration tests for the `GET /stream` live WebSocket feed.
//!
//! Real-loopback suite (hyper only attaches the `OnUpgrade` extension on a
//! live connection — `tower::oneshot` can NEVER produce 101, so every
//! handshake/message-flow test serves the production router on a
//! `TcpListener` and connects with a real `tokio_tungstenite` client):
//!
//! - the 101 upgrade completes through the existing `secure()` auth via
//!   `?token=` (zero new auth code),
//! - published envelopes arrive as the typed JSON shape, `event` and
//!   `adjudication` classified correctly,
//! - a new connection receives ONLY messages published after it subscribed
//!   (no backlog replay),
//! - no token means 401 (oneshot is fine for rejections).

use axum::extract::ws::Utf8Bytes;
use axum::http::HeaderValue;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use futures::StreamExt;
use sondera_dashboard::storage::ReadOnlyStore;
use sondera_dashboard::{AppState, build_router, cors::cors_layer, stream};
use sondera_harness::{
    Action, Actor, Adjudicated, Agent, Control, Event, ToolCall, TrajectoryEvent,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;

const TOKEN: &str = "sondera-test-token-0001";

/// Bound on every async wait so a broken stream fails loudly, never hangs.
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

fn test_agent() -> Agent {
    Agent {
        id: "test-agent".to_string(),
        provider_id: "test-provider".to_string(),
    }
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
    .with_raw(serde_json::json!({"agent_native": "SENTINEL-raw-must-not-cross"}))
}

fn cedar_adjudicated_event(traj: &str) -> Event {
    Event::new(
        test_agent(),
        traj,
        TrajectoryEvent::Control(Control::Adjudicated(
            Adjudicated::deny().with_reason("multi-hop forbid"),
        )),
    )
    .with_actor(Actor::policy("cedar"))
    .with_raw(serde_json::json!({
        "response": { "decision": "Deny", "reason": [], "errors": [] },
    }))
}

fn default_cors() -> CorsLayer {
    cors_layer(&[
        HeaderValue::from_static("http://localhost:5173"),
        HeaderValue::from_static("http://127.0.0.1:5173"),
    ])
}

fn test_state(token: &str) -> AppState {
    test_state_with_capacity(token, stream::BROADCAST_CAPACITY)
}

/// AppState with an explicit broadcast capacity — the lag/no-stall suite
/// uses a SMALL ring so overruns are cheap to provoke; no production knob
/// exists (tests construct AppState directly).
fn test_state_with_capacity(token: &str, capacity: usize) -> AppState {
    let unique = uuid::Uuid::new_v4();
    let base = std::env::temp_dir().join(format!("sondera-dash-test-{unique}"));
    AppState {
        token: token.to_string(),
        db_path: base.join("trajectories.db"),
        trajectories_dir: base.join("trajectories"),
        // Absent DB is fine: stream tests never touch the store.
        store: std::sync::Arc::new(ReadOnlyStore::new(
            base.join("trajectories.db"),
            base.join("dashboard-cache"),
        )),
        stream_tx: broadcast::channel(capacity).0,
    }
}

/// Serve the production router on a loopback listener; return the bound
/// address, a clone of the broadcast sender (tests publish directly — no
/// real tail needed), and the server task handle.
async fn serve_app(token: &str) -> (SocketAddr, broadcast::Sender<Utf8Bytes>, JoinHandle<()>) {
    serve_app_with_capacity(token, stream::BROADCAST_CAPACITY).await
}

async fn serve_app_with_capacity(
    token: &str,
    capacity: usize,
) -> (SocketAddr, broadcast::Sender<Utf8Bytes>, JoinHandle<()>) {
    let state = test_state_with_capacity(token, capacity);
    let stream_tx = state.stream_tx.clone();
    let app = build_router(state, default_cors());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, stream_tx, server)
}

/// Wait until the server-side forward loop has subscribed (deterministic —
/// no sleeps): `subscribe()` happens inside `on_upgrade`, which can land
/// after `connect_async` returns.
async fn wait_for_subscriber(tx: &broadcast::Sender<Utf8Bytes>, count: usize) {
    tokio::time::timeout(RECV_TIMEOUT, async {
        while tx.receiver_count() < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("server forward loop must subscribe within the timeout");
}

/// Read the next text frame from the client and parse it as JSON.
async fn next_json(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> serde_json::Value {
    loop {
        let msg = tokio::time::timeout(RECV_TIMEOUT, ws.next())
            .await
            .expect("frame must arrive within the timeout")
            .expect("stream must not end")
            .expect("frame must not error");
        if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
            return serde_json::from_str(text.as_str()).expect("text frame is JSON");
        }
        // Ignore pings/pongs from the keepalive arm.
    }
}

#[tokio::test]
async fn ws_101_with_query_token() {
    let (addr, _tx, server) = serve_app(TOKEN).await;
    let url = format!("ws://{addr}/stream?token={TOKEN}");
    let (_ws, response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("WS handshake through secure()'s ?token= path must succeed");
    assert_eq!(response.status().as_u16(), 101);
    server.abort();
}

#[tokio::test]
async fn envelope_happy_path() {
    let (addr, tx, server) = serve_app(TOKEN).await;
    let url = format!("ws://{addr}/stream?token={TOKEN}");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    wait_for_subscriber(&tx, 1).await;

    stream::publish(&tx, &action_event("traj-happy"));
    stream::publish(&tx, &cedar_adjudicated_event("traj-happy"));

    let first = next_json(&mut ws).await;
    assert_eq!(first["type"], "event");
    assert_eq!(first["trajectory_id"], "traj-happy");
    assert!(
        first["data"].as_object().unwrap().contains_key("eventId"),
        "data is the camelCase EventDto, got: {first}"
    );
    assert!(
        !first.to_string().contains("SENTINEL-raw-must-not-cross"),
        "raw agent payloads must never cross a WS frame (D-44 via D-68)"
    );

    let second = next_json(&mut ws).await;
    assert_eq!(second["type"], "adjudication");
    assert_eq!(second["trajectory_id"], "traj-happy");
    assert_eq!(second["data"]["decision"], "Deny");

    server.abort();
}

#[tokio::test]
async fn new_connection_gets_new_only() {
    let (addr, tx, server) = serve_app(TOKEN).await;

    // Published BEFORE the client connects — must never be received.
    stream::publish(&tx, &action_event("traj-history"));

    let url = format!("ws://{addr}/stream?token={TOKEN}");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    wait_for_subscriber(&tx, 1).await;

    stream::publish(&tx, &action_event("traj-live"));

    let first = next_json(&mut ws).await;
    assert_eq!(
        first["trajectory_id"], "traj-live",
        "first frame must be the post-subscribe message — no backlog replay (D-69)"
    );

    server.abort();
}

// --- notify JSONL tail integration --------------------------------------
//
// These subscribe to the broadcast sender directly (no WS handshake
// needed — keeps the FS-timing tests narrow); every recv is bounded by
// RECV_TIMEOUT so a dead tail fails loudly instead of hanging.

/// Append one serialized harness `Event` as a JSONL line — the exact
/// harness write shape (`crates/harness/src/storage/file.rs`).
fn append_event_line(path: &std::path::Path, event: &Event) {
    let json = serde_json::to_string(event).unwrap();
    append_raw_line(path, &json);
}

fn append_raw_line(path: &std::path::Path, line: &str) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(file, "{line}").unwrap();
}

async fn recv_envelope(rx: &mut broadcast::Receiver<Utf8Bytes>) -> serde_json::Value {
    let payload = tokio::time::timeout(RECV_TIMEOUT, rx.recv())
        .await
        .expect("envelope must arrive within the timeout")
        .expect("broadcast channel must stay open");
    serde_json::from_str(payload.as_str()).expect("envelope is JSON")
}

#[tokio::test]
async fn tail_picks_up_appended_lines() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("traj-tail.jsonl");

    // Pre-existing content before spawn_tail is NEVER emitted (offsets
    // initialize at EOF).
    append_event_line(&file_path, &action_event("traj-preexisting"));

    let (tx, mut rx) = broadcast::channel::<Utf8Bytes>(64);
    stream::tail::spawn_tail(dir.path().to_path_buf(), tx.clone())
        .expect("spawn_tail must succeed on an existing tempdir");

    append_event_line(&file_path, &action_event("traj-append-1"));
    let first = recv_envelope(&mut rx).await;
    assert_eq!(
        first["trajectory_id"], "traj-append-1",
        "first envelope is the post-spawn append, never pre-existing history (D-69), got: {first}"
    );
    assert_eq!(first["type"], "event");

    // Second append to the SAME file: the offset advanced past line one.
    append_event_line(&file_path, &action_event("traj-append-2"));
    let second = recv_envelope(&mut rx).await;
    assert_eq!(
        second["trajectory_id"], "traj-append-2",
        "offset must advance — no re-emission of earlier lines, got: {second}"
    );
}

#[tokio::test]
async fn tail_skips_malformed_line() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("traj-malformed.jsonl");

    let (tx, mut rx) = broadcast::channel::<Utf8Bytes>(64);
    stream::tail::spawn_tail(dir.path().to_path_buf(), tx.clone())
        .expect("spawn_tail must succeed on an existing tempdir");

    // A complete line of invalid JSON must be warned + skipped without
    // killing the tail task.
    append_raw_line(&file_path, "this is not json {");
    append_event_line(&file_path, &action_event("traj-valid"));

    let envelope = recv_envelope(&mut rx).await;
    assert_eq!(
        envelope["trajectory_id"], "traj-valid",
        "only the valid envelope arrives — the tail survived the malformed line, got: {envelope}"
    );
}

// --- Slow-client lag + no-stall ----------------------------------------

/// End-to-end proof on an 8-capacity ring: a deliberately slow WS client
/// (handshake completed, never reading) receives
/// `{"type":"lagged","missed":n}` and keeps streaming from the
/// repositioned cursor, while a concurrently-reading fast client receives
/// every one of 64 large messages without stalling — and server memory
/// stays bounded by the broadcast ring (no per-client queues exist
/// anywhere in the stream path).
#[tokio::test]
async fn slow_client_lags_fast_client_unaffected() {
    const RING: usize = 8;
    const N: usize = 64;

    let (addr, tx, server) = serve_app_with_capacity(TOKEN, RING).await;
    let url = format!("ws://{addr}/stream?token={TOKEN}");

    // FAST client: reads continuously below. SLOW client: completes the
    // handshake then never reads — its forward task will park on
    // sink.send once the TCP buffers fill, so its receiver cursor falls
    // behind the ring (deterministic lag with large payloads).
    let (mut fast_ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut slow_ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    wait_for_subscriber(&tx, 2).await;

    // Envelope-shaped JSON padded to ~256 KiB. Built directly (bypassing
    // publish()) — the test targets transport behavior, not projection.
    let filler = "x".repeat(256 * 1024);
    let payload = |i: usize| {
        let msg = serde_json::json!({
            "type": "event",
            "trajectory_id": format!("traj-lag-{i}"),
            "data": { "filler": filler },
        });
        Utf8Bytes::from(msg.to_string())
    };

    // Property 1 (no-stall): publish all 64 and drain the FAST client in
    // lockstep — every read completes while the slow client stays parked.
    // Lockstep also keeps the fast receiver inside the 8-ring, so any lag
    // it suffered would indicate cross-client interference. 30 s ceiling
    // on the whole drain (expected ~seconds).
    let received: Vec<serde_json::Value> = tokio::time::timeout(Duration::from_secs(30), async {
        let mut received = Vec::with_capacity(N);
        for i in 0..N {
            tx.send(payload(i)).expect("both forward tasks subscribed");
            received.push(next_json(&mut fast_ws).await);
        }
        received
    })
    .await
    .expect("fast client must drain all 64 messages within the ceiling");
    assert_eq!(received.len(), N, "fast client received every message");
    for (i, envelope) in received.iter().enumerate() {
        assert_eq!(
            envelope["trajectory_id"],
            format!("traj-lag-{i}"),
            "fast client sees every message, in order, no lagged notice"
        );
    }

    // Property 2 (notice + continue): the SLOW client now starts reading.
    // The few messages its parked forward task already pushed into the TCP
    // buffers arrive first, then the lagged notice, then the stream
    // CONTINUES from the repositioned cursor — never a disconnect.
    let missed = tokio::time::timeout(Duration::from_secs(30), async {
        for _ in 0..32 {
            let envelope = next_json(&mut slow_ws).await;
            if envelope["type"] == "lagged" {
                return envelope["missed"]
                    .as_u64()
                    .expect("lagged notice carries numeric missed");
            }
        }
        panic!("no lagged notice within the first 32 frames");
    })
    .await
    .expect("slow client must surface the lagged notice within the ceiling");
    assert!(missed >= 1, "missed must report at least 1, got {missed}");

    let after_notice = next_json(&mut slow_ws).await;
    assert_eq!(
        after_notice["type"], "event",
        "the stream continues after the notice (D-70: notice + continue, \
         never disconnect), got: {after_notice}"
    );

    // Property 3 (bounded memory): the broadcast ring is the ONLY buffer —
    // after the burst the sender holds at most RING queued messages.
    assert!(
        tx.len() <= RING,
        "sender queue must stay ring-bounded, got {}",
        tx.len()
    );

    server.abort();
}

// --- Turso-poll fallback ------------------------------------------------
//
// Like the tail tests these subscribe to the broadcast sender directly —
// no WS handshake needed. Seeding goes through the harness
// `TrajectoryStore` (allowed in tests/, forbidden in src/).

/// The poll fallback publishes ONLY rows inserted AFTER the task started:
/// the cursor initializes at MAX(id) (a new dashboard process never replays
/// history) and reads go through the snapshot store.
#[tokio::test]
async fn poll_publishes_only_post_spawn_rows() {
    use sondera_harness::TrajectoryStore;

    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");

    // Two pre-existing rows the poll task must NEVER publish.
    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        store
            .insert_event(&action_event("traj-poll-pre-1"))
            .await
            .unwrap();
        store
            .insert_event(&action_event("traj-poll-pre-2"))
            .await
            .unwrap();
    } // DROP so the snapshot-copy path actually runs.

    let store = std::sync::Arc::new(ReadOnlyStore::new(
        db_path.clone(),
        tmp.path().join("cache"),
    ));
    let (tx, mut rx) = broadcast::channel::<Utf8Bytes>(64);
    stream::poll::spawn_poll(store.clone(), tx.clone());

    // Deterministic sync (no sleeps): the cursor init's refresh takes the
    // first snapshot copy — once `snapshot_taken_at` is Some, MAX(id) is
    // read from a copy that predates the row seeded below.
    tokio::time::timeout(Duration::from_secs(10), async {
        while store.snapshot_taken_at().await.is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("poll task must take its cursor-init snapshot within the timeout");

    // The harness writes a third row while the poll task runs.
    {
        let store = TrajectoryStore::open(&db_path).await.unwrap();
        store
            .insert_event(&action_event("traj-poll-live"))
            .await
            .unwrap();
    }

    let payload = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("poll fallback must publish the new row within the timeout")
        .expect("broadcast channel must stay open");
    let envelope: serde_json::Value = serde_json::from_str(payload.as_str()).unwrap();
    assert_eq!(
        envelope["trajectory_id"], "traj-poll-live",
        "first envelope is the post-spawn row — pre-existing rows never \
         replay (D-69), got: {envelope}"
    );
    assert_eq!(envelope["type"], "event");
    // Rows publish in id-batch order, so a replay would have put a
    // pre-existing row first; nothing else may be queued behind the new row.
    assert!(
        rx.try_recv().is_err(),
        "exactly one envelope — the pre-existing rows were never published"
    );
}

/// Error-path proof: a failed cursor init RETRIES until `MAX(id)` succeeds —
/// it never defaults the cursor to 0 and never replays history into the
/// broadcast ring.
///
/// The live file stays PRESENT for the whole test: an absent live DB
/// legally returns `Ok(0)` (an empty system), so only an unreadable
/// present file exercises the Err path. Garbage bytes copy fine but fail
/// BOTH snapshot opens, so `max_event_row_id` errs — the retry path, not
/// a 0 cursor.
#[tokio::test]
async fn poll_cursor_init_retries_then_never_replays_history() {
    use sondera_harness::TrajectoryStore;

    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("trajectories.db");
    let wal = |p: &std::path::Path| {
        let mut s = p.as_os_str().to_os_string();
        s.push("-wal");
        std::path::PathBuf::from(s)
    };

    // (1) An unreadable-but-present live file: cursor init must ERR.
    std::fs::write(&db_path, "this is not a sqlite database file".repeat(64)).unwrap();

    // (2) Subscribe BEFORE spawning so any history replay would be seen.
    let store = std::sync::Arc::new(
        ReadOnlyStore::new(db_path.clone(), tmp.path().join("cache"))
            .with_refresh_debounce(Duration::ZERO),
    );
    let (tx, mut rx) = broadcast::channel::<Utf8Bytes>(64);
    stream::poll::spawn_poll(store.clone(), tx.clone());

    // (3) Let at least one cursor-init attempt fail against the garbage.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // (4) Build a VALID 3-event db at a sibling path, then atomically swap
    // it over the live path — wal sidecar FIRST (the intermediate state
    // pairs the new wal with the garbage db, which still fails open; a
    // half-valid db could never yield MAX(id) = 0).
    let history: Vec<Event> = (0..3).map(|_| action_event("traj-init-history")).collect();
    let staging = tmp.path().join("staging.db");
    {
        let seed = TrajectoryStore::open(&staging).await.unwrap();
        for event in &history {
            seed.insert_event(event).await.unwrap();
        }
    } // DROP so the files are quiescent before the rename.
    if wal(&staging).exists() {
        std::fs::rename(wal(&staging), wal(&db_path)).unwrap();
    }
    std::fs::rename(&staging, &db_path).unwrap();

    // (5) The ONLY store caller before the cursor breaks is
    // max_event_row_id, so snapshot_taken_at() turning Some proves the
    // cursor initialized from a copy containing the 3 rows — cursor ==
    // MAX(id) == 3, never 0.
    tokio::time::timeout(Duration::from_secs(15), async {
        while store.snapshot_taken_at().await.is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cursor init must succeed once the live db turns valid");

    // (6) The harness writes a 4th event while the poll task runs.
    let live_event = action_event("traj-init-live");
    {
        let seed = TrajectoryStore::open(&db_path).await.unwrap();
        seed.insert_event(&live_event).await.unwrap();
    }

    // (7) The FIRST envelope is event 4 — rows publish in id order, so any
    // history replay would have put events 1-3 first.
    let payload = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("poll fallback must publish the post-init row within the timeout")
        .expect("broadcast channel must stay open");
    let envelope: serde_json::Value = serde_json::from_str(payload.as_str()).unwrap();
    assert_eq!(
        envelope["data"]["eventId"],
        live_event.event_id.as_str(),
        "first envelope must be event 4 — the cursor never defaulted to 0 \
         (WR-03; D-69 on the error path), got: {envelope}"
    );
    assert_eq!(envelope["trajectory_id"], "traj-init-live");

    // Drain: NO envelope for events 1-3 may ever arrive.
    while let Ok(extra) = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
        let extra: serde_json::Value = serde_json::from_str(extra.unwrap().as_str()).unwrap();
        let id = extra["data"]["eventId"].as_str().unwrap_or_default();
        assert!(
            !history.iter().any(|e| e.event_id == id),
            "history event must never replay (D-69), got: {extra}"
        );
    }
}

#[tokio::test]
async fn ws_401_without_token() {
    // Rejection happens before the upgrade, so oneshot works here.
    let app = build_router(test_state(TOKEN), default_cors());
    let res = app
        .oneshot(
            Request::get("/stream")
                .header("connection", "Upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
