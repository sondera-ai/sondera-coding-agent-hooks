//! Security-contract integration tests for the dashboard auth gate.
//!
//! Proves from outside the crate boundary that the bearer token is required
//! on EVERY route — including `/health` (no carve-outs), unmatched paths
//! (401 before 404: no route-table leak), and non-GET methods (401 before
//! 405) — and that the `?token=` query parameter is honored ONLY on
//! WebSocket upgrade requests:
//! - GET /health: 401 without a token, 401 with a same-length wrong token,
//!   200 with the correct bearer,
//! - GET /health?token=<correct> without an upgrade: 401 (tokens stay out of
//!   URLs on regular routes),
//! - POST /health: 401 unauthenticated, 405 authenticated (proves zero
//!   non-GET routes exist),
//! - unknown paths: 401, not 404,
//! - WebSocket upgrade (test-only route wrapped in the IDENTICAL production
//!   layering via `secure()`): 401 with no token, 101 with `?token=`
//!   correct, 401 with `?token=` wrong. The 101 case runs over a real
//!   loopback connection because hyper only attaches the `OnUpgrade`
//!   extension (required by the `WebSocketUpgrade` extractor) on a live
//!   connection — `tower::oneshot` can never produce 101.

use axum::extract::ws::WebSocketUpgrade;
use axum::http::HeaderValue;
use axum::response::Response;
use axum::routing::get;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use sondera_dashboard::storage::ReadOnlyStore;
use sondera_dashboard::{AppState, build_router, cors::cors_layer, secure};
use tower::ServiceExt;
use tower_http::cors::CorsLayer;

/// The test bearer token; WRONG_TOKEN has the SAME byte length so the
/// constant-time compare's content path (not just the length check) is
/// exercised.
const TOKEN: &str = "sondera-test-token-0001";
const WRONG_TOKEN: &str = "sondera-test-token-9999";

fn test_state(token: &str) -> AppState {
    let unique = uuid::Uuid::new_v4();
    let base = std::env::temp_dir().join(format!("sondera-dash-test-{unique}"));
    AppState {
        token: token.to_string(),
        db_path: base.join("trajectories.db"),
        trajectories_dir: base.join("trajectories"),
        // Absent DB is fine: the store serves empty and never creates the
        // file; these tests only assert status codes.
        store: std::sync::Arc::new(ReadOnlyStore::new(
            base.join("trajectories.db"),
            base.join("dashboard-cache"),
        )),
        stream_tx: tokio::sync::broadcast::channel(sondera_dashboard::stream::BROADCAST_CAPACITY).0,
    }
}

fn default_cors() -> CorsLayer {
    cors_layer(&[
        HeaderValue::from_static("http://localhost:5173"),
        HeaderValue::from_static("http://127.0.0.1:5173"),
    ])
}

/// Production router with the default Vite CORS origins.
fn test_app(token: &str) -> Router {
    build_router(test_state(token), default_cors())
}

#[tokio::test]
async fn get_health_without_token_is_401() {
    let app = test_app(TOKEN);
    let res = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_health_with_wrong_same_length_token_is_401() {
    assert_eq!(TOKEN.len(), WRONG_TOKEN.len());
    let app = test_app(TOKEN);
    let res = app
        .oneshot(
            Request::get("/health")
                .header("authorization", format!("Bearer {WRONG_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_health_with_correct_bearer_is_200() {
    let app = test_app(TOKEN);
    let res = app
        .oneshot(
            Request::get("/health")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// With an empty tempdir both halves report "absent" (empty system, still
/// 200), and the body carries status + db.state + jsonl.state.
#[tokio::test]
async fn authenticated_health_body_reports_absent_states() {
    let app = test_app(TOKEN);
    let res = app
        .oneshot(
            Request::get("/health")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("/health body is JSON");
    assert_eq!(body["status"], "ok");
    assert_eq!(
        body["db"]["state"], "absent",
        "empty tempdir: DB half reports absent, got: {body}"
    );
    assert_eq!(
        body["jsonl"]["state"], "absent",
        "empty tempdir: JSONL half reports absent, got: {body}"
    );
}

#[tokio::test]
async fn query_token_on_regular_get_is_401() {
    // ?token= is honored ONLY on WebSocket upgrades.
    let app = test_app(TOKEN);
    let res = app
        .oneshot(
            Request::get(format!("/health?token={TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_health_without_token_is_401() {
    // Auth runs before method dispatch (Router::layer, not route_layer).
    let app = test_app(TOKEN);
    let res = app
        .oneshot(Request::post("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_health_with_valid_bearer_is_405() {
    // Proves zero non-GET routes exist.
    let app = test_app(TOKEN);
    let res = app
        .oneshot(
            Request::post("/health")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn unknown_path_without_token_is_401_not_404() {
    // Router::layer covers unmatched paths — no route-table leak.
    let app = test_app(TOKEN);
    let res = app
        .oneshot(Request::get("/does-not-exist").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// --- WebSocket upgrade coverage ----------------------------------------
//
// The production router has no WS route yet; this wraps a test-only
// /test-ws route in the IDENTICAL production layering via secure() so the
// auth guarantee provably covers upgrades (header-based detection — the
// real /stream route inherits it automatically).

async fn test_ws_handler(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|_socket| async {})
}

fn test_ws_app(token: &str) -> Router {
    let router = Router::new().route("/test-ws", get(test_ws_handler));
    secure(router, test_state(token), default_cors())
}

fn ws_upgrade_request(uri: &str) -> Request<Body> {
    Request::get(uri)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn ws_upgrade_without_token_is_401() {
    let app = test_ws_app(TOKEN);
    let res = app.oneshot(ws_upgrade_request("/test-ws")).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// Perform a raw WebSocket handshake against `app` served on a real
/// loopback listener and return the HTTP status code of the response.
async fn ws_handshake_status(app: Router, uri_path: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET {uri_path} HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    // Read until the status line is complete.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }
    server.abort();

    let response = String::from_utf8_lossy(&buf);
    response
        .split_whitespace()
        .nth(1)
        .expect("HTTP status line")
        .parse()
        .expect("numeric status code")
}

#[tokio::test]
async fn ws_upgrade_with_correct_query_token_is_101() {
    let app = test_ws_app(TOKEN);
    let status = ws_handshake_status(app, &format!("/test-ws?token={TOKEN}")).await;
    assert_eq!(status, 101);
}

#[tokio::test]
async fn ws_upgrade_with_wrong_query_token_is_401() {
    let app = test_ws_app(TOKEN);
    let res = app
        .oneshot(ws_upgrade_request(&format!("/test-ws?token={WRONG_TOKEN}")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
