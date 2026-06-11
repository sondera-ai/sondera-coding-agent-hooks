//! CORS integration tests for the dashboard.
//!
//! Proves from outside the crate boundary that:
//! - a browser preflight (`OPTIONS` with no Authorization header) succeeds
//!   for an allowed origin — the CORS layer is OUTERMOST, so preflights
//!   bypass auth,
//! - an allowed origin is echoed in `access-control-allow-origin` on an
//!   authenticated GET,
//! - a disallowed origin receives NO `access-control-allow-origin` header
//!   (explicit allowlist — never `*`).

use axum::http::HeaderValue;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use sondera_dashboard::storage::ReadOnlyStore;
use sondera_dashboard::{AppState, build_router, cors::cors_layer};
use tower::ServiceExt;
use tower_http::cors::CorsLayer;

const TOKEN: &str = "sondera-test-token-0001";
const ALLOWED_ORIGIN: &str = "http://localhost:5173";
const EVIL_ORIGIN: &str = "http://evil.example";

fn test_state(token: &str) -> AppState {
    let unique = uuid::Uuid::new_v4();
    let base = std::env::temp_dir().join(format!("sondera-dash-test-{unique}"));
    AppState {
        token: token.to_string(),
        db_path: base.join("trajectories.db"),
        trajectories_dir: base.join("trajectories"),
        // Absent DB is fine: the store serves empty and never creates the
        // file; these tests only assert status codes and headers.
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

fn test_app(token: &str) -> Router {
    build_router(test_state(token), default_cors())
}

#[tokio::test]
async fn preflight_without_token_succeeds_for_allowed_origin() {
    let app = test_app(TOKEN);
    let res = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/health")
                .header("origin", ALLOWED_ORIGIN)
                .header("access-control-request-method", "GET")
                .header("access-control-request-headers", "authorization")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("access-control-allow-origin")
            .expect("preflight must echo the allowed origin"),
        ALLOWED_ORIGIN
    );
}

#[tokio::test]
async fn allowed_origin_echoed_on_authenticated_get() {
    let app = test_app(TOKEN);
    let res = app
        .oneshot(
            Request::get("/health")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("origin", ALLOWED_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("access-control-allow-origin")
            .expect("allowed origin must be echoed"),
        ALLOWED_ORIGIN
    );
}

/// Without `expose_headers` the snapshot freshness header would be invisible
/// to browser JS (CORS only exposes a safelist by default).
#[tokio::test]
async fn snapshot_header_exposed_for_allowed_origin() {
    let app = test_app(TOKEN);
    let res = app
        .oneshot(
            Request::get("/health")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("origin", ALLOWED_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let exposed = res
        .headers()
        .get("access-control-expose-headers")
        .expect("expose-headers must be present for an allowed origin")
        .to_str()
        .unwrap();
    assert!(
        exposed.contains("x-sondera-snapshot-at"),
        "x-sondera-snapshot-at must be exposed to browser JS (D-66/Pitfall 6), got: {exposed}"
    );
}

#[tokio::test]
async fn disallowed_origin_gets_no_allow_origin_header() {
    let app = test_app(TOKEN);
    let res = app
        .oneshot(
            Request::get("/health")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("origin", EVIL_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        res.headers().get("access-control-allow-origin").is_none(),
        "disallowed origin must not receive an allow-origin header"
    );
}
