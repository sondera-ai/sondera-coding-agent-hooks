//! Static-SPA-serving auth matrix.
//!
//! Proves from outside the crate boundary that `build_router_with_ui` serves
//! the built SPA as an UNAUTHENTICATED static fallback while every data
//! route keeps the bearer gate:
//! - with ui-dir: GET /health, /trajectories, /trajectories/{id}/events,
//!   /trajectories/{id}/adjudications, and /stream each 401 WITHOUT a token
//!   (data routes stay gated),
//! - with ui-dir: GET / without a token is 200 and the body carries the
//!   SPA shell sentinel,
//! - with ui-dir: GET /trajectories/some-client-route without a token is a
//!   200 shell (ServeDir::fallback returns index.html so SvelteKit client
//!   routes resolve; the path does NOT collide with the API's
//!   /trajectories/{id}/events shape),
//! - with ui-dir: GET /_app/test.js without a token is 200 with the real
//!   asset body (files are served, not just the fallback),
//! - with ui-dir: GET /trajectories WITH the bearer is neither 401 nor 404
//!   (authenticated data routes still resolve to the API, not the shell),
//! - WITHOUT ui-dir (plain `build_router`): GET /no-such-path without a
//!   token is 401, not 404 (regression mirror of auth_gate.rs — the default
//!   fallback stays auth-wrapped).

use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Request, StatusCode},
};
use sondera_dashboard::storage::ReadOnlyStore;
use sondera_dashboard::{AppState, build_router, build_router_with_ui, cors::cors_layer};
use std::path::PathBuf;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;

const TOKEN: &str = "sondera-test-token-0001";

/// Sentinel body written to the tempdir index.html so shell responses are
/// distinguishable from real assets and from API responses.
const SHELL_SENTINEL: &str = "sondera-spa-shell";

fn test_state(token: &str) -> AppState {
    let unique = uuid::Uuid::new_v4();
    let base = std::env::temp_dir().join(format!("sondera-dash-test-{unique}"));
    AppState {
        token: token.to_string(),
        db_path: base.join("trajectories.db"),
        trajectories_dir: base.join("trajectories"),
        // Absent DB is fine: the store serves empty and never creates the
        // file; these tests only assert status codes and bodies.
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

/// Build a tempdir shaped like `web/build`: an index.html shell carrying
/// the sentinel plus a nested real asset under `_app/`. The `TempDir` must
/// stay alive for the duration of the test (`_temp_dir` convention).
fn build_ui_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("index.html"),
        format!("<!doctype html><title>{SHELL_SENTINEL}</title>"),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("_app")).unwrap();
    std::fs::write(
        dir.path().join("_app").join("test.js"),
        "console.log('sondera-asset');",
    )
    .unwrap();
    let path = dir.path().to_path_buf();
    (dir, path)
}

/// The IDENTICAL production layering with the static fallback attached.
fn ui_app() -> (tempfile::TempDir, Router) {
    let (tmp, ui_dir) = build_ui_dir();
    let app = build_router_with_ui(test_state(TOKEN), default_cors(), Some(ui_dir));
    (tmp, app)
}

async fn body_string(res: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

// --- Matrix cell 1: data routes stay gated -----------------------------

#[tokio::test]
async fn with_ui_dir_data_routes_are_401_without_token() {
    let (_temp_dir, app) = ui_app();
    for path in [
        "/health",
        "/trajectories",
        "/trajectories/x/events",
        "/trajectories/x/adjudications",
        "/stream",
    ] {
        let res = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "data route {path} must stay bearer-gated with --ui-dir set (D-75)"
        );
    }
}

// --- Matrix cell 2: the shell is public --------------------------------

#[tokio::test]
async fn with_ui_dir_root_without_token_is_200_shell() {
    let (_temp_dir, app) = ui_app();
    let res = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_string(res).await;
    assert!(
        body.contains(SHELL_SENTINEL),
        "GET / must serve the SPA shell, got: {body}"
    );
}

// --- Matrix cell 3: SPA client routes resolve to the shell -------------

#[tokio::test]
async fn with_ui_dir_spa_client_route_without_token_is_200_shell() {
    let (_temp_dir, app) = ui_app();
    let res = app
        .oneshot(
            Request::get("/trajectories/some-client-route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "SPA fallback must return the shell with 200 so client routes resolve (D-71)"
    );
    let body = body_string(res).await;
    assert!(
        body.contains(SHELL_SENTINEL),
        "unknown path must fall back to index.html, got: {body}"
    );
}

// --- Matrix cell 4: real assets are served, not just the fallback ------

#[tokio::test]
async fn with_ui_dir_nested_asset_without_token_is_200_asset_body() {
    let (_temp_dir, app) = ui_app();
    let res = app
        .oneshot(Request::get("/_app/test.js").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_string(res).await;
    assert!(
        body.contains("sondera-asset"),
        "GET /_app/test.js must serve the real asset body, got: {body}"
    );
    assert!(
        !body.contains(SHELL_SENTINEL),
        "asset request must not fall back to the shell"
    );
}

// --- Matrix cell 5: authenticated data routes still work ---------------

#[tokio::test]
async fn with_ui_dir_trajectories_with_token_is_not_401_not_404() {
    let (_temp_dir, app) = ui_app();
    let res = app
        .oneshot(
            Request::get("/trajectories")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 200 or 500-family acceptable depending on store state — the route
    // must resolve to the API (not 404 the shell-side) and pass auth.
    assert_ne!(res.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(res.status(), StatusCode::NOT_FOUND);
}

// --- Matrix cell 6: absent flag preserves the no-UI behavior -----------

#[tokio::test]
async fn without_ui_dir_unknown_path_without_token_is_401_not_404() {
    // Regression mirror of auth_gate.rs::unknown_path_without_token_is_401_not_404:
    // with no fallback attached, the auth-wrapped default fallback 401s.
    let app = build_router(test_state(TOKEN), default_cors());
    let res = app
        .oneshot(Request::get("/no-such-path").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
