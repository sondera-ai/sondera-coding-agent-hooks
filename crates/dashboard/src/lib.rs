//! Read-only trajectory dashboard API.
//!
//! Assembles the axum router for the dashboard server. The security posture
//! is concentrated here and in [`auth`] / [`cors`]:
//! - every DATA route requires the bearer token (built static assets are the
//!   ONLY unauthenticated surface), enforced via `Router::layer` so unmatched
//!   paths 401 instead of leaking 404s,
//! - the optional static SPA is a `fallback_service` attached AFTER the
//!   auth layer (deliberately unauthenticated) — never a route, so only
//!   `get()` registrations may ever appear in [`build_router_with_ui`],
//! - the CORS layer is outermost so browser preflights bypass auth.

pub mod auth;
pub mod config;
pub mod cors;
pub mod dto;
pub mod filter;
pub mod routes;
pub mod storage;
pub mod stream;

use axum::{Router, middleware, routing::get};
use std::path::PathBuf;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};

/// Response header carrying the RFC 3339 time the store's snapshot copy
/// was taken. Lowercase so `HeaderName::from_static` accepts it; exposed to
/// browser JS via [`cors::cors_layer`].
pub const SNAPSHOT_AT_HEADER: &str = "x-sondera-snapshot-at";

/// Shared state for the dashboard router.
///
/// DB readability is proven through `store` (snapshot-copy backed — the
/// live file is never opened); the health route reads `trajectories_dir`
/// entries directly for the JSONL half.
#[derive(Clone)]
pub struct AppState {
    /// The bearer token every request must present.
    pub token: String,
    /// Path to the live trajectories database (stat-only outside `store`).
    pub db_path: PathBuf,
    /// Directory containing per-trajectory JSONL files.
    pub trajectories_dir: PathBuf,
    /// Read-only trajectory store (typed SELECT-only surface).
    pub store: std::sync::Arc<storage::ReadOnlyStore>,
    /// Global firehose sender of pre-serialized envelopes; WS clients
    /// subscribe per connection and see only messages published after they
    /// connect.
    pub stream_tx: tokio::sync::broadcast::Sender<axum::extract::ws::Utf8Bytes>,
}

/// Apply the canonical production layering to a router: auth middleware via
/// `Router::layer` applied to the WHOLE router (never a per-route layer —
/// unmatched paths must still 401), then the CORS layer so it ends up
/// outermost and preflights bypass auth.
///
/// This exists as a separate helper so integration tests can wrap a
/// test-only `/test-ws` route in the IDENTICAL production layering — the
/// WebSocket auth-coverage guarantee.
pub fn secure(router: Router<AppState>, state: AppState, cors: CorsLayer) -> Router {
    secure_with_ui(router, state, cors, None)
}

/// The ONE canonical layering body: auth wraps every route registered so far
/// PLUS the default fallback; the optional static SPA fallback is attached
/// strictly AFTER the auth layer (axum `Router::layer` only wraps prior
/// registrations) so it is deliberately unauthenticated; CORS stays outermost.
///
/// Encapsulating the ordering here means callers can never attach the
/// static fallback before auth. When `ui_dir` is `None`, no fallback replaces
/// the auth-wrapped default, so unmatched paths keep returning 401.
pub fn secure_with_ui(
    router: Router<AppState>,
    state: AppState,
    cors: CorsLayer,
    ui_dir: Option<PathBuf>,
) -> Router {
    // (1) Auth via Router::layer — covers all data routes AND the default
    // fallback (unmatched paths 401, never 404).
    let mut router = router.layer(middleware::from_fn_with_state(
        state.clone(),
        auth::require_bearer,
    ));
    // (2) Registered AFTER the auth layer => deliberately unauthenticated.
    // ServeDir::fallback (NOT not_found_service) so SPA client routes like
    // /trajectories/<id> get a 200 shell. tower-http's ServeDir performs path
    // sanitization — no hand-rolled file handler.
    if let Some(dir) = ui_dir {
        router = router
            .fallback_service(ServeDir::new(&dir).fallback(ServeFile::new(dir.join("index.html"))));
    }
    // (3) CORS outermost so browser preflights bypass auth; (4) state last.
    router.layer(cors).with_state(state)
}

/// Build the production router: `GET /health`, the trajectory list route,
/// the trajectory detail routes, and the live WS stream.
///
/// Only `get()` registrations may ever appear here, and every route passes
/// through [`secure`] — never per-route layers. `/stream` inherits auth from
/// the same layering (`?token=` is honored on upgrade requests by the
/// existing middleware — zero new auth code).
pub fn build_router(state: AppState, cors: CorsLayer) -> Router {
    build_router_with_ui(state, cors, None)
}

/// [`build_router`] plus the optional static SPA fallback: identical route
/// set, identical layering via [`secure_with_ui`]. Only `get()` registrations
/// may ever appear here — the static SPA is a fallback SERVICE, never a route.
pub fn build_router_with_ui(state: AppState, cors: CorsLayer, ui_dir: Option<PathBuf>) -> Router {
    let router = Router::new()
        .route("/health", get(routes::health::health))
        .route("/trajectories", get(routes::trajectories::list))
        .route(
            "/trajectories/{id}/events",
            get(routes::trajectories::events),
        )
        .route(
            "/trajectories/{id}/adjudications",
            get(routes::trajectories::adjudications),
        )
        .route("/stream", get(routes::stream::stream_handler));
    secure_with_ui(router, state, cors, ui_dir)
}
