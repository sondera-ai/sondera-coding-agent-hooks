//! CORS layer construction from validated explicit origins.

use axum::http::{HeaderName, HeaderValue, Method, header};
use tower_http::cors::CorsLayer;

/// Build the CORS layer from an explicit origin allowlist — never
/// `Any`/wildcard. Methods are restricted to GET and headers to
/// `Authorization`. The snapshot freshness header is explicitly exposed so
/// browser JS can read it — CORS only exposes a safelist by default.
pub fn cors_layer(origins: &[HeaderValue]) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(origins.to_vec())
        .allow_methods([Method::GET])
        .allow_headers([header::AUTHORIZATION])
        .expose_headers([HeaderName::from_static(crate::SNAPSHOT_AT_HEADER)])
}
