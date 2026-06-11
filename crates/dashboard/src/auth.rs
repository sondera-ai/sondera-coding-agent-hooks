//! Bearer-token auth middleware.
//!
//! Every route requires `Authorization: Bearer <token>`; the `?token=`
//! query parameter is honored ONLY on WebSocket upgrade requests, where
//! browsers cannot set headers.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, Uri, header},
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;

use crate::AppState;

/// Middleware enforcing the bearer token on every request.
///
/// Header `Authorization: Bearer <token>` is the only accepted credential on
/// regular routes; WebSocket upgrades may fall back to `?token=`. Comparison
/// is constant-time via `subtle::ConstantTimeEq`.
pub async fn require_bearer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let presented: Option<&str> = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let presented = match presented {
        Some(t) => Some(t),
        // ?token= ONLY for WebSocket upgrades.
        None if is_ws_upgrade(req.headers()) => token_query_param(req.uri()),
        None => None,
    };

    match presented {
        // NOTE: `ct_eq` on slices short-circuits on length mismatch — token
        // LENGTH is timing-observable, token CONTENT is not. Accepted for
        // this threat model (localhost bind + high-entropy token).
        Some(t) if bool::from(t.as_bytes().ct_eq(state.token.as_bytes())) => {
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Whether the request is a WebSocket upgrade — header-based, not
/// path-based, so future stream routes are automatically covered.
pub fn is_ws_upgrade(headers: &HeaderMap) -> bool {
    let upgrade_is_websocket = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    upgrade_is_websocket || headers.contains_key(header::SEC_WEBSOCKET_KEY)
}

/// Extract the `token` query parameter from a raw URI, if present.
///
/// Minimal split on `&` then `=` — no query-string dependency. Values are
/// taken verbatim (no percent-decoding); high-entropy tokens should be
/// URL-safe strings.
pub fn token_query_param(uri: &Uri) -> Option<&str> {
    uri.query()?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == "token").then_some(value)
    })
}
