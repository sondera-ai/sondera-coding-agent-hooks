//! `GET /stream` — live WebSocket feed of new events and decisions.
//!
//! The route registers inside `build_router` BEFORE `secure()`, so the
//! upgrade flows through the existing auth layering with ZERO new auth code
//! (the middleware detects upgrades by header and honors `?token=` there —
//! and only there).
//!
//! Per-client semantics:
//! - `subscribe()` happens after the upgrade, so each client receives only
//!   messages published from that point on,
//! - on `RecvError::Lagged(n)` the client gets a typed
//!   `{"type":"lagged","missed":n}` notice and the stream CONTINUES from
//!   the repositioned cursor — disconnect happens only on send failure,
//! - logging is connection-count only — never URIs (the `?token=` query
//!   would leak) and never frame payloads.

use crate::AppState;
use crate::stream::StreamMessage;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

/// Keepalive ping interval (discretion — cheap insurance on localhost;
/// tungstenite auto-answers client pings during reads).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// WS upgrade handler for `GET /stream`. Auth is already enforced by
/// `secure()`'s middleware before this handler runs (header OR `?token=`
/// on upgrade requests).
pub async fn stream_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| handle_stream(socket, state))
}

/// Per-client forward loop.
async fn handle_stream(socket: WebSocket, state: AppState) {
    // Subscribe AFTER the upgrade: this client sees only messages published
    // from now on — history comes from REST.
    let mut rx = state.stream_tx.subscribe();
    tracing::info!(
        clients = state.stream_tx.receiver_count(),
        "stream client connected"
    );

    let (mut sink, mut source) = socket.split();
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    // Consume the immediate first tick so the first ping waits a full
    // interval.
    keepalive.tick().await;

    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(payload) => {
                    // Disconnect only on send failure.
                    if sink.send(Message::Text(payload)).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(missed)) => {
                    // The receiver has been repositioned to the oldest
                    // retained message; notify and CONTINUE.
                    let notice = StreamMessage::Lagged { missed };
                    match serde_json::to_string(&notice) {
                        Ok(json) => {
                            if sink.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            tracing::warn!(%err, "failed to serialize lagged notice");
                        }
                    }
                }
                Err(RecvError::Closed) => break, // source task gone
            },
            client = source.next() => match client {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                // Ignore other client frames; tungstenite auto-answers
                // pings during reads.
                Some(Ok(_)) => {}
            },
            _ = keepalive.tick() => {
                if sink.send(Message::Ping(axum::body::Bytes::new())).await.is_err() {
                    break;
                }
            }
        }
    }

    tracing::info!(
        clients = state.stream_tx.receiver_count().saturating_sub(1),
        "stream client disconnected"
    );
}
