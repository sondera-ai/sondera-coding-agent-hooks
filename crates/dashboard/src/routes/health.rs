//! Authenticated `GET /health`: DB + JSONL readability report.
//!
//! The DB half is store-backed: readability is proven by an actual
//! open+SELECT against the dashboard's snapshot copy — never the live file.
//! A missing DB or JSONL dir is an empty system, not an error: the handler
//! always returns 200 when authenticated; degraded states live in body
//! fields.

use axum::{Json, extract::State};
use serde::Serialize;

use crate::AppState;
use crate::storage::DbState;

/// `/health` response body (camelCase wire).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: String,
    pub db: DbHealth,
    pub jsonl: JsonlHealth,
}

/// Database readability, proven via the snapshot copy.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbHealth {
    /// "absent" | "readable" | "unavailable"
    pub state: String,
    /// Total event rows visible through the snapshot copy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_count: Option<u64>,
    /// Seconds since the current snapshot copy was taken.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_age_seconds: Option<u64>,
}

/// JSONL trajectory-directory health.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonlHealth {
    /// "readable" | "absent"
    pub state: String,
    pub file_count: u64,
}

/// Health handler: reports store-backed DB readability and JSONL dir
/// readability.
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let store_health = state.store.health().await;
    let db = DbHealth {
        state: match store_health.db_state {
            DbState::Absent => "absent",
            DbState::Readable => "readable",
            DbState::Unavailable => "unavailable",
        }
        .to_string(),
        event_count: store_health.event_count,
        snapshot_age_seconds: store_health.snapshot_age_seconds,
    };

    let jsonl = match std::fs::read_dir(&state.trajectories_dir) {
        Ok(entries) => {
            let file_count = entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".jsonl"))
                .count() as u64;
            JsonlHealth {
                state: "readable".to_string(),
                file_count,
            }
        }
        // A missing dir is an empty system, not an error.
        Err(_) => JsonlHealth {
            state: "absent".to_string(),
            file_count: 0,
        },
    };

    Json(HealthResponse {
        status: "ok".to_string(),
        db,
        jsonl,
    })
}
