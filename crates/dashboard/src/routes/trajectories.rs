//! Trajectory routes: `GET /trajectories`,
//! `GET /trajectories/{id}/events` and
//! `GET /trajectories/{id}/adjudications`.
//!
//! Thin handlers over the projection layer (`EventDto` and
//! `AdjudicationDto::project` are the complete rulebook; no new projection
//! rules here):
//! - an empty query result triggers ONE `force_refresh` + retry before
//!   404ing — the live feed can announce an event before the REST snapshot
//!   has it,
//! - every success response carries the `X-Sondera-Snapshot-At` freshness
//!   header,
//! - store errors map to a generic 500 body; the real error goes to
//!   `tracing::warn!` only — never echoed to the client.
//!
//! The list handler folds the page-scoped Control rows in Rust: status is
//! pure lifecycle, deny/escalate counts are restricted to
//! `actor_id == "cedar"` rows so synthetic monitor records can never
//! inflate them structurally.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{AppendHeaders, IntoResponse};
use serde::Serialize;
use sondera_harness::{Control, Decision, TrajectoryEvent};

use crate::{AppState, dto};

/// The pinned JSON error-body shape for 400/404/500 responses
/// (`{"error": "<message>"}`). The 401 response stays bodyless.
///
/// `pub` (not `pub(crate)`): the public handlers name it in their return
/// type, so anything narrower trips the `private_interfaces` lint under
/// `-D warnings`.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub(crate) error: String,
}

type ErrorResponse = (StatusCode, Json<ErrorBody>);

/// 400 with the pinned ErrorBody shape — the message names the offending
/// key/value (bounded echo of the bad param only).
fn bad_request(message: String) -> ErrorResponse {
    (StatusCode::BAD_REQUEST, Json(ErrorBody { error: message }))
}

fn not_found() -> ErrorResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: "trajectory not found".to_string(),
        }),
    )
}

/// Generic 500: the real error is logged, never echoed.
fn internal(err: anyhow::Error) -> ErrorResponse {
    tracing::warn!(error = %err, "trajectory detail query failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "internal error".to_string(),
        }),
    )
}

/// Fetch the trajectory's events with retry-on-miss: an empty result forces
/// ONE snapshot refresh (debounce bypassed; the (mtime,len) check still
/// bounds re-copies) and retries the query once.
async fn fetch_events_with_retry(
    state: &AppState,
    id: &str,
) -> Result<Vec<sondera_harness::Event>, ErrorResponse> {
    let events = state
        .store
        .events_for_trajectory(id)
        .await
        .map_err(internal)?;
    if !events.is_empty() {
        return Ok(events);
    }
    state.store.force_refresh().await.map_err(internal)?;
    state
        .store
        .events_for_trajectory(id)
        .await
        .map_err(internal)
}

/// The freshness header: zero-or-one `X-Sondera-Snapshot-At` entries
/// carrying the RFC 3339 time the snapshot copy was taken.
async fn snapshot_header(state: &AppState) -> AppendHeaders<Vec<(&'static str, String)>> {
    AppendHeaders(
        state
            .store
            .snapshot_taken_at()
            .await
            .map(|taken_at| (crate::SNAPSHOT_AT_HEADER, taken_at.to_rfc3339()))
            .into_iter()
            .collect(),
    )
}

/// `GET /trajectories/{id}/events`: the ordered event sequence as a bare
/// JSON array of `EventDto` — raw agent payloads never cross.
pub async fn events(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let events = fetch_events_with_retry(&state, &id).await?;
    if events.is_empty() {
        return Err(not_found());
    }
    let dtos: Vec<dto::EventDto> = events.iter().map(dto::EventDto::from).collect();
    Ok((snapshot_header(&state).await, Json(dtos)))
}

/// `GET /trajectories/{id}/adjudications`: every Adjudicated record — cedar
/// AND monitor actors both included (the mirrored monitor verdict is data;
/// never filter it out here). An existing trajectory with zero adjudications
/// is 200 `[]`, not 404.
pub async fn adjudications(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let events = fetch_events_with_retry(&state, &id).await?;
    if events.is_empty() {
        return Err(not_found());
    }
    let dtos: Vec<dto::AdjudicationDto> = events
        .iter()
        .filter_map(dto::AdjudicationDto::project)
        .collect();
    Ok((snapshot_header(&state).await, Json(dtos)))
}

// ============================================================================
// GET /trajectories — list
// ============================================================================

/// One list row: the lifecycle `status` plus the summary DTO (the DTO
/// carries everything but status, so status lives in a route-local wrapper,
/// never in dto.rs).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrajectoryListItem {
    pub status: &'static str,
    #[serde(flatten)]
    pub summary: dto::TrajectorySummaryDto,
}

/// The list page: trajectories newest-last-activity-first plus the keyset
/// cursor for the next (older) page when the page is full.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrajectoryListResponse {
    pub trajectories: Vec<TrajectoryListItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before_id: Option<String>,
}

/// Pure-lifecycle status mapper, fed by the LAST lifecycle-typed Control row
/// per trajectory (Adjudicated rows excluded). Security signal stays in the
/// deny/escalate counts — the two dimensions never blend.
pub fn lifecycle_status(last_lifecycle_event_type: Option<&str>) -> &'static str {
    match last_lifecycle_event_type {
        Some("Completed") => "completed",
        Some("Failed") => "failed",
        Some("Terminated") => "terminated",
        // Started / Resumed / Suspended / none / unknown -> active
        // (Suspended is NOT a terminal state).
        _ => "active",
    }
}

/// Per-trajectory output of the Control-row fold.
#[derive(Default)]
struct ControlFold {
    /// `event_type` of the LAST lifecycle row (rows arrive timestamp ASC,
    /// id ASC, so plain overwrite keeps the latest).
    last_lifecycle: Option<String>,
    deny_count: u64,
    escalate_count: u64,
}

/// Fold the page-scoped Control rows into status input + decision counts.
///
/// Deny/escalate counts come ONLY from `actor_id == "cedar"` Adjudicated
/// rows: monitor records are Allow by contract, but the actor gate makes
/// the exclusion structural.
fn fold_control_rows(
    rows: &[crate::storage::ControlRow],
) -> Result<HashMap<String, ControlFold>, ErrorResponse> {
    let mut folds: HashMap<String, ControlFold> = HashMap::new();
    for row in rows {
        let fold = folds.entry(row.trajectory_id.clone()).or_default();
        if row.event_type == "Adjudicated" {
            if row.actor_id != "cedar" {
                continue;
            }
            let event: TrajectoryEvent = serde_json::from_str(&row.event_json).map_err(|e| {
                internal(anyhow::anyhow!(
                    "control row event_json no longer matches harness types \
                     (trajectory {}): {e}",
                    row.trajectory_id
                ))
            })?;
            if let TrajectoryEvent::Control(Control::Adjudicated(adjudicated)) = event {
                match adjudicated.decision {
                    Decision::Deny => fold.deny_count += 1,
                    Decision::Escalate => fold.escalate_count += 1,
                    Decision::Allow => {}
                }
            }
        } else {
            fold.last_lifecycle = Some(row.event_type.clone());
        }
    }
    Ok(folds)
}

/// Parse the stored RFC 3339 TEXT leniently — aggregate output is the
/// harness's own `to_rfc3339()` form, so a failure here is schema drift;
/// surfaced as a missing optional, never a 500.
fn parse_stored_ts(text: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// Compute the surviving trajectory-id set from the Adjudicated scan (the
/// Rust post-filter phase):
///
/// - per dimension WITH values, a trajectory survives when ANY of its
///   rows matches ANY requested value (any-match within trajectory; OR
///   within a dimension),
/// - the result is the INTERSECTION across active dimensions (AND),
/// - decision matching is restricted to `actor_id == "cedar"` rows —
///   synthetic monitor records never match `?decision=`,
/// - policy ids match ANY `Annotation.policy_id` in the typed payload
///   (backstop ids like `monitor-backstop-*` are legitimate matches),
/// - labels match through the filter-local raw-monitor target only —
///   boolean result, raw content never crosses.
fn surviving_ids(
    rows: &[crate::storage::AdjudicatedRow],
    filter: &crate::filter::FilterSet,
) -> Result<Vec<String>, ErrorResponse> {
    use std::collections::HashSet;

    let mut decision_match: HashSet<String> = HashSet::new();
    let mut policy_match: HashSet<String> = HashSet::new();
    let mut label_match: HashSet<String> = HashSet::new();

    let need_payload = !filter.decisions.is_empty() || !filter.policy_ids.is_empty();
    for row in rows {
        let adjudicated = if need_payload {
            let event: TrajectoryEvent = serde_json::from_str(&row.event_json).map_err(|e| {
                internal(anyhow::anyhow!(
                    "adjudicated row event_json no longer matches harness types \
                     (trajectory {}): {e}",
                    row.trajectory_id
                ))
            })?;
            match event {
                TrajectoryEvent::Control(Control::Adjudicated(adjudicated)) => Some(adjudicated),
                _ => None,
            }
        } else {
            None
        };

        if let Some(adjudicated) = &adjudicated {
            // Decision: cedar-actor rows ONLY. The typed Decision's Debug
            // rendering IS the canonical wire string the filter stores.
            if !filter.decisions.is_empty() && row.actor_id == "cedar" {
                let rendered = format!("{:?}", adjudicated.decision);
                if filter.decisions.contains(&rendered) {
                    decision_match.insert(row.trajectory_id.clone());
                }
            }
            if !filter.policy_ids.is_empty()
                && adjudicated.annotations.iter().any(|annotation| {
                    annotation
                        .policy_id
                        .as_deref()
                        .is_some_and(|id| filter.policy_ids.iter().any(|p| p == id))
                })
            {
                policy_match.insert(row.trajectory_id.clone());
            }
        }

        if !filter.labels.is_empty()
            && row
                .raw_json
                .as_deref()
                .is_some_and(|raw| crate::filter::raw_label_matches(raw, &filter.labels))
        {
            label_match.insert(row.trajectory_id.clone());
        }
    }

    // AND across dimensions: intersect only the dimensions with values.
    let mut survivors: Option<HashSet<String>> = None;
    for (active, matches) in [
        (!filter.decisions.is_empty(), decision_match),
        (!filter.policy_ids.is_empty(), policy_match),
        (!filter.labels.is_empty(), label_match),
    ] {
        if !active {
            continue;
        }
        survivors = Some(match survivors.take() {
            None => matches,
            Some(current) => current.intersection(&matches).cloned().collect(),
        });
    }

    let mut ids: Vec<String> = survivors.unwrap_or_default().into_iter().collect();
    ids.sort();
    Ok(ids)
}

/// `GET /trajectories`: recent trajectories newest-last-activity-first with
/// lifecycle status, event count, and deny/escalate counts, bounded by the
/// limit clamp, narrowed by the query filters, and keyset-paginated on
/// `(MAX(timestamp), trajectory_id)`.
pub async fn list(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> Result<impl IntoResponse, ErrorResponse> {
    let filter = crate::filter::FilterSet::parse(query.as_deref()).map_err(bad_request)?;

    // Render from/to to the stored +00:00 TEXT form so the SQL comparison
    // is chronologically sound.
    let from_text = filter.from.map(|dt| dt.to_rfc3339());
    let to_text = filter.to.map(|dt| dt.to_rfc3339());

    // Two-phase pipeline: (1) payload filters -> Adjudicated scan + Rust
    // post-filter; (2) time-only -> DISTINCT-id scan; (3) no filters -> no
    // restriction.
    let restrict_ids: Option<Vec<String>> = if filter.has_payload_filters() {
        let rows = state
            .store
            .adjudicated_rows(from_text.as_deref(), to_text.as_deref())
            .await
            .map_err(internal)?;
        Some(surviving_ids(&rows, &filter)?)
    } else if from_text.is_some() || to_text.is_some() {
        Some(
            state
                .store
                .trajectory_ids_in_range(from_text.as_deref(), to_text.as_deref())
                .await
                .map_err(internal)?,
        )
    } else {
        None
    };

    // An empty surviving set short-circuits to an empty page — never emit
    // `IN ()`. The store also guards this; belt and suspenders.
    if restrict_ids.as_ref().is_some_and(|ids| ids.is_empty()) {
        let response = TrajectoryListResponse {
            trajectories: Vec::new(),
            next_before: None,
            next_before_id: None,
        };
        return Ok((snapshot_header(&state).await, Json(response)));
    }

    // Keyset cursor: parse-then-re-render the timestamp so it matches the
    // stored +00:00 form; unparseable -> 400.
    let cursor: Option<(String, String)> = match (&filter.before, &filter.before_id) {
        (Some(before), Some(before_id)) => {
            let rendered = chrono::DateTime::parse_from_rfc3339(before)
                .map_err(|_| {
                    bad_request(format!(
                        "invalid before '{before}': must be an RFC 3339 timestamp"
                    ))
                })?
                .with_timezone(&chrono::Utc)
                .to_rfc3339();
            Some((rendered, before_id.clone()))
        }
        (None, None) => None,
        _ => {
            return Err(bad_request(
                "before and before_id must be provided together".to_string(),
            ));
        }
    };

    let aggregates = state
        .store
        .trajectory_aggregates(
            restrict_ids.as_deref(),
            cursor.as_ref().map(|(ts, id)| (ts.as_str(), id.as_str())),
            filter.limit,
        )
        .await
        .map_err(internal)?;

    // Next-page cursor from the LAST row's (last_activity, trajectory_id)
    // — only when the page is full.
    let next = if aggregates.len() == filter.limit as usize {
        aggregates
            .last()
            .map(|row| (row.last_activity.clone(), row.trajectory_id.clone()))
    } else {
        None
    };

    let page_ids: Vec<String> = aggregates
        .iter()
        .map(|row| row.trajectory_id.clone())
        .collect();
    let control = state
        .store
        .control_rows(&page_ids)
        .await
        .map_err(internal)?;
    let mut folds = fold_control_rows(&control)?;

    let trajectories: Vec<TrajectoryListItem> = aggregates
        .into_iter()
        .map(|row| {
            let fold = folds.remove(&row.trajectory_id).unwrap_or_default();
            let status = lifecycle_status(fold.last_lifecycle.as_deref());
            let first_event_at = parse_stored_ts(&row.first_event_at);
            let last_event_at = parse_stored_ts(&row.last_activity);
            let duration_seconds = first_event_at
                .zip(last_event_at)
                .map(|(first, last)| (last - first).num_seconds());
            let aggregate = dto::TrajectoryAggregateRow {
                trajectory_id: row.trajectory_id,
                event_count: row.event_count,
                first_event_at,
                last_event_at,
                duration_seconds,
                agent_id: (!row.agent_id.is_empty()).then_some(row.agent_id),
                agent_provider: (!row.agent_provider.is_empty()).then_some(row.agent_provider),
                action_count: row.action_count,
                observation_count: row.observation_count,
                control_count: row.control_count,
                state_count: row.state_count,
                deny_count: fold.deny_count,
                escalate_count: fold.escalate_count,
            };
            TrajectoryListItem {
                status,
                summary: dto::TrajectorySummaryDto::from(aggregate),
            }
        })
        .collect();

    let (next_before, next_before_id) = match next {
        Some((before, before_id)) => (Some(before), Some(before_id)),
        None => (None, None),
    };
    let response = TrajectoryListResponse {
        trajectories,
        next_before,
        next_before_id,
    };
    Ok((snapshot_header(&state).await, Json(response)))
}
