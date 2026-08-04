//! Transport-neutral trajectory handlers.
//!
//! The harness owns ledger writes. These handlers consume bare ids and typed
//! domain queries, returning the same domain projections to every adapter.

use crate::sparkline::{MAX_SPARKLINE_BATCH, TrajectorySparkline, sparkline};
use sondera_types::{
    EventDetail, Page, StoreError, Trajectory, TrajectoryQuery, TrajectoryReaderWriter,
};

pub async fn get_trajectory<S: TrajectoryReaderWriter>(
    store: &S,
    id: &str,
) -> Result<Trajectory, StoreError> {
    store
        .get_trajectory(id)
        .await?
        .ok_or_else(|| StoreError::not_found(format!("Trajectory not found: {id}")))
}

pub async fn list_trajectory_events<S: TrajectoryReaderWriter>(
    store: &S,
    id: &str,
    offset: usize,
    limit: usize,
) -> Result<Page<EventDetail>, StoreError> {
    store.list_trajectory_events(id, offset, limit).await
}

pub async fn list_trajectories<S: TrajectoryReaderWriter>(
    store: &S,
    query: &TrajectoryQuery,
) -> Result<Page<Trajectory>, StoreError> {
    store.list_trajectories(query).await
}

pub async fn batch_get_trajectory_sparklines<S: TrajectoryReaderWriter>(
    store: &S,
    ids: &[String],
) -> Result<Vec<TrajectorySparkline>, StoreError> {
    if ids.len() > MAX_SPARKLINE_BATCH {
        return Err(StoreError::invalid_argument(format!(
            "at most {MAX_SPARKLINE_BATCH} trajectory names may be requested"
        )));
    }

    let mut sparklines = Vec::with_capacity(ids.len());
    for id in ids {
        let events = store.trajectory_events(id).await?;
        if !events.is_empty() {
            sparklines.push(sparkline(id, &events));
        }
    }
    Ok(sparklines)
}
