//! Shared console handlers.
//!
//! Resource-name parsing, protobuf conversion, and MCP JSON framing stay in the
//! adapters. This layer owns endpoint behavior over `sondera-types`, ensuring
//! every transport executes the same store reads, writes, and projections.

mod agents;
mod trajectories;

use sondera_types::{
    AgentFilter, AgentQuery, AgentStats, EventDetail, Page, ReaderWriter, StoreError, Trajectory,
    TrajectoryQuery,
};
use std::sync::Arc;

pub use agents::AgentView;

/// Transport-neutral console endpoint handlers over a shared store.
pub struct ConsoleHandlers<S> {
    store: Arc<S>,
}

impl<S> ConsoleHandlers<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    pub(crate) fn store(&self) -> &S {
        &self.store
    }
}

impl<S: ReaderWriter> ConsoleHandlers<S> {
    pub async fn list_agents(&self, query: &AgentQuery) -> Result<Page<AgentView>, StoreError> {
        agents::list_agents(self.store(), query).await
    }

    pub async fn get_agent(&self, id: &str) -> Result<AgentView, StoreError> {
        agents::get_agent(self.store(), id).await
    }

    pub async fn update_agent(&self, id: &str) -> Result<AgentView, StoreError> {
        agents::update_agent(self.store(), id).await
    }

    pub async fn analyze_agents(&self, filter: &AgentFilter) -> Result<AgentStats, StoreError> {
        agents::analyze_agents(self.store(), filter).await
    }

    pub async fn delete_agent(&self, id: &str) -> Result<(), StoreError> {
        agents::delete_agent(self.store(), id).await
    }

    pub async fn get_trajectory(&self, id: &str) -> Result<Trajectory, StoreError> {
        trajectories::get_trajectory(self.store(), id).await
    }

    pub async fn list_trajectory_events(
        &self,
        id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Page<EventDetail>, StoreError> {
        trajectories::list_trajectory_events(self.store(), id, offset, limit).await
    }

    pub async fn list_trajectories(
        &self,
        query: &TrajectoryQuery,
    ) -> Result<Page<Trajectory>, StoreError> {
        trajectories::list_trajectories(self.store(), query).await
    }

    pub async fn batch_get_trajectory_sparklines(
        &self,
        ids: &[String],
    ) -> Result<Vec<crate::sparkline::TrajectorySparkline>, StoreError> {
        trajectories::batch_get_trajectory_sparklines(self.store(), ids).await
    }
}
