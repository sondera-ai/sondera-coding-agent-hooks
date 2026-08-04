//! Transport-neutral agent handlers.
//!
//! Adapters parse their resource names and request grammar before calling this
//! layer. These handlers consume and return domain types, so gRPC and MCP share
//! the same store operations and console-specific sparkline composition.

use crate::sparkline::{TrajectorySparkline, sparkline};
use sondera_types::{
    AgentActivity, AgentFilter, AgentQuery, AgentStats, Page, ReaderWriter, StoreError,
};

/// An agent activity rollup with the representative strip from its latest run.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AgentView {
    pub activity: AgentActivity,
    pub sparkline: Option<TrajectorySparkline>,
}

async fn agent_sparkline<S: ReaderWriter>(
    store: &S,
    agent_id: &str,
) -> Result<Option<TrajectorySparkline>, StoreError> {
    let Some(trajectory_id) = store.latest_trajectory_id(agent_id).await? else {
        return Ok(None);
    };
    let events = store.trajectory_events(&trajectory_id).await?;
    if events.is_empty() {
        return Ok(None);
    }
    Ok(Some(sparkline(&trajectory_id, &events)))
}

async fn view<S: ReaderWriter>(
    store: &S,
    activity: AgentActivity,
) -> Result<AgentView, StoreError> {
    let sparkline = agent_sparkline(store, &activity.agent.id).await?;
    Ok(AgentView {
        activity,
        sparkline,
    })
}

pub async fn list_agents<S: ReaderWriter>(
    store: &S,
    query: &AgentQuery,
) -> Result<Page<AgentView>, StoreError> {
    let page = store.list_agents(query).await?;
    let mut agents = Vec::with_capacity(page.items.len());
    for activity in page.items {
        agents.push(view(store, activity).await?);
    }
    Ok(Page::new(agents, page.total))
}

pub async fn get_agent<S: ReaderWriter>(store: &S, id: &str) -> Result<AgentView, StoreError> {
    let activity = store
        .get_agent(id)
        .await?
        .ok_or_else(|| StoreError::not_found(format!("Agent not found: {id}")))?;
    view(store, activity).await
}

/// Verify an agent exists and return its stored projection.
///
/// No agent field is console-writable today, so this intentionally delegates to
/// the same read as [`get_agent`] and persists nothing.
pub async fn update_agent<S: ReaderWriter>(store: &S, id: &str) -> Result<AgentView, StoreError> {
    get_agent(store, id).await
}

pub async fn analyze_agents<S: ReaderWriter>(
    store: &S,
    filter: &AgentFilter,
) -> Result<AgentStats, StoreError> {
    store.analyze_agents(filter).await
}

pub async fn delete_agent<S: ReaderWriter>(store: &S, id: &str) -> Result<(), StoreError> {
    if !store.delete_agent(id).await? {
        return Err(StoreError::not_found(format!("Agent not found: {id}")));
    }
    Ok(())
}
