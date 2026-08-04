//! Agent identity, the activity rollups derived from an agent's events, and the
//! agent store surface.
//!
//! [`Agent`] carries just enough to identify the AI coding agent that produced a
//! trajectory event: a stable id plus the provider and runtime platform it runs
//! on. Capability inventories ("agent cards") are intentionally not modeled here
//! — hooks normalize raw events into trajectory tool actions rather than
//! collecting agent capability documents.
//!
//! [`AgentActivity`] is that identity *composed with* the liveness rollups a
//! store computes from the agent's stored trajectory events. It holds an
//! [`Agent`] rather than restating its fields, so there is one definition of
//! agent identity in the workspace and no projection can drift from it.
//!
//! Nothing here speaks AIP: the store surface takes bare agent ids, and
//! `agents/{id}` resource names are built and parsed at the wire edge (see
//! `sondera_schema::names`).

use crate::error::StoreError;
use crate::page::Page;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::future::Future;

type Result<T> = std::result::Result<T, StoreError>;

/// Agent represents a unique AI agent in the environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    /// Unique identifier for the agent.
    ///
    /// Ids are minted by the hooks from provider + scope and may be **compound**
    /// — e.g. `claude-code-developer/rs-harness-engineer`. They are only ever bound
    /// as opaque values (SQL parameters, display-name derivation), never
    /// re-parsed as a path, so embedded slashes are safe.
    pub id: String,
    /// Identifier for the provider of the agent (for example: "anthropic").
    pub provider: String,
    /// Runtime platform identifier (for example: "claude-code", "cursor").
    pub platform: String,
}

impl Agent {
    /// Construct an agent from its identity fields.
    pub fn new(
        id: impl Into<String>,
        provider: impl Into<String>,
        platform: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            provider: provider.into(),
            platform: platform.into(),
        }
    }
}

/// Agent liveness rollup, computed from recent trajectory activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    #[default]
    Unspecified,
    Healthy,
    Degraded,
    Offline,
}

/// An agent's identity together with the activity rollups derived from its
/// stored trajectory events.
///
/// Identity is harness-owned and lives in [`Self::agent`]; everything else is
/// computed by the store from the agent's events and is never written by a
/// caller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentActivity {
    /// The agent this rollup describes.
    pub agent: Agent,
    pub status: AgentStatus,
    pub health_score: i32,
    pub last_active_time: Option<DateTime<Utc>>,
    pub runs_today: i32,
    pub deny_rate: f64,
}

/// The identity-only rollup for an agent that has reported in but whose activity
/// has not been computed yet: every derived field starts zeroed.
impl From<Agent> for AgentActivity {
    fn from(agent: Agent) -> Self {
        Self {
            agent,
            status: AgentStatus::Unspecified,
            health_score: 0,
            last_active_time: None,
            runs_today: 0,
            deny_rate: 0.0,
        }
    }
}

/// Fleet-wide agent rollup: how many agents sit in each liveness bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentStats {
    pub total: i32,
    pub healthy: i32,
    pub degraded: i32,
    pub offline: i32,
}

impl AgentStats {
    /// Aggregate a set of already-filtered agent rollups into stats.
    pub fn tally(agents: &[AgentActivity]) -> Self {
        let mut stats = Self {
            total: agents.len() as i32,
            ..Default::default()
        };
        for agent in agents {
            match agent.status {
                AgentStatus::Healthy => stats.healthy += 1,
                AgentStatus::Degraded => stats.degraded += 1,
                AgentStatus::Offline => stats.offline += 1,
                AgentStatus::Unspecified => {}
            }
        }
        stats
    }
}

/// Which agents a list or analyze read should consider.
///
/// Every field is a narrowing clause; `None` means "do not narrow on this". A
/// default filter therefore matches every agent. Parsing the wire filter
/// grammar into this shape is the service edge's job.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentFilter {
    pub agent_id: Option<String>,
    pub provider: Option<String>,
    pub platform: Option<String>,
}

impl AgentFilter {
    /// Whether an agent satisfies every clause set on this filter.
    pub fn matches(&self, agent: &Agent) -> bool {
        let narrows = |clause: &Option<String>, value: &str| {
            clause.as_ref().is_some_and(|wanted| wanted != value)
        };
        !narrows(&self.agent_id, &agent.id)
            && !narrows(&self.provider, &agent.provider)
            && !narrows(&self.platform, &agent.platform)
    }
}

/// The orderings a store can sort an agent roster by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentOrderBy {
    /// Most-recently-active first by default, so the roster reads as "who is
    /// working right now".
    #[default]
    LastActive,
    /// The agent id, which is also what a UI shows as the display name.
    Id,
    RunsToday,
}

/// A complete agent list read: which agents, in what order, and which window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentQuery {
    pub filter: AgentFilter,
    pub order_by: AgentOrderBy,
    pub descending: bool,
    pub offset: usize,
    pub limit: usize,
}

impl Default for AgentQuery {
    fn default() -> Self {
        Self {
            filter: AgentFilter::default(),
            order_by: AgentOrderBy::default(),
            // Newest-active first is the useful default for a roster.
            descending: true,
            offset: 0,
            // Unbounded: a domain query has no opinion about page sizes, so an
            // unset limit reads every match. Service edges clamp before calling.
            limit: usize::MAX,
        }
    }
}

/// The agent store surface, shared by the harness (writes) and the console gRPC
/// service (reads).
///
/// Agent identity is harness-owned: [`AgentReaderWriter::upsert_agent`] is
/// called on the ingest path when a hook first reports in, and read callers
/// never mutate it. Every method takes a bare agent id — resource names are
/// parsed at the service edge.
pub trait AgentReaderWriter: Send + Sync {
    /// Register (or refresh) an agent's identity. Called by the harness before
    /// inserting events so agent reads see every agent that has reported in,
    /// including one whose events have all been deleted.
    fn upsert_agent(&self, agent: &Agent) -> impl Future<Output = Result<()>> + Send;

    /// A window of agent rollups matching `query`.
    fn list_agents(
        &self,
        query: &AgentQuery,
    ) -> impl Future<Output = Result<Page<AgentActivity>>> + Send;

    /// One agent's rollup, or `None` when no agent with that id has reported in.
    fn get_agent(&self, id: &str) -> impl Future<Output = Result<Option<AgentActivity>>> + Send;

    /// Bucket counts over every agent matching `filter`.
    fn analyze_agents(
        &self,
        filter: &AgentFilter,
    ) -> impl Future<Output = Result<AgentStats>> + Send;

    /// Hard-delete an agent by id, cascading to its trajectory events.
    ///
    /// Returns `Ok(true)` when a row was removed and `Ok(false)` when no agent
    /// matched. Callers map `false` to a not-found response; idempotent callers
    /// may treat it as success.
    fn delete_agent(&self, id: &str) -> impl Future<Output = Result<bool>> + Send;

    /// The id of the trajectory this agent touched most recently, if any.
    ///
    /// Exists so a caller can render a representative strip for the agent
    /// without the store needing to know what a strip is.
    fn latest_trajectory_id(
        &self,
        agent_id: &str,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activity(status: AgentStatus) -> AgentActivity {
        AgentActivity {
            status,
            ..Agent::new("a", "anthropic", "claude-code").into()
        }
    }

    #[test]
    fn stats_count_each_status_bucket() {
        let stats = AgentStats::tally(&[
            activity(AgentStatus::Healthy),
            activity(AgentStatus::Healthy),
            activity(AgentStatus::Degraded),
            activity(AgentStatus::Offline),
            activity(AgentStatus::Unspecified),
        ]);
        assert_eq!(stats.total, 5);
        assert_eq!(stats.healthy, 2);
        assert_eq!(stats.degraded, 1);
        assert_eq!(stats.offline, 1);
    }

    #[test]
    fn an_empty_filter_matches_every_agent() {
        assert!(AgentFilter::default().matches(&Agent::new("a", "anthropic", "claude-code")));
    }

    #[test]
    fn every_clause_on_a_filter_must_match() {
        let agent = Agent::new("a", "anthropic", "claude-code");
        let filter = AgentFilter {
            provider: Some("anthropic".to_string()),
            platform: Some("claude-code".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&agent));

        let narrowed = AgentFilter {
            agent_id: Some("b".to_string()),
            ..filter
        };
        assert!(!narrowed.matches(&agent));
    }
}
