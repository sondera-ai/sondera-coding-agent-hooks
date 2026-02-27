use crate::types::{Adjudicated, Event};
use anyhow::Result;
use std::future::Future;

/// Core interface for the Sondera harness service.
///
/// Implementations of this trait provide trajectory management and policy
/// adjudication for AI agent governance. The gRPC `Client` is the primary
/// implementation, but this trait enables alternative backends (e.g., in-memory
/// for testing).
pub trait Harness: Send + Sync {
    /// Add a step to a trajectory and return the adjudicated result.
    ///
    /// The harness evaluates the step against configured policies and guardrails,
    /// returning an `AdjudicatedStep` with the decision (Allow/Deny/Escalate).
    ///
    /// `context` provides policy-engine-specific context (e.g., Cedar context
    /// fields like session_id, cwd, permission_mode).
    fn adjudicate(&self, event: Event) -> impl Future<Output = Result<Adjudicated>> + Send;
}
