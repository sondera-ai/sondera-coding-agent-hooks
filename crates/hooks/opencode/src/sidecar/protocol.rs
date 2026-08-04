//! Wire types exchanged with the OpenCode plugin.
//!
//! OpenCode delivers events from a long-lived host plugin rather than as
//! one-shot CLI invocations, so its adapter normalizes each one into a
//! [`SidecarRequest`] and answers with a [`SidecarResponse`]. Keeping that
//! vocabulary in its own module separates the shape on the wire from
//! [`super`]'s mapping of OpenCode events onto trajectory events.
//!
//! These types are `serde`-derived because the peer is the
//! `@sondera/opencode-plugin` package; changing a field name or an enum variant
//! is a breaking change to that contract, not just a local refactor.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookCriticality {
    ObservationOnly,
    ContextInjectionCapable,
    AdjudicationCritical,
}

impl HookCriticality {
    pub fn is_blocking(self) -> bool {
        match self {
            Self::AdjudicationCritical => true,
            // Context-injection-capable hooks can steer future model behavior,
            // but they cannot block the current host operation.
            Self::ContextInjectionCapable | Self::ObservationOnly => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidecarEvent {
    pub kind: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidecarRequest {
    pub id: String,
    pub provider: String,
    pub platform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trajectory_id: Option<String>,
    pub criticality: HookCriticality,
    pub event: SidecarEvent,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SidecarDecision {
    Allow,
    Deny,
    Escalate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidecarResponse {
    pub id: String,
    pub decision: SidecarDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SidecarResponse {
    pub fn allow(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SidecarDecision::Allow,
            reason: None,
            additional_context: None,
            error: None,
        }
    }

    pub fn deny(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            decision: SidecarDecision::Deny,
            reason: Some(reason.into()),
            additional_context: None,
            error: None,
        }
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips_through_json() {
        let request = SidecarRequest {
            id: "req-1".to_string(),
            provider: "opencode".to_string(),
            platform: "opencode-bun".to_string(),
            session_id: Some("session-1".to_string()),
            trajectory_id: None,
            criticality: HookCriticality::AdjudicationCritical,
            event: SidecarEvent {
                kind: "tool.execute.before".to_string(),
                payload: serde_json::json!({"tool": "bash"}),
            },
            metadata: Value::Null,
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: SidecarRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn only_adjudication_critical_hooks_can_block() {
        assert!(HookCriticality::AdjudicationCritical.is_blocking());
        assert!(!HookCriticality::ContextInjectionCapable.is_blocking());
        assert!(!HookCriticality::ObservationOnly.is_blocking());
    }

    #[test]
    fn an_allow_carrying_an_error_still_allows() {
        // The degraded path on a non-blocking hook: report what failed without
        // turning it into a denial.
        let response = SidecarResponse::allow("req-1").with_error("harness unreachable");
        assert_eq!(response.decision, SidecarDecision::Allow);
        assert_eq!(response.error.as_deref(), Some("harness unreachable"));
    }
}
