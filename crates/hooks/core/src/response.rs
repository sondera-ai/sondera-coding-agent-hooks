//! Response shapes shared by more than one provider.
//!
//! Response *schemas* are provider-specific and live in the provider crates —
//! every host agent has its own JSON envelope, and collapsing them would mean
//! serializing the wrong shape. Only an envelope two providers genuinely share
//! belongs here.

use serde::{Deserialize, Serialize};

/// The minimal flat `{decision, reason, additionalContext}` envelope.
///
/// Shared by the providers whose hook contract is just "print a decision":
/// OpenHands' SDK hooks and OpenCode's direct CLI hook mode both parse exactly
/// this shape, so it lives here rather than one of them depending on the
/// other's crate for it. A hook allows by printing `{}`; it blocks by printing
/// `{"decision":"deny"}` (or exiting 2).
#[must_use]
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionEnvelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

impl DecisionEnvelope {
    /// The no-opinion response: serializes to `{}`.
    pub fn ok() -> Self {
        Self::default()
    }

    /// Block the action with `reason`.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: Some("deny".to_string()),
            reason: Some(reason.into()),
            additional_context: None,
        }
    }

    /// Block the action with `reason`, and hand `context` back to the model.
    pub fn deny_with_context(reason: impl Into<String>, context: impl Into<String>) -> Self {
        Self {
            additional_context: Some(context.into()),
            ..Self::deny(reason)
        }
    }

    /// Allow the action, injecting `context` for the model.
    pub fn additional_context(context: impl Into<String>) -> Self {
        Self {
            additional_context: Some(context.into()),
            ..Self::default()
        }
    }

    /// Whether this envelope blocks the action.
    pub fn is_deny(&self) -> bool {
        self.decision.as_deref() == Some("deny")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ok_serializes_to_empty_json() {
        assert_eq!(
            serde_json::to_string(&DecisionEnvelope::ok()).unwrap(),
            "{}"
        );
    }

    #[test]
    fn deny_uses_the_flat_decision_shape() {
        let value = serde_json::to_value(DecisionEnvelope::deny("blocked")).unwrap();
        assert_eq!(value, json!({"decision":"deny","reason":"blocked"}));
        assert!(
            value.get("hookSpecificOutput").is_none(),
            "the flat contract has no hookSpecificOutput envelope"
        );
    }

    #[test]
    fn deny_can_carry_additional_context() {
        let value =
            serde_json::to_value(DecisionEnvelope::deny_with_context("blocked", "ctx")).unwrap();
        assert_eq!(
            value,
            json!({"decision":"deny","reason":"blocked","additionalContext":"ctx"})
        );
    }

    #[test]
    fn additional_context_alone_does_not_block() {
        let response = DecisionEnvelope::additional_context("ctx");
        assert!(!response.is_deny());
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            json!({"additionalContext":"ctx"})
        );
    }
}
