//! Response types for Hermes Agent shell-hook handlers.
//!
//! Hermes shell hooks consume `action/message` for preventive hooks and
//! `context` for `pre_llm_call`. Other response fields are ignored.

use serde::{Deserialize, Serialize};

#[must_use]
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

impl HookResponse {
    pub fn ok() -> Self {
        Self::default()
    }

    pub fn block(message: impl Into<String>) -> Self {
        Self {
            action: Some("block".to_string()),
            message: Some(message.into()),
            context: None,
        }
    }

    pub fn context(context: impl Into<String>) -> Self {
        Self {
            context: Some(context.into()),
            ..Self::default()
        }
    }

    pub fn continue_turn(message: impl Into<String>) -> Self {
        Self {
            action: Some("continue".to_string()),
            message: Some(message.into()),
            context: None,
        }
    }

    pub fn is_enforcing(&self) -> bool {
        matches!(self.action.as_deref(), Some("block" | "continue"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ok_serializes_to_empty_json() {
        assert_eq!(serde_json::to_string(&HookResponse::ok()).unwrap(), "{}");
    }

    #[test]
    fn block_uses_hermes_canonical_shape() {
        let value = serde_json::to_value(HookResponse::block("blocked")).unwrap();
        assert_eq!(value, json!({"action":"block","message":"blocked"}));
    }

    #[test]
    fn context_shape_matches_pre_llm_shell_contract() {
        let value = serde_json::to_value(HookResponse::context("ctx")).unwrap();
        assert_eq!(value, json!({"context":"ctx"}));
    }
}
