//! Response types and utilities for GitHub Copilot hook handlers.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[must_use]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PreToolUseResponse {
    #[serde(rename = "permissionDecision", skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<String>,
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,
    #[serde(rename = "modifiedArgs", skip_serializing_if = "Option::is_none")]
    pub modified_args: Option<JsonValue>,
}

impl PreToolUseResponse {
    pub fn block(message: impl Into<String>) -> Self {
        Self {
            permission_decision: Some("deny".to_string()),
            permission_decision_reason: Some(message.into()),
            modified_args: None,
        }
    }

    pub fn allow_with_modified_args(args: JsonValue) -> Self {
        Self {
            permission_decision: Some("allow".to_string()),
            permission_decision_reason: None,
            modified_args: Some(args),
        }
    }
}

#[must_use]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionRequestResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interrupt: Option<bool>,
}

impl PermissionRequestResponse {
    pub fn allow(message: impl Into<String>) -> Self {
        Self {
            behavior: Some("allow".to_string()),
            message: Some(message.into()),
            interrupt: None,
        }
    }

    pub fn deny(message: impl Into<String>) -> Self {
        Self {
            behavior: Some("deny".to_string()),
            message: Some(message.into()),
            interrupt: Some(true),
        }
    }
}

#[must_use]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContinuationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ContinuationResponse {
    pub fn block(message: impl Into<String>) -> Self {
        Self {
            decision: Some("block".to_string()),
            reason: Some(message.into()),
        }
    }
}

#[must_use]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdditionalContextResponse {
    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

impl AdditionalContextResponse {
    pub fn context(context: impl Into<String>) -> Self {
        Self {
            additional_context: Some(context.into()),
        }
    }
}

#[must_use]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptTransformationResponse {
    #[serde(
        rename = "modifiedTransformedPrompt",
        skip_serializing_if = "Option::is_none"
    )]
    pub modified_transformed_prompt: Option<String>,
}

impl PromptTransformationResponse {
    pub fn replace(prompt: impl Into<String>) -> Self {
        Self {
            modified_transformed_prompt: Some(prompt.into()),
        }
    }
}

#[must_use]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoOutputResponse {}

#[must_use]
#[derive(Debug, Serialize, PartialEq)]
#[serde(untagged)]
pub enum HookResponse {
    PreToolUse(PreToolUseResponse),
    PermissionRequest(PermissionRequestResponse),
    Continuation(ContinuationResponse),
    AdditionalContext(AdditionalContextResponse),
    PromptTransformation(PromptTransformationResponse),
    NoOutput(NoOutputResponse),
}

impl HookResponse {
    /// Fall through to Copilot's native behavior.
    pub fn ok() -> Self {
        Self::NoOutput(NoOutputResponse {})
    }

    pub fn block_tool(message: impl Into<String>) -> Self {
        Self::PreToolUse(PreToolUseResponse::block(message))
    }

    pub fn allow_tool_with_modified_args(args: JsonValue) -> Self {
        Self::PreToolUse(PreToolUseResponse::allow_with_modified_args(args))
    }

    pub fn permission_allow(message: impl Into<String>) -> Self {
        Self::PermissionRequest(PermissionRequestResponse::allow(message))
    }

    pub fn permission_deny(message: impl Into<String>) -> Self {
        Self::PermissionRequest(PermissionRequestResponse::deny(message))
    }

    pub fn block_continuation(message: impl Into<String>) -> Self {
        Self::Continuation(ContinuationResponse::block(message))
    }

    pub fn additional_context(context: impl Into<String>) -> Self {
        Self::AdditionalContext(AdditionalContextResponse::context(context))
    }

    pub fn replace_transformed_prompt(prompt: impl Into<String>) -> Self {
        Self::PromptTransformation(PromptTransformationResponse::replace(prompt))
    }

    /// Whether this response blocks the operation.
    pub fn is_deny(&self) -> bool {
        match self {
            Self::PreToolUse(r) => r.permission_decision.as_deref() == Some("deny"),
            Self::PermissionRequest(r) => r.behavior.as_deref() == Some("deny"),
            Self::Continuation(r) => r.decision.as_deref() == Some("block"),
            Self::PromptTransformation(r) => r.modified_transformed_prompt.is_some(),
            Self::AdditionalContext(_) | Self::NoOutput(_) => false,
        }
    }
}

impl Default for HookResponse {
    fn default() -> Self {
        Self::ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_json(response: &HookResponse) -> String {
        serde_json::to_string(response).unwrap()
    }

    #[test]
    fn ok_serializes_to_empty_json() {
        assert_eq!(to_json(&HookResponse::ok()), "{}");
    }

    #[test]
    fn modified_args_serializes_as_object() {
        let json = to_json(&HookResponse::allow_tool_with_modified_args(
            serde_json::json!({"command": "git status --short"}),
        ));

        assert!(json.contains("\"permissionDecision\":\"allow\""));
        assert!(json.contains("\"modifiedArgs\":{\"command\":\"git status --short\"}"));
        assert!(!json.contains("\\\"command\\\""));
    }

    #[test]
    fn permission_request_has_separate_behavior_model() {
        let json = to_json(&HookResponse::permission_deny("blocked by Sondera"));
        assert_eq!(
            json,
            r#"{"behavior":"deny","message":"blocked by Sondera","interrupt":true}"#
        );
    }

    #[test]
    fn stop_hooks_use_continuation_model() {
        let json = to_json(&HookResponse::block_continuation("finish cleanup first"));
        assert_eq!(
            json,
            r#"{"decision":"block","reason":"finish cleanup first"}"#
        );
    }

    #[test]
    fn transformed_prompt_rewrite_uses_documented_field() {
        let json = to_json(&HookResponse::replace_transformed_prompt("safe prompt"));

        assert_eq!(json, r#"{"modifiedTransformedPrompt":"safe prompt"}"#);
    }

    #[test]
    fn notification_and_failure_context_use_additional_context() {
        let json = to_json(&HookResponse::additional_context(
            "retry with a safer command",
        ));
        assert_eq!(
            json,
            r#"{"additionalContext":"retry with a safer command"}"#
        );
    }
}
