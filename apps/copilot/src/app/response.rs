//! Response types and utilities for GitHub Copilot hook handlers.
//!
//! This module contains the HookResponse structure and its associated
//! builder methods, used to respond to hook events from GitHub Copilot.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Response structure for preToolUse hooks
/// Uses the Copilot CLI hooks format: {"permissionDecision": "deny", "permissionDecisionReason": "..."}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PreToolUseResponse {
    /// Permission decision: "allow" or "deny"
    #[serde(rename = "permissionDecision", skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<String>,
    /// Reason for the decision (shown when blocking)
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,
    /// Modified tool arguments (optional, for arg transformation)
    #[serde(skip_serializing_if = "Option::is_none", rename = "modifiedArgs")]
    pub modified_args: Option<String>,
}

impl PreToolUseResponse {
    /// Create a response that allows the tool execution
    pub fn allow() -> Self {
        Self {
            permission_decision: Some("allow".to_string()),
            permission_decision_reason: None,
            modified_args: None,
        }
    }

    /// Create a response that blocks the tool execution
    pub fn block(message: impl Into<String>) -> Self {
        Self {
            permission_decision: Some("deny".to_string()),
            permission_decision_reason: Some(message.into()),
            modified_args: None,
        }
    }

    /// Create a response that allows with modified arguments
    pub fn allow_with_modified_args(args: impl Into<String>) -> Self {
        Self {
            permission_decision: Some("allow".to_string()),
            permission_decision_reason: None,
            modified_args: Some(args.into()),
        }
    }
}

/// Response structure for userPromptSubmitted hooks
/// Uses the Copilot CLI hooks format: {"permissionDecision": "deny", "permissionDecisionReason": "..."}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UserPromptSubmittedResponse {
    /// Permission decision: "allow" or "deny"
    #[serde(rename = "permissionDecision", skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<String>,
    /// Reason for the decision (shown when blocking)
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,
}

impl UserPromptSubmittedResponse {
    /// Create a response that allows the prompt submission
    pub fn allow() -> Self {
        Self {
            permission_decision: Some("allow".to_string()),
            permission_decision_reason: None,
        }
    }

    /// Create a response that blocks the prompt submission
    pub fn block(message: impl Into<String>) -> Self {
        Self {
            permission_decision: Some("deny".to_string()),
            permission_decision_reason: Some(message.into()),
        }
    }
}

/// Response structure for observation-only hooks (sessionStart, sessionEnd, postToolUse, errorOccurred)
/// These hooks have no output
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NoOutputResponse {}

impl NoOutputResponse {
    /// Create an empty response
    pub fn ok() -> Self {
        Self {}
    }
}

/// Unified hook response enum that can serialize any hook response type
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum HookResponse {
    /// Response for preToolUse hooks
    PreToolUse(PreToolUseResponse),
    /// Response for userPromptSubmitted hooks
    UserPromptSubmitted(UserPromptSubmittedResponse),
    /// Response for observation-only hooks
    NoOutput(NoOutputResponse),
}

impl HookResponse {
    // ========================================================================
    // preToolUse responses
    // ========================================================================

    /// Create a response that allows tool execution
    pub fn allow_tool() -> Self {
        Self::PreToolUse(PreToolUseResponse::allow())
    }

    /// Create a response that blocks tool execution
    pub fn block_tool(message: impl Into<String>) -> Self {
        Self::PreToolUse(PreToolUseResponse::block(message))
    }

    /// Create a response that allows tool execution with modified arguments
    pub fn allow_tool_with_modified_args(args: impl Into<String>) -> Self {
        Self::PreToolUse(PreToolUseResponse::allow_with_modified_args(args))
    }

    // ========================================================================
    // userPromptSubmitted responses
    // ========================================================================

    /// Create a response that allows prompt submission
    pub fn allow_prompt() -> Self {
        Self::UserPromptSubmitted(UserPromptSubmittedResponse::allow())
    }

    /// Create a response that blocks prompt submission
    pub fn block_prompt(message: impl Into<String>) -> Self {
        Self::UserPromptSubmitted(UserPromptSubmittedResponse::block(message))
    }

    // ========================================================================
    // Observation-only hook responses
    // ========================================================================

    /// Create an empty response for observation-only hooks
    pub fn ok() -> Self {
        Self::NoOutput(NoOutputResponse::ok())
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

    #[test]
    fn test_pre_tool_use_allow() {
        let response = PreToolUseResponse::allow();
        assert_eq!(response.permission_decision, Some("allow".to_string()));
        assert!(response.permission_decision_reason.is_none());
        assert!(response.modified_args.is_none());
    }

    #[test]
    fn test_pre_tool_use_block() {
        let response = PreToolUseResponse::block("Not allowed");
        assert_eq!(response.permission_decision, Some("deny".to_string()));
        assert_eq!(
            response.permission_decision_reason,
            Some("Not allowed".to_string())
        );
        assert!(response.modified_args.is_none());
    }

    #[test]
    fn test_pre_tool_use_modified_args() {
        let response = PreToolUseResponse::allow_with_modified_args(r#"{"command":"safe_ls"}"#);
        assert_eq!(response.permission_decision, Some("allow".to_string()));
        assert!(response.permission_decision_reason.is_none());
        assert_eq!(
            response.modified_args,
            Some(r#"{"command":"safe_ls"}"#.to_string())
        );
    }

    #[test]
    fn test_user_prompt_submitted_allow() {
        let response = UserPromptSubmittedResponse::allow();
        assert_eq!(response.permission_decision, Some("allow".to_string()));
        assert!(response.permission_decision_reason.is_none());
    }

    #[test]
    fn test_user_prompt_submitted_block() {
        let response = UserPromptSubmittedResponse::block("Blocked by policy");
        assert_eq!(response.permission_decision, Some("deny".to_string()));
        assert_eq!(
            response.permission_decision_reason,
            Some("Blocked by policy".to_string())
        );
    }

    #[test]
    fn test_hook_response_allow_tool_serialization() {
        let response = HookResponse::allow_tool();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("allow"));
    }

    #[test]
    fn test_hook_response_block_tool_serialization() {
        let response = HookResponse::block_tool("Not allowed by policy");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("deny"));
        assert!(json.contains("permissionDecisionReason"));
        assert!(json.contains("Not allowed by policy"));
    }

    #[test]
    fn test_hook_response_modified_args_serialization() {
        let response = HookResponse::allow_tool_with_modified_args(r#"{"command":"ls"}"#);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("modifiedArgs"));
        assert!(json.contains("command"));
    }

    #[test]
    fn test_hook_response_allow_prompt_serialization() {
        let response = HookResponse::allow_prompt();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("allow"));
    }

    #[test]
    fn test_hook_response_block_prompt_serialization() {
        let response = HookResponse::block_prompt("Sensitive content detected");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("deny"));
        assert!(json.contains("permissionDecisionReason"));
        assert!(json.contains("Sensitive content detected"));
    }

    #[test]
    fn test_empty_response_serialization() {
        let response = HookResponse::ok();
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, "{}");
    }
}
