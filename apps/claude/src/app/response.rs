//! Response types and utilities for Claude Code hook handlers.
//!
//! This module contains the HookResponse structure and its associated
//! builder methods, used to respond to hook events from Claude Code.
//!
//! The response format follows the Claude Code hooks specification:
//! https://docs.anthropic.com/en/docs/claude-code/hooks

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

/// Permission decision for PreToolUse hooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PermissionDecision {
    /// Bypass the permission system and allow the tool call
    Allow,
    /// Prevent the tool call from executing
    Deny,
    /// Ask the user to confirm the tool call in the UI
    Ask,
}

/// Permission request behavior for PermissionRequest hooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PermissionRequestBehavior {
    Allow,
    Deny,
}

/// Decision for PermissionRequest hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRequestDecision {
    pub behavior: PermissionRequestBehavior,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "updatedInput")]
    pub updated_input: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interrupt: Option<bool>,
}

/// Block decision for PostToolUse, UserPromptSubmit, Stop, SubagentStop hooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum BlockDecision {
    Block,
}

/// Hook-specific output for PreToolUse hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<PermissionDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Hook-specific output for PermissionRequest hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestOutput {
    pub hook_event_name: String,
    pub decision: PermissionRequestDecision,
}

/// Hook-specific output for PostToolUse hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostToolUseOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Hook-specific output for PostToolUseFailure hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostToolUseFailureOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Hook-specific output for UserPromptSubmit hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPromptSubmitOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Hook-specific output for SessionStart hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStartOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
    /// Environment variables to persist for the session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
}

/// Hook-specific output for SubagentStart hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubagentStartOutput {
    pub hook_event_name: String,
    /// Context to inject into the subagent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Hook-specific output for Stop/SubagentStop hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StopOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Enum for all hook-specific outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HookSpecificOutput {
    PreToolUse(PreToolUseOutput),
    PermissionRequest(PermissionRequestOutput),
    PostToolUse(PostToolUseOutput),
    PostToolUseFailure(PostToolUseFailureOutput),
    UserPromptSubmit(UserPromptSubmitOutput),
    SessionStart(SessionStartOutput),
    SubagentStart(SubagentStartOutput),
    Stop(StopOutput),
}

/// Response structure for hook handlers following Claude Code specification
#[derive(Debug, Serialize, Deserialize)]
pub struct HookResponse {
    /// Whether Claude should continue after hook execution (default: true)
    #[serde(default = "default_continue")]
    #[serde(rename = "continue")]
    #[serde(skip_serializing_if = "is_true")]
    pub continue_execution: bool,

    /// Message shown when continue is false
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "stopReason")]
    pub stop_reason: Option<String>,

    /// Hide stdout from transcript mode (default: false)
    #[serde(default)]
    #[serde(rename = "suppressOutput")]
    #[serde(skip_serializing_if = "is_false")]
    pub suppress_output: bool,

    /// Optional warning message shown to the user
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "systemMessage")]
    pub system_message: Option<String>,

    /// Decision for PostToolUse, UserPromptSubmit, Stop, SubagentStop hooks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<BlockDecision>,

    /// Reason for the decision (required when decision is "block")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Hook-specific output
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: Option<HookSpecificOutput>,
}

fn default_continue() -> bool {
    true
}

fn is_true(v: &bool) -> bool {
    *v
}

fn is_false(v: &bool) -> bool {
    !*v
}

impl Default for HookResponse {
    fn default() -> Self {
        Self {
            continue_execution: true,
            stop_reason: None,
            suppress_output: false,
            system_message: None,
            decision: None,
            reason: None,
            hook_specific_output: None,
        }
    }
}

impl HookResponse {
    /// Return an empty `HookResponse` (serializes to `{}`).
    ///
    /// We omit `hook_specific_output` instead of setting an explicit allow decision (e.g.,
    /// `permissionDecision: "allow"` for PreToolUse, `behavior: "allow"` for PermissionRequest),
    /// because the latter would bypass Claude Code's normal permission system — the user wouldn't
    /// be prompted for permission, the tool call would just execute. By not specifying
    /// `hook_specific_output`, our hook expresses no opinion and Claude Code falls back to its
    /// default behavior (e.g., prompting the user in default mode, auto-approving in accept-edits
    /// mode).
    pub fn allow() -> Self {
        Self::default()
    }

    /// Create a response that stops Claude entirely
    #[allow(dead_code)]
    pub fn stop(reason: String) -> Self {
        Self {
            continue_execution: false,
            stop_reason: Some(reason),
            ..Self::default()
        }
    }

    /// Create a response that blocks the action with a reason (for Stop/SubagentStop hooks)
    #[allow(dead_code)]
    pub fn block(reason: String) -> Self {
        Self {
            decision: Some(BlockDecision::Block),
            reason: Some(reason),
            ..Self::default()
        }
    }

    // PreToolUse responses

    /// Create a PreToolUse response that denies the tool call
    pub fn pre_tool_deny(reason: String) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::PreToolUse(PreToolUseOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: Some(PermissionDecision::Deny),
                permission_decision_reason: Some(reason),
                updated_input: None,
                additional_context: None,
            })),
            ..Self::default()
        }
    }

    /// Create a PreToolUse response that asks the user to confirm
    pub fn pre_tool_ask(reason: String) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::PreToolUse(PreToolUseOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: Some(PermissionDecision::Ask),
                permission_decision_reason: Some(reason),
                updated_input: None,
                additional_context: None,
            })),
            ..Self::default()
        }
    }

    // PermissionRequest responses

    /// Create a PermissionRequest response that denies the permission
    pub fn permission_deny(message: String) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::PermissionRequest(
                PermissionRequestOutput {
                    hook_event_name: "PermissionRequest".to_string(),
                    decision: PermissionRequestDecision {
                        behavior: PermissionRequestBehavior::Deny,
                        updated_input: None,
                        message: Some(message),
                        interrupt: None,
                    },
                },
            )),
            ..Self::default()
        }
    }

    /// Create a PermissionRequest response that denies and interrupts Claude
    #[allow(dead_code)]
    pub fn permission_deny_and_interrupt(message: String) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::PermissionRequest(
                PermissionRequestOutput {
                    hook_event_name: "PermissionRequest".to_string(),
                    decision: PermissionRequestDecision {
                        behavior: PermissionRequestBehavior::Deny,
                        updated_input: None,
                        message: Some(message),
                        interrupt: Some(true),
                    },
                },
            )),
            ..Self::default()
        }
    }

    // PostToolUse responses

    /// Create a PostToolUse response that blocks with a reason
    #[allow(dead_code)]
    pub fn post_tool_block(reason: String) -> Self {
        Self {
            decision: Some(BlockDecision::Block),
            reason: Some(reason),
            hook_specific_output: Some(HookSpecificOutput::PostToolUse(PostToolUseOutput {
                hook_event_name: "PostToolUse".to_string(),
                additional_context: None,
            })),
            ..Self::default()
        }
    }

    /// Create a PostToolUse response with additional context
    #[allow(dead_code)]
    pub fn post_tool_with_context(context: String) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::PostToolUse(PostToolUseOutput {
                hook_event_name: "PostToolUse".to_string(),
                additional_context: Some(context),
            })),
            ..Self::default()
        }
    }

    // UserPromptSubmit responses

    /// Create a UserPromptSubmit response that blocks the prompt
    #[allow(dead_code)]
    pub fn prompt_block(reason: String) -> Self {
        Self {
            decision: Some(BlockDecision::Block),
            reason: Some(reason),
            hook_specific_output: Some(HookSpecificOutput::UserPromptSubmit(
                UserPromptSubmitOutput {
                    hook_event_name: "UserPromptSubmit".to_string(),
                    additional_context: None,
                },
            )),
            ..Self::default()
        }
    }

    /// Create a UserPromptSubmit response with additional context
    pub fn prompt_with_context(context: String) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::UserPromptSubmit(
                UserPromptSubmitOutput {
                    hook_event_name: "UserPromptSubmit".to_string(),
                    additional_context: Some(context),
                },
            )),
            ..Self::default()
        }
    }

    // SessionStart responses

    /// Create a SessionStart response with additional context
    pub fn session_start_with_context(context: String) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::SessionStart(SessionStartOutput {
                hook_event_name: "SessionStart".to_string(),
                additional_context: if context.is_empty() {
                    None
                } else {
                    Some(context)
                },
                env: None,
            })),
            ..Self::default()
        }
    }

    /// Create a SessionStart response with environment variables
    #[allow(dead_code)]
    pub fn session_start_with_env(env: HashMap<String, String>) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::SessionStart(SessionStartOutput {
                hook_event_name: "SessionStart".to_string(),
                additional_context: None,
                env: Some(env),
            })),
            ..Self::default()
        }
    }

    // SubagentStart responses

    /// Create a SubagentStart response with additional context
    #[allow(dead_code)]
    pub fn subagent_start_with_context(context: String) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::SubagentStart(SubagentStartOutput {
                hook_event_name: "SubagentStart".to_string(),
                additional_context: Some(context),
            })),
            ..Self::default()
        }
    }

    // Stop/SubagentStop responses

    /// Create a Stop response that blocks Claude from stopping (forces continuation)
    #[allow(dead_code)]
    pub fn stop_block(reason: String) -> Self {
        Self {
            decision: Some(BlockDecision::Block),
            reason: Some(reason),
            hook_specific_output: Some(HookSpecificOutput::Stop(StopOutput {
                hook_event_name: "Stop".to_string(),
                additional_context: None,
            })),
            ..Self::default()
        }
    }

    /// Create a SubagentStop response that blocks the subagent from stopping
    #[allow(dead_code)]
    pub fn subagent_stop_block(reason: String) -> Self {
        Self {
            decision: Some(BlockDecision::Block),
            reason: Some(reason),
            hook_specific_output: Some(HookSpecificOutput::Stop(StopOutput {
                hook_event_name: "SubagentStop".to_string(),
                additional_context: None,
            })),
            ..Self::default()
        }
    }

    // PostToolUseFailure responses

    /// Create a PostToolUseFailure response with additional context
    #[allow(dead_code)]
    pub fn post_tool_failure_with_context(context: String) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::PostToolUseFailure(
                PostToolUseFailureOutput {
                    hook_event_name: "PostToolUseFailure".to_string(),
                    additional_context: Some(context),
                },
            )),
            ..Self::default()
        }
    }

    // Builder methods

    /// Set suppress output flag
    #[allow(dead_code)]
    pub fn with_suppress_output(mut self) -> Self {
        self.suppress_output = true;
        self
    }

    /// Set system message
    #[allow(dead_code)]
    pub fn with_system_message(mut self, message: String) -> Self {
        self.system_message = Some(message);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_response_allow() {
        let response = HookResponse::allow();
        assert!(response.continue_execution);
        assert!(response.stop_reason.is_none());
        assert!(!response.suppress_output);
        assert!(response.system_message.is_none());
        assert!(response.decision.is_none());
    }

    #[test]
    fn test_hook_response_stop() {
        let response = HookResponse::stop("Test stop".to_string());
        assert!(!response.continue_execution);
        assert_eq!(response.stop_reason, Some("Test stop".to_string()));
    }

    #[test]
    fn test_hook_response_block() {
        let response = HookResponse::block("Test block".to_string());
        assert!(response.continue_execution);
        assert_eq!(response.decision, Some(BlockDecision::Block));
        assert_eq!(response.reason, Some("Test block".to_string()));
    }

    #[test]
    fn test_pre_tool_deny() {
        let response = HookResponse::pre_tool_deny("Not allowed".to_string());
        match response.hook_specific_output {
            Some(HookSpecificOutput::PreToolUse(output)) => {
                assert_eq!(output.permission_decision, Some(PermissionDecision::Deny));
                assert_eq!(
                    output.permission_decision_reason,
                    Some("Not allowed".to_string())
                );
            }
            _ => panic!("Expected PreToolUse output"),
        }
    }

    #[test]
    fn test_permission_deny() {
        let response = HookResponse::permission_deny("Denied by policy".to_string());
        match response.hook_specific_output {
            Some(HookSpecificOutput::PermissionRequest(output)) => {
                assert_eq!(output.decision.behavior, PermissionRequestBehavior::Deny);
                assert_eq!(
                    output.decision.message,
                    Some("Denied by policy".to_string())
                );
            }
            _ => panic!("Expected PermissionRequest output"),
        }
    }

    #[test]
    fn test_post_tool_with_context() {
        let response = HookResponse::post_tool_with_context("Additional info".to_string());
        match response.hook_specific_output {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                assert_eq!(
                    output.additional_context,
                    Some("Additional info".to_string())
                );
            }
            _ => panic!("Expected PostToolUse output"),
        }
    }

    #[test]
    fn test_prompt_block() {
        let response = HookResponse::prompt_block("Blocked prompt".to_string());
        assert_eq!(response.decision, Some(BlockDecision::Block));
        assert_eq!(response.reason, Some("Blocked prompt".to_string()));
    }

    #[test]
    fn test_session_start_with_context() {
        let response = HookResponse::session_start_with_context("Session context".to_string());
        match response.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(output)) => {
                assert_eq!(
                    output.additional_context,
                    Some("Session context".to_string())
                );
            }
            _ => panic!("Expected SessionStart output"),
        }
    }

    #[test]
    fn test_with_suppress_output() {
        let response = HookResponse::allow().with_suppress_output();
        assert!(response.suppress_output);
    }

    #[test]
    fn test_with_system_message() {
        let response = HookResponse::allow().with_system_message("Warning".to_string());
        assert_eq!(response.system_message, Some("Warning".to_string()));
    }

    #[test]
    fn test_json_serialization() {
        let response = HookResponse::pre_tool_deny("Not allowed".to_string());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("deny"));
    }

    #[test]
    fn test_json_serialization_minimal() {
        // Test that default values are not serialized
        let response = HookResponse::allow();
        let json = serde_json::to_string(&response).unwrap();
        // continue: true should be skipped
        assert!(!json.contains("continue"));
        // suppressOutput: false should be skipped
        assert!(!json.contains("suppressOutput"));
    }

    #[test]
    fn test_session_start_with_env() {
        let mut env = HashMap::new();
        env.insert("MY_VAR".to_string(), "my_value".to_string());
        let response = HookResponse::session_start_with_env(env);
        match response.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(output)) => {
                assert!(output.env.is_some());
                let env = output.env.unwrap();
                assert_eq!(env.get("MY_VAR"), Some(&"my_value".to_string()));
            }
            _ => panic!("Expected SessionStart output"),
        }
    }

    #[test]
    fn test_subagent_start_with_context() {
        let response = HookResponse::subagent_start_with_context("Follow guidelines".to_string());
        match response.hook_specific_output {
            Some(HookSpecificOutput::SubagentStart(output)) => {
                assert_eq!(output.hook_event_name, "SubagentStart");
                assert_eq!(
                    output.additional_context,
                    Some("Follow guidelines".to_string())
                );
            }
            _ => panic!("Expected SubagentStart output"),
        }
    }

    #[test]
    fn test_stop_block() {
        let response = HookResponse::stop_block("Must continue".to_string());
        assert_eq!(response.decision, Some(BlockDecision::Block));
        assert_eq!(response.reason, Some("Must continue".to_string()));
        match response.hook_specific_output {
            Some(HookSpecificOutput::Stop(output)) => {
                assert_eq!(output.hook_event_name, "Stop");
            }
            _ => panic!("Expected Stop output"),
        }
    }

    #[test]
    fn test_subagent_stop_block() {
        let response = HookResponse::subagent_stop_block("Subagent must continue".to_string());
        assert_eq!(response.decision, Some(BlockDecision::Block));
        assert_eq!(response.reason, Some("Subagent must continue".to_string()));
        match response.hook_specific_output {
            Some(HookSpecificOutput::Stop(output)) => {
                assert_eq!(output.hook_event_name, "SubagentStop");
            }
            _ => panic!("Expected Stop output"),
        }
    }

    #[test]
    fn test_post_tool_failure_with_context() {
        let response = HookResponse::post_tool_failure_with_context("Error info".to_string());
        match response.hook_specific_output {
            Some(HookSpecificOutput::PostToolUseFailure(output)) => {
                assert_eq!(output.hook_event_name, "PostToolUseFailure");
                assert_eq!(output.additional_context, Some("Error info".to_string()));
            }
            _ => panic!("Expected PostToolUseFailure output"),
        }
    }

    #[test]
    fn test_session_start_empty_context() {
        // Empty context should result in None, not Some("")
        let response = HookResponse::session_start_with_context("".to_string());
        match response.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(output)) => {
                assert!(output.additional_context.is_none());
            }
            _ => panic!("Expected SessionStart output"),
        }
    }
}
