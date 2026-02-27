//! Response types and utilities for Cursor hook handlers.
//!
//! This module contains the HookResponse structure and its associated
//! builder methods, used to respond to hook events from Cursor.
//!
//! The response format follows the Cursor hooks specification:
//! https://cursor.com/docs/agent/hooks

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Permission decision for before* hooks
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PermissionDecision {
    /// Allow the operation to proceed
    Allow,
    /// Deny the operation
    Deny,
    /// Ask the user to confirm
    Ask,
}

/// Response structure for beforeShellExecution and beforeMCPExecution hooks
#[derive(Debug, Serialize, Deserialize)]
pub struct BeforeExecutionResponse {
    /// Permission decision
    pub permission: PermissionDecision,
    /// Message shown in the client UI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
    /// Message sent to the agent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_message: Option<String>,
}

impl Default for BeforeExecutionResponse {
    fn default() -> Self {
        Self {
            permission: PermissionDecision::Allow,
            user_message: None,
            agent_message: None,
        }
    }
}

impl BeforeExecutionResponse {
    /// Create a response that allows the execution
    pub fn allow() -> Self {
        Self::default()
    }

    /// Create a response that denies the execution
    pub fn deny(user_message: impl Into<String>) -> Self {
        Self {
            permission: PermissionDecision::Deny,
            user_message: Some(user_message.into()),
            agent_message: None,
        }
    }

    /// Create a response that denies with both user and agent messages
    pub fn deny_with_agent_message(
        user_message: impl Into<String>,
        agent_message: impl Into<String>,
    ) -> Self {
        Self {
            permission: PermissionDecision::Deny,
            user_message: Some(user_message.into()),
            agent_message: Some(agent_message.into()),
        }
    }

    /// Create a response that asks the user to confirm
    pub fn ask(user_message: impl Into<String>) -> Self {
        Self {
            permission: PermissionDecision::Ask,
            user_message: Some(user_message.into()),
            agent_message: None,
        }
    }
}

/// Response structure for beforeTabFileRead hooks
#[derive(Debug, Serialize, Deserialize)]
pub struct BeforeTabFileReadResponse {
    /// Permission decision (only allow or deny for Tab)
    pub permission: PermissionDecision,
}

impl Default for BeforeTabFileReadResponse {
    fn default() -> Self {
        Self {
            permission: PermissionDecision::Allow,
        }
    }
}

impl BeforeTabFileReadResponse {
    /// Create a response that allows the file read
    pub fn allow() -> Self {
        Self::default()
    }

    /// Create a response that denies the file read
    pub fn deny() -> Self {
        Self {
            permission: PermissionDecision::Deny,
        }
    }
}

/// Response structure for beforeSubmitPrompt hooks
#[derive(Debug, Serialize, Deserialize)]
pub struct BeforeSubmitPromptResponse {
    /// Whether to allow the prompt submission to proceed
    #[serde(rename = "continue")]
    pub continue_execution: bool,
    /// Message shown to the user when the prompt is blocked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
}

impl Default for BeforeSubmitPromptResponse {
    fn default() -> Self {
        Self {
            continue_execution: true,
            user_message: None,
        }
    }
}

impl BeforeSubmitPromptResponse {
    /// Create a response that allows the prompt submission
    pub fn allow() -> Self {
        Self::default()
    }

    /// Create a response that blocks the prompt submission
    pub fn block(user_message: impl Into<String>) -> Self {
        Self {
            continue_execution: false,
            user_message: Some(user_message.into()),
        }
    }
}

/// Response structure for sessionStart hook
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStartResponse {
    /// Whether to allow the session to proceed
    #[serde(rename = "continue")]
    pub continue_execution: bool,
    /// Environment variables to inject into the session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    /// Additional context to inject into the conversation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
    /// Message shown to the user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
}

impl Default for SessionStartResponse {
    fn default() -> Self {
        Self {
            continue_execution: true,
            env: None,
            additional_context: None,
            user_message: None,
        }
    }
}

impl SessionStartResponse {
    /// Create a response that allows the session
    pub fn allow() -> Self {
        Self::default()
    }

    /// Create a response that blocks the session
    pub fn block(user_message: impl Into<String>) -> Self {
        Self {
            continue_execution: false,
            env: None,
            additional_context: None,
            user_message: Some(user_message.into()),
        }
    }
}

/// Response structure for subagentStart hook
#[derive(Debug, Serialize, Deserialize)]
pub struct SubagentStartResponse {
    /// Decision (allow or deny)
    pub decision: ToolUseDecision,
    /// Optional reason for the decision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Default for SubagentStartResponse {
    fn default() -> Self {
        Self {
            decision: ToolUseDecision::Allow,
            reason: None,
        }
    }
}

impl SubagentStartResponse {
    /// Create a response that allows the subagent
    pub fn allow() -> Self {
        Self::default()
    }

    /// Create a response that denies the subagent
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: ToolUseDecision::Deny,
            reason: Some(reason.into()),
        }
    }
}

/// Response structure for preCompact hook
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PreCompactResponse {
    /// Optional message to show the user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
}

impl PreCompactResponse {
    /// Create a response with no message
    pub fn ok() -> Self {
        Self::default()
    }
}

/// Response structure for stop hooks
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StopResponse {
    /// Optional follow-up message to auto-submit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub followup_message: Option<String>,
}

/// Decision for preToolUse hook
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ToolUseDecision {
    /// Allow the tool use to proceed
    Allow,
    /// Deny the tool use
    Deny,
}

/// Response structure for preToolUse hook
#[derive(Debug, Serialize, Deserialize)]
pub struct PreToolUseResponse {
    /// Decision (allow or deny)
    pub decision: ToolUseDecision,
    /// Optional reason for the decision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional updated input parameters (for modifying tool inputs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<serde_json::Value>,
}

impl Default for PreToolUseResponse {
    fn default() -> Self {
        Self {
            decision: ToolUseDecision::Allow,
            reason: None,
            updated_input: None,
        }
    }
}

impl PreToolUseResponse {
    /// Create a response that allows tool use
    pub fn allow(updated_input: Option<serde_json::Value>) -> Self {
        Self {
            decision: ToolUseDecision::Allow,
            reason: None,
            updated_input,
        }
    }

    /// Create a response that denies tool use
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: ToolUseDecision::Deny,
            reason: Some(reason.into()),
            updated_input: None,
        }
    }
}

impl StopResponse {
    /// Create a response with no follow-up
    pub fn done() -> Self {
        Self::default()
    }

    /// Create a response with a follow-up message
    #[allow(dead_code)]
    pub fn with_followup(message: impl Into<String>) -> Self {
        Self {
            followup_message: Some(message.into()),
        }
    }
}

/// Response structure for afterShellExecution, afterMCPExecution, afterFileEdit,
/// afterTabFileEdit, afterAgentResponse, and afterAgentThought hooks
/// These are observation-only hooks with no output
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
    /// Response for beforeShellExecution and beforeMCPExecution
    BeforeExecution(BeforeExecutionResponse),
    /// Response for beforeTabFileRead
    BeforeTabFileRead(BeforeTabFileReadResponse),
    /// Response for beforeSubmitPrompt
    BeforeSubmitPrompt(BeforeSubmitPromptResponse),
    /// Response for preToolUse
    PreToolUse(PreToolUseResponse),
    /// Response for sessionStart
    SessionStart(SessionStartResponse),
    /// Response for subagentStart
    SubagentStart(SubagentStartResponse),
    /// Response for preCompact
    PreCompact(PreCompactResponse),
    /// Response for stop hooks
    Stop(StopResponse),
    /// Response for observation-only hooks
    NoOutput(NoOutputResponse),
}

impl HookResponse {
    // ========================================================================
    // beforeShellExecution / beforeMCPExecution responses
    // ========================================================================

    /// Create a response that allows shell/MCP execution
    pub fn allow_execution() -> Self {
        Self::BeforeExecution(BeforeExecutionResponse::allow())
    }

    /// Create a response that denies shell/MCP execution
    pub fn deny_execution(user_message: impl Into<String>) -> Self {
        Self::BeforeExecution(BeforeExecutionResponse::deny(user_message))
    }

    /// Create a response that denies with agent message
    pub fn deny_execution_with_agent_message(
        user_message: impl Into<String>,
        agent_message: impl Into<String>,
    ) -> Self {
        Self::BeforeExecution(BeforeExecutionResponse::deny_with_agent_message(
            user_message,
            agent_message,
        ))
    }

    /// Create a response that asks user to confirm
    pub fn ask_execution(user_message: impl Into<String>) -> Self {
        Self::BeforeExecution(BeforeExecutionResponse::ask(user_message))
    }

    // ========================================================================
    // beforeTabFileRead responses
    // ========================================================================

    /// Create a response that allows Tab file read
    pub fn allow_tab_read() -> Self {
        Self::BeforeTabFileRead(BeforeTabFileReadResponse::allow())
    }

    /// Create a response that denies Tab file read
    pub fn deny_tab_read() -> Self {
        Self::BeforeTabFileRead(BeforeTabFileReadResponse::deny())
    }

    // ========================================================================
    // beforeSubmitPrompt responses
    // ========================================================================

    /// Create a response that allows prompt submission
    pub fn allow_prompt() -> Self {
        Self::BeforeSubmitPrompt(BeforeSubmitPromptResponse::allow())
    }

    /// Create a response that blocks prompt submission
    pub fn block_prompt(user_message: impl Into<String>) -> Self {
        Self::BeforeSubmitPrompt(BeforeSubmitPromptResponse::block(user_message))
    }

    // ========================================================================
    // preToolUse responses
    // ========================================================================

    /// Create a response that allows tool use
    pub fn allow_tool_use(updated_input: Option<serde_json::Value>) -> Self {
        Self::PreToolUse(PreToolUseResponse::allow(updated_input))
    }

    /// Create a response that denies tool use
    pub fn deny_tool_use(reason: impl Into<String>) -> Self {
        Self::PreToolUse(PreToolUseResponse::deny(reason))
    }

    // ========================================================================
    // stop responses
    // ========================================================================

    /// Create a response for stop hook with no follow-up
    pub fn stop_done() -> Self {
        Self::Stop(StopResponse::done())
    }

    /// Create a response for stop hook with follow-up message
    #[allow(dead_code)]
    pub fn stop_with_followup(message: impl Into<String>) -> Self {
        Self::Stop(StopResponse::with_followup(message))
    }

    // ========================================================================
    // Observation-only hook responses
    // ========================================================================

    /// Create an empty response for observation-only hooks
    pub fn ok() -> Self {
        Self::NoOutput(NoOutputResponse::ok())
    }

    // ========================================================================
    // Session responses
    // ========================================================================

    /// Create a response for sessionStart hook
    pub fn session_start_ok() -> Self {
        Self::SessionStart(SessionStartResponse::allow())
    }

    /// Create a response that blocks the session
    pub fn session_start_block(user_message: impl Into<String>) -> Self {
        Self::SessionStart(SessionStartResponse::block(user_message))
    }

    // ========================================================================
    // beforeReadFile responses
    // ========================================================================

    /// Create a response that allows file read
    pub fn allow_read_file() -> Self {
        Self::BeforeExecution(BeforeExecutionResponse::allow())
    }

    /// Create a response that denies file read
    pub fn deny_read_file(user_message: impl Into<String>) -> Self {
        Self::BeforeExecution(BeforeExecutionResponse::deny(user_message))
    }

    // ========================================================================
    // Subagent responses
    // ========================================================================

    /// Create a response that allows subagent creation
    pub fn subagent_start_allow() -> Self {
        Self::SubagentStart(SubagentStartResponse::allow())
    }

    /// Create a response that denies subagent creation
    pub fn subagent_start_deny(reason: impl Into<String>) -> Self {
        Self::SubagentStart(SubagentStartResponse::deny(reason))
    }

    /// Create a response for subagent stop
    pub fn subagent_stop_done() -> Self {
        Self::Stop(StopResponse::done())
    }

    // ========================================================================
    // preCompact response
    // ========================================================================

    /// Create a response for preCompact hook
    pub fn pre_compact_ok() -> Self {
        Self::PreCompact(PreCompactResponse::ok())
    }
}

impl HookResponse {
    /// Returns true if this response blocks/denies the action.
    ///
    /// Cursor uses process exit code 2 to enforce blocks, so callers
    /// should check this and exit accordingly.
    pub fn is_deny(&self) -> bool {
        match self {
            Self::BeforeExecution(r) => r.permission == PermissionDecision::Deny,
            Self::BeforeTabFileRead(r) => r.permission == PermissionDecision::Deny,
            Self::BeforeSubmitPrompt(r) => !r.continue_execution,
            Self::PreToolUse(r) => r.decision == ToolUseDecision::Deny,
            Self::SessionStart(r) => !r.continue_execution,
            Self::SubagentStart(r) => r.decision == ToolUseDecision::Deny,
            Self::Stop(_) | Self::PreCompact(_) | Self::NoOutput(_) => false,
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

    #[test]
    fn test_before_execution_allow() {
        let response = BeforeExecutionResponse::allow();
        assert_eq!(response.permission, PermissionDecision::Allow);
        assert!(response.user_message.is_none());
    }

    #[test]
    fn test_before_execution_deny() {
        let response = BeforeExecutionResponse::deny("Not allowed");
        assert_eq!(response.permission, PermissionDecision::Deny);
        assert_eq!(response.user_message, Some("Not allowed".to_string()));
    }

    #[test]
    fn test_before_execution_ask() {
        let response = BeforeExecutionResponse::ask("Please confirm");
        assert_eq!(response.permission, PermissionDecision::Ask);
        assert_eq!(response.user_message, Some("Please confirm".to_string()));
    }

    #[test]
    fn test_before_submit_prompt_allow() {
        let response = BeforeSubmitPromptResponse::allow();
        assert!(response.continue_execution);
        assert!(response.user_message.is_none());
    }

    #[test]
    fn test_before_submit_prompt_block() {
        let response = BeforeSubmitPromptResponse::block("Blocked by policy");
        assert!(!response.continue_execution);
        assert_eq!(response.user_message, Some("Blocked by policy".to_string()));
    }

    #[test]
    fn test_stop_done() {
        let response = StopResponse::done();
        assert!(response.followup_message.is_none());
    }

    #[test]
    fn test_stop_with_followup() {
        let response = StopResponse::with_followup("Continue with next task");
        assert_eq!(
            response.followup_message,
            Some("Continue with next task".to_string())
        );
    }

    #[test]
    fn test_hook_response_serialization() {
        let response = HookResponse::deny_execution("Not allowed by policy");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("permission"));
        assert!(json.contains("deny"));
        assert!(json.contains("Not allowed by policy"));
    }

    #[test]
    fn test_before_submit_prompt_serialization() {
        let response = HookResponse::block_prompt("Sensitive content detected");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("continue"));
        assert!(json.contains("false"));
        assert!(json.contains("Sensitive content detected"));
    }

    #[test]
    fn test_stop_response_serialization() {
        let response = HookResponse::stop_with_followup("Run tests");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("followup_message"));
        assert!(json.contains("Run tests"));
    }

    #[test]
    fn test_empty_response_serialization() {
        let response = HookResponse::ok();
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_tab_file_read_responses() {
        let allow = HookResponse::allow_tab_read();
        let deny = HookResponse::deny_tab_read();

        let allow_json = serde_json::to_string(&allow).unwrap();
        let deny_json = serde_json::to_string(&deny).unwrap();

        assert!(allow_json.contains("allow"));
        assert!(deny_json.contains("deny"));
    }
}
