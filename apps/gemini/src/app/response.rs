//! Response types and utilities for Gemini CLI hook handlers.
//!
//! This module contains the GeminiHookResponse structure and its associated
//! builder methods, used to respond to hook events from Gemini CLI.
//!
//! Gemini CLI uses a universal response format where all hooks can receive
//! the same response structure, with hook-specific output in a dedicated field.
//!
//! Reference: https://geminicli.com/docs/hooks/reference

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Decision for hooks that support allow/deny
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Allow the operation to proceed
    Allow,
    /// Deny the operation (alias: "block")
    Deny,
    /// Block the operation (alias for Deny)
    Block,
}

/// Tool configuration for BeforeToolSelection response
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ToolConfig {
    /// Tool selection mode: "AUTO", "ANY", or "NONE"
    /// - "NONE": Disables all tools (wins over other hooks)
    /// - "ANY": Forces at least one tool call
    /// - "AUTO": Automatic tool selection (default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Whitelist of tool names. Multiple hooks' whitelists are combined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_function_names: Option<Vec<String>>,
}

impl ToolConfig {
    /// Create a ToolConfig that allows all tools automatically
    pub fn auto() -> Self {
        Self {
            mode: Some("AUTO".to_string()),
            allowed_function_names: None,
        }
    }

    /// Create a ToolConfig that allows any tools
    pub fn any() -> Self {
        Self {
            mode: Some("ANY".to_string()),
            allowed_function_names: None,
        }
    }

    /// Create a ToolConfig that disables all tools
    pub fn none() -> Self {
        Self {
            mode: Some("NONE".to_string()),
            allowed_function_names: None,
        }
    }

    /// Create a ToolConfig with a specific list of allowed tools
    pub fn with_allowed_tools(tools: Vec<String>) -> Self {
        Self {
            mode: Some("AUTO".to_string()),
            allowed_function_names: Some(tools),
        }
    }
}

/// Hook-specific output for specialized responses
///
/// Different hooks use different fields within this structure:
/// - BeforeAgent/SessionStart: `additionalContext`
/// - AfterAgent: `clearContext`
/// - BeforeModel: `llm_request` (override), `llm_response` (synthetic/mock)
/// - AfterModel: `llm_response` (replacement)
/// - BeforeToolSelection: `toolConfig`
/// - BeforeTool: `tool_input` (merge/override)
/// - AfterTool: `additionalContext`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    /// Additional context to append to prompt/tool result (BeforeAgent, AfterTool, SessionStart)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
    /// If true, clears conversation history while preserving UI display (AfterAgent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clear_context: Option<bool>,
    /// Modified tool input that merges with and overrides model's arguments (BeforeTool)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_input: Option<Value>,
    /// Tool configuration (BeforeToolSelection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_config: Option<ToolConfig>,
    /// Override parts of the outgoing LLM request (BeforeModel)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_request: Option<Value>,
    /// Synthetic/mock response to skip LLM call (BeforeModel) or
    /// replacement response chunk (AfterModel)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_response: Option<Value>,
}

/// Universal response structure for Gemini CLI hooks
///
/// Gemini CLI uses a single response format for all hooks, where different
/// fields are relevant for different hook types:
/// - Decision hooks (BeforeAgent, BeforeModel, BeforeTool, AfterAgent, AfterModel): use `decision` and `reason`
/// - Advisory hooks (SessionStart/End, PreCompress, Notification): typically return empty or just systemMessage
/// - Tool selection hooks (BeforeToolSelection): use `hookSpecificOutput.toolConfig`
///
/// Reference: https://geminicli.com/docs/hooks/reference#common-output-fields
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GeminiHookResponse {
    /// Decision to allow or deny (for decision hooks).
    /// "allow" proceeds normally, "deny" (or "block") blocks the operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    /// Feedback/error message when decision is "deny".
    /// For BeforeTool: sent to the agent as a tool error.
    /// For AfterAgent: sent to the agent as a new prompt to request correction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Displayed immediately to the user in the terminal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_message: Option<String>,
    /// If true, hides internal hook metadata from logs/telemetry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppress_output: Option<bool>,
    /// If false, stops the entire agent loop immediately.
    #[serde(rename = "continue", skip_serializing_if = "Option::is_none")]
    pub continue_execution: Option<bool>,
    /// Displayed to the user when `continue` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    /// Hook-specific output for specialized responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<HookSpecificOutput>,
}

impl GeminiHookResponse {
    // ========================================================================
    // Decision responses (for BeforeAgent, BeforeModel, BeforeTool)
    // ========================================================================

    /// Create a response that allows the operation
    pub fn allow() -> Self {
        Self {
            decision: Some(Decision::Allow),
            ..Default::default()
        }
    }

    /// Create a response that denies the operation
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: Some(Decision::Deny),
            reason: Some(reason.into()),
            ..Default::default()
        }
    }

    /// Create a response that denies with a system message
    pub fn deny_with_message(reason: impl Into<String>, system_message: impl Into<String>) -> Self {
        Self {
            decision: Some(Decision::Deny),
            reason: Some(reason.into()),
            system_message: Some(system_message.into()),
            ..Default::default()
        }
    }

    // ========================================================================
    // Advisory responses (for SessionStart, SessionEnd, AfterAgent, etc.)
    // ========================================================================

    /// Create an empty response for advisory hooks
    pub fn ok() -> Self {
        Self::default()
    }

    /// Create a response with just a system message
    pub fn with_system_message(message: impl Into<String>) -> Self {
        Self {
            system_message: Some(message.into()),
            ..Default::default()
        }
    }

    // ========================================================================
    // Tool selection responses (for BeforeToolSelection)
    // ========================================================================

    /// Create a response that allows all tools automatically
    pub fn allow_all_tools() -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput {
                tool_config: Some(ToolConfig::auto()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Create a response that disables all tools via toolConfig.
    /// BeforeToolSelection does not support `decision` or `systemMessage`,
    /// so we only set `hookSpecificOutput.toolConfig`.
    pub fn disable_all_tools(_reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput {
                tool_config: Some(ToolConfig::none()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Create a response that allows only specific tools
    pub fn allow_tools(tools: Vec<String>) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput {
                tool_config: Some(ToolConfig::with_allowed_tools(tools)),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // ========================================================================
    // Tool input modification (for BeforeTool)
    // ========================================================================

    /// Create a response that allows with modified tool input
    pub fn allow_with_modified_input(tool_input: Value) -> Self {
        Self {
            decision: Some(Decision::Allow),
            hook_specific_output: Some(HookSpecificOutput {
                tool_input: Some(tool_input),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // ========================================================================
    // AfterAgent specific responses
    // ========================================================================

    /// Create a response that rejects the agent response and forces a retry
    /// The reason is sent to the agent as a new prompt to request correction.
    pub fn retry(feedback: impl Into<String>) -> Self {
        Self {
            decision: Some(Decision::Deny),
            reason: Some(feedback.into()),
            ..Default::default()
        }
    }

    /// Create a response that clears the conversation context
    pub fn clear_context() -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput {
                clear_context: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // ========================================================================
    // BeforeModel specific responses
    // ========================================================================

    /// Create a response that modifies the LLM request
    pub fn with_llm_request_override(llm_request: Value) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput {
                llm_request: Some(llm_request),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Create a synthetic/mock response that skips the LLM call entirely
    pub fn mock_llm_response(llm_response: Value) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput {
                llm_response: Some(llm_response),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // ========================================================================
    // AfterModel specific responses
    // ========================================================================

    /// Create a response that replaces the model's response chunk
    pub fn replace_llm_response(llm_response: Value) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput {
                llm_response: Some(llm_response),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    // ========================================================================
    // Stop/halt responses
    // ========================================================================

    /// Create a response that stops the entire agent loop immediately
    pub fn stop(reason: impl Into<String>) -> Self {
        Self {
            continue_execution: Some(false),
            stop_reason: Some(reason.into()),
            ..Default::default()
        }
    }

    // ========================================================================
    // Builder methods
    // ========================================================================

    /// Add a system message to the response
    pub fn with_system_msg(mut self, message: impl Into<String>) -> Self {
        self.system_message = Some(message.into());
        self
    }

    /// Set suppress_output flag
    pub fn suppress(mut self) -> Self {
        self.suppress_output = Some(true);
        self
    }

    /// Set continue_execution flag
    pub fn with_continue(mut self, cont: bool) -> Self {
        self.continue_execution = Some(cont);
        self
    }

    /// Set stop_reason (used when continue is false)
    pub fn with_stop_reason(mut self, reason: impl Into<String>) -> Self {
        self.stop_reason = Some(reason.into());
        self
    }

    /// Add additional context (appended to prompt/tool result)
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        let output = self
            .hook_specific_output
            .get_or_insert_with(Default::default);
        output.additional_context = Some(context.into());
        self
    }

    /// Add LLM request override
    pub fn with_llm_request(mut self, llm_request: Value) -> Self {
        let output = self
            .hook_specific_output
            .get_or_insert_with(Default::default);
        output.llm_request = Some(llm_request);
        self
    }

    /// Add LLM response (synthetic for BeforeModel, replacement for AfterModel)
    pub fn with_llm_response(mut self, llm_response: Value) -> Self {
        let output = self
            .hook_specific_output
            .get_or_insert_with(Default::default);
        output.llm_response = Some(llm_response);
        self
    }

    /// Set clear_context flag (AfterAgent)
    pub fn with_clear_context(mut self, clear: bool) -> Self {
        let output = self
            .hook_specific_output
            .get_or_insert_with(Default::default);
        output.clear_context = Some(clear);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_response() {
        let response = GeminiHookResponse::allow();
        assert_eq!(response.decision, Some(Decision::Allow));
        assert!(response.reason.is_none());
    }

    #[test]
    fn test_deny_response() {
        let response = GeminiHookResponse::deny("Not allowed by policy");
        assert_eq!(response.decision, Some(Decision::Deny));
        assert_eq!(response.reason, Some("Not allowed by policy".to_string()));
    }

    #[test]
    fn test_deny_with_message() {
        let response =
            GeminiHookResponse::deny_with_message("Denied", "Please use a different approach");
        assert_eq!(response.decision, Some(Decision::Deny));
        assert_eq!(response.reason, Some("Denied".to_string()));
        assert_eq!(
            response.system_message,
            Some("Please use a different approach".to_string())
        );
    }

    #[test]
    fn test_ok_response() {
        let response = GeminiHookResponse::ok();
        assert!(response.decision.is_none());
        assert!(response.reason.is_none());
    }

    #[test]
    fn test_system_message_response() {
        let response = GeminiHookResponse::with_system_message("Session started");
        assert_eq!(response.system_message, Some("Session started".to_string()));
    }

    #[test]
    fn test_allow_all_tools() {
        let response = GeminiHookResponse::allow_all_tools();
        assert!(response.hook_specific_output.is_some());
        let output = response.hook_specific_output.unwrap();
        assert!(output.tool_config.is_some());
        assert_eq!(output.tool_config.unwrap().mode, Some("AUTO".to_string()));
    }

    #[test]
    fn test_disable_all_tools() {
        let response = GeminiHookResponse::disable_all_tools("Tools disabled by policy");
        // BeforeToolSelection does not support `decision`, only `toolConfig`
        assert!(response.decision.is_none());
        assert!(response.hook_specific_output.is_some());
        let output = response.hook_specific_output.unwrap();
        assert_eq!(output.tool_config.unwrap().mode, Some("NONE".to_string()));
    }

    #[test]
    fn test_allow_specific_tools() {
        let response = GeminiHookResponse::allow_tools(vec![
            "read_file".to_string(),
            "write_file".to_string(),
        ]);
        assert!(response.hook_specific_output.is_some());
        let output = response.hook_specific_output.unwrap();
        let config = output.tool_config.unwrap();
        assert_eq!(config.mode, Some("AUTO".to_string()));
        assert_eq!(
            config.allowed_function_names,
            Some(vec!["read_file".to_string(), "write_file".to_string()])
        );
    }

    #[test]
    fn test_allow_serialization() {
        let response = GeminiHookResponse::allow();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("allow"));
    }

    #[test]
    fn test_deny_serialization() {
        let response = GeminiHookResponse::deny("Blocked by policy");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("deny"));
        assert!(json.contains("Blocked by policy"));
    }

    #[test]
    fn test_empty_response_serialization() {
        let response = GeminiHookResponse::ok();
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_continue_field_serialization() {
        let response = GeminiHookResponse::ok().with_continue(true);
        let json = serde_json::to_string(&response).unwrap();
        // JSON field should be "continue", not "continue_execution"
        assert!(json.contains("\"continue\""));
        assert!(!json.contains("continue_execution"));
    }

    #[test]
    fn test_builder_methods() {
        let response = GeminiHookResponse::allow()
            .with_system_msg("Additional info")
            .with_context("Context data")
            .suppress();

        assert_eq!(response.decision, Some(Decision::Allow));
        assert_eq!(response.system_message, Some("Additional info".to_string()));
        assert_eq!(response.suppress_output, Some(true));
        assert!(response.hook_specific_output.is_some());
        assert_eq!(
            response.hook_specific_output.unwrap().additional_context,
            Some("Context data".to_string())
        );
    }

    #[test]
    fn test_tool_config_modes() {
        let auto = ToolConfig::auto();
        assert_eq!(auto.mode, Some("AUTO".to_string()));

        let any = ToolConfig::any();
        assert_eq!(any.mode, Some("ANY".to_string()));

        let none = ToolConfig::none();
        assert_eq!(none.mode, Some("NONE".to_string()));
    }

    #[test]
    fn test_retry_response() {
        let response = GeminiHookResponse::retry("Please fix the syntax error");
        assert_eq!(response.decision, Some(Decision::Deny));
        assert_eq!(
            response.reason,
            Some("Please fix the syntax error".to_string())
        );
    }

    #[test]
    fn test_clear_context_response() {
        let response = GeminiHookResponse::clear_context();
        assert!(response.hook_specific_output.is_some());
        let output = response.hook_specific_output.unwrap();
        assert_eq!(output.clear_context, Some(true));
    }

    #[test]
    fn test_stop_response() {
        let response = GeminiHookResponse::stop("Security violation detected");
        assert_eq!(response.continue_execution, Some(false));
        assert_eq!(
            response.stop_reason,
            Some("Security violation detected".to_string())
        );
    }

    #[test]
    fn test_stop_reason_serialization() {
        let response = GeminiHookResponse::stop("Critical error");
        let json = serde_json::to_string(&response).unwrap();
        // Verify camelCase serialization
        assert!(json.contains("\"stopReason\""));
        assert!(json.contains("Critical error"));
    }

    #[test]
    fn test_mock_llm_response() {
        let mock_response = serde_json::json!({
            "content": "This is a mocked response"
        });
        let response = GeminiHookResponse::mock_llm_response(mock_response.clone());
        assert!(response.hook_specific_output.is_some());
        let output = response.hook_specific_output.unwrap();
        assert_eq!(output.llm_response, Some(mock_response));
    }

    #[test]
    fn test_llm_request_override() {
        let override_request = serde_json::json!({
            "model": "gemini-2.0-flash"
        });
        let response = GeminiHookResponse::with_llm_request_override(override_request.clone());
        assert!(response.hook_specific_output.is_some());
        let output = response.hook_specific_output.unwrap();
        assert_eq!(output.llm_request, Some(override_request));
    }

    #[test]
    fn test_camel_case_serialization() {
        let response = GeminiHookResponse::ok()
            .with_system_msg("Test")
            .with_clear_context(true);
        let json = serde_json::to_string(&response).unwrap();
        // Verify camelCase field names
        assert!(json.contains("\"systemMessage\""));
        assert!(json.contains("\"hookSpecificOutput\""));
        assert!(json.contains("\"clearContext\""));
        // Should not contain snake_case
        assert!(!json.contains("system_message"));
        assert!(!json.contains("hook_specific_output"));
        assert!(!json.contains("clear_context"));
    }

    #[test]
    fn test_tool_config_camel_case_serialization() {
        let response = GeminiHookResponse::allow_tools(vec!["read_file".to_string()]);
        let json = serde_json::to_string(&response).unwrap();
        // Verify camelCase field names
        assert!(json.contains("\"toolConfig\""));
        assert!(json.contains("\"allowedFunctionNames\""));
    }
}
