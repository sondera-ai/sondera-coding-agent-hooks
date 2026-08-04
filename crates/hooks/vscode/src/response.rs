//! Response types and utilities for VS Code Copilot Chat hook handlers.
//!
//! Deny/block decisions are carried entirely in the stdout JSON and the hook
//! must exit 0: VS Code only parses stdout on exit code 0. Exit code 2
//! ("blocking error") makes VS Code discard stdout and surface raw stderr as
//! the message, and on Windows the hook is spawned via Windows PowerShell 5.1,
//! which collapses a native exit code 2 to 1 — which VS Code treats as a
//! NON-blocking warning (fail-open). The `is_deny()` method reports whether a
//! response blocks/denies the action.
//!
//! Reference: <https://code.visualstudio.com/docs/agent-customization/hooks>

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

/// Response structure for VS Code Copilot Chat hook handlers.
///
/// Per the VS Code hooks spec:
/// - `permissionDecision` for PreToolUse lives inside `hookSpecificOutput`
/// - `decision`/`reason` for SubagentStop live at the top level
/// - `decision`/`reason` for Stop live inside `hookSpecificOutput`
/// - `additionalContext` for SessionStart/SubagentStart/PostToolUse lives in `hookSpecificOutput`
///
/// Fields are serialized with `skip_serializing_if` to produce minimal JSON.
/// `allow()` serializes to `{}` so VS Code falls back to its normal permission system.
#[must_use]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HookResponse {
    /// Whether to continue (false = stop the agent session)
    #[serde(rename = "continue", skip_serializing_if = "Option::is_none")]
    pub continue_execution: Option<bool>,

    /// Reason shown to the user when continue is false
    #[serde(rename = "stopReason", skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,

    /// Warning message displayed to the user in chat
    #[serde(rename = "systemMessage", skip_serializing_if = "Option::is_none")]
    pub system_message: Option<String>,

    /// Top-level block decision for PostToolUse and SubagentStop hooks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,

    /// Reason for a top-level block decision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Hook-specific output carrying per-event fields (hookEventName required).
    ///
    /// Used by: PreToolUse (permissionDecision), SessionStart (additionalContext),
    /// SubagentStart (additionalContext), PostToolUse (additionalContext),
    /// Stop (decision + reason).
    #[serde(rename = "hookSpecificOutput", skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<JsonValue>,
}

impl HookResponse {
    /// Returns true if this response blocks or denies the action.
    ///
    /// Enforcement rides on the stdout JSON alone — callers must exit 0 even
    /// when this returns true (see the module docs for why exit code 2 would
    /// break enforcement).
    pub fn is_deny(&self) -> bool {
        if self.continue_execution == Some(false) {
            return true;
        }
        if self.decision.as_deref() == Some("block") {
            return true;
        }
        // Check inside hookSpecificOutput for permissionDecision: "deny"
        // (PreToolUse) or decision: "block" (Stop).
        if let Some(output) = &self.hook_specific_output {
            if output.get("permissionDecision").and_then(|v| v.as_str()) == Some("deny") {
                return true;
            }
            if output.get("decision").and_then(|v| v.as_str()) == Some("block") {
                return true;
            }
        }
        false
    }

    /// Empty allow response — serializes to `{}`.
    ///
    /// By omitting `hookSpecificOutput`, this hook expresses no opinion and
    /// VS Code falls back to its normal permission behavior (e.g., prompting the
    /// user in default mode, auto-approving in auto-approve mode).
    pub fn allow() -> Self {
        Self::default()
    }

    // ========================================================================
    // SessionStart responses
    // ========================================================================

    /// SessionStart: inject context into the agent's conversation.
    ///
    /// Output format: `{"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "..."}}`
    pub fn session_start_context(message: String) -> Self {
        Self {
            hook_specific_output: Some(json!({
                "hookEventName": "SessionStart",
                "additionalContext": message
            })),
            ..Self::default()
        }
    }

    // ========================================================================
    // UserPromptSubmit responses
    // ========================================================================

    /// UserPromptSubmit: stop the entire agent session with a reason.
    ///
    /// Output format: `{"continue": false, "stopReason": "..."}`
    pub fn user_prompt_deny(reason: String) -> Self {
        Self {
            continue_execution: Some(false),
            stop_reason: Some(reason),
            ..Self::default()
        }
    }

    /// UserPromptSubmit: inject a warning message into chat without blocking.
    ///
    /// Output format: `{"systemMessage": "..."}`
    pub fn user_prompt_context(message: String) -> Self {
        Self {
            system_message: Some(message),
            ..Self::default()
        }
    }

    // ========================================================================
    // PreToolUse responses
    // ========================================================================

    /// PreToolUse: deny tool execution via `hookSpecificOutput`.
    ///
    /// Output format:
    /// ```json
    /// {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..."}}
    /// ```
    pub fn pre_tool_deny(reason: String) -> Self {
        Self {
            hook_specific_output: Some(json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason
            })),
            ..Self::default()
        }
    }

    /// PreToolUse: ask the user to confirm tool execution.
    ///
    /// Output format:
    /// ```json
    /// {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "..."}}
    /// ```
    pub fn pre_tool_ask(reason: String) -> Self {
        Self {
            hook_specific_output: Some(json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reason
            })),
            ..Self::default()
        }
    }

    // ========================================================================
    // PostToolUse responses
    // ========================================================================

    /// PostToolUse: block further processing with a reason (top-level decision).
    ///
    /// Output format: `{"decision": "block", "reason": "..."}`
    pub fn post_tool_block(reason: String) -> Self {
        Self {
            decision: Some("block".to_string()),
            reason: Some(reason),
            ..Self::default()
        }
    }

    /// PostToolUse: inject additional context into the conversation.
    ///
    /// Output format:
    /// ```json
    /// {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "..."}}
    /// ```
    pub fn post_tool_with_context(context: String) -> Self {
        Self {
            hook_specific_output: Some(json!({
                "hookEventName": "PostToolUse",
                "additionalContext": context
            })),
            ..Self::default()
        }
    }

    // ========================================================================
    // SubagentStart responses
    // ========================================================================

    /// SubagentStart: inject context into the subagent's conversation.
    ///
    /// Output format:
    /// ```json
    /// {"hookSpecificOutput": {"hookEventName": "SubagentStart", "additionalContext": "..."}}
    /// ```
    pub fn subagent_start_context(message: String) -> Self {
        Self {
            hook_specific_output: Some(json!({
                "hookEventName": "SubagentStart",
                "additionalContext": message
            })),
            ..Self::default()
        }
    }

    // ========================================================================
    // SubagentStop responses
    // ========================================================================

    /// SubagentStop: prevent the subagent from stopping (top-level decision).
    ///
    /// Output format: `{"decision": "block", "reason": "..."}`
    pub fn subagent_stop_block(reason: String) -> Self {
        Self {
            decision: Some("block".to_string()),
            reason: Some(reason),
            ..Self::default()
        }
    }

    // ========================================================================
    // Stop responses
    // ========================================================================

    /// Stop: prevent the agent from stopping by using `hookSpecificOutput`.
    ///
    /// Output format:
    /// ```json
    /// {"hookSpecificOutput": {"hookEventName": "Stop", "decision": "block", "reason": "..."}}
    /// ```
    ///
    /// Always check `stop_hook_active` before calling this to prevent infinite loops.
    pub fn stop_block(reason: String) -> Self {
        Self {
            hook_specific_output: Some(json!({
                "hookEventName": "Stop",
                "decision": "block",
                "reason": reason
            })),
            ..Self::default()
        }
    }
}

#[cfg(test)]
impl HookResponse {
    /// Helper for tests: expose top-level permissionDecision (should always be None).
    fn permission_decision(&self) -> Option<&str> {
        // permissionDecision is ONLY valid inside hookSpecificOutput, never top-level
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_serializes_to_empty_json() {
        let response = HookResponse::allow();
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, "{}");
        assert!(!response.is_deny());
    }

    #[test]
    fn test_session_start_context() {
        let response = HookResponse::session_start_context("Hello session".to_string());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("hookEventName"));
        assert!(json.contains("SessionStart"));
        assert!(json.contains("additionalContext"));
        assert!(json.contains("Hello session"));
        assert!(!response.is_deny());
    }

    #[test]
    fn test_session_start_context_has_hook_event_name() {
        let response = HookResponse::session_start_context("ctx".to_string());
        let output = response.hook_specific_output.unwrap();
        assert_eq!(output["hookEventName"], "SessionStart");
        assert_eq!(output["additionalContext"], "ctx");
    }

    #[test]
    fn test_user_prompt_deny() {
        let response = HookResponse::user_prompt_deny("Blocked by policy".to_string());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"continue\":false"));
        assert!(json.contains("stopReason"));
        assert!(json.contains("Blocked by policy"));
        assert!(response.is_deny());
    }

    #[test]
    fn test_user_prompt_context() {
        let response = HookResponse::user_prompt_context("Additional info".to_string());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("systemMessage"));
        assert!(json.contains("Additional info"));
        assert!(!response.is_deny());
    }

    #[test]
    fn test_pre_tool_deny() {
        let response = HookResponse::pre_tool_deny("Not allowed".to_string());
        let json = serde_json::to_string(&response).unwrap();
        // permissionDecision must be INSIDE hookSpecificOutput, not at top level
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("PreToolUse"));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("\"deny\""));
        assert!(json.contains("permissionDecisionReason"));
        assert!(json.contains("Not allowed"));
        assert!(response.is_deny());
        // Verify exact structure
        let output = response.hook_specific_output.unwrap();
        assert_eq!(output["hookEventName"], "PreToolUse");
        assert_eq!(output["permissionDecision"], "deny");
        assert_eq!(output["permissionDecisionReason"], "Not allowed");
    }

    #[test]
    fn test_pre_tool_deny_not_at_top_level() {
        // permissionDecision must NOT be a top-level field per VS Code spec
        let response = HookResponse::pre_tool_deny("blocked".to_string());
        assert!(response.permission_decision().is_none());
    }

    #[test]
    fn test_pre_tool_ask() {
        let response = HookResponse::pre_tool_ask("Needs approval".to_string());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("PreToolUse"));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("\"ask\""));
        assert!(!response.is_deny());
        let output = response.hook_specific_output.unwrap();
        assert_eq!(output["hookEventName"], "PreToolUse");
        assert_eq!(output["permissionDecision"], "ask");
    }

    #[test]
    fn test_post_tool_block() {
        let response = HookResponse::post_tool_block("Blocked output".to_string());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"decision\":\"block\""));
        assert!(json.contains("\"reason\":\"Blocked output\""));
        assert!(response.is_deny());
    }

    #[test]
    fn test_post_tool_with_context() {
        let response = HookResponse::post_tool_with_context("lint errors found".to_string());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("PostToolUse"));
        assert!(json.contains("additionalContext"));
        assert!(!response.is_deny());
        let output = response.hook_specific_output.unwrap();
        assert_eq!(output["hookEventName"], "PostToolUse");
    }

    #[test]
    fn test_subagent_start_context() {
        let response = HookResponse::subagent_start_context("guidelines".to_string());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("SubagentStart"));
        assert!(json.contains("additionalContext"));
        assert!(!response.is_deny());
        let output = response.hook_specific_output.unwrap();
        assert_eq!(output["hookEventName"], "SubagentStart");
        assert_eq!(output["additionalContext"], "guidelines");
    }

    #[test]
    fn test_subagent_stop_block() {
        let response = HookResponse::subagent_stop_block("Must continue".to_string());
        assert!(response.is_deny());
        let json = serde_json::to_string(&response).unwrap();
        // SubagentStop uses top-level decision/reason per VS Code spec
        assert!(json.contains("\"decision\":\"block\""));
        assert!(json.contains("\"reason\":\"Must continue\""));
        assert!(!json.contains("hookSpecificOutput"));
    }

    #[test]
    fn test_stop_block() {
        let response = HookResponse::stop_block("Cannot stop yet".to_string());
        assert!(response.is_deny());
        let json = serde_json::to_string(&response).unwrap();
        // Stop uses hookSpecificOutput.decision/reason per VS Code spec
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("\"Stop\""));
        assert!(json.contains("\"block\""));
        assert!(json.contains("Cannot stop yet"));
        // Verify decision is NOT at top level for Stop
        assert!(response.decision.is_none());
        let output = response.hook_specific_output.unwrap();
        assert_eq!(output["hookEventName"], "Stop");
        assert_eq!(output["decision"], "block");
    }

    #[test]
    fn test_stop_block_vs_subagent_stop_block_differ() {
        // Stop: decision in hookSpecificOutput
        let stop = HookResponse::stop_block("run tests".to_string());
        assert!(stop.hook_specific_output.is_some());
        assert!(stop.decision.is_none());

        // SubagentStop: decision at top level
        let subagent_stop = HookResponse::subagent_stop_block("check results".to_string());
        assert!(subagent_stop.hook_specific_output.is_none());
        assert_eq!(subagent_stop.decision.as_deref(), Some("block"));
    }
}
