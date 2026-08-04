//! Response types and utilities for OpenAI Codex CLI hook handlers.
//!
//! This module contains the HookResponse structure and its associated
//! builder methods, used to respond to hook events from Codex CLI.
//!
//! CRITICAL DESIGN RULES:
//! - Allow = `{}` (empty JSON). Never serialize `permissionDecision: "allow"`
//!   explicitly, as this bypasses Codex's normal permission system.
//! - Deny uses the `hookSpecificOutput` wrapper format for PreToolUse, and
//!   the flat `decision`/`reason` format for other blockable events.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ============================================================================
// hookSpecificOutput types (PreToolUse deny format)
// ============================================================================

/// The `hookSpecificOutput` wrapper used for PreToolUse deny responses.
#[must_use]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseHookOutput {
    /// Must be "PreToolUse"
    pub hook_event_name: String,
    /// "deny" to block, "ask" to preserve normal permission UI
    pub permission_decision: String,
    /// Reason shown to the user when blocking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    /// Rewrite tool input before execution (not used by our adapter)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<serde_json::Value>,
}

/// Response structure wrapping hookSpecificOutput for PreToolUse.
#[must_use]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<PreToolUseHookOutput>,
}

impl PreToolUseResponse {
    /// Create a deny response for PreToolUse.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: Some(PreToolUseHookOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: Some(reason.into()),
                updated_input: None,
            }),
        }
    }

    /// Create an "ask" response for PreToolUse, preserving Codex's
    /// normal permission UI for user approval.
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: Some(PreToolUseHookOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "ask".to_string(),
                permission_decision_reason: Some(reason.into()),
                updated_input: None,
            }),
        }
    }
}

#[must_use]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionDecision {
    pub behavior: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[must_use]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestHookOutput {
    pub hook_event_name: String,
    pub decision: PermissionDecision,
}

#[must_use]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestResponse {
    pub hook_specific_output: PermissionRequestHookOutput,
}

impl PermissionRequestResponse {
    pub fn allow() -> Self {
        Self {
            hook_specific_output: PermissionRequestHookOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionDecision {
                    behavior: "allow".to_string(),
                    message: None,
                },
            },
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: PermissionRequestHookOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionDecision {
                    behavior: "deny".to_string(),
                    message: Some(reason.into()),
                },
            },
        }
    }
}

// ============================================================================
// Flat decision types (UserPromptSubmit, PostToolUse deny format)
// ============================================================================

/// Flat decision response used for UserPromptSubmit and PostToolUse blocking.
#[must_use]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FlatDecisionResponse {
    /// "block" to deny
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// Reason shown to the user when blocking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl FlatDecisionResponse {
    /// Create a block response.
    pub fn block(reason: impl Into<String>) -> Self {
        Self {
            decision: Some("block".to_string()),
            reason: Some(reason.into()),
        }
    }
}

// ============================================================================
// Observation-only response (SessionStart, Stop, PostToolUse allow)
// ============================================================================

/// Response structure for observation-only hooks.
/// Serializes to `{}`.
#[must_use]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NoOutputResponse {}

impl NoOutputResponse {
    /// Create an empty response.
    pub fn ok() -> Self {
        Self {}
    }
}

// ============================================================================
// Unified hook response enum
// ============================================================================

/// Unified hook response enum that can serialize any hook response type.
#[must_use]
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum HookResponse {
    /// Response for PreToolUse hooks (hookSpecificOutput wrapper)
    PreToolUse(PreToolUseResponse),
    /// Response for PermissionRequest hooks.
    PermissionRequest(PermissionRequestResponse),
    /// Response for blockable events using flat decision format
    FlatDecision(FlatDecisionResponse),
    /// Response for observation-only hooks
    NoOutput(NoOutputResponse),
}

impl HookResponse {
    // ========================================================================
    // Allow / pass-through (all events)
    // ========================================================================

    /// Create an empty response for any event where we want to allow.
    /// Serializes to `{}` -- never sets explicit allow.
    pub fn ok() -> Self {
        Self::NoOutput(NoOutputResponse::ok())
    }

    // ========================================================================
    // PreToolUse deny
    // ========================================================================

    /// Create a deny response for PreToolUse using hookSpecificOutput.
    pub fn deny_tool(reason: impl Into<String>) -> Self {
        Self::PreToolUse(PreToolUseResponse::deny(reason))
    }

    /// Create an "ask" response for PreToolUse, preserving Codex's normal
    /// permission UI. Used for escalated decisions that should prompt the
    /// user for approval rather than hard-blocking.
    pub fn ask_tool(reason: impl Into<String>) -> Self {
        Self::PreToolUse(PreToolUseResponse::ask(reason))
    }

    // ========================================================================
    // UserPromptSubmit / PostToolUse deny
    // ========================================================================

    /// Create a block response for UserPromptSubmit.
    pub fn block_prompt(reason: impl Into<String>) -> Self {
        Self::FlatDecision(FlatDecisionResponse::block(reason))
    }

    /// Create a block response for PostToolUse (if needed).
    pub fn block_post_tool(reason: impl Into<String>) -> Self {
        Self::FlatDecision(FlatDecisionResponse::block(reason))
    }

    /// Allow a Codex permission request using its nested decision envelope.
    pub fn allow_permission() -> Self {
        Self::PermissionRequest(PermissionRequestResponse::allow())
    }

    /// Deny a Codex permission request using its nested decision envelope.
    pub fn deny_permission(reason: impl Into<String>) -> Self {
        Self::PermissionRequest(PermissionRequestResponse::deny(reason))
    }

    /// Ask Codex to continue a stopped subagent.
    pub fn continue_subagent(reason: impl Into<String>) -> Self {
        Self::FlatDecision(FlatDecisionResponse::block(reason))
    }
}

impl Default for HookResponse {
    fn default() -> Self {
        Self::ok()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn to_json(response: &HookResponse) -> String {
        serde_json::to_string(response).unwrap()
    }

    // CRITICAL: Guard against the bug where Allow responses bypass Codex's
    // permission system. HookResponse::ok() MUST serialize to "{}" (empty
    // JSON) so that Codex falls back to its normal permission behavior.

    #[test]
    fn test_allow_response_serializes_to_empty_json() {
        let json = to_json(&HookResponse::ok());
        assert_eq!(
            json, "{}",
            "HookResponse::ok() must serialize to empty JSON, got: {json}"
        );
    }

    #[test]
    fn test_deny_tool_uses_hook_specific_output() {
        let json = to_json(&HookResponse::deny_tool("blocked by policy"));
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("\"deny\""));
        assert!(json.contains("blocked by policy"));
        assert!(json.contains("PreToolUse"));
    }

    #[test]
    fn test_deny_tool_does_not_contain_allow() {
        let json = to_json(&HookResponse::deny_tool("reason"));
        // Ensure no explicit "allow" appears anywhere
        assert!(!json.contains("\"allow\""));
    }

    #[test]
    fn test_block_prompt_uses_flat_decision() {
        let json = to_json(&HookResponse::block_prompt("prompt denied"));
        assert!(json.contains("\"decision\""));
        assert!(json.contains("\"block\""));
        assert!(json.contains("prompt denied"));
    }

    #[test]
    fn test_block_post_tool_uses_flat_decision() {
        let json = to_json(&HookResponse::block_post_tool("output blocked"));
        assert!(json.contains("\"decision\""));
        assert!(json.contains("\"block\""));
        assert!(json.contains("output blocked"));
    }

    #[test]
    fn test_no_output_response_serialization() {
        let response = NoOutputResponse::ok();
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_pre_tool_use_deny_structure() {
        let response = PreToolUseResponse::deny("dangerous command");
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let hso = &parsed["hookSpecificOutput"];
        assert_eq!(hso["hookEventName"], "PreToolUse");
        assert_eq!(hso["permissionDecision"], "deny");
        assert_eq!(hso["permissionDecisionReason"], "dangerous command");
        assert!(hso.get("updatedInput").is_none());
    }

    #[test]
    fn test_ask_tool_uses_hook_specific_output_with_ask() {
        let json = to_json(&HookResponse::ask_tool("requires approval"));
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("\"ask\""));
        assert!(json.contains("requires approval"));
        assert!(!json.contains("\"deny\""));
    }

    #[test]
    fn test_permission_request_uses_nested_decision_envelope() {
        let allow = serde_json::to_value(HookResponse::allow_permission()).unwrap();
        assert_eq!(
            allow,
            serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "allow"}
                }
            })
        );

        let deny = serde_json::to_value(HookResponse::deny_permission("blocked")).unwrap();
        assert_eq!(deny["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(deny["hookSpecificOutput"]["decision"]["message"], "blocked");
    }

    #[test]
    fn test_default_response_is_ok() {
        let response = HookResponse::default();
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, "{}");
    }
}
