//! Response types and utilities for Claude Code hook handlers.
//!
//! This module contains the HookResponse structure and its associated
//! builder methods, used to respond to hook events from Claude Code.
//!
//! The response format follows the Claude Code hooks specification:
//! <https://docs.anthropic.com/en/docs/claude-code/hooks>

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sondera_hooks::adjudication::fail_closed_reason;
use sondera_hooks::error::HookError;
use std::collections::HashMap;

/// Permission decision for PreToolUse hooks
#[must_use]
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
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PermissionRequestBehavior {
    Allow,
    Deny,
}

/// Decision for PermissionRequest hooks
#[must_use]
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

/// Block decision for blockable Claude hooks.
#[must_use]
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
    /// Replacement tool output delivered to Claude when policy blocks output.
    ///
    /// Claude Code's PostToolUse `decision: "block"` only appends a reason next to
    /// the original tool result. The hooks contract requires `updatedToolOutput`
    /// to hide/replace that result, and the replacement must match the original
    /// tool output shape: <https://code.claude.com/docs/en/hooks>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_tool_output: Option<JsonValue>,
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

/// Enum for all hook-specific outputs
#[must_use]
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
}

/// Response structure for hook handlers following Claude Code specification
#[must_use]
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

    /// Decision for blockable Claude hooks.
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

fn redact_tool_output(value: &JsonValue) -> JsonValue {
    // Claude Code ignores `updatedToolOutput` for built-in tools when the
    // replacement does not match the original output schema. Preserve the JSON
    // shape while redacting scalar values per the hooks docs:
    // https://code.claude.com/docs/en/hooks
    const PLACEHOLDER: &str = "Output withheld by Sondera policy. See hook block reason.";

    // Structural discriminant keys whose string values must survive redaction.
    // A tool result delivered back to the model is a list of content blocks
    // tagged by `type` (`text`, `image`, `document`, `search_result`,
    // `tool_reference`). Overwriting that discriminant with prose keeps the JSON
    // shape but produces a block the Anthropic API rejects with a 400 ("Input
    // tag '<placeholder>' ... does not match any of the expected tags"), and the
    // poisoned block lingers in conversation history so every later turn fails
    // until the session is restarted. Hide the payload, never the tag.
    //
    // `media_type` is a discriminant too: an `image`/`document` block carries
    // `source.media_type`, which the API validates against a fixed set. Leaving
    // it redacted reintroduces the exact 400 this list exists to prevent — just
    // one level deeper. The bytes live in `source.data`, which still redacts.
    const PRESERVED_KEYS: &[&str] = &["type", "media_type"];

    match value {
        JsonValue::Array(values) => {
            JsonValue::Array(values.iter().map(redact_tool_output).collect())
        }
        JsonValue::Object(map) => JsonValue::Object(
            map.iter()
                .map(|(key, value)| {
                    let redacted = match value {
                        JsonValue::String(_) if PRESERVED_KEYS.contains(&key.as_str()) => {
                            value.clone()
                        }
                        _ => redact_tool_output(value),
                    };
                    (key.clone(), redacted)
                })
                .collect(),
        ),
        JsonValue::String(_) => JsonValue::String(PLACEHOLDER.to_string()),
        JsonValue::Number(number) if number.is_i64() || number.is_u64() => {
            JsonValue::Number(0.into())
        }
        JsonValue::Number(_) => serde_json::json!(0.0),
        JsonValue::Bool(_) => JsonValue::Bool(false),
        JsonValue::Null => JsonValue::Null,
    }
}

/// Build a fail-closed Claude Code response for enforcement-critical hooks.
///
/// Observation-only hooks return `None` so callers can fall back to their
/// provider-specific degraded behavior (for example, injecting context on
/// `SessionStart` or returning an empty allow response).
///
/// `error` is the classified failure that triggered the fail-closed path; its
/// category selects the denial reason text (see [`fail_closed_reason`]) so a
/// server-side policy/schema rejection is not described as a connectivity
/// problem.
pub fn fail_closed_response(
    hook_event_name: &str,
    hook_input: Option<&JsonValue>,
    error: &HookError,
) -> Option<HookResponse> {
    let reason = fail_closed_reason(error);

    if matches!(error, HookError::BudgetExceeded { .. })
        && lifecycle_hook_budget_timeout_degrades_open(hook_event_name)
    {
        return Some(HookResponse::allow().with_system_message(reason.to_string()));
    }

    match hook_event_name {
        "ConfigChange" if is_policy_settings_config_change(hook_input) => None,
        "ConfigChange" => Some(HookResponse::block(reason.to_string())),
        "PreToolUse" => Some(HookResponse::pre_tool_deny(reason.to_string())),
        "PermissionRequest" => Some(HookResponse::permission_deny_and_interrupt(
            reason.to_string(),
        )),
        "PostToolUse" => {
            let reason = reason.to_string();
            match hook_input.and_then(|input| input.get("tool_response")) {
                Some(tool_response) if !tool_response.is_null() => Some(
                    HookResponse::post_tool_block_with_redacted_output(reason, tool_response),
                ),
                _ => Some(HookResponse::post_tool_block(reason)),
            }
        }
        "PreCompact" => Some(HookResponse::block(reason.to_string())),
        "SubagentStop" => Some(HookResponse::subagent_stop_block(reason.to_string())),
        "TaskCompleted" | "TeammateIdle" => Some(HookResponse::stop(reason.to_string())),
        "UserPromptSubmit" => Some(HookResponse::prompt_block(reason.to_string())),
        _ => None,
    }
}

fn lifecycle_hook_budget_timeout_degrades_open(hook_event_name: &str) -> bool {
    matches!(
        hook_event_name,
        "SubagentStop" | "TaskCompleted" | "TeammateIdle"
    )
}

fn is_policy_settings_config_change(hook_input: Option<&JsonValue>) -> bool {
    hook_input
        .and_then(|input| input.get("source").or_else(|| input.get("config_type")))
        .and_then(JsonValue::as_str)
        .is_some_and(|source| source == "policy_settings")
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
    pub fn stop(reason: String) -> Self {
        Self {
            continue_execution: false,
            stop_reason: Some(reason),
            ..Self::default()
        }
    }

    /// Create a response that blocks the action with a reason (for Stop/SubagentStop hooks)
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

    /// Create a PostToolUse response that blocks with a reason.
    pub fn post_tool_block(reason: String) -> Self {
        Self::post_tool_block_with_output(reason, None)
    }

    /// Create a PostToolUse response that blocks and replaces the tool output.
    pub fn post_tool_block_with_redacted_output(
        reason: String,
        original_output: &JsonValue,
    ) -> Self {
        let redacted_output =
            (!original_output.is_null()).then(|| redact_tool_output(original_output));
        Self::post_tool_block_with_output(reason, redacted_output)
    }

    fn post_tool_block_with_output(reason: String, updated_tool_output: Option<JsonValue>) -> Self {
        Self {
            decision: Some(BlockDecision::Block),
            reason: Some(reason),
            hook_specific_output: Some(HookSpecificOutput::PostToolUse(PostToolUseOutput {
                hook_event_name: "PostToolUse".to_string(),
                additional_context: None,
                updated_tool_output,
            })),
            ..Self::default()
        }
    }

    /// Create a PostToolUse response with additional context
    pub fn post_tool_with_context(context: String) -> Self {
        Self {
            hook_specific_output: Some(HookSpecificOutput::PostToolUse(PostToolUseOutput {
                hook_event_name: "PostToolUse".to_string(),
                additional_context: Some(context),
                updated_tool_output: None,
            })),
            ..Self::default()
        }
    }

    // UserPromptSubmit responses

    /// Create a UserPromptSubmit response that blocks the prompt
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
    pub fn stop_block(reason: String) -> Self {
        Self {
            decision: Some(BlockDecision::Block),
            reason: Some(reason),
            ..Self::default()
        }
    }

    /// Create a SubagentStop response that blocks the subagent from stopping
    pub fn subagent_stop_block(reason: String) -> Self {
        Self {
            decision: Some(BlockDecision::Block),
            reason: Some(reason),
            ..Self::default()
        }
    }

    // PostToolUseFailure responses

    /// Create a PostToolUseFailure response with additional context
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
    pub fn with_suppress_output(mut self) -> Self {
        self.suppress_output = true;
        self
    }

    /// Set system message
    pub fn with_system_message(mut self, message: String) -> Self {
        self.system_message = Some(message);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_hook_budget_timeout_reason(reason: &str) {
        assert!(
            reason.contains("timed out"),
            "timeout reason should name timeout cause: {reason}"
        );
        assert!(
            reason.contains("hook setup latency"),
            "timeout reason should point at hook setup latency: {reason}"
        );
        assert!(
            !reason.contains("reachable"),
            "outer hook timeout reason must not claim harness reachability: {reason}"
        );
        assert!(
            !reason.contains("sondera serve"),
            "timeout reason must not steer toward doctor: {reason}"
        );
        assert!(
            !reason.contains("connectivity"),
            "timeout reason must not steer toward connectivity: {reason}"
        );
    }

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
    fn test_post_tool_block_with_redacted_output_replaces_sensitive_values() {
        let original = serde_json::json!({
            "stdout": "secret output",
            "stderr": "secret error",
            "interrupted": true,
            "code": 42,
            "nested": {"token": "abc123"},
        });
        let response = HookResponse::post_tool_block_with_redacted_output(
            "Tool output blocked by policy".to_string(),
            &original,
        );

        assert_eq!(response.decision, Some(BlockDecision::Block));
        match response.hook_specific_output {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                let updated = output.updated_tool_output.expect("updated tool output");
                assert_eq!(
                    updated["stdout"],
                    "Output withheld by Sondera policy. See hook block reason."
                );
                assert_eq!(
                    updated["stderr"],
                    "Output withheld by Sondera policy. See hook block reason."
                );
                assert_eq!(updated["interrupted"], false);
                assert_eq!(updated["code"], 0);
                assert_eq!(
                    updated["nested"]["token"],
                    "Output withheld by Sondera policy. See hook block reason."
                );
            }
            other => panic!("Expected PostToolUse output, got {other:?}"),
        }
    }

    #[test]
    fn test_post_tool_block_with_redacted_output_preserves_content_block_type() {
        // Built-in tool results are an array of content blocks tagged by `type`.
        // Redaction must hide the payload but keep the discriminant, otherwise
        // Claude bakes an invalid block into history and the Anthropic API 400s
        // on every subsequent turn until the session restarts.
        let original = serde_json::json!([
            {"type": "text", "text": "secret stdout"},
            {"type": "image", "source": {"type": "base64", "data": "c2VjcmV0"}},
        ]);
        let response = HookResponse::post_tool_block_with_redacted_output(
            "Tool output blocked by policy".to_string(),
            &original,
        );

        match response.hook_specific_output {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                let updated = output.updated_tool_output.expect("updated tool output");
                let placeholder = "Output withheld by Sondera policy. See hook block reason.";

                // Discriminant tags survive verbatim so the blocks stay valid.
                assert_eq!(updated[0]["type"], "text");
                assert_eq!(updated[1]["type"], "image");
                assert_eq!(updated[1]["source"]["type"], "base64");

                // Payload scalars are still redacted.
                assert_eq!(updated[0]["text"], placeholder);
                assert_eq!(updated[1]["source"]["data"], placeholder);
            }
            other => panic!("Expected PostToolUse output, got {other:?}"),
        }
    }

    #[test]
    fn test_post_tool_block_with_redacted_output_preserves_source_media_type() {
        // `source.media_type` is validated against a fixed set, so redacting it
        // 400s the replayed block exactly like a redacted `type` would.
        let original = serde_json::json!([
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "c2VjcmV0"}},
        ]);
        let response = HookResponse::post_tool_block_with_redacted_output(
            "Tool output blocked by policy".to_string(),
            &original,
        );

        match response.hook_specific_output {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                let updated = output.updated_tool_output.expect("updated tool output");
                assert_eq!(updated[0]["source"]["media_type"], "image/png");
            }
            other => panic!("Expected PostToolUse output, got {other:?}"),
        }
    }

    #[test]
    fn test_post_tool_block_with_null_output_omits_updated_tool_output() {
        let response = HookResponse::post_tool_block_with_redacted_output(
            "Tool output blocked by policy".to_string(),
            &JsonValue::Null,
        );

        match response.hook_specific_output {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                assert!(output.updated_tool_output.is_none());
            }
            other => panic!("Expected PostToolUse output, got {other:?}"),
        }
    }

    #[test]
    fn test_fail_closed_response_blocks_enforcement_hooks() {
        let post_tool_input = serde_json::json!({
            "tool_response": {
                "stdout": "secret output",
                "interrupted": true,
            }
        });

        let pre_tool = fail_closed_response(
            "PreToolUse",
            None,
            &HookError::ServiceUnavailable(String::new()),
        )
        .expect("PreToolUse response");
        assert!(matches!(
            pre_tool.hook_specific_output,
            Some(HookSpecificOutput::PreToolUse(_))
        ));

        let permission = fail_closed_response(
            "PermissionRequest",
            None,
            &HookError::ServiceUnavailable(String::new()),
        )
        .expect("PermissionRequest response");
        match permission.hook_specific_output {
            Some(HookSpecificOutput::PermissionRequest(output)) => {
                assert_eq!(output.decision.behavior, PermissionRequestBehavior::Deny);
                assert_eq!(output.decision.interrupt, Some(true));
            }
            other => panic!("Expected PermissionRequest output, got {other:?}"),
        }

        let post_tool = fail_closed_response(
            "PostToolUse",
            Some(&post_tool_input),
            &HookError::ServiceUnavailable(String::new()),
        )
        .expect("PostToolUse response");
        match post_tool.hook_specific_output {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                let updated = output.updated_tool_output.expect("updated tool output");
                assert_eq!(
                    updated["stdout"],
                    "Output withheld by Sondera policy. See hook block reason."
                );
                assert_eq!(updated["interrupted"], false);
            }
            other => panic!("Expected PostToolUse output, got {other:?}"),
        }

        let post_tool_without_shape = fail_closed_response(
            "PostToolUse",
            None,
            &HookError::ServiceUnavailable(String::new()),
        )
        .expect("PostToolUse response");
        match post_tool_without_shape.hook_specific_output {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                assert!(output.updated_tool_output.is_none());
            }
            other => panic!("Expected PostToolUse output, got {other:?}"),
        }

        let prompt = fail_closed_response(
            "UserPromptSubmit",
            None,
            &HookError::ServiceUnavailable(String::new()),
        )
        .expect("UserPromptSubmit response");
        assert_eq!(prompt.decision, Some(BlockDecision::Block));

        for event_name in ["ConfigChange", "PreCompact", "SubagentStop"] {
            let response = fail_closed_response(
                event_name,
                None,
                &HookError::ServiceUnavailable(String::new()),
            )
            .expect("blockable lifecycle response");
            assert_eq!(
                response.decision,
                Some(BlockDecision::Block),
                "{event_name}"
            );
            assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("sondera serve")),
                "{event_name} should include actionable diagnostic guidance"
            );
        }

        for event_name in ["TaskCompleted", "TeammateIdle"] {
            let response = fail_closed_response(
                event_name,
                None,
                &HookError::ServiceUnavailable(String::new()),
            )
            .expect("team lifecycle response");
            assert!(!response.continue_execution, "{event_name}");
            assert!(response.decision.is_none(), "{event_name}");
            assert!(
                response
                    .stop_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("sondera serve")),
                "{event_name} should use continue=false with diagnostic guidance"
            );
        }

        let policy_settings = serde_json::json!({"source": "policy_settings"});
        assert!(
            fail_closed_response(
                "ConfigChange",
                Some(&policy_settings),
                &HookError::ServiceUnavailable(String::new())
            )
            .is_none()
        );
        let legacy_policy_settings = serde_json::json!({"config_type": "policy_settings"});
        assert!(
            fail_closed_response(
                "ConfigChange",
                Some(&legacy_policy_settings),
                &HookError::ServiceUnavailable(String::new())
            )
            .is_none()
        );

        assert!(
            fail_closed_response(
                "SessionStart",
                None,
                &HookError::ServiceUnavailable(String::new())
            )
            .is_none()
        );
        assert!(
            fail_closed_response("Stop", None, &HookError::ServiceUnavailable(String::new()))
                .is_none()
        );
    }

    #[test]
    fn test_hook_budget_timeout_lifecycle_hooks_degrade_open_by_default() {
        for event_name in ["SubagentStop", "TaskCompleted", "TeammateIdle"] {
            let response = fail_closed_response(
                event_name,
                None,
                &HookError::BudgetExceeded { budget_secs: 30 },
            )
            .expect("lifecycle timeout response");
            assert!(response.continue_execution, "{event_name}");
            assert!(response.decision.is_none(), "{event_name}");
            assert!(response.stop_reason.is_none(), "{event_name}");
            let message = response.system_message.as_deref().expect("system message");
            assert_hook_budget_timeout_reason(message);
        }

        let pre_tool = fail_closed_response(
            "PreToolUse",
            None,
            &HookError::BudgetExceeded { budget_secs: 30 },
        )
        .expect("PreToolUse timeout response");
        match pre_tool.hook_specific_output {
            Some(HookSpecificOutput::PreToolUse(output)) => {
                assert_eq!(output.permission_decision, Some(PermissionDecision::Deny));
                let reason = output
                    .permission_decision_reason
                    .as_deref()
                    .expect("deny reason");
                assert_hook_budget_timeout_reason(reason);
            }
            other => panic!("Expected PreToolUse output, got {other:?}"),
        }

        let permission = fail_closed_response(
            "PermissionRequest",
            None,
            &HookError::BudgetExceeded { budget_secs: 30 },
        )
        .expect("PermissionRequest timeout response");
        match permission.hook_specific_output {
            Some(HookSpecificOutput::PermissionRequest(output)) => {
                assert_eq!(output.decision.behavior, PermissionRequestBehavior::Deny);
                assert_eq!(output.decision.interrupt, Some(true));
                let reason = output.decision.message.as_deref().expect("deny message");
                assert_hook_budget_timeout_reason(reason);
            }
            other => panic!("Expected PermissionRequest output, got {other:?}"),
        }

        let post_tool_input = serde_json::json!({
            "tool_response": {
                "stdout": "secret output",
                "interrupted": true,
            }
        });
        let post_tool = fail_closed_response(
            "PostToolUse",
            Some(&post_tool_input),
            &HookError::BudgetExceeded { budget_secs: 30 },
        )
        .expect("PostToolUse timeout response");
        let post_tool_reason = post_tool.reason.as_deref().expect("block reason");
        assert_hook_budget_timeout_reason(post_tool_reason);
        match post_tool.hook_specific_output {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                let updated = output.updated_tool_output.expect("updated tool output");
                assert_eq!(
                    updated["stdout"],
                    "Output withheld by Sondera policy. See hook block reason."
                );
                assert_eq!(updated["interrupted"], false);
            }
            other => panic!("Expected PostToolUse output, got {other:?}"),
        }

        let config_change = fail_closed_response(
            "ConfigChange",
            None,
            &HookError::BudgetExceeded { budget_secs: 30 },
        )
        .expect("ConfigChange timeout response");
        assert_eq!(config_change.decision, Some(BlockDecision::Block));
        assert_hook_budget_timeout_reason(config_change.reason.as_deref().expect("block reason"));

        let pre_compact = fail_closed_response(
            "PreCompact",
            None,
            &HookError::BudgetExceeded { budget_secs: 30 },
        )
        .expect("PreCompact timeout response");
        assert_eq!(pre_compact.decision, Some(BlockDecision::Block));
        assert_hook_budget_timeout_reason(pre_compact.reason.as_deref().expect("block reason"));

        assert!(
            fail_closed_response("Stop", None, &HookError::BudgetExceeded { budget_secs: 30 })
                .is_none()
        );

        let policy_settings = serde_json::json!({"source": "policy_settings"});
        assert!(
            fail_closed_response(
                "ConfigChange",
                Some(&policy_settings),
                &HookError::BudgetExceeded { budget_secs: 30 }
            )
            .is_none()
        );

        let prompt = fail_closed_response(
            "UserPromptSubmit",
            None,
            &HookError::BudgetExceeded { budget_secs: 30 },
        )
        .expect("UserPromptSubmit timeout response");
        assert_eq!(prompt.decision, Some(BlockDecision::Block));
        assert_hook_budget_timeout_reason(prompt.reason.as_deref().expect("block reason"));
    }

    #[test]
    fn test_fail_closed_reason_varies_by_category() {
        // Server-side rejection: reason must NOT steer the user toward
        // connectivity and must name the server-side cause.
        let server = fail_closed_response(
            "UserPromptSubmit",
            None,
            &HookError::ServerRejected(String::new()),
        )
        .expect("UserPromptSubmit response");
        let server_reason = server.reason.as_deref().expect("block reason");
        assert!(
            server_reason.contains("server-side"),
            "server reason should name the server-side cause: {server_reason}"
        );
        assert!(
            !server_reason.contains("sondera serve"),
            "server reason must not steer toward connectivity: {server_reason}"
        );

        // Timeout: the service was reachable, but adjudication exceeded the
        // hook budget. It should not steer users toward connectivity/doctor.
        let timeout = fail_closed_response("UserPromptSubmit", None, &HookError::ServiceTimeout)
            .expect("UserPromptSubmit response");
        let timeout_reason = timeout.reason.as_deref().expect("block reason");
        assert!(
            timeout_reason.contains("timed out"),
            "timeout reason should name the timeout cause: {timeout_reason}"
        );
        assert!(
            timeout_reason.contains("latency/load"),
            "timeout reason should point at latency/load: {timeout_reason}"
        );
        assert!(
            timeout_reason.contains("reachable"),
            "RPC timeout reason should name that the service was reachable: {timeout_reason}"
        );
        assert!(
            !timeout_reason.contains("sondera serve"),
            "timeout reason must not steer toward doctor: {timeout_reason}"
        );
        assert!(
            !timeout_reason.contains("connectivity"),
            "timeout reason must not steer toward connectivity: {timeout_reason}"
        );

        // Outer hook-budget timeouts can fire during setup/connect work, so
        // they must not assert that the harness was reached.
        let hook_timeout = fail_closed_response(
            "UserPromptSubmit",
            None,
            &HookError::BudgetExceeded { budget_secs: 30 },
        )
        .expect("UserPromptSubmit response");
        let hook_timeout_reason = hook_timeout.reason.as_deref().expect("block reason");
        assert!(
            hook_timeout_reason.contains("timed out"),
            "hook timeout reason should name the timeout cause: {hook_timeout_reason}"
        );
        assert!(
            hook_timeout_reason.contains("hook setup latency"),
            "hook timeout reason should point at setup latency: {hook_timeout_reason}"
        );
        assert!(
            !hook_timeout_reason.contains("reachable"),
            "hook timeout reason must not claim reachability: {hook_timeout_reason}"
        );
        assert!(
            !hook_timeout_reason.contains("sondera serve"),
            "hook timeout reason must not steer toward doctor: {hook_timeout_reason}"
        );
        assert!(
            !hook_timeout_reason.contains("connectivity"),
            "hook timeout reason must not steer toward connectivity: {hook_timeout_reason}"
        );

        // Network/service errors keep the connectivity/credentials default.
        let network = fail_closed_response(
            "UserPromptSubmit",
            None,
            &HookError::ServiceUnavailable(String::new()),
        )
        .expect("UserPromptSubmit response");
        let network_reason = network.reason.as_deref().expect("block reason");
        assert!(
            network_reason.contains("sondera serve"),
            "network reason should retain connectivity guidance: {network_reason}"
        );
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
        assert!(response.hook_specific_output.is_none());
    }

    #[test]
    fn test_subagent_stop_block() {
        let response = HookResponse::subagent_stop_block("Subagent must continue".to_string());
        assert_eq!(response.decision, Some(BlockDecision::Block));
        assert_eq!(response.reason, Some("Subagent must continue".to_string()));
        assert!(response.hook_specific_output.is_none());
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
