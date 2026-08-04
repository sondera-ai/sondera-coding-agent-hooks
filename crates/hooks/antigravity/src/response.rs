//! Response types for Antigravity CLI (`agy`) hook handlers.
//!
//! Antigravity hooks communicate over stdin/stdout as JSON with **camelCase**
//! field names. Each event returns a different output shape:
//!
//! - `PreToolUse` → `{ decision, reason?, permissionOverrides? }` (gates the tool call)
//! - `PostToolUse` → `{}` (observation only)
//! - `PreInvocation` → `{ injectSteps? }`
//! - `PostInvocation` → `{ injectSteps?, terminationBehavior? }`
//! - `Stop` → `{ decision, reason? }` (`"continue"` re-enters the loop; any
//!   other value allows the stop)
//!
//! Reference: <https://antigravity.google/docs/hooks>

// reason: builder API surface is exposed for hook authors; not every constructor
// is exercised by in-tree consumers yet. Mirrors the cursor response module.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// `PreToolUse` decision values. Serializes to `allow` / `deny` / `ask` /
/// `force_ask`.
#[must_use]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolDecision {
    /// Automatically allow the tool execution.
    Allow,
    /// Hard-block execution immediately.
    Deny,
    /// Prompt the user, but respect "Always Allow" settings.
    Ask,
    /// Always prompt the user, ignoring cached permissions.
    ForceAsk,
}

/// Output for the `PreToolUse` event.
#[must_use]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseResponse {
    /// How the tool call is gated.
    pub decision: ToolDecision,
    /// Explanation shown to the agent or user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Resource strings (e.g. `["command(npm test)"]`) overriding default tool
    /// permissions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_overrides: Option<Vec<String>>,
}

/// Output for the `Stop` event.
#[must_use]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StopResponse {
    /// `"continue"` prevents the agent from stopping and re-enters the loop;
    /// any other value allows the stop.
    pub decision: String,
    /// When `decision` is `"continue"`, injected as a system message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A single step injected into the trajectory by `PreInvocation` /
/// `PostInvocation`. Exactly one field is typically set.
#[must_use]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InjectStep {
    /// A tool call to execute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call: Option<serde_json::Value>,
    /// A message from the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
    /// A transient system message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_message: Option<String>,
}

/// Output for the `PreInvocation` event.
#[must_use]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreInvocationResponse {
    /// Steps to inject before the model is called.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inject_steps: Option<Vec<InjectStep>>,
}

/// Output for the `PostInvocation` event.
#[must_use]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostInvocationResponse {
    /// Steps to inject after the invocation completes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inject_steps: Option<Vec<InjectStep>>,
    /// `"force_continue"` / `"terminate"` / `""` (default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub termination_behavior: Option<String>,
}

/// An empty `{}` response (used by `PostToolUse` and advisory no-ops).
#[must_use]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EmptyResponse {}

/// Unified Antigravity hook response that serializes to the correct per-event
/// shape. Only `Serialize` is derived (these are written to stdout); the
/// untagged representation simply emits the inner value.
#[must_use]
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum AntigravityHookResponse {
    /// `PreToolUse` decision.
    PreToolUse(PreToolUseResponse),
    /// `Stop` decision.
    Stop(StopResponse),
    /// `PreInvocation` injection.
    PreInvocation(PreInvocationResponse),
    /// `PostInvocation` injection / termination control.
    PostInvocation(PostInvocationResponse),
    /// Empty `{}` (PostToolUse, advisory no-ops).
    Empty(EmptyResponse),
}

impl AntigravityHookResponse {
    /// Allow the tool call (`PreToolUse`).
    pub fn allow_tool() -> Self {
        Self::PreToolUse(PreToolUseResponse {
            decision: ToolDecision::Allow,
            reason: None,
            permission_overrides: None,
        })
    }

    /// Hard-block the tool call with a reason (`PreToolUse`).
    pub fn deny_tool(reason: impl Into<String>) -> Self {
        Self::PreToolUse(PreToolUseResponse {
            decision: ToolDecision::Deny,
            reason: Some(reason.into()),
            permission_overrides: None,
        })
    }

    /// Prompt the user to confirm the tool call (`PreToolUse`) — used to map a
    /// harness escalation.
    pub fn ask_tool(reason: impl Into<String>) -> Self {
        Self::PreToolUse(PreToolUseResponse {
            decision: ToolDecision::Ask,
            reason: Some(reason.into()),
            permission_overrides: None,
        })
    }

    /// Allow the agent to stop (`Stop`).
    pub fn allow_stop() -> Self {
        Self::Stop(StopResponse {
            decision: "stop".to_string(),
            reason: None,
        })
    }

    /// Prevent the agent from stopping and re-enter the loop (`Stop`).
    pub fn continue_loop(reason: impl Into<String>) -> Self {
        Self::Stop(StopResponse {
            decision: "continue".to_string(),
            reason: Some(reason.into()),
        })
    }

    /// An empty `{}` response (PostToolUse and advisory no-ops).
    pub fn ok() -> Self {
        Self::Empty(EmptyResponse {})
    }

    /// True if this response blocks the action (`PreToolUse` deny).
    pub fn is_deny(&self) -> bool {
        matches!(
            self,
            Self::PreToolUse(PreToolUseResponse {
                decision: ToolDecision::Deny,
                ..
            })
        )
    }
}

impl Default for AntigravityHookResponse {
    fn default() -> Self {
        Self::ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(r: &AntigravityHookResponse) -> serde_json::Value {
        serde_json::to_value(r).unwrap()
    }

    #[test]
    fn allow_tool_serializes_decision_allow() {
        assert_eq!(
            json(&AntigravityHookResponse::allow_tool())["decision"],
            "allow"
        );
    }

    #[test]
    fn deny_tool_carries_reason() {
        let v = json(&AntigravityHookResponse::deny_tool("blocked"));
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "blocked");
    }

    #[test]
    fn ask_tool_maps_to_ask() {
        assert_eq!(
            json(&AntigravityHookResponse::ask_tool("confirm"))["decision"],
            "ask"
        );
    }

    #[test]
    fn force_ask_renders_snake_case() {
        let v = serde_json::to_value(ToolDecision::ForceAsk).unwrap();
        assert_eq!(v, "force_ask");
    }

    #[test]
    fn ok_serializes_to_empty_object() {
        assert_eq!(json(&AntigravityHookResponse::ok()).to_string(), "{}");
    }

    #[test]
    fn stop_allow_uses_non_continue_decision() {
        let v = json(&AntigravityHookResponse::allow_stop());
        assert_eq!(v["decision"], "stop");
        assert_ne!(v["decision"], "continue");
    }

    #[test]
    fn continue_loop_matches_doc_example() {
        // Doc Stop output example: { "decision": "continue", "reason": "Not done yet" }
        let v = json(&AntigravityHookResponse::continue_loop("Not done yet"));
        assert_eq!(v["decision"], "continue");
        assert_eq!(v["reason"], "Not done yet");
    }

    #[test]
    fn pre_tool_doc_example_round_trips() {
        // Doc PreToolUse output example.
        let resp = PreToolUseResponse {
            decision: ToolDecision::Ask,
            reason: Some("Requires confirmation for test execution.".into()),
            permission_overrides: Some(vec!["command(npm test)".into()]),
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["decision"], "ask");
        assert_eq!(v["permissionOverrides"][0], "command(npm test)");
    }

    #[test]
    fn pre_invocation_inject_steps_camel_case() {
        // Doc PreInvocation output example: ephemeralMessage inject step.
        let resp = PreInvocationResponse {
            inject_steps: Some(vec![InjectStep {
                ephemeral_message: Some("Remember to lint".into()),
                ..Default::default()
            }]),
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["injectSteps"][0]["ephemeralMessage"], "Remember to lint");
    }
}
