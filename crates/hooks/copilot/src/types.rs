//! Type definitions for GitHub Copilot CLI hook events.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as JsonValue;
use sondera_hooks::error::{HookError, Result};

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
pub struct CommonInput {
    #[serde(default, deserialize_with = "deserialize_flexible_timestamp")]
    pub timestamp: u64,
    #[serde(default, alias = "Cwd")]
    pub cwd: String,
    #[serde(
        default,
        alias = "sessionId",
        alias = "session_id",
        alias = "SessionId"
    )]
    pub session_id: Option<String>,
    #[serde(default, alias = "transcriptPath", alias = "transcript_path")]
    pub transcript_path: Option<String>,
    #[serde(default, alias = "matcher", alias = "Matcher")]
    pub matcher: Option<JsonValue>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStartSource {
    #[default]
    New,
    Resume,
    Startup,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    Complete,
    Error,
    Abort,
    Timeout,
    UserExit,
    #[default]
    Completed,
    Aborted,
    #[serde(other)]
    Unknown,
}

fn json_value_from_string_or_value<'de, D>(
    deserializer: D,
) -> std::result::Result<JsonValue, D::Error>
where
    D: Deserializer<'de>,
{
    let value = JsonValue::deserialize(deserializer)?;
    Ok(match value {
        JsonValue::String(raw) => serde_json::from_str(&raw).unwrap_or(JsonValue::String(raw)),
        other => other,
    })
}

fn default_json_object() -> JsonValue {
    JsonValue::Object(Default::default())
}

/// Deserialize the hook `timestamp` from **either** a numeric epoch (`u64`,
/// what Copilot historically sent) **or** an ISO-8601 / RFC 3339 string
/// (e.g. `"2026-06-23T20:16:53.591Z"`, what newer GitHub Copilot builds send).
///
/// A schema change on Copilot's side previously failed the entire hook event
/// (`invalid type: string …, expected u64`), aborting the hook with
/// `E_COMMAND_FAILED`. The value is not used by the adapter, so this accepts
/// both forms and never errors: strings are normalized to epoch milliseconds,
/// and anything absent or unparseable yields `0`.
fn deserialize_flexible_timestamp<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    use chrono::{DateTime, Utc};
    Ok(match JsonValue::deserialize(deserializer)? {
        JsonValue::Number(n) => n.as_u64().unwrap_or(0),
        JsonValue::String(s) => DateTime::parse_from_rfc3339(&s)
            .map(|dt| dt.with_timezone(&Utc).timestamp_millis().max(0) as u64)
            .unwrap_or(0),
        _ => 0,
    })
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SessionStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub source: SessionStartSource,
    #[serde(
        default,
        alias = "initialPrompt",
        alias = "initial_prompt",
        alias = "prompt"
    )]
    pub initial_prompt: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SessionEndEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub reason: Option<EndReason>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct UserPromptSubmittedEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "Prompt")]
    pub prompt: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct UserPromptTransformedEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "Prompt")]
    pub prompt: String,
    #[serde(default, alias = "transformedPrompt", alias = "TransformedPrompt")]
    pub transformed_prompt: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct ToolEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "toolName", alias = "tool_name", alias = "ToolName")]
    pub tool_name: String,
    #[serde(
        default = "default_json_object",
        alias = "toolArgs",
        alias = "tool_args",
        alias = "toolInput",
        alias = "tool_input",
        alias = "ToolArgs",
        alias = "ToolInput",
        deserialize_with = "json_value_from_string_or_value"
    )]
    pub tool_args: JsonValue,
}

impl ToolEvent {
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            return Err(HookError::message("tool_name cannot be empty"));
        }
        Ok(())
    }
}

pub type PreToolUseEvent = ToolEvent;
pub type PermissionRequestEvent = ToolEvent;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct PostToolUseEvent {
    #[serde(flatten)]
    pub tool: ToolEvent,
    #[serde(
        default,
        alias = "toolResult",
        alias = "tool_result",
        alias = "ToolResult",
        deserialize_with = "json_value_from_string_or_value"
    )]
    pub tool_result: JsonValue,
    #[serde(default)]
    pub duration: f64,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct PostToolUseFailureEvent {
    #[serde(flatten)]
    pub tool: ToolEvent,
    #[serde(
        default,
        alias = "toolError",
        alias = "tool_error",
        alias = "error",
        deserialize_with = "json_value_from_string_or_value"
    )]
    pub tool_error: JsonValue,
    #[serde(default, alias = "exitCode", alias = "exit_code")]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct ErrorOccurredEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(
        default,
        alias = "Error",
        deserialize_with = "json_value_from_string_or_value"
    )]
    pub error: JsonValue,
    #[serde(
        default,
        alias = "errorCode",
        alias = "error_code",
        alias = "ErrorCode"
    )]
    pub error_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct NotificationEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "message", alias = "Message")]
    pub message: Option<String>,
    #[serde(default, alias = "notificationType", alias = "notification_type")]
    pub notification_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct PreCompactEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "reason", alias = "Reason")]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct AgentStopEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "reason", alias = "Reason")]
    pub reason: Option<String>,
}

pub type SubagentStopEvent = AgentStopEvent;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SubagentStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "subagentId", alias = "subagent_id")]
    pub subagent_id: Option<String>,
    #[serde(default, alias = "task", alias = "Task", alias = "prompt")]
    pub task: Option<String>,
}

impl SessionStartEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl SessionEndEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl UserPromptTransformedEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl UserPromptSubmittedEvent {
    pub fn validate(&self) -> Result<()> {
        // Prompt can potentially be empty (edge case)
        Ok(())
    }
}

impl PostToolUseEvent {
    pub fn validate(&self) -> Result<()> {
        self.tool.validate()
    }
}

impl PostToolUseFailureEvent {
    pub fn validate(&self) -> Result<()> {
        self.tool.validate()
    }
}

impl ErrorOccurredEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl NotificationEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl PreCompactEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl AgentStopEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl SubagentStartEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

pub fn session_key(common: &CommonInput) -> String {
    common
        .session_id
        .as_ref()
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| common.cwd.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_event_matrix_matches_cli_reference() {
        let events: Vec<&str> = crate::event::HOOK_EVENTS
            .iter()
            .map(|event| event.event)
            .collect();

        assert_eq!(
            events,
            vec![
                "agentStop",
                "errorOccurred",
                "notification",
                "permissionRequest",
                "postToolUse",
                "postToolUseFailure",
                "preCompact",
                "preToolUse",
                "sessionEnd",
                "sessionStart",
                "subagentStart",
                "subagentStop",
                "userPromptSubmitted",
                "userPromptTransformed",
            ]
        );
    }

    #[test]
    fn pre_tool_use_accepts_structured_tool_args() {
        let event: PreToolUseEvent = serde_json::from_str(
            r#"{"cwd":"/repo","toolName":"bash","toolArgs":{"command":"git status"}}"#,
        )
        .unwrap();

        assert_eq!(event.tool_name, "bash");
        assert_eq!(event.tool_args["command"], "git status");
    }

    #[test]
    fn pre_tool_use_accepts_string_tool_args() {
        let event: PreToolUseEvent = serde_json::from_str(
            r#"{"cwd":"/repo","ToolName":"bash","tool_input":"{\"command\":\"ls\"}"}"#,
        )
        .unwrap();

        assert_eq!(event.tool_args["command"], "ls");
    }

    #[test]
    fn permission_request_accepts_vs_code_compatible_form() {
        let event: PermissionRequestEvent = serde_json::from_str(
            r#"{"Cwd":"/repo","ToolName":"bash","ToolInput":{"command":"rm -rf build"}}"#,
        )
        .unwrap();

        assert_eq!(event.common.cwd, "/repo");
        assert_eq!(event.tool_args["command"], "rm -rf build");
    }

    #[test]
    fn post_tool_use_failure_accepts_structured_error() {
        let event: PostToolUseFailureEvent = serde_json::from_str(
            r#"{"cwd":"/repo","toolName":"bash","toolArgs":{"command":"test"},"toolError":{"stderr":"boom"},"exitCode":2}"#,
        )
        .unwrap();

        assert_eq!(event.tool.tool_args["command"], "test");
        assert_eq!(event.tool_error["stderr"], "boom");
        assert_eq!(event.exit_code, Some(2));
    }

    #[test]
    fn session_key_falls_back_to_cwd() {
        let event: SessionStartEvent = serde_json::from_str(r#"{"cwd":"/repo"}"#).unwrap();
        assert_eq!(session_key(&event.common), "/repo");
    }

    #[test]
    fn timestamp_accepts_iso8601_string_regression() {
        // Newer GitHub Copilot sends `timestamp` as an ISO-8601 string; the
        // adapter must accept it rather than failing the whole event with
        // `invalid type: string …, expected u64` (which aborted the hook with
        // E_COMMAND_FAILED). Payload mirrors the reported customer event.
        let event: SessionStartEvent = serde_json::from_str(
            r#"{"timestamp":"2026-06-23T20:16:53.591Z","hook_event_name":"SessionStart","session_id":"a25771ad-8967-4f3b-a358-0b3a78679c4f","source":"new","model":"gpt-5.4","cwd":"/Users/test/projects/x"}"#,
        )
        .expect("ISO-8601 timestamp must parse");
        assert!(
            event.common.timestamp > 0,
            "ISO string normalized to epoch millis"
        );
        assert_eq!(event.common.cwd, "/Users/test/projects/x");
        assert_eq!(event.source, SessionStartSource::New);
    }

    #[test]
    fn timestamp_still_accepts_numeric_epoch() {
        // Backward compatibility with older Copilot that sent a numeric epoch.
        let event: SessionStartEvent =
            serde_json::from_str(r#"{"timestamp":1782346613591,"cwd":"/repo"}"#).unwrap();
        assert_eq!(event.common.timestamp, 1_782_346_613_591);
    }

    #[test]
    fn timestamp_tolerates_unparseable_value() {
        // An unknown/unparseable form must not fail the event (timestamp is
        // not load-bearing for the adapter).
        let event: SessionStartEvent =
            serde_json::from_str(r#"{"timestamp":"not-a-date","cwd":"/repo"}"#).unwrap();
        assert_eq!(event.common.timestamp, 0);
    }
}
