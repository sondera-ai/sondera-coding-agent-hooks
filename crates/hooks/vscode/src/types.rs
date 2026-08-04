//! Type definitions for VS Code Copilot Chat hook events and enums.
//!
//! All types are designed to be resilient to variations in VS Code's JSON
//! payloads by using default values and field aliases.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sondera_hooks::error::Result;

// ============================================================================
// Enums
// ============================================================================

/// Source that triggered a session start.
///
/// VS Code currently documents `"new"`; the older `startup`, `resume`, and
/// `clear` values are kept for backward compatibility with previous previews.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStartSource {
    New,
    #[default]
    Startup,
    Resume,
    Clear,
    #[serde(other)]
    Unknown,
}

/// Trigger for pre-compact events
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CompactTrigger {
    #[default]
    Manual,
    Auto,
    #[serde(other)]
    Unknown,
}

// ============================================================================
// Common input fields
// ============================================================================

/// Common input fields present in all hook events.
///
/// Reference: <https://code.visualstudio.com/docs/agent-customization/hooks#_common-input-fields>
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CommonInput {
    /// Current working directory
    #[serde(default)]
    pub cwd: String,
    /// Timestamp — ISO 8601 string ("2026-02-09T10:30:00.000Z") or Unix ms integer.
    /// Stored as a raw JSON value to handle both wire formats.
    #[serde(default)]
    pub timestamp: serde_json::Value,
    /// Session identifier (camelCase from VS Code, snake_case for compatibility)
    #[serde(default, alias = "sessionId", alias = "session_id")]
    pub session_id: Option<String>,
    /// Name of the hook event that fired (e.g. "PreToolUse")
    #[serde(default, alias = "hookEventName", alias = "hook_event_name")]
    pub hook_event_name: Option<String>,
    /// Path to the session transcript file
    #[serde(default, alias = "transcriptPath", alias = "transcript_path")]
    pub transcript_path: Option<String>,
}

// ============================================================================
// Hook event structures
// ============================================================================

/// sessionStart hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub source: SessionStartSource,
}

/// userPromptSubmit hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct UserPromptSubmitEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub prompt: String,
}

/// preToolUse hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PreToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "toolName", alias = "tool_name")]
    pub tool_name: String,
    #[serde(default, alias = "toolInput", alias = "tool_input")]
    pub tool_input: JsonValue,
    #[serde(default, alias = "toolUseId", alias = "tool_use_id")]
    pub tool_use_id: String,
}

/// postToolUse hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PostToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "toolName", alias = "tool_name")]
    pub tool_name: String,
    #[serde(default, alias = "toolInput", alias = "tool_input")]
    pub tool_input: JsonValue,
    #[serde(default, alias = "toolResponse", alias = "tool_response")]
    pub tool_response: JsonValue,
    #[serde(default, alias = "toolUseId", alias = "tool_use_id")]
    pub tool_use_id: String,
}

/// preCompact hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PreCompactEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub trigger: CompactTrigger,
}

/// subagentStart hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SubagentStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "agentId", alias = "agent_id")]
    pub agent_id: String,
    #[serde(default, alias = "agentType", alias = "agent_type")]
    pub agent_type: String,
}

/// subagentStop hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SubagentStopEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "agentId", alias = "agent_id")]
    pub agent_id: String,
    #[serde(default, alias = "agentType", alias = "agent_type")]
    pub agent_type: String,
    #[serde(default, alias = "stopHookActive", alias = "stop_hook_active")]
    pub stop_hook_active: bool,
}

/// stop hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct StopEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "stopHookActive", alias = "stop_hook_active")]
    pub stop_hook_active: bool,
}

// ============================================================================
// Validation implementations
// ============================================================================

impl SessionStartEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl UserPromptSubmitEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl PreToolUseEvent {
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            return Err(sondera_hooks::error::HookError::message(
                "tool_name cannot be empty",
            ));
        }
        Ok(())
    }
}

impl PostToolUseEvent {
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            return Err(sondera_hooks::error::HookError::message(
                "tool_name cannot be empty",
            ));
        }
        Ok(())
    }
}

impl PreCompactEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl SubagentStartEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl SubagentStopEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl StopEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_start_deserialization() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project",
            "sessionId": "session-123",
            "source": "startup"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.common.timestamp, serde_json::json!(1704614400000u64));
        assert_eq!(event.common.cwd, "/home/user/project");
        assert_eq!(event.common.session_id, Some("session-123".to_string()));
        assert_eq!(event.source, SessionStartSource::Startup);
    }

    #[test]
    fn test_session_start_timestamp_as_iso_string() {
        // VS Code may send timestamp as an ISO 8601 string
        let json = r#"{
            "timestamp": "2026-02-09T10:30:00.000Z",
            "cwd": "/home/user/project"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(
            event.common.timestamp,
            serde_json::json!("2026-02-09T10:30:00.000Z")
        );
    }

    #[test]
    fn test_session_start_without_session_id() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.common.session_id, None);
        assert_eq!(event.source, SessionStartSource::Startup);
    }

    #[test]
    fn test_common_input_hook_event_name_and_transcript_path() {
        // VS Code sends hookEventName and transcript_path in every event
        let json = r#"{
            "cwd": "/workspace",
            "sessionId": "sess-1",
            "hookEventName": "PreToolUse",
            "transcript_path": "/tmp/session.jsonl"
        }"#;
        let event: PreToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.common.hook_event_name.as_deref(), Some("PreToolUse"));
        assert_eq!(
            event.common.transcript_path.as_deref(),
            Some("/tmp/session.jsonl")
        );
    }

    #[test]
    fn test_session_start_new_source() {
        let json = r#"{
            "cwd": "/home/user/project",
            "source": "new"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.source, SessionStartSource::New);
    }

    #[test]
    fn test_session_start_resume_source() {
        let json = r#"{
            "cwd": "/home/user/project",
            "source": "resume"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.source, SessionStartSource::Resume);
    }

    #[test]
    fn test_session_start_unknown_source() {
        let json = r#"{
            "cwd": "/home/user/project",
            "source": "invalid"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.source, SessionStartSource::Unknown);
    }

    #[test]
    fn test_user_prompt_submit_deserialization() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project",
            "prompt": "Help me fix this bug"
        }"#;
        let event: UserPromptSubmitEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.prompt, "Help me fix this bug");
    }

    #[test]
    fn test_pre_tool_use_deserialization() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project",
            "toolName": "terminal",
            "toolInput": {"command": "ls -la"},
            "toolUseId": "tool-123"
        }"#;
        let event: PreToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "terminal");
        assert_eq!(event.tool_use_id, "tool-123");
    }

    #[test]
    fn test_pre_tool_use_snake_case() {
        let json = r#"{
            "cwd": "/home/user/project",
            "tool_name": "editFile",
            "tool_input": {"path": "/tmp/test.txt"},
            "tool_use_id": "tool-456"
        }"#;
        let event: PreToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "editFile");
    }

    #[test]
    fn test_post_tool_use_deserialization() {
        let json = r#"{
            "cwd": "/home/user/project",
            "toolName": "terminal",
            "toolInput": {"command": "echo hello"},
            "toolResponse": {"output": "hello\n"},
            "toolUseId": "tool-789"
        }"#;
        let event: PostToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "terminal");
        assert_eq!(event.tool_use_id, "tool-789");
    }

    #[test]
    fn test_pre_compact_deserialization() {
        let json = r#"{
            "cwd": "/home/user/project",
            "trigger": "auto"
        }"#;
        let event: PreCompactEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.trigger, CompactTrigger::Auto);
    }

    #[test]
    fn test_subagent_start_deserialization() {
        let json = r#"{
            "cwd": "/home/user/project",
            "agentId": "subagent-1",
            "agentType": "code-review"
        }"#;
        let event: SubagentStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.agent_id, "subagent-1");
        assert_eq!(event.agent_type, "code-review");
    }

    #[test]
    fn test_subagent_stop_deserialization() {
        let json = r#"{
            "cwd": "/home/user/project",
            "agentId": "subagent-1",
            "agentType": "code-review",
            "stopHookActive": true
        }"#;
        let event: SubagentStopEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.agent_id, "subagent-1");
        assert!(event.stop_hook_active);
    }

    #[test]
    fn test_stop_deserialization() {
        let json = r#"{
            "cwd": "/home/user/project",
            "stopHookActive": false
        }"#;
        let event: StopEvent = serde_json::from_str(json).unwrap();
        assert!(!event.stop_hook_active);
    }

    #[test]
    fn test_unknown_compact_trigger() {
        let unknown: CompactTrigger = serde_json::from_str("\"invalid\"").unwrap();
        assert_eq!(unknown, CompactTrigger::Unknown);
    }

    #[test]
    fn test_validation_pre_tool_use() {
        let valid = PreToolUseEvent {
            common: CommonInput::default(),
            tool_name: "terminal".to_string(),
            tool_input: serde_json::json!({}),
            tool_use_id: String::new(),
        };
        assert!(valid.validate().is_ok());

        let invalid = PreToolUseEvent {
            common: CommonInput::default(),
            tool_name: "".to_string(),
            tool_input: serde_json::json!({}),
            tool_use_id: String::new(),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_validation_post_tool_use() {
        let valid = PostToolUseEvent {
            common: CommonInput::default(),
            tool_name: "terminal".to_string(),
            tool_input: serde_json::json!({}),
            tool_response: serde_json::json!({}),
            tool_use_id: String::new(),
        };
        assert!(valid.validate().is_ok());

        let invalid = PostToolUseEvent {
            common: CommonInput::default(),
            tool_name: "  ".to_string(),
            tool_input: serde_json::json!({}),
            tool_response: serde_json::json!({}),
            tool_use_id: String::new(),
        };
        assert!(invalid.validate().is_err());
    }
}
