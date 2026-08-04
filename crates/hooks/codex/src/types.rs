//! Type definitions for OpenAI Codex CLI hook events and enums.
//!
//! This module contains all the data structures and enums used to represent
//! hook events from the Codex CLI agent, including event payloads and context data.
//!
//! All types are designed to be resilient to variations in Codex's JSON
//! payloads by using default values and field aliases. The Codex hooks API
//! is experimental (`codex_hooks = true` in config.toml), so forward
//! compatibility is critical.
//!
//! Reference: <https://developers.openai.com/codex/hooks>

use serde::{Deserialize, Serialize};
use sondera_hooks::error::{HookError, Result};
use std::collections::HashMap;

// ============================================================================
// Common input fields (base schema)
// ============================================================================

/// Common input fields present in all Codex hook events.
///
/// Every event includes session identity, working directory, model info,
/// and permission mode. Turn-scoped events additionally carry a `turn_id`
/// in their own structs.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CommonInput {
    /// Current session/thread ID
    #[serde(default)]
    pub session_id: String,
    /// Path to session transcript file
    #[serde(default)]
    pub transcript_path: Option<String>,
    /// Current working directory
    #[serde(default)]
    pub cwd: String,
    /// PascalCase event name (e.g. "SessionStart", "PreToolUse")
    #[serde(default)]
    pub hook_event_name: String,
    /// Active model slug (e.g. "o3-mini")
    #[serde(default)]
    pub model: String,
    /// Current permission mode
    #[serde(default)]
    pub permission_mode: PermissionMode,
}

// ============================================================================
// Enums
// ============================================================================

/// Codex permission modes.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PermissionMode {
    /// Default permission mode
    #[default]
    Default,
    /// Accept edits without prompting
    #[serde(alias = "acceptEdits")]
    AcceptEdits,
    /// Plan-only mode
    Plan,
    /// Don't ask for permission
    #[serde(alias = "dontAsk")]
    DontAsk,
    /// Bypass all permissions (full auto)
    #[serde(alias = "bypassPermissions")]
    BypassPermissions,
    /// Unknown/future permission mode
    #[serde(other)]
    Unknown,
}

/// Source for SessionStart events.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStartSource {
    /// New session startup
    #[default]
    Startup,
    /// Resumed session
    Resume,
    /// Session cleared/reset
    Clear,
    /// Session resumed after compaction.
    Compact,
    /// Unknown source
    #[serde(other)]
    Unknown,
}

// ============================================================================
// Hook event structures
// ============================================================================

/// SessionStart hook event data.
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Session source (startup, resume, clear)
    #[serde(default)]
    pub source: SessionStartSource,
    /// Catch-all for future fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// SessionEnd hook event data.
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionEndEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub reason: String,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// SubagentStart hook event data.
#[derive(Debug, Deserialize, Serialize)]
pub struct SubagentStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub turn_id: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub agent_type: String,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// PermissionRequest hook event data.
#[derive(Debug, Deserialize, Serialize)]
pub struct PermissionRequestEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub turn_id: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Shared payload for pre- and post-compaction hooks.
#[derive(Debug, Deserialize, Serialize)]
pub struct CompactEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub turn_id: String,
    #[serde(default)]
    pub trigger: String,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

pub type PreCompactEvent = CompactEvent;
pub type PostCompactEvent = CompactEvent;

/// SubagentStop hook event data.
#[derive(Debug, Deserialize, Serialize)]
pub struct SubagentStopEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub turn_id: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub agent_type: String,
    #[serde(default)]
    pub agent_transcript_path: Option<String>,
    #[serde(default)]
    pub stop_hook_active: bool,
    #[serde(default)]
    pub last_assistant_message: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// PreToolUse hook event data.
///
/// Currently only `Bash` tool triggers this event, but we accept any
/// tool name for forward compatibility.
#[derive(Debug, Deserialize, Serialize)]
pub struct PreToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Turn identifier for correlation
    #[serde(default)]
    pub turn_id: String,
    /// Name of the tool being invoked (currently always "Bash")
    #[serde(default)]
    pub tool_name: String,
    /// Unique tool invocation ID
    #[serde(default)]
    pub tool_use_id: String,
    /// Tool input object (for Bash: `{ "command": "..." }`)
    #[serde(default)]
    pub tool_input: serde_json::Value,
    /// Catch-all for future fields Codex may add.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// PostToolUse hook event data.
#[derive(Debug, Deserialize, Serialize)]
pub struct PostToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Turn identifier for correlation
    #[serde(default)]
    pub turn_id: String,
    /// Name of the tool that was invoked
    #[serde(default)]
    pub tool_name: String,
    /// Unique tool invocation ID (matches PreToolUse)
    #[serde(default)]
    pub tool_use_id: String,
    /// Tool input object
    #[serde(default)]
    pub tool_input: serde_json::Value,
    /// Tool execution output (schema is `true`, meaning any JSON)
    #[serde(default)]
    pub tool_response: serde_json::Value,
    /// Catch-all for future fields Codex may add.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// UserPromptSubmit hook event data.
#[derive(Debug, Deserialize, Serialize)]
pub struct UserPromptSubmitEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Turn identifier for correlation
    #[serde(default)]
    pub turn_id: String,
    /// The user's prompt text
    #[serde(default)]
    pub prompt: String,
    /// Catch-all for future fields Codex may add.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Stop hook event data.
#[derive(Debug, Deserialize, Serialize)]
pub struct StopEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Turn identifier for correlation
    #[serde(default)]
    pub turn_id: String,
    /// Whether the stop hook is currently active
    #[serde(default)]
    pub stop_hook_active: bool,
    /// Final assistant message text
    #[serde(default)]
    pub last_assistant_message: Option<String>,
    /// Catch-all for future fields Codex may add.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ============================================================================
// Validation implementations
// ============================================================================

impl SessionStartEvent {
    /// Validates that required fields are present.
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl SessionEndEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl SubagentStartEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl PermissionRequestEvent {
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            return Err(HookError::message("tool_name cannot be empty"));
        }
        Ok(())
    }
}

impl CompactEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl SubagentStopEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl PreToolUseEvent {
    /// Validates that required fields are present.
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            return Err(HookError::message("tool_name cannot be empty"));
        }
        Ok(())
    }
}

impl PostToolUseEvent {
    /// Validates that required fields are present.
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            return Err(HookError::message("tool_name cannot be empty"));
        }
        Ok(())
    }
}

impl UserPromptSubmitEvent {
    /// Validates that required fields are present.
    pub fn validate(&self) -> Result<()> {
        // Prompt can potentially be empty (edge case)
        Ok(())
    }
}

impl StopEvent {
    /// Validates that required fields are present.
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
    use std::collections::HashMap;

    #[test]
    fn test_session_start_deserialization() {
        let json = r#"{
            "session_id": "sess-abc123",
            "transcript_path": "/home/user/.codex/sessions/sess-abc123.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "SessionStart",
            "model": "o3-mini",
            "permission_mode": "default",
            "source": "startup"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.common.session_id, "sess-abc123");
        assert_eq!(event.common.cwd, "/home/user/project");
        assert_eq!(event.common.model, "o3-mini");
        assert_eq!(event.source, SessionStartSource::Startup);
    }

    #[test]
    fn test_session_start_with_resume_source() {
        let json = r#"{
            "session_id": "sess-abc123",
            "cwd": "/home/user/project",
            "hook_event_name": "SessionStart",
            "model": "o3-mini",
            "permission_mode": "default",
            "source": "resume"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.source, SessionStartSource::Resume);
    }

    #[test]
    fn test_session_start_unknown_source() {
        let json = r#"{
            "session_id": "sess-abc123",
            "cwd": "/tmp",
            "hook_event_name": "SessionStart",
            "model": "o3-mini",
            "permission_mode": "default",
            "source": "future_value"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.source, SessionStartSource::Unknown);
    }

    #[test]
    fn test_pre_tool_use_deserialization() {
        let json = r#"{
            "session_id": "sess-abc123",
            "transcript_path": "/home/user/.codex/sessions/sess-abc123.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "PreToolUse",
            "model": "o3-mini",
            "permission_mode": "default",
            "turn_id": "turn-001",
            "tool_name": "Bash",
            "tool_use_id": "toolu_01XYZ",
            "tool_input": {
                "command": "rm -rf /tmp/build"
            }
        }"#;
        let event: PreToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "Bash");
        assert_eq!(event.turn_id, "turn-001");
        assert_eq!(
            event.tool_input["command"].as_str().unwrap(),
            "rm -rf /tmp/build"
        );
    }

    #[test]
    fn test_pre_tool_use_validation_empty_tool_name() {
        let event = PreToolUseEvent {
            common: CommonInput::default(),
            turn_id: String::new(),
            tool_name: String::new(),
            tool_use_id: String::new(),
            tool_input: serde_json::Value::Null,
            extra: HashMap::new(),
        };
        assert!(event.validate().is_err());
    }

    #[test]
    fn test_post_tool_use_deserialization() {
        let json = r#"{
            "session_id": "sess-abc123",
            "cwd": "/home/user/project",
            "hook_event_name": "PostToolUse",
            "model": "o3-mini",
            "permission_mode": "default",
            "turn_id": "turn-001",
            "tool_name": "Bash",
            "tool_use_id": "toolu_01XYZ",
            "tool_input": { "command": "ls -la" },
            "tool_response": "total 48\ndrwxr-xr-x  12 user user 384 Mar 30 10:00 ."
        }"#;
        let event: PostToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "Bash");
        assert_eq!(event.tool_use_id, "toolu_01XYZ");
    }

    #[test]
    fn test_user_prompt_submit_deserialization() {
        let json = r#"{
            "session_id": "sess-abc123",
            "cwd": "/home/user/project",
            "hook_event_name": "UserPromptSubmit",
            "model": "o3-mini",
            "permission_mode": "default",
            "turn_id": "turn-001",
            "prompt": "Delete all test files"
        }"#;
        let event: UserPromptSubmitEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.prompt, "Delete all test files");
        assert_eq!(event.turn_id, "turn-001");
    }

    #[test]
    fn test_stop_deserialization() {
        let json = r#"{
            "session_id": "sess-abc123",
            "cwd": "/home/user/project",
            "hook_event_name": "Stop",
            "model": "o3-mini",
            "permission_mode": "default",
            "turn_id": "turn-001",
            "stop_hook_active": false,
            "last_assistant_message": "I've completed the task."
        }"#;
        let event: StopEvent = serde_json::from_str(json).unwrap();
        assert!(!event.stop_hook_active);
        assert_eq!(
            event.last_assistant_message,
            Some("I've completed the task.".to_string())
        );
    }

    #[test]
    fn test_permission_mode_variants() {
        let mode: PermissionMode = serde_json::from_str("\"default\"").unwrap();
        assert_eq!(mode, PermissionMode::Default);

        let mode: PermissionMode = serde_json::from_str("\"bypassPermissions\"").unwrap();
        assert_eq!(mode, PermissionMode::BypassPermissions);

        let mode: PermissionMode = serde_json::from_str("\"dontAsk\"").unwrap();
        assert_eq!(mode, PermissionMode::DontAsk);

        let mode: PermissionMode = serde_json::from_str("\"future_mode\"").unwrap();
        assert_eq!(mode, PermissionMode::Unknown);
    }

    #[test]
    fn test_forward_compatible_deserialization() {
        // Codex may add new fields in the future; verify we don't fail
        // and that unknown fields are captured in the `extra` catch-all.
        let json = r#"{
            "session_id": "sess-abc123",
            "cwd": "/tmp",
            "hook_event_name": "PreToolUse",
            "model": "o3-mini",
            "permission_mode": "default",
            "turn_id": "turn-001",
            "tool_name": "Bash",
            "tool_use_id": "toolu_01XYZ",
            "tool_input": { "command": "echo hi" },
            "unknown_future_field": "some_value",
            "another_new_field": 42
        }"#;
        let event: PreToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "Bash");
        // Unknown fields are captured, not silently dropped.
        assert_eq!(
            event.extra.get("unknown_future_field"),
            Some(&serde_json::json!("some_value"))
        );
        assert_eq!(
            event.extra.get("another_new_field"),
            Some(&serde_json::json!(42))
        );
    }

    #[test]
    fn test_forward_compatible_session_start() {
        let json = r#"{
            "session_id": "sess-001",
            "cwd": "/tmp",
            "hook_event_name": "SessionStart",
            "model": "o3-mini",
            "permission_mode": "default",
            "source": "startup",
            "new_codex_field": true,
            "config_version": "2.0"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.source, SessionStartSource::Startup);
        assert_eq!(
            event.extra.get("new_codex_field"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            event.extra.get("config_version"),
            Some(&serde_json::json!("2.0"))
        );
    }

    #[test]
    fn test_forward_compatible_stop() {
        let json = r#"{
            "session_id": "sess-001",
            "cwd": "/tmp",
            "hook_event_name": "Stop",
            "model": "o3-mini",
            "permission_mode": "default",
            "turn_id": "turn-001",
            "stop_hook_active": false,
            "last_assistant_message": "Done.",
            "exit_code": 0,
            "telemetry_id": "tel-xyz"
        }"#;
        let event: StopEvent = serde_json::from_str(json).unwrap();
        assert!(!event.stop_hook_active);
        assert_eq!(event.extra.get("exit_code"), Some(&serde_json::json!(0)));
        assert_eq!(
            event.extra.get("telemetry_id"),
            Some(&serde_json::json!("tel-xyz"))
        );
    }

    #[test]
    fn test_forward_compatible_unknown_fields_roundtrip() {
        // Verify that unknown fields survive serialize -> deserialize roundtrip.
        let json = r#"{
            "session_id": "sess-001",
            "cwd": "/tmp",
            "hook_event_name": "UserPromptSubmit",
            "model": "o3-mini",
            "permission_mode": "default",
            "turn_id": "turn-001",
            "prompt": "hello",
            "context_window_size": 128000
        }"#;
        let event: UserPromptSubmitEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.prompt, "hello");
        assert_eq!(
            event.extra.get("context_window_size"),
            Some(&serde_json::json!(128000))
        );

        // Roundtrip: serialize back and re-parse.
        let serialized = serde_json::to_string(&event).unwrap();
        let roundtripped: UserPromptSubmitEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(roundtripped.prompt, "hello");
        assert_eq!(
            roundtripped.extra.get("context_window_size"),
            Some(&serde_json::json!(128000))
        );
    }

    #[test]
    fn test_validation_functions() {
        // PreToolUseEvent
        let valid = PreToolUseEvent {
            common: CommonInput::default(),
            turn_id: String::new(),
            tool_name: "Bash".to_string(),
            tool_use_id: String::new(),
            tool_input: serde_json::json!({ "command": "ls" }),
            extra: HashMap::new(),
        };
        assert!(valid.validate().is_ok());

        let invalid = PreToolUseEvent {
            common: CommonInput::default(),
            turn_id: String::new(),
            tool_name: "  ".to_string(),
            tool_use_id: String::new(),
            tool_input: serde_json::Value::Null,
            extra: HashMap::new(),
        };
        assert!(invalid.validate().is_err());

        // PostToolUseEvent
        let valid_post = PostToolUseEvent {
            common: CommonInput::default(),
            turn_id: String::new(),
            tool_name: "Bash".to_string(),
            tool_use_id: String::new(),
            tool_input: serde_json::Value::Null,
            tool_response: serde_json::Value::Null,
            extra: HashMap::new(),
        };
        assert!(valid_post.validate().is_ok());

        let invalid_post = PostToolUseEvent {
            common: CommonInput::default(),
            turn_id: String::new(),
            tool_name: String::new(),
            tool_use_id: String::new(),
            tool_input: serde_json::Value::Null,
            tool_response: serde_json::Value::Null,
            extra: HashMap::new(),
        };
        assert!(invalid_post.validate().is_err());
    }
}
