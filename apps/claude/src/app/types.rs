//! Type definitions for Claude Code hook events and enums.
//!
//! This module contains all the data structures and enums used to represent
//! hook events from Claude Code, including event payloads, context data,
//! and session information.
//!
//! Reference: https://docs.anthropic.com/en/docs/claude-code/hooks

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Permission mode for Claude Code sessions
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PermissionMode {
    #[default]
    Default,
    Plan,
    AcceptEdits,
    DontAsk,
    BypassPermissions,
    #[serde(other)]
    Unknown,
}

/// Notification types for Claude Code notifications
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    /// Permission requests from Claude Code
    PermissionPrompt,
    /// When Claude is waiting for user input (after 60+ seconds of idle time)
    IdlePrompt,
    /// Authentication success notifications
    AuthSuccess,
    /// When Claude Code needs input for MCP tool elicitation
    ElicitationDialog,
    #[default]
    #[serde(other)]
    Unknown,
}

/// Compact trigger type (manual or auto)
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CompactTrigger {
    #[default]
    Manual,
    Auto,
    #[serde(other)]
    Unknown,
}

/// Session start source type
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStartSource {
    #[default]
    Startup,
    Resume,
    Clear,
    Compact,
    #[serde(other)]
    Unknown,
}

/// Session end reason
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    /// Session cleared with /clear command
    Clear,
    /// User logged out
    Logout,
    /// User exited while prompt input was visible
    PromptInputExit,
    /// Bypass permissions mode was disabled
    BypassPermissionsDisabled,
    /// Other exit reasons
    #[default]
    #[serde(other)]
    Other,
}

// Hook event structures that match Claude Code's JSON payloads

/// Pre-tool-use hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PreToolUseEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: JsonValue,
    #[serde(default)]
    pub tool_use_id: String,
}

/// Permission request hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PermissionRequestEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: JsonValue,
    #[serde(default)]
    pub tool_use_id: String,
}

/// Post-tool-use hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PostToolUseEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: JsonValue,
    pub tool_response: JsonValue,
    #[serde(default)]
    pub tool_use_id: String,
}

/// Notification event data
#[derive(Debug, Deserialize, Serialize)]
pub struct NotificationEvent {
    pub session_id: String,
    #[serde(default)]
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    pub message: String,
    #[serde(default)]
    pub notification_type: NotificationType,
}

/// User prompt submit event data
#[derive(Debug, Deserialize, Serialize)]
pub struct UserPromptSubmitEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    pub prompt: String,
}

/// Stop event data
#[derive(Debug, Deserialize, Serialize)]
pub struct StopEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub stop_hook_active: bool,
}

/// Post-tool-use failure hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PostToolUseFailureEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: JsonValue,
    /// Error message from the failed tool execution
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub tool_use_id: String,
}

/// Subagent start event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SubagentStartEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    /// Unique identifier for the subagent
    pub agent_id: String,
    /// Type of the subagent (Bash, Explore, Plan, or custom agent names)
    pub agent_type: String,
}

/// Subagent stop event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SubagentStopEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub stop_hook_active: bool,
    /// Unique identifier for the subagent
    #[serde(default)]
    pub agent_id: String,
    /// Type of the subagent
    #[serde(default)]
    pub agent_type: String,
    /// Path to the subagent's own transcript
    #[serde(default)]
    pub agent_transcript_path: String,
}

/// Teammate idle event data (when an agent team teammate is about to go idle)
#[derive(Debug, Deserialize, Serialize)]
pub struct TeammateIdleEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    /// Name of the teammate that is about to go idle
    pub teammate_name: String,
    /// Name of the team
    pub team_name: String,
}

/// Task completed event data (when a task is being marked as completed)
#[derive(Debug, Deserialize, Serialize)]
pub struct TaskCompletedEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    /// Identifier of the task being completed
    pub task_id: String,
    /// Title of the task
    pub task_subject: String,
    /// Detailed description of the task (optional)
    #[serde(default)]
    pub task_description: Option<String>,
    /// Name of the teammate completing the task (optional)
    #[serde(default)]
    pub teammate_name: Option<String>,
    /// Name of the team (optional)
    #[serde(default)]
    pub team_name: Option<String>,
}

/// Pre-compaction event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PreCompactEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub trigger: CompactTrigger,
    #[serde(default)]
    pub custom_instructions: String,
}

/// Session start event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionStartEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub source: SessionStartSource,
}

/// Session end event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionEndEvent {
    pub session_id: String,
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: PermissionMode,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub reason: SessionEndReason,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_start_event_deserialization() {
        // Test with source present
        let json_with_source =
            r#"{"source": "startup", "session_id": "test-123", "transcript_path": "/tmp/test"}"#;
        let event: SessionStartEvent = serde_json::from_str(json_with_source).unwrap();
        assert_eq!(event.source, SessionStartSource::Startup);
        assert_eq!(event.session_id, "test-123");

        // Test with missing source (should use default)
        let json_missing_source = r#"{"session_id": "test-456", "transcript_path": "/tmp/test"}"#;
        let event: SessionStartEvent = serde_json::from_str(json_missing_source).unwrap();
        assert_eq!(event.source, SessionStartSource::Startup); // Default
        assert_eq!(event.session_id, "test-456");

        // Test with resume source
        let json_resume =
            r#"{"session_id": "test-789", "source": "resume", "transcript_path": "/tmp/test"}"#;
        let event: SessionStartEvent = serde_json::from_str(json_resume).unwrap();
        assert_eq!(event.source, SessionStartSource::Resume);

        // Test with unknown source (should map to Unknown)
        let json_unknown_source =
            r#"{"source": "invalid", "session_id": "test-999", "transcript_path": "/tmp/test"}"#;
        let event: SessionStartEvent = serde_json::from_str(json_unknown_source).unwrap();
        assert_eq!(event.source, SessionStartSource::Unknown);
    }

    #[test]
    fn test_enum_unknown_variants() {
        let unknown_notification: NotificationType = serde_json::from_str("\"invalid\"").unwrap();
        assert_eq!(unknown_notification, NotificationType::Unknown);

        let unknown_compact: CompactTrigger = serde_json::from_str("\"invalid\"").unwrap();
        assert_eq!(unknown_compact, CompactTrigger::Unknown);

        let unknown_session_end: SessionEndReason = serde_json::from_str("\"invalid\"").unwrap();
        assert_eq!(unknown_session_end, SessionEndReason::Other);

        let unknown_session_start: SessionStartSource =
            serde_json::from_str("\"invalid\"").unwrap();
        assert_eq!(unknown_session_start, SessionStartSource::Unknown);

        let unknown_permission_mode: PermissionMode = serde_json::from_str("\"invalid\"").unwrap();
        assert_eq!(unknown_permission_mode, PermissionMode::Unknown);
    }

    #[test]
    fn test_pre_tool_use_event_deserialization() {
        let json = r#"{
            "session_id": "abc123",
            "transcript_path": "/Users/test/.claude/projects/test.jsonl",
            "cwd": "/Users/test",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/path/to/file.txt", "content": "file content"},
            "tool_use_id": "toolu_01ABC123"
        }"#;
        let event: PreToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, "abc123");
        assert_eq!(event.tool_name, "Write");
        assert_eq!(event.tool_use_id, "toolu_01ABC123");
        assert_eq!(event.permission_mode, PermissionMode::Default);
    }

    #[test]
    fn test_notification_event_deserialization() {
        let json = r#"{
            "session_id": "abc123",
            "transcript_path": "/Users/test/.claude/projects/test.jsonl",
            "cwd": "/Users/test",
            "permission_mode": "default",
            "hook_event_name": "Notification",
            "message": "Claude needs your permission to use Bash",
            "notification_type": "permission_prompt"
        }"#;
        let event: NotificationEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, "abc123");
        assert_eq!(event.message, "Claude needs your permission to use Bash");
        assert_eq!(event.notification_type, NotificationType::PermissionPrompt);
    }

    #[test]
    fn test_pre_compact_event_deserialization() {
        let json = r#"{
            "session_id": "abc123",
            "transcript_path": "/Users/test/.claude/projects/test.jsonl",
            "cwd": "/Users/test",
            "permission_mode": "default",
            "hook_event_name": "PreCompact",
            "trigger": "manual",
            "custom_instructions": ""
        }"#;
        let event: PreCompactEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, "abc123");
        assert_eq!(event.trigger, CompactTrigger::Manual);
        assert_eq!(event.custom_instructions, "");
    }

    #[test]
    fn test_post_tool_use_failure_event_deserialization() {
        let json = r#"{
            "session_id": "abc123",
            "transcript_path": "/Users/test/.claude/projects/test.jsonl",
            "cwd": "/Users/test",
            "permission_mode": "default",
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "error": "Permission denied",
            "tool_use_id": "toolu_01ABC123"
        }"#;
        let event: PostToolUseFailureEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, "abc123");
        assert_eq!(event.tool_name, "Bash");
        assert_eq!(event.error, "Permission denied");
        assert_eq!(event.tool_use_id, "toolu_01ABC123");
    }

    #[test]
    fn test_subagent_start_event_deserialization() {
        let json = r#"{
            "session_id": "abc123",
            "transcript_path": "/Users/test/.claude/projects/test.jsonl",
            "cwd": "/Users/test",
            "permission_mode": "default",
            "hook_event_name": "SubagentStart",
            "agent_id": "agent-abc123",
            "agent_type": "Explore"
        }"#;
        let event: SubagentStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, "abc123");
        assert_eq!(event.agent_id, "agent-abc123");
        assert_eq!(event.agent_type, "Explore");
    }

    #[test]
    fn test_subagent_stop_event_deserialization() {
        let json = r#"{
            "session_id": "abc123",
            "transcript_path": "~/.claude/projects/.../abc123.jsonl",
            "cwd": "/Users/test",
            "permission_mode": "default",
            "hook_event_name": "SubagentStop",
            "stop_hook_active": false,
            "agent_id": "def456",
            "agent_type": "Explore",
            "agent_transcript_path": "~/.claude/projects/.../abc123/subagents/agent-def456.jsonl"
        }"#;
        let event: SubagentStopEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, "abc123");
        assert!(!event.stop_hook_active);
        assert_eq!(event.agent_id, "def456");
        assert_eq!(event.agent_type, "Explore");
        assert!(event.agent_transcript_path.contains("subagents"));
    }

    #[test]
    fn test_teammate_idle_event_deserialization() {
        let json = r#"{
            "session_id": "abc123",
            "transcript_path": "/Users/test/.claude/projects/test.jsonl",
            "cwd": "/Users/test",
            "permission_mode": "default",
            "hook_event_name": "TeammateIdle",
            "teammate_name": "researcher",
            "team_name": "my-project"
        }"#;
        let event: TeammateIdleEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, "abc123");
        assert_eq!(event.teammate_name, "researcher");
        assert_eq!(event.team_name, "my-project");
    }

    #[test]
    fn test_task_completed_event_deserialization() {
        let json = r#"{
            "session_id": "abc123",
            "transcript_path": "/Users/test/.claude/projects/test.jsonl",
            "cwd": "/Users/test",
            "permission_mode": "default",
            "hook_event_name": "TaskCompleted",
            "task_id": "task-001",
            "task_subject": "Implement user authentication",
            "task_description": "Add login and signup endpoints",
            "teammate_name": "implementer",
            "team_name": "my-project"
        }"#;
        let event: TaskCompletedEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, "abc123");
        assert_eq!(event.task_id, "task-001");
        assert_eq!(event.task_subject, "Implement user authentication");
        assert_eq!(
            event.task_description,
            Some("Add login and signup endpoints".to_string())
        );
        assert_eq!(event.teammate_name, Some("implementer".to_string()));
        assert_eq!(event.team_name, Some("my-project".to_string()));
    }

    #[test]
    fn test_task_completed_event_minimal() {
        // Test without optional fields
        let json = r#"{
            "session_id": "abc123",
            "transcript_path": "/tmp/test.jsonl",
            "hook_event_name": "TaskCompleted",
            "task_id": "task-002",
            "task_subject": "Simple task"
        }"#;
        let event: TaskCompletedEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.task_id, "task-002");
        assert!(event.task_description.is_none());
        assert!(event.teammate_name.is_none());
        assert!(event.team_name.is_none());
    }
}
