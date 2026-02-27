//! Type definitions for GitHub Copilot hook events and enums.
//!
//! This module contains all the data structures and enums used to represent
//! hook events from GitHub Copilot agents, including event payloads and context data.
//!
//! All types are designed to be resilient to variations in Copilot's JSON
//! payloads by using default values and field aliases.
//!
//! Reference: https://docs.github.com/en/copilot/reference/hooks-configuration

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

// ============================================================================
// Common input fields (base schema)
// ============================================================================

/// Common input fields present in all hook events
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CommonInput {
    /// Unix timestamp in milliseconds
    #[serde(default)]
    pub timestamp: u64,
    /// Current working directory
    #[serde(default)]
    pub cwd: String,
}

// ============================================================================
// Session start source enum
// ============================================================================

/// Source for sessionStart events
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStartSource {
    /// New session
    #[default]
    New,
    /// Resumed session
    Resume,
    /// Startup
    Startup,
    /// Unknown source
    #[serde(other)]
    Unknown,
}

// ============================================================================
// Session end reason enum
// ============================================================================

/// End reason for sessionEnd events
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EndReason {
    /// Session completed normally
    Complete,
    /// Session had an error
    Error,
    /// Session was aborted
    Abort,
    /// Session timed out
    Timeout,
    /// User exited
    #[serde(rename = "user_exit")]
    UserExit,
    /// Session completed (alternative spelling)
    #[default]
    Completed,
    /// Session was aborted (alternative spelling)
    Aborted,
    /// Unknown end reason
    #[serde(other)]
    Unknown,
}

// ============================================================================
// Hook event structures
// ============================================================================

/// sessionStart hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Session source (new, resume, startup)
    #[serde(default)]
    pub source: SessionStartSource,
    /// Optional initial prompt
    #[serde(default, alias = "initialPrompt", alias = "initial_prompt")]
    pub initial_prompt: Option<String>,
    /// Optional session identifier
    #[serde(default, alias = "sessionId", alias = "session_id")]
    pub session_id: Option<String>,
}

/// sessionEnd hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionEndEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Session identifier
    #[serde(default, alias = "sessionId", alias = "session_id")]
    pub session_id: Option<String>,
    /// Reason the session ended
    #[serde(default)]
    pub reason: Option<EndReason>,
}

/// userPromptSubmitted hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct UserPromptSubmittedEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// User's prompt text
    #[serde(default)]
    pub prompt: String,
}

/// preToolUse hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PreToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Name of the tool being invoked
    #[serde(default, alias = "toolName", alias = "tool_name")]
    pub tool_name: String,
    /// JSON string of tool arguments
    #[serde(default, alias = "toolArgs", alias = "tool_args")]
    pub tool_args: String,
}

/// postToolUse hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PostToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Name of the tool that was invoked
    #[serde(default, alias = "toolName", alias = "tool_name")]
    pub tool_name: String,
    /// JSON string of tool arguments
    #[serde(default, alias = "toolArgs", alias = "tool_args")]
    pub tool_args: String,
    /// Tool execution result
    #[serde(default, alias = "toolResult", alias = "tool_result")]
    pub tool_result: String,
    /// Duration in milliseconds
    #[serde(default)]
    pub duration: f64,
}

/// errorOccurred hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorOccurredEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Error message
    #[serde(default)]
    pub error: String,
    /// Optional error code
    #[serde(default, alias = "errorCode", alias = "error_code")]
    pub error_code: Option<String>,
}

// ============================================================================
// Validation implementations
// ============================================================================

impl SessionStartEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl SessionEndEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl UserPromptSubmittedEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        // Prompt can potentially be empty (edge case)
        Ok(())
    }
}

impl PreToolUseEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            bail!("tool_name cannot be empty");
        }
        Ok(())
    }
}

impl PostToolUseEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            bail!("tool_name cannot be empty");
        }
        Ok(())
    }
}

impl ErrorOccurredEvent {
    /// Validates that required fields are present
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
            "sessionId": "session-123"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.common.timestamp, 1704614400000);
        assert_eq!(event.common.cwd, "/home/user/project");
        assert_eq!(event.session_id, Some("session-123".to_string()));
    }

    #[test]
    fn test_session_start_without_session_id() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, None);
    }

    #[test]
    fn test_session_end_deserialization() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project",
            "sessionId": "session-123",
            "reason": "completed"
        }"#;
        let event: SessionEndEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.session_id, Some("session-123".to_string()));
        assert_eq!(event.reason, Some(EndReason::Completed));
    }

    #[test]
    fn test_user_prompt_submitted_deserialization() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project",
            "prompt": "Help me fix this bug"
        }"#;
        let event: UserPromptSubmittedEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.prompt, "Help me fix this bug");
    }

    #[test]
    fn test_pre_tool_use_deserialization() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project",
            "toolName": "bash",
            "toolArgs": "{\"command\": \"ls -la\"}"
        }"#;
        let event: PreToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "bash");
        assert_eq!(event.tool_args, "{\"command\": \"ls -la\"}");
    }

    #[test]
    fn test_pre_tool_use_snake_case() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project",
            "tool_name": "read_file",
            "tool_args": "{\"path\": \"/tmp/test.txt\"}"
        }"#;
        let event: PreToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "read_file");
    }

    #[test]
    fn test_post_tool_use_deserialization() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project",
            "toolName": "bash",
            "toolArgs": "{\"command\": \"echo hello\"}",
            "toolResult": "hello\n",
            "duration": 150.5
        }"#;
        let event: PostToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "bash");
        assert_eq!(event.tool_result, "hello\n");
        assert_eq!(event.duration, 150.5);
    }

    #[test]
    fn test_error_occurred_deserialization() {
        let json = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project",
            "error": "Tool execution failed",
            "errorCode": "TOOL_EXEC_FAILED"
        }"#;
        let event: ErrorOccurredEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.error, "Tool execution failed");
        assert_eq!(event.error_code, Some("TOOL_EXEC_FAILED".to_string()));
    }

    #[test]
    fn test_unknown_end_reason() {
        let unknown_reason: EndReason = serde_json::from_str("\"invalid\"").unwrap();
        assert_eq!(unknown_reason, EndReason::Unknown);
    }

    #[test]
    fn test_validation_functions() {
        // Test PreToolUseEvent validation
        let valid_event = PreToolUseEvent {
            common: CommonInput::default(),
            tool_name: "bash".to_string(),
            tool_args: "{}".to_string(),
        };
        assert!(valid_event.validate().is_ok());

        let invalid_event = PreToolUseEvent {
            common: CommonInput::default(),
            tool_name: "".to_string(),
            tool_args: "{}".to_string(),
        };
        assert!(invalid_event.validate().is_err());

        // Test PostToolUseEvent validation
        let valid_post = PostToolUseEvent {
            common: CommonInput::default(),
            tool_name: "bash".to_string(),
            tool_args: "{}".to_string(),
            tool_result: "output".to_string(),
            duration: 100.0,
        };
        assert!(valid_post.validate().is_ok());

        let invalid_post = PostToolUseEvent {
            common: CommonInput::default(),
            tool_name: "".to_string(),
            tool_args: "{}".to_string(),
            tool_result: "output".to_string(),
            duration: 100.0,
        };
        assert!(invalid_post.validate().is_err());
    }
}
