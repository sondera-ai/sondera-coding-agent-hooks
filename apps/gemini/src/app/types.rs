//! Type definitions for Gemini CLI hook events and enums.
//!
//! This module contains all the data structures and enums used to represent
//! hook events from Gemini CLI, including event payloads, context data,
//! and session information.
//!
//! All types are designed to be resilient to variations in Gemini's JSON
//! payloads by using default values, field aliases, and the `#[serde(other)]`
//! variant for enums to handle unknown values gracefully.
//!
//! Reference: https://geminicli.com/docs/hooks/reference

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// Common input fields (base schema)
// ============================================================================

/// Common input fields present in all Gemini hook events
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CommonInput {
    /// Stable ID of the session
    #[serde(default)]
    pub session_id: String,
    /// Path to the conversation transcript file
    #[serde(default)]
    pub transcript_path: Option<String>,
    /// Current working directory
    #[serde(default)]
    pub cwd: String,
    /// Which hook is being run
    #[serde(default)]
    pub hook_event_name: String,
    /// Timestamp of the event (ISO 8601 format)
    #[serde(default)]
    pub timestamp: Option<String>,
}

// ============================================================================
// Session lifecycle enums
// ============================================================================

/// Source for sessionStart events
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStartSource {
    /// New session startup
    #[default]
    Startup,
    /// Session resumed
    Resume,
    /// Session cleared and restarted
    Clear,
    /// Unknown source
    #[serde(other)]
    Unknown,
}

/// Reason for sessionEnd events
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    /// User exited
    #[default]
    Exit,
    /// Session cleared
    Clear,
    /// User logged out
    Logout,
    /// User exited via prompt input (Ctrl+D, etc.)
    PromptInputExit,
    /// Other/unknown reason
    #[serde(other)]
    Other,
}

// ============================================================================
// Pre-compress trigger enum
// ============================================================================

/// Trigger for preCompress events
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CompressTrigger {
    /// Automatic compression
    #[default]
    Auto,
    /// Manual compression
    Manual,
    /// Unknown trigger
    #[serde(other)]
    Unknown,
}

// ============================================================================
// MCP context for tool events
// ============================================================================

/// MCP context for BeforeTool events
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct McpContext {
    /// MCP server name
    #[serde(default)]
    pub server_name: Option<String>,
    /// MCP server URL
    #[serde(default)]
    pub server_url: Option<String>,
}

// ============================================================================
// Hook event structures
// ============================================================================

/// SessionStart hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Source of session start
    #[serde(default)]
    pub source: SessionStartSource,
}

/// SessionEnd hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionEndEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Reason for session end
    #[serde(default)]
    pub reason: SessionEndReason,
}

/// BeforeAgent hook event data - after user input, before planning
#[derive(Debug, Deserialize, Serialize)]
pub struct BeforeAgentEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// User prompt
    #[serde(default)]
    pub prompt: String,
}

/// AfterAgent hook event data - when agent loop completes
#[derive(Debug, Deserialize, Serialize)]
pub struct AfterAgentEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Original user prompt
    #[serde(default)]
    pub prompt: String,
    /// Agent's response
    #[serde(default)]
    pub prompt_response: String,
    /// Indicates if this hook is already running as part of a retry sequence
    #[serde(default)]
    pub stop_hook_active: bool,
}

/// BeforeToolSelection hook event data - filter available tools
#[derive(Debug, Deserialize, Serialize)]
pub struct BeforeToolSelectionEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// LLM request payload (includes available tools)
    #[serde(default)]
    pub llm_request: Value,
}

/// BeforeTool hook event data - before tool execution
#[derive(Debug, Deserialize, Serialize)]
pub struct BeforeToolEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Name of the tool being invoked
    #[serde(default)]
    pub tool_name: String,
    /// Tool input arguments
    #[serde(default)]
    pub tool_input: Value,
    /// Optional MCP context
    #[serde(default)]
    pub mcp_context: Option<McpContext>,
}

/// AfterTool hook event data - after tool execution
#[derive(Debug, Deserialize, Serialize)]
pub struct AfterToolEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Name of the tool that was invoked
    #[serde(default)]
    pub tool_name: String,
    /// Tool input arguments
    #[serde(default)]
    pub tool_input: Value,
    /// Tool response containing llmContent, returnDisplay, and optional error
    #[serde(default)]
    pub tool_response: Value,
    /// Optional MCP context
    #[serde(default)]
    pub mcp_context: Option<McpContext>,
}

/// PreCompress hook event data - before context compression
#[derive(Debug, Deserialize, Serialize)]
pub struct PreCompressEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Trigger for compression
    #[serde(default)]
    pub trigger: CompressTrigger,
}

/// Notification hook event data - system notifications
#[derive(Debug, Deserialize, Serialize)]
pub struct NotificationEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Type of notification (e.g., "ToolPermission")
    #[serde(default)]
    pub notification_type: String,
    /// Summary of the alert
    #[serde(default)]
    pub message: String,
    /// JSON object with alert-specific metadata (e.g., tool name, file path)
    #[serde(default)]
    pub details: Value,
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

impl BeforeAgentEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        // Prompt can potentially be empty
        Ok(())
    }
}

impl AfterAgentEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl BeforeToolSelectionEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl BeforeToolEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            bail!("tool_name cannot be empty");
        }
        Ok(())
    }
}

impl AfterToolEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            bail!("tool_name cannot be empty");
        }
        Ok(())
    }
}

impl PreCompressEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl NotificationEvent {
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
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "SessionStart",
            "timestamp": "2024-01-15T10:30:00Z",
            "source": "startup"
        }"#;
        let event: SessionStartEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.common.session_id, "sess-123");
        assert_eq!(event.common.cwd, "/home/user/project");
        assert_eq!(event.source, SessionStartSource::Startup);
    }

    #[test]
    fn test_session_end_deserialization() {
        let json = r#"{
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "SessionEnd",
            "reason": "exit"
        }"#;
        let event: SessionEndEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.reason, SessionEndReason::Exit);
    }

    #[test]
    fn test_before_agent_deserialization() {
        let json = r#"{
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "BeforeAgent",
            "prompt": "Help me write a function"
        }"#;
        let event: BeforeAgentEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.prompt, "Help me write a function");
    }

    #[test]
    fn test_after_agent_deserialization() {
        let json = r#"{
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "AfterAgent",
            "prompt": "Help me write a function",
            "prompt_response": "Here's a function...",
            "stop_hook_active": false
        }"#;
        let event: AfterAgentEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.prompt, "Help me write a function");
        assert_eq!(event.prompt_response, "Here's a function...");
        assert!(!event.stop_hook_active);
    }

    #[test]
    fn test_after_agent_with_stop_hook_active() {
        let json = r#"{
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "AfterAgent",
            "prompt": "Fix the issue",
            "prompt_response": "Trying again...",
            "stop_hook_active": true
        }"#;
        let event: AfterAgentEvent = serde_json::from_str(json).unwrap();
        assert!(event.stop_hook_active);
    }

    #[test]
    fn test_before_tool_selection_deserialization() {
        let json = r#"{
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "BeforeToolSelection",
            "llm_request": {"tools": ["read_file", "write_file"]}
        }"#;
        let event: BeforeToolSelectionEvent = serde_json::from_str(json).unwrap();
        assert!(event.llm_request.is_object());
    }

    #[test]
    fn test_before_tool_deserialization() {
        let json = r#"{
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "BeforeTool",
            "tool_name": "read_file",
            "tool_input": {"path": "/tmp/test.txt"},
            "mcp_context": {"server_name": "local", "server_url": "http://localhost:3000"}
        }"#;
        let event: BeforeToolEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "read_file");
        assert!(event.tool_input.is_object());
        assert!(event.mcp_context.is_some());
    }

    #[test]
    fn test_after_tool_deserialization() {
        let json = r#"{
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "AfterTool",
            "tool_name": "read_file",
            "tool_input": {"path": "/tmp/test.txt"},
            "tool_response": {"content": "file contents"}
        }"#;
        let event: AfterToolEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "read_file");
        assert!(event.tool_response.is_object());
    }

    #[test]
    fn test_pre_compress_deserialization() {
        let json = r#"{
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "PreCompress",
            "trigger": "auto"
        }"#;
        let event: PreCompressEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.trigger, CompressTrigger::Auto);
    }

    #[test]
    fn test_notification_deserialization() {
        let json = r#"{
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "Notification",
            "notification_type": "ToolPermission",
            "message": "Tool permission requested",
            "details": {"tool_name": "write_file", "path": "/etc/passwd"}
        }"#;
        let event: NotificationEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.notification_type, "ToolPermission");
        assert_eq!(event.message, "Tool permission requested");
        assert!(event.details.is_object());
        assert_eq!(event.details["tool_name"], "write_file");
    }

    #[test]
    fn test_unknown_session_source() {
        let unknown: SessionStartSource = serde_json::from_str("\"invalid\"").unwrap();
        assert_eq!(unknown, SessionStartSource::Unknown);
    }

    #[test]
    fn test_unknown_session_end_reason() {
        let unknown: SessionEndReason = serde_json::from_str("\"invalid\"").unwrap();
        assert_eq!(unknown, SessionEndReason::Other);
    }

    #[test]
    fn test_session_end_prompt_input_exit() {
        let json = r#"{
            "session_id": "sess-123",
            "cwd": "/home/user/project",
            "hook_event_name": "SessionEnd",
            "reason": "prompt_input_exit"
        }"#;
        let event: SessionEndEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.reason, SessionEndReason::PromptInputExit);
    }

    #[test]
    fn test_validation_functions() {
        // Test BeforeToolEvent validation
        let valid_event = BeforeToolEvent {
            common: CommonInput::default(),
            tool_name: "read_file".to_string(),
            tool_input: serde_json::json!({}),
            mcp_context: None,
        };
        assert!(valid_event.validate().is_ok());

        let invalid_event = BeforeToolEvent {
            common: CommonInput::default(),
            tool_name: "".to_string(),
            tool_input: serde_json::json!({}),
            mcp_context: None,
        };
        assert!(invalid_event.validate().is_err());

        // Test AfterToolEvent validation
        let valid_after = AfterToolEvent {
            common: CommonInput::default(),
            tool_name: "write_file".to_string(),
            tool_input: serde_json::json!({}),
            tool_response: serde_json::json!({}),
            mcp_context: None,
        };
        assert!(valid_after.validate().is_ok());

        let invalid_after = AfterToolEvent {
            common: CommonInput::default(),
            tool_name: "".to_string(),
            tool_input: serde_json::json!({}),
            tool_response: serde_json::json!({}),
            mcp_context: None,
        };
        assert!(invalid_after.validate().is_err());
    }
}
