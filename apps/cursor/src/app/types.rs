//! Type definitions for Cursor hook events and enums.
//!
//! This module contains all the data structures and enums used to represent
//! hook events from Cursor, including event payloads, context data,
//! and session information.
//!
//! All types are designed to be resilient to variations in Cursor's JSON
//! payloads by using default values, field aliases, and the `#[serde(other)]`
//! variant for enums to handle unknown values gracefully.
//!
//! Reference: https://cursor.com/docs/agent/hooks

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

// ============================================================================
// Common input fields (base schema)
// ============================================================================

/// Common input fields present in all hook events
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CommonInput {
    /// Stable ID of the conversation across many turns
    #[serde(default)]
    pub conversation_id: String,
    /// The current generation that changes with every user message
    #[serde(default)]
    pub generation_id: String,
    /// The model configured for the composer that triggered the hook
    #[serde(default)]
    pub model: String,
    /// Which hook is being run
    #[serde(default)]
    pub hook_event_name: String,
    /// Cursor application version (e.g. "1.7.2")
    #[serde(default)]
    pub cursor_version: String,
    /// The list of root folders in the workspace
    #[serde(default)]
    pub workspace_roots: Vec<String>,
    /// Email address of the authenticated user, if available
    #[serde(default)]
    pub user_email: Option<String>,
    /// Path to the transcript file for this conversation
    #[serde(default)]
    pub transcript_path: Option<String>,
}

// ============================================================================
// Session status enums
// ============================================================================

/// Composer mode for session events
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ComposerMode {
    /// Agent mode
    #[default]
    Agent,
    /// Ask mode
    Ask,
    /// Edit mode
    Edit,
    /// Unknown mode
    #[serde(other)]
    Unknown,
}

/// End reason for sessionEnd events
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EndReason {
    /// Session completed normally
    #[default]
    Completed,
    /// Session was aborted
    Aborted,
    /// Session encountered an error
    Error,
    /// Unknown end reason
    #[serde(other)]
    Unknown,
}

// ============================================================================
// Stop status enum
// ============================================================================

/// Status values for stop hook events
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StopStatus {
    /// Agent completed successfully
    #[default]
    Completed,
    /// Agent was aborted by user
    Aborted,
    /// Agent encountered an error
    Error,
    /// Unknown status
    #[serde(other)]
    Unknown,
}

impl std::str::FromStr for StopStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "completed" => Ok(StopStatus::Completed),
            "aborted" => Ok(StopStatus::Aborted),
            "error" => Ok(StopStatus::Error),
            _ => Err(format!("Invalid stop status: {}", s)),
        }
    }
}

// ============================================================================
// Attachment types
// ============================================================================

/// Attachment type for beforeSubmitPrompt
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AttachmentType {
    /// File attachment
    #[default]
    File,
    /// Rule attachment
    Rule,
    /// Unknown attachment type
    #[serde(other)]
    Unknown,
}

/// Attachment info for beforeSubmitPrompt
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Attachment {
    /// Type of attachment
    #[serde(default, rename = "type")]
    pub attachment_type: AttachmentType,
    /// Absolute path to the file
    #[serde(default, alias = "filePath")]
    pub file_path: String,
}

// ============================================================================
// Edit types
// ============================================================================

/// Edit range for afterTabFileEdit
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct EditRange {
    /// Starting line number (1-indexed)
    #[serde(default)]
    pub start_line_number: u32,
    /// Starting column
    #[serde(default)]
    pub start_column: u32,
    /// Ending line number
    #[serde(default)]
    pub end_line_number: u32,
    /// Ending column
    #[serde(default)]
    pub end_column: u32,
}

/// Edit info for afterFileEdit
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Edit {
    /// Original string being replaced
    #[serde(default)]
    pub old_string: String,
    /// Replacement string
    #[serde(default)]
    pub new_string: String,
}

/// Extended edit info for afterTabFileEdit
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TabEdit {
    /// Original string being replaced
    #[serde(default)]
    pub old_string: String,
    /// Replacement string
    #[serde(default)]
    pub new_string: String,
    /// Edit range in the file
    #[serde(default)]
    pub range: EditRange,
    /// The line content before the edit
    #[serde(default)]
    pub old_line: String,
    /// The line content after the edit
    #[serde(default)]
    pub new_line: String,
}

// ============================================================================
// Hook event structures
// ============================================================================

/// sessionStart hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Unique session identifier
    #[serde(default)]
    pub session_id: String,
    /// Whether this is a background agent session
    #[serde(default)]
    pub is_background_agent: bool,
    /// Composer mode (agent, ask, or edit)
    #[serde(default)]
    pub mode: ComposerMode,
}

/// sessionEnd hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionEndEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Reason the session ended
    #[serde(default)]
    pub reason: EndReason,
    /// Session duration in milliseconds
    #[serde(default)]
    pub duration_ms: f64,
    /// Whether this was a background agent session
    #[serde(default)]
    pub is_background_agent: bool,
    /// Final status of the session
    #[serde(default)]
    pub final_status: Option<String>,
    /// Error message if any
    #[serde(default)]
    pub error_message: Option<String>,
}

/// beforeShellExecution hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct BeforeShellExecutionEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// The full terminal command to be executed
    #[serde(default)]
    pub command: String,
    /// Current working directory
    #[serde(default)]
    pub cwd: String,
    /// Timeout in milliseconds for the shell command
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// beforeMCPExecution hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct BeforeMCPExecutionEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Name of the MCP tool
    #[serde(default)]
    pub tool_name: String,
    /// JSON params for the tool
    #[serde(default)]
    pub tool_input: String,
    /// Server URL (for remote MCP servers)
    #[serde(default)]
    pub url: Option<String>,
    /// Command string (for local MCP servers)
    #[serde(default)]
    pub command: Option<String>,
}

/// afterShellExecution hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct AfterShellExecutionEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// The full terminal command that was executed
    #[serde(default)]
    pub command: String,
    /// Full output captured from the terminal
    #[serde(default)]
    pub output: String,
    /// Duration in milliseconds
    #[serde(default)]
    pub duration: f64,
}

/// afterMCPExecution hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct AfterMCPExecutionEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Name of the MCP tool
    #[serde(default)]
    pub tool_name: String,
    /// JSON params string passed to the tool
    #[serde(default)]
    pub tool_input: String,
    /// JSON string of the tool response
    #[serde(default)]
    pub result_json: String,
    /// Duration in milliseconds
    #[serde(default)]
    pub duration: f64,
}

/// beforeReadFile hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct BeforeReadFileEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Absolute path to the file
    #[serde(default, alias = "file_path")]
    pub file_path: String,
    /// File contents
    #[serde(default)]
    pub content: String,
    /// Prompt attachments
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

/// afterFileEdit hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct AfterFileEditEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Absolute path to the file
    #[serde(default, alias = "file_path")]
    pub file_path: String,
    /// List of edits made
    #[serde(default)]
    pub edits: Vec<Edit>,
}

/// beforeSubmitPrompt hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct BeforeSubmitPromptEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// User prompt text
    #[serde(default)]
    pub prompt: String,
    /// Prompt attachments
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

/// afterAgentResponse hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct AfterAgentResponseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Assistant's final text response
    #[serde(default)]
    pub text: String,
}

/// afterAgentThought hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct AfterAgentThoughtEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Fully aggregated thinking text
    #[serde(default)]
    pub text: String,
    /// Duration in milliseconds for the thinking block
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

/// stop hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct StopEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Status of the agent loop
    #[serde(default)]
    pub status: StopStatus,
    /// Number of times stop hook has triggered auto follow-up
    #[serde(default)]
    pub loop_count: u32,
}

// ============================================================================
// Subagent hooks
// ============================================================================

/// Subagent type for subagentStart/subagentStop hooks
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SubagentType {
    /// General purpose subagent
    #[default]
    GeneralPurpose,
    /// Explore subagent
    Explore,
    /// Shell subagent
    Shell,
    /// Unknown subagent type
    #[serde(other)]
    Unknown,
}

/// subagentStart hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SubagentStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Type of subagent being started
    #[serde(default)]
    pub subagent_type: SubagentType,
    /// Prompt for the subagent
    #[serde(default)]
    pub prompt: String,
}

/// Subagent stop status
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SubagentStatus {
    /// Subagent completed successfully
    #[default]
    Completed,
    /// Subagent encountered an error
    Error,
    /// Unknown status
    #[serde(other)]
    Unknown,
}

/// subagentStop hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct SubagentStopEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Type of subagent that stopped
    #[serde(default)]
    pub subagent_type: SubagentType,
    /// Status of the subagent (completed or error)
    #[serde(default)]
    pub status: SubagentStatus,
    /// Output/result from the subagent
    #[serde(default)]
    pub result: String,
    /// Execution time in milliseconds
    #[serde(default)]
    pub duration: f64,
    /// Path to the subagent's transcript file
    #[serde(default)]
    pub agent_transcript_path: Option<String>,
}

// ============================================================================
// Compaction hook
// ============================================================================

/// Compact trigger type
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CompactTrigger {
    /// Automatic compaction
    #[default]
    Auto,
    /// Manual compaction
    Manual,
    /// Unknown trigger
    #[serde(other)]
    Unknown,
}

/// preCompact hook event data
#[derive(Debug, Deserialize, Serialize)]
pub struct PreCompactEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// What triggered the compaction: "auto" or "manual"
    #[serde(default)]
    pub trigger: CompactTrigger,
    /// Current context window usage as a percentage (0-100)
    #[serde(default)]
    pub context_usage_percent: f64,
    /// Current context window token count
    #[serde(default)]
    pub context_tokens: u64,
    /// Maximum context window size in tokens
    #[serde(default)]
    pub context_window_size: u64,
    /// Number of messages in the conversation
    #[serde(default)]
    pub message_count: u32,
    /// Number of messages that will be summarized
    #[serde(default)]
    pub messages_to_compact: u32,
    /// Whether this is the first compaction for this conversation
    #[serde(default)]
    pub is_first_compaction: bool,
}

// ============================================================================
// Tab-specific hook events
// ============================================================================

/// beforeTabFileRead hook event data (Tab-specific)
#[derive(Debug, Deserialize, Serialize)]
pub struct BeforeTabFileReadEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Absolute path to the file
    #[serde(default, alias = "file_path")]
    pub file_path: String,
    /// File contents
    #[serde(default)]
    pub content: String,
}

/// afterTabFileEdit hook event data (Tab-specific)
#[derive(Debug, Deserialize, Serialize)]
pub struct AfterTabFileEditEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Absolute path to the file
    #[serde(default, alias = "file_path")]
    pub file_path: String,
    /// List of edits with extended info
    #[serde(default)]
    pub edits: Vec<TabEdit>,
}

// ============================================================================
// Generic tool hooks (preToolUse/postToolUse)
// ============================================================================

/// preToolUse hook event data - generic pre-execution hook for all tools
#[derive(Debug, Deserialize, Serialize)]
pub struct PreToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Name of the tool being invoked
    #[serde(default)]
    pub tool_name: String,
    /// JSON input for the tool
    #[serde(default)]
    pub tool_input: serde_json::Value,
    /// Unique identifier for this tool use
    #[serde(default)]
    pub tool_use_id: String,
    /// Current working directory
    #[serde(default)]
    pub cwd: String,
    /// Agent message associated with the tool use
    #[serde(default)]
    pub agent_message: Option<String>,
}

/// postToolUse hook event data - generic post-execution hook for all tools
#[derive(Debug, Deserialize, Serialize)]
pub struct PostToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Name of the tool that was invoked
    #[serde(default)]
    pub tool_name: String,
    /// JSON input that was passed to the tool
    #[serde(default)]
    pub tool_input: serde_json::Value,
    /// Tool output (string or JSON)
    #[serde(default)]
    pub tool_output: serde_json::Value,
    /// Unique identifier for this tool use
    #[serde(default)]
    pub tool_use_id: String,
    /// Duration in milliseconds
    #[serde(default)]
    pub duration: f64,
}

/// postToolUseFailure hook event data - hook for failed tool executions
#[derive(Debug, Deserialize, Serialize)]
pub struct PostToolUseFailureEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Name of the tool that failed
    #[serde(default)]
    pub tool_name: String,
    /// JSON input that was passed to the tool
    #[serde(default)]
    pub tool_input: serde_json::Value,
    /// Unique identifier for this tool use
    #[serde(default)]
    pub tool_use_id: String,
    /// Error message
    #[serde(default)]
    pub error_message: String,
    /// Type of failure
    #[serde(default)]
    pub failure_type: Option<String>,
    /// Whether the failure was caused by an interrupt
    #[serde(default)]
    pub is_interrupt: bool,
    /// Duration in milliseconds before failure
    #[serde(default)]
    pub duration: f64,
}

// ============================================================================
// Validation implementations
// ============================================================================

impl BeforeShellExecutionEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.command.trim().is_empty() {
            bail!("command cannot be empty");
        }
        Ok(())
    }
}

impl BeforeMCPExecutionEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            bail!("tool_name cannot be empty");
        }
        Ok(())
    }
}

impl AfterShellExecutionEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.command.trim().is_empty() {
            bail!("command cannot be empty");
        }
        Ok(())
    }
}

impl AfterMCPExecutionEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            bail!("tool_name cannot be empty");
        }
        Ok(())
    }
}

impl BeforeReadFileEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.file_path.trim().is_empty() {
            bail!("file_path cannot be empty");
        }
        Ok(())
    }
}

impl AfterFileEditEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.file_path.trim().is_empty() {
            bail!("file_path cannot be empty");
        }
        Ok(())
    }
}

impl BeforeSubmitPromptEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        // Prompt can potentially be empty (edge case)
        Ok(())
    }
}

impl StopEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl BeforeTabFileReadEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.file_path.trim().is_empty() {
            bail!("file_path cannot be empty");
        }
        Ok(())
    }
}

impl AfterTabFileEditEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.file_path.trim().is_empty() {
            bail!("file_path cannot be empty");
        }
        Ok(())
    }
}

impl AfterAgentResponseEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl AfterAgentThoughtEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

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

impl PostToolUseFailureEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            bail!("tool_name cannot be empty");
        }
        Ok(())
    }
}

impl SubagentStartEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl SubagentStopEvent {
    /// Validates that required fields are present
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl PreCompactEvent {
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
    fn test_stop_status_parsing() {
        assert_eq!(
            "completed".parse::<StopStatus>().unwrap(),
            StopStatus::Completed
        );
        assert_eq!(
            "aborted".parse::<StopStatus>().unwrap(),
            StopStatus::Aborted
        );
        assert_eq!("error".parse::<StopStatus>().unwrap(), StopStatus::Error);
        assert!("invalid".parse::<StopStatus>().is_err());
    }

    #[test]
    fn test_before_shell_execution_deserialization() {
        let json = r#"{
            "conversation_id": "conv-123",
            "generation_id": "gen-456",
            "model": "gpt-4",
            "hook_event_name": "beforeShellExecution",
            "cursor_version": "1.7.2",
            "workspace_roots": ["/home/user/project"],
            "user_email": "user@example.com",
            "command": "npm install",
            "cwd": "/home/user/project"
        }"#;
        let event: BeforeShellExecutionEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.command, "npm install");
        assert_eq!(event.cwd, "/home/user/project");
        assert_eq!(event.common.conversation_id, "conv-123");
        assert_eq!(event.common.model, "gpt-4");
    }

    #[test]
    fn test_before_mcp_execution_deserialization() {
        let json = r#"{
            "conversation_id": "conv-123",
            "generation_id": "gen-456",
            "model": "gpt-4",
            "hook_event_name": "beforeMCPExecution",
            "cursor_version": "1.7.2",
            "workspace_roots": [],
            "tool_name": "read_file",
            "tool_input": "{\"path\": \"/tmp/test.txt\"}",
            "url": "http://localhost:3000"
        }"#;
        let event: BeforeMCPExecutionEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.tool_name, "read_file");
        assert_eq!(event.url, Some("http://localhost:3000".to_string()));
    }

    #[test]
    fn test_after_shell_execution_deserialization() {
        let json = r#"{
            "conversation_id": "conv-123",
            "generation_id": "gen-456",
            "model": "gpt-4",
            "hook_event_name": "afterShellExecution",
            "cursor_version": "1.7.2",
            "workspace_roots": [],
            "command": "echo hello",
            "output": "hello\n",
            "duration": 150.5
        }"#;
        let event: AfterShellExecutionEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.command, "echo hello");
        assert_eq!(event.output, "hello\n");
        assert_eq!(event.duration, 150.5);
    }

    #[test]
    fn test_after_file_edit_deserialization() {
        let json = r#"{
            "conversation_id": "conv-123",
            "generation_id": "gen-456",
            "model": "gpt-4",
            "hook_event_name": "afterFileEdit",
            "cursor_version": "1.7.2",
            "workspace_roots": [],
            "file_path": "/home/user/project/src/main.rs",
            "edits": [
                {"old_string": "fn main() {}", "new_string": "fn main() { println!(\"Hello!\"); }"}
            ]
        }"#;
        let event: AfterFileEditEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.file_path, "/home/user/project/src/main.rs");
        assert_eq!(event.edits.len(), 1);
        assert_eq!(event.edits[0].old_string, "fn main() {}");
    }

    #[test]
    fn test_before_submit_prompt_deserialization() {
        let json = r#"{
            "conversation_id": "conv-123",
            "generation_id": "gen-456",
            "model": "gpt-4",
            "hook_event_name": "beforeSubmitPrompt",
            "cursor_version": "1.7.2",
            "workspace_roots": [],
            "prompt": "Fix the bug in main.rs",
            "attachments": [
                {"type": "file", "filePath": "/home/user/project/src/main.rs"}
            ]
        }"#;
        let event: BeforeSubmitPromptEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.prompt, "Fix the bug in main.rs");
        assert_eq!(event.attachments.len(), 1);
        assert_eq!(event.attachments[0].attachment_type, AttachmentType::File);
    }

    #[test]
    fn test_stop_event_deserialization() {
        let json = r#"{
            "conversation_id": "conv-123",
            "generation_id": "gen-456",
            "model": "gpt-4",
            "hook_event_name": "stop",
            "cursor_version": "1.7.2",
            "workspace_roots": [],
            "status": "completed",
            "loop_count": 0
        }"#;
        let event: StopEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.status, StopStatus::Completed);
        assert_eq!(event.loop_count, 0);
    }

    #[test]
    fn test_after_tab_file_edit_deserialization() {
        let json = r#"{
            "conversation_id": "conv-123",
            "generation_id": "gen-456",
            "model": "gpt-4",
            "hook_event_name": "afterTabFileEdit",
            "cursor_version": "1.7.2",
            "workspace_roots": [],
            "file_path": "/home/user/project/src/main.rs",
            "edits": [
                {
                    "old_string": "let x = 1",
                    "new_string": "let x = 42",
                    "range": {
                        "start_line_number": 10,
                        "start_column": 5,
                        "end_line_number": 10,
                        "end_column": 14
                    },
                    "old_line": "    let x = 1;",
                    "new_line": "    let x = 42;"
                }
            ]
        }"#;
        let event: AfterTabFileEditEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.file_path, "/home/user/project/src/main.rs");
        assert_eq!(event.edits.len(), 1);
        assert_eq!(event.edits[0].range.start_line_number, 10);
    }

    #[test]
    fn test_unknown_stop_status() {
        let unknown_status: StopStatus = serde_json::from_str("\"invalid\"").unwrap();
        assert_eq!(unknown_status, StopStatus::Unknown);
    }

    #[test]
    fn test_validation_functions() {
        // Test BeforeShellExecutionEvent validation
        let valid_event = BeforeShellExecutionEvent {
            common: CommonInput::default(),
            command: "echo hello".to_string(),
            cwd: "/tmp".to_string(),
            timeout: None,
        };
        assert!(valid_event.validate().is_ok());

        let invalid_event = BeforeShellExecutionEvent {
            common: CommonInput::default(),
            command: "".to_string(),
            cwd: "/tmp".to_string(),
            timeout: None,
        };
        assert!(invalid_event.validate().is_err());

        // Test BeforeMCPExecutionEvent validation
        let valid_mcp = BeforeMCPExecutionEvent {
            common: CommonInput::default(),
            tool_name: "read_file".to_string(),
            tool_input: "{}".to_string(),
            url: None,
            command: None,
        };
        assert!(valid_mcp.validate().is_ok());

        let invalid_mcp = BeforeMCPExecutionEvent {
            common: CommonInput::default(),
            tool_name: "".to_string(),
            tool_input: "{}".to_string(),
            url: None,
            command: None,
        };
        assert!(invalid_mcp.validate().is_err());
    }

    #[test]
    fn test_after_agent_thought_deserialization() {
        let json = r#"{
            "conversation_id": "conv-123",
            "generation_id": "gen-456",
            "model": "gpt-4",
            "hook_event_name": "afterAgentThought",
            "cursor_version": "1.7.2",
            "workspace_roots": [],
            "text": "I need to analyze the code structure first...",
            "duration_ms": 5000
        }"#;
        let event: AfterAgentThoughtEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.text, "I need to analyze the code structure first...");
        assert_eq!(event.duration_ms, Some(5000));
    }
}
