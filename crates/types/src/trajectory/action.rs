//! Action events: agent-initiated operations.
//!
//! Actions are the side-effecting (or side-effect-intending) operations an
//! agent emits: tool/function calls, shell commands, web fetches, and file
//! system operations. They are one of the four [`TrajectoryEvent`] categories.
//!
//! [`TrajectoryEvent`]: super::TrajectoryEvent

use serde::{Deserialize, Serialize};
use strum_macros::Display;

/// Agent-initiated operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum Action {
    ToolCall(ToolCall),
    ShellCommand(ShellCommand),
    WebFetch(WebFetch),
    FileOperation(FileOperation),
}

/// Generic tool/function invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCall {
    pub call_id: String,
    pub tool: String,
    pub arguments: serde_json::Value,
}

impl ToolCall {
    pub fn new(tool_name: impl Into<String>, arguments: serde_json::Value) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            tool: tool_name.into(),
            arguments,
        }
    }
}

/// Shell command execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellCommand {
    pub call_id: String,
    pub command: String,
    pub working_dir: Option<String>,
}

impl ShellCommand {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            command: command.into(),
            working_dir: None,
        }
    }

    pub fn with_cwd(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }
}

/// Web fetch operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebFetch {
    pub call_id: String,
    pub url: String,
    pub prompt: String,
}

impl WebFetch {
    pub fn new(url: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            url: url.into(),
            prompt: prompt.into(),
        }
    }
}

/// File system operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileOperation {
    pub call_id: String,
    pub operation: FileOpType,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// For edit operations, the content being replaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_content: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
pub enum FileOpType {
    Read,
    Write,
    Edit,
    Delete,
}

impl FileOperation {
    pub fn read(path: impl Into<String>) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            operation: FileOpType::Read,
            path: path.into(),
            content: None,
            old_content: None,
        }
    }

    pub fn write(path: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            operation: FileOpType::Write,
            path: path.into(),
            content: Some(content.into()),
            old_content: None,
        }
    }

    pub fn edit(
        path: impl Into<String>,
        old_content: impl Into<String>,
        new_content: impl Into<String>,
    ) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            operation: FileOpType::Edit,
            path: path.into(),
            content: Some(new_content.into()),
            old_content: Some(old_content.into()),
        }
    }

    pub fn delete(path: impl Into<String>) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            operation: FileOpType::Delete,
            path: path.into(),
            content: None,
            old_content: None,
        }
    }
}
