//! Observation events: environment responses and agent observations.
//!
//! Observations are what the agent perceives in response to its actions or
//! from its environment: prompts, internal reasoning, and the outputs of tool
//! calls, shell commands, web fetches, and file operations. They are one of the
//! four [`TrajectoryEvent`] categories.
//!
//! [`TrajectoryEvent`]: super::TrajectoryEvent

use serde::{Deserialize, Serialize};
use strum_macros::Display;

/// Environment responses and agent observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum Observation {
    Prompt(Prompt),
    Thought(Thought),
    ToolOutput(ToolOutput),
    ShellCommandOutput(ShellCommandOutput),
    WebFetchOutput(WebFetchOutput),
    FileOperationResult(FileOperationResult),
}

/// User or system prompt input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Prompt {
    pub content: String,
    pub role: PromptRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
pub enum PromptRole {
    User,
    System,
    Assistant,
}

impl Prompt {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            role: PromptRole::User,
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            role: PromptRole::System,
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            role: PromptRole::Assistant,
        }
    }
}

/// Internal reasoning (no side effects).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Thought {
    pub thought: String,
}

impl Thought {
    pub fn new(thought: impl Into<String>) -> Self {
        Self {
            thought: thought.into(),
        }
    }
}

/// Generic tool output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolOutput {
    pub call_id: String,
    pub success: bool,
    pub output: serde_json::Value,
    pub error: Option<String>,
}

impl ToolOutput {
    pub fn success(call_id: impl Into<String>, output: impl Into<serde_json::Value>) -> Self {
        Self {
            call_id: call_id.into(),
            success: true,
            output: output.into(),
            error: None,
        }
    }

    pub fn error(call_id: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            success: false,
            output: serde_json::Value::Null,
            error: Some(error.into()),
        }
    }
}

/// Shell command output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellCommandOutput {
    pub call_id: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ShellCommandOutput {
    pub fn new(
        call_id: impl Into<String>,
        exit_code: i32,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            exit_code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }
}

/// Web fetch output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebFetchOutput {
    pub call_id: String,
    pub url: String,
    pub code: i32,
    pub result: String,
}

impl WebFetchOutput {
    pub fn new(
        call_id: impl Into<String>,
        url: impl Into<String>,
        code: i32,
        result: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            url: url.into(),
            code,
            result: result.into(),
        }
    }
}

/// File operation result.
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileOperationResult {
    pub call_id: String,
    pub success: bool,
    pub path: Option<String>,
    pub content: Option<String>,
    pub error: Option<String>,
}

impl FileOperationResult {
    pub fn success(call_id: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            success: true,
            path: None,
            content: None,
            error: None,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_content(mut self, content: impl Into<String>) -> Self {
        self.content = Some(content.into());
        self
    }

    pub fn error(call_id: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            success: false,
            path: None,
            content: None,
            error: Some(error.into()),
        }
    }
}
