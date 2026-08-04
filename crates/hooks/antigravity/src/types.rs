//! Type definitions for Antigravity CLI hook events.
//!
//! Antigravity delivers hook input on stdin as JSON with **camelCase** field
//! names. All events share a common metadata block (`conversationId`,
//! `workspacePaths`, `transcriptPath`, `artifactDirectoryPath`). Types are
//! resilient to missing fields via `#[serde(default)]`.
//!
//! Reference: <https://antigravity.google/docs/hooks>

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sondera_hooks::error::{HookError, Result};

/// System metadata present in every hook input payload.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommonInput {
    /// UUID of the active agent conversation. Used as the trajectory id.
    #[serde(default)]
    pub conversation_id: String,
    /// Absolute paths of the user's mounted workspaces.
    #[serde(default)]
    pub workspace_paths: Vec<String>,
    /// Absolute path to the persistent `transcript.jsonl` log.
    #[serde(default)]
    pub transcript_path: Option<String>,
    /// Absolute path to the conversation artifacts/screenshots directory.
    #[serde(default)]
    pub artifact_directory_path: Option<String>,
}

/// A proposed tool call carried by `PreToolUse`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolCall {
    /// Tool name (e.g. `run_command`). Matches the installer's `matcher`.
    #[serde(default)]
    pub name: String,
    /// Tool arguments. Keys are PascalCase (e.g. `CommandLine`, `TargetFile`).
    #[serde(default)]
    pub args: Value,
}

/// `PreToolUse` — fires before a tool is executed (the adjudicated event).
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Details of the proposed tool call.
    #[serde(default)]
    pub tool_call: ToolCall,
    /// 0-based index of the current step in the trajectory.
    #[serde(default)]
    pub step_idx: i64,
}

/// `PostToolUse` — fires after a tool completes (observation only).
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// 0-based index of the completed step.
    #[serde(default)]
    pub step_idx: i64,
    /// Runtime error message if the tool call failed; empty/absent if it
    /// succeeded.
    #[serde(default)]
    pub error: Option<String>,
}

/// `PreInvocation` — fires before the model is called (advisory).
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreInvocationEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Sequence number of the current model invocation.
    #[serde(default)]
    pub invocation_num: i64,
    /// Number of steps currently in the trajectory.
    #[serde(default)]
    pub initial_num_steps: i64,
}

/// `PostInvocation` — fires after tool calls finish (advisory). Same input
/// fields as `PreInvocation`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostInvocationEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub invocation_num: i64,
    #[serde(default)]
    pub initial_num_steps: i64,
}

/// `Stop` — fires when the execution loop terminates.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    /// Sequence number of the execution attempt.
    #[serde(default)]
    pub execution_num: i64,
    /// Why execution is stopping (e.g. `model_stop`, `max_steps_exceeded`).
    #[serde(default)]
    pub termination_reason: String,
    /// Error message if termination was caused by a system error.
    #[serde(default)]
    pub error: Option<String>,
    /// True if the agent is completely finished and all background tasks
    /// completed.
    #[serde(default)]
    pub fully_idle: bool,
}

impl PreToolUseEvent {
    /// Require a non-empty `conversationId` (used verbatim as the harness
    /// trajectory id — an empty default would collapse unrelated sessions onto
    /// one blank trajectory) and a non-empty tool name (what we adjudicate on).
    pub fn validate(&self) -> Result<()> {
        if self.common.conversation_id.trim().is_empty() {
            return Err(HookError::message("conversationId cannot be empty"));
        }
        if self.tool_call.name.trim().is_empty() {
            return Err(HookError::message("toolCall.name cannot be empty"));
        }
        Ok(())
    }
}

impl PostToolUseEvent {
    /// Require a non-empty `conversationId` — it is recorded as the trajectory
    /// id, so a blank value would pollute the trajectory store (see
    /// [`PreToolUseEvent::validate`]).
    pub fn validate(&self) -> Result<()> {
        if self.common.conversation_id.trim().is_empty() {
            return Err(HookError::message("conversationId cannot be empty"));
        }
        Ok(())
    }
}

impl PreInvocationEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl PostInvocationEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl StopEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Inputs below are the verbatim examples from the Antigravity hooks docs.

    #[test]
    fn pre_tool_use_doc_example_deserializes() {
        let json = r#"{
            "toolCall": {
                "name": "run_command",
                "args": { "CommandLine": "npm test", "Cwd": "/workspace/project", "WaitMsBeforeAsync": 5000 }
            },
            "stepIdx": 19,
            "conversationId": "ec33ebf9-0cba-4100-8142-c61503f6c587",
            "workspacePaths": ["/workspace/project"],
            "transcriptPath": "/workspace/project/.gemini/antigravity/transcript.jsonl",
            "artifactDirectoryPath": "/workspace/project/.gemini/antigravity/artifacts"
        }"#;
        let e: PreToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(e.tool_call.name, "run_command");
        assert_eq!(e.tool_call.args["CommandLine"], "npm test");
        assert_eq!(e.step_idx, 19);
        assert_eq!(
            e.common.conversation_id,
            "ec33ebf9-0cba-4100-8142-c61503f6c587"
        );
        assert_eq!(e.common.workspace_paths, vec!["/workspace/project"]);
        assert!(e.validate().is_ok());
    }

    #[test]
    fn pre_tool_use_empty_name_fails_validation() {
        let e: PreToolUseEvent =
            serde_json::from_str(r#"{"conversationId":"c1","toolCall":{"name":""}}"#).unwrap();
        assert!(e.validate().is_err());
    }

    #[test]
    fn pre_tool_use_missing_conversation_id_fails_validation() {
        // conversationId omitted → serde default "" → must be rejected so events
        // don't collapse onto one blank trajectory id.
        let e: PreToolUseEvent =
            serde_json::from_str(r#"{"toolCall":{"name":"run_command"}}"#).unwrap();
        assert!(e.common.conversation_id.is_empty());
        assert!(e.validate().is_err());
    }

    #[test]
    fn post_tool_use_missing_conversation_id_fails_validation() {
        let e: PostToolUseEvent = serde_json::from_str(r#"{"stepIdx":5}"#).unwrap();
        assert!(e.validate().is_err());
    }

    #[test]
    fn post_tool_use_doc_example_deserializes() {
        let json = r#"{
            "stepIdx": 5,
            "error": "exit status 1",
            "conversationId": "ec33ebf9-0cba-4100-8142-c61503f6c587",
            "workspacePaths": ["/workspace/project"],
            "transcriptPath": "/workspace/project/.gemini/antigravity/transcript.jsonl",
            "artifactDirectoryPath": "/workspace/project/.gemini/antigravity/artifacts"
        }"#;
        let e: PostToolUseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(e.step_idx, 5);
        assert_eq!(e.error.as_deref(), Some("exit status 1"));
    }

    #[test]
    fn pre_invocation_doc_example_deserializes() {
        let json = r#"{
            "invocationNum": 3,
            "initialNumSteps": 10,
            "conversationId": "ec33ebf9-0cba-4100-8142-c61503f6c587",
            "workspacePaths": ["/workspace/project"]
        }"#;
        let e: PreInvocationEvent = serde_json::from_str(json).unwrap();
        assert_eq!(e.invocation_num, 3);
        assert_eq!(e.initial_num_steps, 10);
    }

    #[test]
    fn stop_doc_example_deserializes() {
        let json = r#"{
            "executionNum": 1,
            "terminationReason": "model_stop",
            "error": "",
            "fullyIdle": true,
            "conversationId": "ec33ebf9-0cba-4100-8142-c61503f6c587",
            "workspacePaths": ["/workspace/project"]
        }"#;
        let e: StopEvent = serde_json::from_str(json).unwrap();
        assert_eq!(e.execution_num, 1);
        assert_eq!(e.termination_reason, "model_stop");
        assert!(e.fully_idle);
    }
}
