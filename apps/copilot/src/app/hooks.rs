//! Hook handler implementations for GitHub Copilot events.
//!
//! This module contains all the business logic for handling different types
//! of hook events from GitHub Copilot, including tool execution, prompt submission,
//! session management, and error handling.

use super::response::HookResponse;
use super::types::*;
use anyhow::Result;

use sondera_harness::{
    Action, Actor, Agent, Control, Decision, Event, FileOpType, FileOperation, FileOperationResult,
    Harness, Observation, Prompt, ShellCommand, ShellCommandOutput, Started, ToolCall, ToolOutput,
    TrajectoryEvent,
};
use tracing::{debug, info, warn};

pub struct Hooks<H: Harness> {
    harness: H,
    agent: Agent,
}

impl<H: Harness> Hooks<H> {
    /// Create a new Hooks instance
    pub fn new(harness: H, agent_id: String) -> Self {
        let agent = Agent {
            id: agent_id,
            provider_id: "copilot".to_string(),
        };
        Self { harness, agent }
    }

    /// Create an Event with the current agent
    fn event(&self, trajectory_id: &str, event: TrajectoryEvent) -> Event {
        Event::new(self.agent.clone(), trajectory_id, event)
    }

    /// Get a session key from the event. Uses session_id if provided, otherwise falls back to cwd.
    fn get_session_key(session_id: &Option<String>, cwd: &str) -> String {
        session_id
            .as_ref()
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| cwd.to_string())
    }

    // ============================================================================
    // Session lifecycle hooks
    // ============================================================================

    /// Handle sessionStart hook
    pub async fn handle_session_start(&mut self, event: SessionStartEvent) -> Result<HookResponse> {
        debug!("sessionStart event: {:?}", event);

        let session_key = Self::get_session_key(&event.session_id, &event.common.cwd);

        let started = TrajectoryEvent::Control(Control::Started(Started::new(&self.agent.id)));

        let ev = self
            .event(&session_key, started)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::ok())
    }

    /// Handle sessionEnd hook
    pub async fn handle_session_end(&mut self, event: SessionEndEvent) -> Result<HookResponse> {
        debug!("sessionEnd event: {:?}", event);

        let session_key = Self::get_session_key(&event.session_id, &event.common.cwd);

        info!("Session {} ended (reason: {:?})", session_key, event.reason);

        Ok(HookResponse::ok())
    }

    // ============================================================================
    // User prompt hook
    // ============================================================================

    /// Handle userPromptSubmitted hook
    pub async fn handle_user_prompt_submitted(
        &mut self,
        event: UserPromptSubmittedEvent,
    ) -> Result<HookResponse> {
        debug!("userPromptSubmitted event: {:?}", event);

        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&event.prompt)));

        let ev = self
            .event(&event.common.cwd, prompt)
            .with_actor(Actor::human(&self.agent.id))
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("User prompt allowed");
                HookResponse::ok()
            }
            Decision::Deny => {
                let msg = adjudicated.deny_message("Prompt blocked by policy");
                warn!("User prompt denied: {}", msg);
                HookResponse::block_prompt(msg)
            }
            Decision::Escalate => {
                let msg = adjudicated.deny_message("Prompt escalated for review");
                warn!("User prompt escalated: {}", msg);
                HookResponse::block_prompt(msg)
            }
        };
        Ok(response)
    }

    // ============================================================================
    // Tool execution hooks
    // ============================================================================

    /// Handle preToolUse hook
    pub async fn handle_pre_tool_use(&mut self, event: PreToolUseEvent) -> Result<HookResponse> {
        debug!("preToolUse event: {:?}", event);

        let tool_name = event.tool_name.clone();

        // Parse tool_args if it's valid JSON, otherwise wrap in a string value
        let args = serde_json::from_str::<serde_json::Value>(&event.tool_args)
            .unwrap_or_else(|_| serde_json::json!({ "raw_args": event.tool_args }));

        let action = match tool_name.as_str() {
            "bash" => {
                let command = args
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Action::ShellCommand(ShellCommand {
                    call_id: format!("call-{}", uuid::Uuid::new_v4()),
                    command,
                    working_dir: Some(event.common.cwd.clone()),
                })
            }
            "read_file" | "view" => {
                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Action::FileOperation(FileOperation {
                    call_id: format!("call-{}", uuid::Uuid::new_v4()),
                    operation: FileOpType::Read,
                    path,
                    content: None,
                    old_content: None,
                })
            }
            "edit" | "str_replace" => {
                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let old_content = args
                    .get("old_str")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let content = args
                    .get("new_str")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Action::FileOperation(FileOperation {
                    call_id: format!("call-{}", uuid::Uuid::new_v4()),
                    operation: FileOpType::Edit,
                    path,
                    content,
                    old_content,
                })
            }
            "write_file" | "create" => {
                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let content = args
                    .get("content")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Action::FileOperation(FileOperation {
                    call_id: format!("call-{}", uuid::Uuid::new_v4()),
                    operation: FileOpType::Write,
                    path,
                    content,
                    old_content: None,
                })
            }
            _ => Action::ToolCall(ToolCall {
                call_id: format!("call-{}", uuid::Uuid::new_v4()),
                tool: tool_name.clone(),
                arguments: args,
            }),
        };

        let trajectory_event = TrajectoryEvent::Action(action);

        let ev = self
            .event(&event.common.cwd, trajectory_event)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        // Map the adjudication to a hook response.
        //
        // IMPORTANT: For Allow we return HookResponse::ok() which
        // serializes to `{}`. We must NOT set permissionDecision: "allow"
        // explicitly unless we want to bypass Copilot's normal permission system.
        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Tool '{}' execution allowed", tool_name);
                HookResponse::ok()
            }
            Decision::Deny => {
                let msg = adjudicated
                    .deny_message(&format!("Tool '{tool_name}' execution denied by policy"));
                warn!("Tool '{}' execution denied: {}", tool_name, msg);
                HookResponse::block_tool(msg)
            }
            Decision::Escalate => {
                let msg = adjudicated
                    .deny_message(&format!("Tool '{tool_name}' execution requires approval"));
                info!(
                    "Tool '{}' execution escalated for approval: {}",
                    tool_name, msg
                );
                HookResponse::block_tool(msg)
            }
        };

        Ok(response)
    }

    /// Handle postToolUse hook
    pub async fn handle_post_tool_use(&mut self, event: PostToolUseEvent) -> Result<HookResponse> {
        debug!("postToolUse event: {:?}", event);

        let tool_name = event.tool_name.clone();

        // Parse tool_result if it's valid JSON, otherwise wrap in a string value
        let result_value = serde_json::from_str::<serde_json::Value>(&event.tool_result)
            .unwrap_or_else(|_| {
                serde_json::json!({
                    "output": event.tool_result,
                    "duration": event.duration,
                })
            });

        let tool_output = match tool_name.as_str() {
            "bash" => {
                let exit_code = result_value
                    .get("exit_code")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32;
                let stdout = result_value
                    .get("output")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&event.tool_result)
                    .to_string();
                TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput {
                    call_id: format!("call-{}", uuid::Uuid::new_v4()),
                    exit_code,
                    stdout,
                    stderr: String::new(),
                }))
            }
            "read_file" | "view" => {
                let content = result_value
                    .get("content")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let result = FileOperationResult::success(format!("call-{}", uuid::Uuid::new_v4()));
                let result = if let Some(c) = content {
                    result.with_content(c)
                } else {
                    result
                };
                TrajectoryEvent::Observation(Observation::FileOperationResult(result))
            }
            "edit" | "str_replace" | "write_file" | "create" => {
                let result = FileOperationResult::success(format!("call-{}", uuid::Uuid::new_v4()));
                TrajectoryEvent::Observation(Observation::FileOperationResult(result))
            }
            _ => TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput::success(
                format!("call-{}", uuid::Uuid::new_v4()),
                serde_json::to_string(&result_value).unwrap_or_default(),
            ))),
        };

        let ev = self
            .event(&event.common.cwd, tool_output)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::ok())
    }

    // ============================================================================
    // Error handling hook
    // ============================================================================

    /// Handle errorOccurred hook
    pub async fn handle_error_occurred(
        &mut self,
        event: ErrorOccurredEvent,
    ) -> Result<HookResponse> {
        debug!("errorOccurred event: {:?}", event);

        let error_content = if let Some(code) = &event.error_code {
            format!("[ERROR {}] {}", code, event.error)
        } else {
            format!("[ERROR] {}", event.error)
        };

        warn!("Error occurred: {}", error_content);

        Ok(HookResponse::ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_json(response: &HookResponse) -> String {
        serde_json::to_string(response).unwrap()
    }

    // Guard against the bug where Allow responses bypass Copilot's permission system.
    // HookResponse::ok() MUST serialize to "{}" (empty JSON) so that Copilot falls
    // back to its normal permission behavior.

    #[test]
    fn test_allow_response_serializes_to_empty_json() {
        let json = to_json(&HookResponse::ok());
        assert_eq!(
            json, "{}",
            "HookResponse::ok() must serialize to empty JSON, got: {json}"
        );
    }

    #[test]
    fn test_block_tool_sets_permission_decision() {
        let json = to_json(&HookResponse::block_tool("blocked by policy".to_string()));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("\"deny\""));
        assert!(json.contains("blocked by policy"));
    }

    #[test]
    fn test_block_prompt_sets_permission_decision() {
        let json = to_json(&HookResponse::block_prompt("denied by policy".to_string()));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("\"deny\""));
        assert!(json.contains("denied by policy"));
    }
}
