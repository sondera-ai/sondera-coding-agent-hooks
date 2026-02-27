//! Hook handler implementations for Claude Code events.
//!
//! This module contains all the business logic for handling different types
//! of hook events from Claude Code, including tool use, notifications,
//! session management, and user prompt processing.

use super::response::HookResponse;
use super::types::*;
use anyhow::Result;

use sondera_harness::{
    Action, Actor, Agent, Control, Decision, Event, FileOpType, FileOperation, FileOperationResult,
    Harness, Observation, Prompt, ShellCommand, ShellCommandOutput, Started, ToolCall, ToolOutput,
    TrajectoryEvent, WebFetch, WebFetchOutput,
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
            provider_id: "claude".to_string(),
        };
        Self { harness, agent }
    }

    /// Create an Event with the current agent
    fn event(&self, trajectory_id: &str, event: TrajectoryEvent) -> Event {
        Event::new(self.agent.clone(), trajectory_id, event)
    }

    // ============================================================================
    // Session lifecycle hooks
    // ============================================================================

    /// Handle sessionStart hook
    pub async fn handle_session_start(&mut self, event: SessionStartEvent) -> Result<HookResponse> {
        debug!("sessionStart event: {:?}", event);

        let started = TrajectoryEvent::Control(Control::Started(Started::new(&self.agent.id)));

        let ev = self
            .event(&event.session_id, started)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::session_start_with_context("".to_string()))
    }

    /// Handle sessionEnd hook
    pub async fn handle_session_end(&mut self, event: SessionEndEvent) -> Result<HookResponse> {
        debug!("sessionEnd event: {:?}", event);

        info!(
            "Session {} ended (reason: {:?})",
            event.session_id, event.reason
        );

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // Tool execution hooks
    // ============================================================================

    /// Handle preToolUse hook
    pub async fn handle_pre_tool_use(&mut self, event: PreToolUseEvent) -> Result<HookResponse> {
        debug!("preToolUse event: {:?}", event);

        let tool_name = event.tool_name.clone();

        let action = match tool_name.as_str() {
            "Bash" => {
                let command = event
                    .tool_input
                    .get("command")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!("Bash tool_input missing required 'command' field")
                    })?
                    .to_string();
                Action::ShellCommand(ShellCommand {
                    call_id: event.tool_use_id.clone(),
                    command,
                    working_dir: Some(event.cwd.clone()),
                })
            }
            "Read" => {
                let path = event
                    .tool_input
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!("Read tool_input missing required 'file_path' field")
                    })?
                    .to_string();
                Action::FileOperation(FileOperation {
                    call_id: event.tool_use_id.clone(),
                    operation: FileOpType::Read,
                    path,
                    content: None,
                    old_content: None,
                })
            }
            "Edit" => {
                let path = event
                    .tool_input
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!("Edit tool_input missing required 'file_path' field")
                    })?
                    .to_string();
                let old_content = event
                    .tool_input
                    .get("old_string")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let content = event
                    .tool_input
                    .get("new_string")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Action::FileOperation(FileOperation {
                    call_id: event.tool_use_id.clone(),
                    operation: FileOpType::Edit,
                    path,
                    content,
                    old_content,
                })
            }
            "Write" => {
                let path = event
                    .tool_input
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!("Write tool_input missing required 'file_path' field")
                    })?
                    .to_string();
                let content = event
                    .tool_input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Action::FileOperation(FileOperation {
                    call_id: event.tool_use_id.clone(),
                    operation: FileOpType::Write,
                    path,
                    content,
                    old_content: None,
                })
            }
            "WebFetch" => {
                let url = event
                    .tool_input
                    .get("url")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!("WebFetch tool_input missing required 'url' field")
                    })?
                    .to_string();
                let prompt = event
                    .tool_input
                    .get("prompt")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!("WebFetch tool_input missing required 'prompt' field")
                    })?
                    .to_string();
                Action::WebFetch(WebFetch {
                    call_id: event.tool_use_id.clone(),
                    url,
                    prompt,
                })
            }
            _ => Action::ToolCall(ToolCall {
                call_id: event.tool_use_id.clone(),
                tool: tool_name.clone(),
                arguments: event.tool_input.clone(),
            }),
        };

        let trajectory_event = TrajectoryEvent::Action(action);

        let ev = self
            .event(&event.session_id, trajectory_event)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        // Map the adjudication to a hook response.
        //
        // IMPORTANT: For Allow we return HookResponse::allow() which
        // serializes to `{}`. We must NOT set hookSpecificOutput with permissionDecision:
        // "allow", because that would bypass Claude Code's normal permission system —
        // auto-approving tool calls without ever prompting the user.
        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Tool '{}' execution allowed", tool_name);
                HookResponse::allow()
            }
            Decision::Deny => {
                let msg = adjudicated
                    .deny_message(&format!("Tool '{tool_name}' execution denied by policy"));
                warn!("Tool '{}' execution denied: {}", tool_name, msg);
                HookResponse::pre_tool_deny(msg)
            }
            Decision::Escalate => {
                let msg = adjudicated
                    .deny_message(&format!("Tool '{tool_name}' execution requires approval"));
                info!(
                    "Tool '{}' execution escalated for approval: {}",
                    tool_name, msg
                );
                HookResponse::pre_tool_ask(msg)
            }
        };

        Ok(response)
    }

    /// Handle permissionRequest hook
    pub async fn handle_permission_request(
        &mut self,
        event: PermissionRequestEvent,
    ) -> Result<HookResponse> {
        debug!("permissionRequest event: {:?}", event);

        let tool_name = event.tool_name.clone();

        // Use _permission suffix so the Cedar harness can map to PermissionRequest action
        let tool_call = TrajectoryEvent::Action(Action::ToolCall(ToolCall {
            call_id: event.tool_use_id.clone(),
            tool: format!("{}_permission", tool_name),
            arguments: event.tool_input.clone(),
        }));

        let ev = self
            .event(&event.session_id, tool_call)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        // Map the adjudication to a hook response.
        //
        // IMPORTANT: For Allow we return HookResponse::allow() which
        // serializes to `{}`. We must NOT set hookSpecificOutput with behavior: "allow",
        // because that would bypass Claude Code's normal permission system.
        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Permission for tool '{}' allowed", tool_name);
                HookResponse::allow()
            }
            Decision::Deny | Decision::Escalate => {
                let msg = adjudicated.deny_message(&format!(
                    "Permission for tool '{tool_name}' denied by policy"
                ));
                warn!("Permission for tool '{}' denied: {}", tool_name, msg);
                HookResponse::permission_deny(msg)
            }
        };

        Ok(response)
    }

    /// Handle postToolUse hook
    pub async fn handle_post_tool_use(&mut self, event: PostToolUseEvent) -> Result<HookResponse> {
        debug!("postToolUse event: {:?}", event);

        let observation = match event.tool_name.as_str() {
            "Bash" => {
                let stdout = event
                    .tool_response
                    .get("stdout")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let stderr = event
                    .tool_response
                    .get("stderr")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let interrupted = event
                    .tool_response
                    .get("interrupted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let exit_code = if interrupted { -1 } else { 0 };

                Observation::ShellCommandOutput(ShellCommandOutput::new(
                    &event.tool_use_id,
                    exit_code,
                    stdout,
                    stderr,
                ))
            }
            "WebFetch" => {
                let url = event
                    .tool_response
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let code = event
                    .tool_response
                    .get("code")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32;
                let result = event
                    .tool_response
                    .get("result")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                Observation::WebFetchOutput(WebFetchOutput::new(
                    &event.tool_use_id,
                    url,
                    code,
                    result,
                ))
            }
            "Read" | "Edit" | "Write" => {
                let content = event
                    .tool_response
                    .get("file")
                    .and_then(|f| f.get("content"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let mut result = FileOperationResult::success(&event.tool_use_id);
                if let Some(content) = content {
                    result = result.with_content(content);
                }

                Observation::FileOperationResult(result)
            }
            _ => Observation::ToolOutput(ToolOutput::success(
                &event.tool_use_id,
                event.tool_response.clone(),
            )),
        };

        let tool_output = TrajectoryEvent::Observation(observation);

        let ev = self
            .event(&event.session_id, tool_output)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // Notification hook
    // ============================================================================

    /// Handle notification events
    pub fn handle_notification(&self, event: NotificationEvent) -> Result<HookResponse> {
        let notification_type = event.notification_type;
        let message = event.message;
        let session_id = event.session_id;

        info!(
            "Processing notification: {:?} (session: {:?})",
            notification_type, session_id
        );

        match notification_type {
            NotificationType::PermissionPrompt => {
                info!("Permission prompt notification: {}", message);
            }
            NotificationType::IdlePrompt => {
                info!("Idle prompt notification: {}", message);
            }
            NotificationType::AuthSuccess => {
                info!("Auth success notification: {}", message);
            }
            NotificationType::ElicitationDialog => {
                info!("Elicitation dialog notification: {}", message);
            }
            NotificationType::Unknown => {
                warn!("Unknown notification type received: {}", message);
            }
        }

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // User prompt hook
    // ============================================================================

    /// Handle userPromptSubmit hook
    pub async fn handle_user_prompt_submit(
        &mut self,
        event: UserPromptSubmitEvent,
    ) -> Result<HookResponse> {
        debug!("userPromptSubmit event: {:?}", event);

        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&event.prompt)));

        let ev = self
            .event(&event.session_id, prompt)
            .with_actor(Actor::human(&self.agent.id))
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("User prompt allowed");
                HookResponse::allow()
            }
            Decision::Deny => {
                let msg = adjudicated.deny_message("Prompt blocked by policy");
                warn!("User prompt denied: {}", msg);
                HookResponse::prompt_block(msg)
            }
            Decision::Escalate => {
                let msg = adjudicated.deny_message("Prompt escalated for review");
                warn!("User prompt escalated: {}", msg);
                HookResponse::prompt_with_context(msg)
            }
        };
        Ok(response)
    }

    // ============================================================================
    // Stop hooks
    // ============================================================================

    /// Handle stop hook
    pub fn handle_stop(&self, event: StopEvent) -> Result<HookResponse> {
        let session_id = &event.session_id;
        let stop_hook_active = event.stop_hook_active;

        info!(
            "Processing stop event (session: {}, stop_hook_active: {})",
            session_id, stop_hook_active
        );

        if stop_hook_active {
            // Hook is already active from a previous stop hook - allow stopping to prevent infinite loop
            info!("Stop hook is already active. Allowing stop to prevent infinite loop");
            return Ok(HookResponse::allow());
        }

        // Perform graceful cleanup
        info!("Performing graceful cleanup before stop");

        Ok(HookResponse::allow())
    }

    /// Handle subagentStart hook
    pub async fn handle_subagent_start(
        &mut self,
        event: SubagentStartEvent,
    ) -> Result<HookResponse> {
        debug!("subagentStart event: {:?}", event);

        info!(
            "Processing subagent start (session: {}, agent_id: {}, agent_type: {})",
            event.session_id, event.agent_id, event.agent_type
        );

        // Record the subagent start as a Control::Started event for the subagent
        // Use the subagent's ID as the agent for this event
        let subagent = Agent {
            id: event.agent_id.clone(),
            provider_id: "claude".to_string(),
        };
        let started = TrajectoryEvent::Control(Control::Started(Started::new(&event.agent_id)));

        let ev = Event::new(subagent, &event.session_id, started)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        // SubagentStart hooks cannot block subagent creation, but can inject context
        Ok(HookResponse::allow())
    }

    /// Handle subagentStop hook
    pub fn handle_subagent_stop(&self, event: SubagentStopEvent) -> Result<HookResponse> {
        let session_id = &event.session_id;
        let stop_hook_active = event.stop_hook_active;

        info!(
            "Processing subagent stop (session: {}, agent_id: {}, agent_type: {}, stop_hook_active: {})",
            session_id, event.agent_id, event.agent_type, stop_hook_active
        );

        if stop_hook_active {
            // Hook is already active from a previous stop hook - allow stopping to prevent infinite loop
            info!("Subagent stop hook is already active. Allowing stop to prevent infinite loop");
            return Ok(HookResponse::allow());
        }

        // Add subagent cleanup logic here

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // Team hooks (TeammateIdle, TaskCompleted)
    // ============================================================================

    /// Handle teammateIdle hook
    ///
    /// This fires when an agent team teammate is about to go idle after finishing its turn.
    /// Exit code 2 (blocking error) causes the teammate to receive feedback and continue working.
    pub fn handle_teammate_idle(&self, event: TeammateIdleEvent) -> Result<HookResponse> {
        info!(
            "Processing teammate idle (session: {}, teammate: {}, team: {})",
            event.session_id, event.teammate_name, event.team_name
        );

        // TeammateIdle hooks use exit codes only, not JSON decision control.
        // To block idle and continue working, the hook would need to return exit code 2.
        // For now, we allow the teammate to go idle.
        Ok(HookResponse::allow())
    }

    /// Handle taskCompleted hook
    ///
    /// This fires when a task is being marked as completed. Exit code 2 blocks
    /// the task from being marked complete and provides feedback to the model.
    pub fn handle_task_completed(&self, event: TaskCompletedEvent) -> Result<HookResponse> {
        info!(
            "Processing task completed (session: {}, task_id: {}, subject: {})",
            event.session_id, event.task_id, event.task_subject
        );

        if let Some(ref teammate) = event.teammate_name {
            info!("Task completed by teammate: {}", teammate);
        }

        if let Some(ref team) = event.team_name {
            info!("Task completed in team: {}", team);
        }

        // TaskCompleted hooks use exit codes only, not JSON decision control.
        // To block task completion, the hook would need to return exit code 2.
        // For now, we allow the task to be marked as completed.
        Ok(HookResponse::allow())
    }

    // ============================================================================
    // PostToolUseFailure hook
    // ============================================================================

    /// Handle postToolUseFailure hook
    ///
    /// This fires after a tool call fails. Similar to PostToolUse but includes error information.
    pub async fn handle_post_tool_use_failure(
        &mut self,
        event: PostToolUseFailureEvent,
    ) -> Result<HookResponse> {
        debug!("postToolUseFailure event: {:?}", event);

        let tool_name = event.tool_name.clone();
        let error = event.error.clone();

        info!(
            "Tool '{}' failed with error: {} (session: {})",
            tool_name, error, event.session_id
        );

        // Record the tool failure as an observation
        let tool_output = TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput::error(
            &event.tool_use_id,
            &error,
        )));

        let ev = self
            .event(&event.session_id, tool_output)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // Pre-compact hook
    // ============================================================================

    /// Handle preCompact hook
    pub fn handle_pre_compact(&self, event: PreCompactEvent) -> Result<HookResponse> {
        let trigger = event.trigger;
        let session_id = &event.session_id;
        let custom_instructions = &event.custom_instructions;

        info!(
            "Processing pre-compact event: {:?} (session: {})",
            trigger, session_id
        );

        match trigger {
            CompactTrigger::Auto => {
                info!("Auto-compaction triggered");
            }
            CompactTrigger::Manual => {
                info!(
                    "Manual compaction requested with instructions: {}",
                    if custom_instructions.is_empty() {
                        "(none)"
                    } else {
                        custom_instructions
                    }
                );
            }
            CompactTrigger::Unknown => {
                warn!("Unknown compaction trigger received");
            }
        }

        Ok(HookResponse::allow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_json(response: &HookResponse) -> String {
        serde_json::to_string(response).unwrap()
    }

    // Guard against the bug where Allow responses bypass Claude Code's permission system.
    // HookResponse::allow() MUST serialize to "{}" (empty JSON) so that Claude Code falls
    // back to its normal permission behavior (e.g., prompting the user). If the response
    // contained hookSpecificOutput with permissionDecision: "allow" or behavior: "allow",
    // Claude Code would auto-approve the tool call without ever asking the user.

    #[test]
    fn test_allow_response_serializes_to_empty_json() {
        let json = to_json(&HookResponse::allow());
        assert_eq!(
            json, "{}",
            "HookResponse::allow() must serialize to empty JSON, got: {json}"
        );
    }

    #[test]
    fn test_pre_tool_deny_sets_hook_specific_output() {
        let json = to_json(&HookResponse::pre_tool_deny(
            "blocked by policy".to_string(),
        ));
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("\"deny\""));
        assert!(json.contains("blocked by policy"));
    }

    #[test]
    fn test_pre_tool_ask_sets_hook_specific_output() {
        let json = to_json(&HookResponse::pre_tool_ask("needs approval".to_string()));
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("\"ask\""));
        assert!(json.contains("needs approval"));
    }

    #[test]
    fn test_permission_deny_sets_hook_specific_output() {
        let json = to_json(&HookResponse::permission_deny(
            "denied by policy".to_string(),
        ));
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("\"deny\""));
        assert!(json.contains("denied by policy"));
    }
}
