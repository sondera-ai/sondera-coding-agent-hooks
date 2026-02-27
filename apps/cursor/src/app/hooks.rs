//! Hook handler implementations for Cursor events.
//!
//! This module contains all the business logic for handling different types
//! of hook events from Cursor, including shell execution, MCP tool usage,
//! file access, prompt submission, and agent completion.

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
            provider_id: "cursor".to_string(),
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
            .event(&event.common.conversation_id, started)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::session_start_ok())
    }

    /// Handle sessionEnd hook
    pub async fn handle_session_end(&mut self, event: SessionEndEvent) -> Result<HookResponse> {
        debug!("sessionEnd event: {:?}", event);

        info!(
            "Session {} ended (reason: {:?})",
            event.common.conversation_id, event.reason
        );

        Ok(HookResponse::ok())
    }

    // ============================================================================
    // Shell execution hooks
    // ============================================================================

    /// Handle beforeShellExecution hook
    pub async fn handle_before_shell_execution(
        &mut self,
        event: BeforeShellExecutionEvent,
    ) -> Result<HookResponse> {
        debug!("beforeShellExecution event: {:?}", event);

        let action = Action::ShellCommand(ShellCommand {
            call_id: event.common.generation_id.clone(),
            command: event.command.clone(),
            working_dir: Some(event.cwd.clone()),
        });

        let trajectory_event = TrajectoryEvent::Action(action);

        let ev = self
            .event(&event.common.conversation_id, trajectory_event)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Shell execution allowed");
                HookResponse::allow_execution()
            }
            Decision::Deny => {
                let msg = adjudicated.deny_message("Shell execution denied by policy");
                warn!("Shell execution denied: {}", msg);
                HookResponse::deny_execution(msg)
            }
            Decision::Escalate => {
                let msg = adjudicated.deny_message("Shell execution requires approval");
                info!("Shell execution escalated for approval: {}", msg);
                HookResponse::ask_execution(msg)
            }
        };

        Ok(response)
    }

    /// Handle afterShellExecution hook
    pub async fn handle_after_shell_execution(
        &mut self,
        event: AfterShellExecutionEvent,
    ) -> Result<HookResponse> {
        debug!("afterShellExecution event: {:?}", event);

        let observation =
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput::new(
                &event.common.generation_id,
                0, // exit_code not provided in Cursor hook
                &event.output,
                "",
            )));

        let ev = self
            .event(&event.common.conversation_id, observation)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::ok())
    }

    // ============================================================================
    // MCP execution hooks
    // ============================================================================

    /// Handle beforeMCPExecution hook
    pub async fn handle_before_mcp_execution(
        &mut self,
        event: BeforeMCPExecutionEvent,
    ) -> Result<HookResponse> {
        debug!("beforeMCPExecution event: {:?}", event);

        let tool_input: serde_json::Value =
            serde_json::from_str(&event.tool_input).unwrap_or(serde_json::json!({}));

        let action = Action::ToolCall(ToolCall {
            call_id: event.common.generation_id.clone(),
            tool: event.tool_name.clone(),
            arguments: tool_input,
        });

        let trajectory_event = TrajectoryEvent::Action(action);

        let ev = self
            .event(&event.common.conversation_id, trajectory_event)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let tool_name = &event.tool_name;
        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("MCP tool '{}' execution allowed", tool_name);
                HookResponse::allow_execution()
            }
            Decision::Deny => {
                let msg = adjudicated.deny_message(&format!(
                    "MCP tool '{tool_name}' execution denied by policy"
                ));
                warn!("MCP tool '{}' execution denied: {}", tool_name, msg);
                HookResponse::deny_execution(msg)
            }
            Decision::Escalate => {
                let msg =
                    adjudicated.deny_message(&format!("MCP tool '{tool_name}' requires approval"));
                info!("MCP tool '{}' escalated for approval: {}", tool_name, msg);
                HookResponse::ask_execution(msg)
            }
        };

        Ok(response)
    }

    /// Handle afterMCPExecution hook
    pub async fn handle_after_mcp_execution(
        &mut self,
        event: AfterMCPExecutionEvent,
    ) -> Result<HookResponse> {
        debug!("afterMCPExecution event: {:?}", event);

        let result: serde_json::Value =
            serde_json::from_str(&event.result_json).unwrap_or(serde_json::json!({}));

        let tool_output = TrajectoryEvent::Observation(Observation::ToolOutput(
            ToolOutput::success(&event.common.generation_id, result),
        ));

        let ev = self
            .event(&event.common.conversation_id, tool_output)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::ok())
    }

    // ============================================================================
    // File access hooks
    // ============================================================================

    /// Handle beforeReadFile hook
    pub async fn handle_before_read_file(
        &mut self,
        event: BeforeReadFileEvent,
    ) -> Result<HookResponse> {
        debug!("beforeReadFile event: {:?}", event);

        let action = Action::FileOperation(FileOperation {
            call_id: event.common.generation_id.clone(),
            operation: FileOpType::Read,
            path: event.file_path.clone(),
            content: None,
            old_content: None,
        });

        let trajectory_event = TrajectoryEvent::Action(action);

        let ev = self
            .event(&event.common.conversation_id, trajectory_event)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let file_path = &event.file_path;
        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("File read allowed: {}", file_path);
                HookResponse::allow_read_file()
            }
            Decision::Deny => {
                let msg =
                    adjudicated.deny_message(&format!("File read denied by policy: {file_path}"));
                warn!("File read denied: {}", msg);
                HookResponse::deny_read_file(msg)
            }
            Decision::Escalate => {
                // Cursor beforeReadFile doesn't support "ask", treat as deny
                let msg =
                    adjudicated.deny_message(&format!("File read requires approval: {file_path}"));
                warn!("File read escalated (treating as deny): {}", msg);
                HookResponse::deny_read_file(msg)
            }
        };

        Ok(response)
    }

    /// Handle afterFileEdit hook
    pub async fn handle_after_file_edit(
        &mut self,
        event: AfterFileEditEvent,
    ) -> Result<HookResponse> {
        debug!("afterFileEdit event: {:?}", event);

        // Build content from edits
        let content = event
            .edits
            .iter()
            .map(|e| e.new_string.clone())
            .collect::<Vec<_>>()
            .join("\n");

        let observation = TrajectoryEvent::Observation(Observation::FileOperationResult(
            FileOperationResult::success(&event.common.generation_id).with_content(content),
        ));

        let ev = self
            .event(&event.common.conversation_id, observation)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::ok())
    }

    // ============================================================================
    // Prompt submission hook
    // ============================================================================

    /// Handle beforeSubmitPrompt hook
    pub async fn handle_before_submit_prompt(
        &mut self,
        event: BeforeSubmitPromptEvent,
    ) -> Result<HookResponse> {
        debug!("beforeSubmitPrompt event: {:?}", event);

        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&event.prompt)));

        let ev = self
            .event(&event.common.conversation_id, prompt)
            .with_actor(Actor::human(&self.agent.id))
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("User prompt allowed");
                HookResponse::allow_prompt()
            }
            Decision::Deny => {
                let msg = adjudicated.deny_message("Prompt blocked by policy");
                warn!("User prompt denied: {}", msg);
                HookResponse::block_prompt(msg)
            }
            Decision::Escalate => {
                let reason = adjudicated
                    .reason
                    .as_deref()
                    .unwrap_or("Prompt escalated for review");
                warn!("User prompt escalated: {}", reason);
                // beforeSubmitPrompt doesn't support escalation, just allow with user message
                HookResponse::allow_prompt()
            }
        };

        Ok(response)
    }

    // ============================================================================
    // Agent response hooks
    // ============================================================================

    /// Handle afterAgentResponse hook
    pub async fn handle_after_agent_response(
        &mut self,
        event: AfterAgentResponseEvent,
    ) -> Result<HookResponse> {
        debug!("afterAgentResponse event: {:?}", event);

        let response =
            TrajectoryEvent::Observation(Observation::Prompt(Prompt::system(&event.text)));

        let ev = self
            .event(&event.common.conversation_id, response)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::ok())
    }

    /// Handle afterAgentThought hook
    pub async fn handle_after_agent_thought(
        &mut self,
        event: AfterAgentThoughtEvent,
    ) -> Result<HookResponse> {
        debug!("afterAgentThought event: {:?}", event);

        // Log agent's thinking process - this is observational only
        info!(
            "Agent thought (duration: {:?}ms): {}",
            event.duration_ms,
            event.text.chars().take(100).collect::<String>()
        );

        Ok(HookResponse::ok())
    }

    // ============================================================================
    // Stop hook
    // ============================================================================

    /// Handle stop hook
    pub async fn handle_stop(&mut self, event: StopEvent) -> Result<HookResponse> {
        debug!("stop event: {:?}", event);

        info!(
            "Agent stop (status: {:?}, loop_count: {})",
            event.status, event.loop_count
        );

        Ok(HookResponse::stop_done())
    }

    // ============================================================================
    // Subagent hooks
    // ============================================================================

    /// Handle subagentStart hook
    pub async fn handle_subagent_start(
        &mut self,
        event: SubagentStartEvent,
    ) -> Result<HookResponse> {
        debug!("subagentStart event: {:?}", event);

        // For now, just allow subagent creation
        info!(
            "Subagent {:?} starting with prompt: {}",
            event.subagent_type,
            event.prompt.chars().take(100).collect::<String>()
        );

        Ok(HookResponse::subagent_start_allow())
    }

    /// Handle subagentStop hook
    pub async fn handle_subagent_stop(&mut self, event: SubagentStopEvent) -> Result<HookResponse> {
        debug!("subagentStop event: {:?}", event);

        info!(
            "Subagent {:?} stopped (status: {:?}, duration: {}ms)",
            event.subagent_type, event.status, event.duration
        );

        Ok(HookResponse::subagent_stop_done())
    }

    // ============================================================================
    // Compaction hook
    // ============================================================================

    /// Handle preCompact hook
    pub async fn handle_pre_compact(&mut self, event: PreCompactEvent) -> Result<HookResponse> {
        debug!("preCompact event: {:?}", event);

        info!(
            "Context compaction (trigger: {:?}, usage: {}%, tokens: {}/{})",
            event.trigger,
            event.context_usage_percent,
            event.context_tokens,
            event.context_window_size
        );

        Ok(HookResponse::pre_compact_ok())
    }

    // ============================================================================
    // Tab-specific hooks
    // ============================================================================

    /// Handle beforeTabFileRead hook (Tab-specific)
    pub async fn handle_before_tab_file_read(
        &mut self,
        event: BeforeTabFileReadEvent,
    ) -> Result<HookResponse> {
        debug!("beforeTabFileRead event: {:?}", event);

        let action = Action::FileOperation(FileOperation {
            call_id: event.common.generation_id.clone(),
            operation: FileOpType::Read,
            path: event.file_path.clone(),
            content: None,
            old_content: None,
        });

        let trajectory_event = TrajectoryEvent::Action(action);

        let ev = self
            .event(&event.common.conversation_id, trajectory_event)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let file_path = &event.file_path;
        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Tab file read allowed: {}", file_path);
                HookResponse::allow_tab_read()
            }
            Decision::Deny | Decision::Escalate => {
                let msg = adjudicated
                    .deny_message(&format!("Tab file read denied by policy: {file_path}"));
                warn!("Tab file read denied: {}", msg);
                HookResponse::deny_tab_read()
            }
        };

        Ok(response)
    }

    /// Handle afterTabFileEdit hook (Tab-specific)
    pub async fn handle_after_tab_file_edit(
        &mut self,
        event: AfterTabFileEditEvent,
    ) -> Result<HookResponse> {
        debug!("afterTabFileEdit event: {:?}", event);

        // Build content from edits
        let content = event
            .edits
            .iter()
            .map(|e| e.new_string.clone())
            .collect::<Vec<_>>()
            .join("\n");

        let observation = TrajectoryEvent::Observation(Observation::FileOperationResult(
            FileOperationResult::success(&event.common.generation_id).with_content(content),
        ));

        let ev = self
            .event(&event.common.conversation_id, observation)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::ok())
    }

    // ============================================================================
    // Generic tool hooks (preToolUse/postToolUse)
    // ============================================================================

    /// Handle preToolUse hook - generic pre-execution for all tools
    pub async fn handle_pre_tool_use(&mut self, event: PreToolUseEvent) -> Result<HookResponse> {
        debug!("preToolUse event: {:?}", event);

        let tool_name = event.tool_name.clone();

        let action = match tool_name.as_str() {
            "Shell" => Action::ShellCommand(ShellCommand {
                call_id: event.tool_use_id.clone(),
                command: event
                    .tool_input
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                working_dir: Some(event.cwd.clone()),
            }),
            "Read" => Action::FileOperation(FileOperation {
                call_id: event.tool_use_id.clone(),
                operation: FileOpType::Read,
                path: event
                    .tool_input
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                content: None,
                old_content: None,
            }),
            "Write" => Action::FileOperation(FileOperation {
                call_id: event.tool_use_id.clone(),
                operation: FileOpType::Write,
                path: event
                    .tool_input
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                content: event
                    .tool_input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                old_content: None,
            }),
            "WebFetch" => Action::WebFetch(WebFetch::new(
                event
                    .tool_input
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
                event
                    .tool_input
                    .get("prompt")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            )),
            _ => Action::ToolCall(ToolCall {
                call_id: event.tool_use_id.clone(),
                tool: tool_name.clone(),
                arguments: event.tool_input.clone(),
            }),
        };

        let trajectory_event = TrajectoryEvent::Action(action);

        let ev = self
            .event(&event.common.conversation_id, trajectory_event)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Tool '{}' execution allowed", tool_name);
                HookResponse::allow_tool_use(None)
            }
            Decision::Deny => {
                let msg = adjudicated
                    .deny_message(&format!("Tool '{tool_name}' execution denied by policy"));
                warn!("Tool '{}' execution denied: {}", tool_name, msg);
                HookResponse::deny_tool_use(msg)
            }
            Decision::Escalate => {
                // preToolUse doesn't support "ask", treat as deny
                let msg = adjudicated
                    .deny_message(&format!("Tool '{tool_name}' execution requires approval"));
                warn!("Tool '{}' escalated (treating as deny): {}", tool_name, msg);
                HookResponse::deny_tool_use(msg)
            }
        };

        Ok(response)
    }

    /// Handle postToolUse hook - generic post-execution for all tools
    pub async fn handle_post_tool_use(&mut self, event: PostToolUseEvent) -> Result<HookResponse> {
        debug!("postToolUse event: {:?}", event);

        let observation = match event.tool_name.as_str() {
            "Shell" => {
                let output = event
                    .tool_output
                    .get("output")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                Observation::ShellCommandOutput(ShellCommandOutput::new(
                    &event.tool_use_id,
                    0, // exit_code not provided in Cursor hook
                    output,
                    "",
                ))
            }
            "Read" | "Write" | "Edit" => {
                let content = event
                    .tool_output
                    .get("content")
                    .or_else(|| event.tool_output.get("file").and_then(|f| f.get("content")))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let mut result = FileOperationResult::success(&event.tool_use_id);
                if let Some(content) = content {
                    result = result.with_content(content);
                }

                Observation::FileOperationResult(result)
            }
            "WebFetch" => {
                let url = event
                    .tool_input
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let code = event
                    .tool_output
                    .get("code")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(200) as i32;
                let result = event
                    .tool_output
                    .get("result")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                Observation::WebFetchOutput(WebFetchOutput::new(
                    &event.tool_use_id,
                    url,
                    code,
                    result,
                ))
            }
            _ => Observation::ToolOutput(ToolOutput::success(
                &event.tool_use_id,
                event.tool_output.clone(),
            )),
        };

        let tool_output = TrajectoryEvent::Observation(observation);

        let ev = self
            .event(&event.common.conversation_id, tool_output)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::ok())
    }

    /// Handle postToolUseFailure hook - hook for failed tool executions
    pub async fn handle_post_tool_use_failure(
        &mut self,
        event: PostToolUseFailureEvent,
    ) -> Result<HookResponse> {
        debug!("postToolUseFailure event: {:?}", event);

        let tool_output = TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput::error(
            &event.tool_use_id,
            &event.error_message,
        )));

        let ev = self
            .event(&event.common.conversation_id, tool_output)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(HookResponse::ok())
    }
}
