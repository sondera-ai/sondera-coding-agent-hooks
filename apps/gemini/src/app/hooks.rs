//! Hook handler implementations for Gemini CLI events.
//!
//! This module contains all the business logic for handling different types
//! of hook events from Gemini CLI, including tool execution, model requests,
//! agent lifecycle, and session management.
//!
//! Reference: https://geminicli.com/docs/hooks/reference

use super::response::GeminiHookResponse;
use super::types::*;
use anyhow::Result;

use sondera_harness::{
    Action, Actor, Agent, Control, Decision, Event, FileOpType, FileOperation, FileOperationResult,
    Harness, Observation, Prompt, ShellCommand, ShellCommandOutput, Started, ToolOutput,
    TrajectoryEvent, WebFetch, WebFetchOutput,
};
use tracing::{debug, info, warn};

pub struct Hooks<H: Harness> {
    harness: H,
    agent: Agent,
}

/// Extract user message content from an LLM request, filtering out Gemini CLI's
/// auto-injected `<session_context>` blocks that contain directory listings with
/// filenames like `.ssh/id_rsa` and `.env` which trigger false positive YARA signatures.
fn extract_user_messages(llm_request: &serde_json::Value) -> String {
    let Some(messages) = llm_request.get("messages").and_then(|v| v.as_array()) else {
        return serde_json::to_string(llm_request).unwrap_or_default();
    };

    let parts: Vec<&str> = messages
        .iter()
        .filter_map(|msg| {
            let content = msg.get("content").and_then(|v| v.as_str())?;
            // Skip Gemini CLI auto-injected session context blocks.
            if content.contains("<session_context>") {
                return None;
            }
            if content.trim().is_empty() {
                return None;
            }
            Some(content)
        })
        .collect();

    parts.join("\n")
}

/// Extract the first URL from a text string.
/// Gemini's `web_fetch` tool embeds the URL in the `prompt` field
/// (e.g. "Fetch the content of https://google.com") rather than
/// providing it as a separate field.
fn extract_url(text: &str) -> String {
    text.split_whitespace()
        .find(|word| word.starts_with("http://") || word.starts_with("https://"))
        .unwrap_or("")
        .to_string()
}

impl<H: Harness> Hooks<H> {
    /// Create a new Hooks instance
    pub fn new(harness: H, agent_id: String) -> Self {
        let agent = Agent {
            id: agent_id,
            provider_id: "gemini".to_string(),
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

    /// Handle SessionStart hook - initialize session
    pub async fn handle_session_start(
        &mut self,
        event: SessionStartEvent,
    ) -> Result<GeminiHookResponse> {
        debug!("SessionStart event: {:?}", event);

        let started = TrajectoryEvent::Control(Control::Started(Started::new(&self.agent.id)));

        let ev = self
            .event(&event.common.session_id, started)
            .with_raw(serde_json::to_value(&event)?);

        self.harness.adjudicate(ev).await?;

        Ok(GeminiHookResponse::ok())
    }

    /// Handle SessionEnd hook - finalize session
    pub async fn handle_session_end(
        &mut self,
        event: SessionEndEvent,
    ) -> Result<GeminiHookResponse> {
        debug!("SessionEnd event: {:?}", event);

        info!(
            "Session {} ended (reason: {:?})",
            event.common.session_id, event.reason
        );

        Ok(GeminiHookResponse::ok())
    }

    // ============================================================================
    // Agent hooks (BeforeAgent, AfterAgent)
    // ============================================================================

    /// Handle BeforeAgent hook - after user input, before planning
    ///
    /// This fires after the user submits a prompt but before the agent begins planning.
    /// Used for prompt validation or injecting dynamic context.
    pub async fn handle_before_agent(
        &mut self,
        event: BeforeAgentEvent,
    ) -> Result<GeminiHookResponse> {
        debug!("BeforeAgent event: {:?}", event);

        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&event.prompt)));

        let ev = self
            .event(&event.common.session_id, prompt)
            .with_actor(Actor::human(&self.agent.id))
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        // Map the adjudication to a Gemini hook response.
        // Note: Gemini doesn't support "ask", so escalate is treated as deny.
        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("User prompt allowed");
                GeminiHookResponse::allow()
            }
            Decision::Deny => {
                let msg = adjudicated.deny_message("Agent invocation denied by policy");
                warn!("Agent invocation denied: {}", msg);
                GeminiHookResponse::deny_with_message(&msg, &msg)
            }
            Decision::Escalate => {
                let msg = adjudicated.deny_message("Agent invocation requires approval");
                warn!(
                    "Agent invocation escalated (treating as deny in Gemini): {}",
                    msg
                );
                let msg = format!("Requires approval: {}", msg);
                GeminiHookResponse::deny_with_message(&msg, &msg)
            }
        };

        Ok(response)
    }

    /// Handle AfterAgent hook - when agent loop completes
    ///
    /// Adjudicates the complete agent response (unlike AfterModel which fires
    /// per streaming chunk). This is the right place to scan the full response.
    ///
    /// When `stop_hook_active` is true, a retry is already in progress from a
    /// previous deny. We must allow to prevent infinite retry loops.
    pub async fn handle_after_agent(
        &mut self,
        event: AfterAgentEvent,
    ) -> Result<GeminiHookResponse> {
        debug!("AfterAgent event: {:?}", event);

        // If a retry is already in progress, allow to prevent infinite loops.
        if event.stop_hook_active {
            info!("AfterAgent: stop_hook_active=true, allowing to prevent retry loop");
            return Ok(GeminiHookResponse::ok());
        }

        // Scan the complete agent response for policy violations.
        let observation = TrajectoryEvent::Observation(Observation::Prompt(Prompt::system(
            &event.prompt_response,
        )));

        let ev = self
            .event(&event.common.session_id, observation)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Agent response allowed");
                GeminiHookResponse::ok()
            }
            Decision::Deny => {
                let msg = adjudicated.deny_message("Agent response denied by policy");
                warn!("Agent response denied: {}", msg);
                // AfterAgent deny sends the reason back to the agent as feedback for retry.
                GeminiHookResponse::retry(&msg).with_system_msg(&msg)
            }
            Decision::Escalate => {
                let msg = adjudicated.deny_message("Agent response requires review");
                warn!(
                    "Agent response escalated (treating as deny in Gemini): {}",
                    msg
                );
                let msg = format!("Requires approval: {}", msg);
                GeminiHookResponse::retry(&msg).with_system_msg(&msg)
            }
        };

        Ok(response)
    }

    // ============================================================================
    // Tool selection hook (BeforeToolSelection)
    // ============================================================================

    /// Handle BeforeToolSelection hook - filter available tools
    ///
    /// Used to intelligently reduce the tool space before the LLM selects tools.
    /// Note: BeforeToolSelection does NOT support `decision`, `continue`, or `systemMessage`.
    /// It only supports `hookSpecificOutput.toolConfig`.
    pub async fn handle_before_tool_selection(
        &mut self,
        event: BeforeToolSelectionEvent,
    ) -> Result<GeminiHookResponse> {
        debug!("BeforeToolSelection event: {:?}", event);

        // Extract user message content, filtering out Gemini CLI's auto-injected
        // <session_context> blocks to avoid false positive YARA signatures.
        let llm_content = extract_user_messages(&event.llm_request);
        let prompt =
            TrajectoryEvent::Observation(Observation::Prompt(Prompt::system(&llm_content)));

        let ev = self
            .event(&event.common.session_id, prompt)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        // Map adjudication to toolConfig (BeforeToolSelection only supports hookSpecificOutput).
        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Tool selection allowed (all tools available)");
                GeminiHookResponse::allow_all_tools()
            }
            Decision::Deny | Decision::Escalate => {
                let msg = adjudicated.deny_message("Tool access denied by policy");
                warn!("Tool selection denied: {}", msg);
                GeminiHookResponse::disable_all_tools(msg)
            }
        };

        Ok(response)
    }

    // ============================================================================
    // Tool execution hooks (BeforeTool, AfterTool)
    // ============================================================================

    /// Handle BeforeTool hook - before tool execution
    ///
    /// Used for argument validation, security checks, and parameter rewriting.
    pub async fn handle_before_tool(
        &mut self,
        event: BeforeToolEvent,
    ) -> Result<GeminiHookResponse> {
        debug!("BeforeTool event: {:?}", event);

        let tool_name = event.tool_name.clone();

        // Map Gemini tool names to our action types
        let action = match tool_name.as_str() {
            "run_shell_command" | "run_terminal_cmd" | "shell" => {
                let command = event
                    .tool_input
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let cwd = event
                    .tool_input
                    .get("cwd")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Action::ShellCommand(ShellCommand {
                    call_id: format!("tool-{}", uuid::Uuid::new_v4()),
                    command,
                    working_dir: cwd.or_else(|| Some(event.common.cwd.clone())),
                })
            }
            "read_file" => {
                let path = event
                    .tool_input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Action::FileOperation(FileOperation {
                    call_id: format!("tool-{}", uuid::Uuid::new_v4()),
                    operation: FileOpType::Read,
                    path,
                    content: None,
                    old_content: None,
                })
            }
            "edit_file" => {
                let path = event
                    .tool_input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
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
                    call_id: format!("tool-{}", uuid::Uuid::new_v4()),
                    operation: FileOpType::Edit,
                    path,
                    content,
                    old_content,
                })
            }
            "write_file" => {
                let path = event
                    .tool_input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let content = event
                    .tool_input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Action::FileOperation(FileOperation {
                    call_id: format!("tool-{}", uuid::Uuid::new_v4()),
                    operation: FileOpType::Write,
                    path,
                    content,
                    old_content: None,
                })
            }
            "web_fetch" => {
                let prompt = event
                    .tool_input
                    .get("prompt")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                // Gemini's web_fetch has no separate "url" field — the URL is
                // embedded in the prompt text. Try explicit field first, then
                // extract from prompt.
                let url = event
                    .tool_input
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| extract_url(&prompt));
                Action::WebFetch(WebFetch {
                    call_id: format!("tool-{}", uuid::Uuid::new_v4()),
                    url,
                    prompt,
                })
            }
            _ => {
                // Unknown tools (e.g. SaveMemory) have no Cedar schema mapping.
                // Log and allow without adjudication.
                info!(
                    "Tool '{}' has no policy mapping, allowing by default",
                    tool_name
                );
                return Ok(GeminiHookResponse::allow());
            }
        };

        let ev = self
            .event(&event.common.session_id, TrajectoryEvent::Action(action))
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        // Map the adjudication to a hook response.
        // Note: Gemini doesn't support "ask", so escalate is treated as deny.
        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Tool '{}' execution allowed", tool_name);
                GeminiHookResponse::allow()
            }
            Decision::Deny => {
                let msg = adjudicated
                    .deny_message(&format!("Tool '{tool_name}' execution denied by policy"));
                warn!("Tool '{}' execution denied: {}", tool_name, msg);
                GeminiHookResponse::deny_with_message(&msg, &msg)
            }
            Decision::Escalate => {
                let msg =
                    adjudicated.deny_message(&format!("Tool '{tool_name}' requires approval"));
                warn!(
                    "Tool '{}' escalated (treating as deny in Gemini): {}",
                    tool_name, msg
                );
                let msg = format!("Requires approval: {}", msg);
                GeminiHookResponse::deny_with_message(&msg, &msg)
            }
        };

        Ok(response)
    }

    /// Handle AfterTool hook - after tool execution
    ///
    /// Used for result auditing, context injection, or hiding sensitive output.
    pub async fn handle_after_tool(&mut self, event: AfterToolEvent) -> Result<GeminiHookResponse> {
        debug!("AfterTool event: {:?}", event);

        // Map tool response to appropriate observation type
        let tool_output = match event.tool_name.as_str() {
            "run_shell_command" | "run_terminal_cmd" | "shell" => {
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
                let exit_code = event
                    .tool_response
                    .get("exit_code")
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32)
                    .unwrap_or(0);
                TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput {
                    call_id: format!("tool-{}", event.tool_name),
                    exit_code,
                    stdout,
                    stderr,
                }))
            }
            "read_file" | "edit_file" | "write_file" => {
                let success = event
                    .tool_response
                    .get("error")
                    .map(|v| v.is_null())
                    .unwrap_or(true);
                let content = event
                    .tool_response
                    .get("content")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let error = event
                    .tool_response
                    .get("error")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                TrajectoryEvent::Observation(Observation::FileOperationResult(
                    FileOperationResult {
                        call_id: format!("tool-{}", event.tool_name),
                        success,
                        content,
                        error,
                    },
                ))
            }
            "web_fetch" => {
                let prompt = event
                    .tool_input
                    .get("prompt")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let url = event
                    .tool_input
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| extract_url(prompt));
                let code = event
                    .tool_response
                    .get("code")
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32)
                    .unwrap_or(200);
                let result = event
                    .tool_response
                    .get("result")
                    .or_else(|| event.tool_response.get("content"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
                    format!("tool-{}", event.tool_name),
                    url,
                    code,
                    result,
                )))
            }
            _ => TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput {
                call_id: format!("tool-{}", event.tool_name),
                success: event
                    .tool_response
                    .get("error")
                    .map(|v| v.is_null())
                    .unwrap_or(true),
                output: event.tool_response.clone(),
                error: event
                    .tool_response
                    .get("error")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            })),
        };

        let ev = self
            .event(&event.common.session_id, tool_output)
            .with_raw(serde_json::to_value(&event)?);

        let adjudicated = self.harness.adjudicate(ev).await?;

        // AfterTool deny hides the real tool output from the agent and replaces
        // it with the reason text.
        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Tool '{}' result allowed", event.tool_name);
                GeminiHookResponse::ok()
            }
            Decision::Deny => {
                let msg = adjudicated.deny_message(&format!(
                    "Tool '{}' output blocked by policy",
                    event.tool_name
                ));
                warn!("Tool '{}' result denied: {}", event.tool_name, msg);
                GeminiHookResponse::deny_with_message(&msg, &msg)
            }
            Decision::Escalate => {
                let msg = adjudicated.deny_message(&format!(
                    "Tool '{}' output requires review",
                    event.tool_name
                ));
                warn!(
                    "Tool '{}' result escalated (treating as deny): {}",
                    event.tool_name, msg
                );
                let msg = format!("Requires approval: {}", msg);
                GeminiHookResponse::deny_with_message(&msg, &msg)
            }
        };

        Ok(response)
    }

    // ============================================================================
    // Advisory hooks (PreCompress, Notification)
    // ============================================================================

    /// Handle PreCompress hook - before context compression
    ///
    /// This is advisory only - we just log it. Cannot block compression.
    pub fn handle_pre_compress(&self, event: PreCompressEvent) -> Result<GeminiHookResponse> {
        debug!("PreCompress event: {:?}", event);

        info!(
            "Context compression triggered ({:?}) for session {}",
            event.trigger, event.common.session_id
        );

        Ok(GeminiHookResponse::ok())
    }

    /// Handle Notification hook - system notifications
    ///
    /// This is advisory only - cannot block alerts or grant permissions.
    pub fn handle_notification(&self, event: NotificationEvent) -> Result<GeminiHookResponse> {
        debug!("Notification event: {:?}", event);

        info!(
            "Received notification [{}]: {}",
            event.notification_type, event.message
        );

        Ok(GeminiHookResponse::ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_json(response: &GeminiHookResponse) -> String {
        serde_json::to_string(response).unwrap()
    }

    #[test]
    fn test_allow_response_serializes_correctly() {
        let json = to_json(&GeminiHookResponse::allow());
        assert!(json.contains("allow"), "Expected allow in: {json}");
    }

    #[test]
    fn test_deny_response_serializes_correctly() {
        let json = to_json(&GeminiHookResponse::deny("blocked by policy".to_string()));
        assert!(json.contains("deny"), "Expected deny in: {json}");
        assert!(
            json.contains("blocked by policy"),
            "Expected reason in: {json}"
        );
    }

    #[test]
    fn test_ok_response_serializes_to_empty() {
        let json = to_json(&GeminiHookResponse::ok());
        assert_eq!(json, "{}", "ok() should serialize to empty JSON: {json}");
    }

    #[test]
    fn test_extract_user_messages_filters_session_context() {
        let llm_request = serde_json::json!({
            "model": "gemini-2.5-flash",
            "messages": [
                {"role": "user", "content": "<session_context>\nThis is the Gemini CLI.\n- .ssh/id_rsa\n- .env\n</session_context>"},
                {"role": "user", "content": "hello"}
            ],
            "config": {"temperature": 1}
        });
        let result = extract_user_messages(&llm_request);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_extract_user_messages_preserves_real_messages() {
        let llm_request = serde_json::json!({
            "messages": [
                {"role": "user", "content": "write a function"},
                {"role": "assistant", "content": "here is a function"}
            ]
        });
        let result = extract_user_messages(&llm_request);
        assert_eq!(result, "write a function\nhere is a function");
    }

    #[test]
    fn test_extract_user_messages_skips_empty() {
        let llm_request = serde_json::json!({
            "messages": [
                {"role": "user", "content": ""},
                {"role": "user", "content": "actual prompt"}
            ]
        });
        let result = extract_user_messages(&llm_request);
        assert_eq!(result, "actual prompt");
    }

    #[test]
    fn test_extract_user_messages_fallback_no_messages() {
        let llm_request = serde_json::json!({"model": "gemini-2.5-flash"});
        let result = extract_user_messages(&llm_request);
        // Falls back to serializing the whole object
        assert!(result.contains("gemini-2.5-flash"));
    }

    #[test]
    fn test_extract_url_from_prompt() {
        assert_eq!(
            extract_url("Fetch the content of https://google.com"),
            "https://google.com"
        );
    }

    #[test]
    fn test_extract_url_http() {
        assert_eq!(
            extract_url("Get http://example.com/page"),
            "http://example.com/page"
        );
    }

    #[test]
    fn test_extract_url_none() {
        assert_eq!(extract_url("no url here"), "");
    }
}
