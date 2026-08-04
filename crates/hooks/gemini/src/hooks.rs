//! Hook handler implementations for Gemini CLI events.
//!
//! This module contains all the business logic for handling different types
//! of hook events from Gemini CLI, including tool execution, model requests,
//! agent lifecycle, and session management.
//!
//! Reference: <https://geminicli.com/docs/hooks/reference>

use super::types::*;
use crate::response::GeminiHookResponse;
use sondera_hooks::error::Result;
use sondera_hooks::tool::{file_path_arg, normalize_tool_name, string_arg};

use sondera_harness_client::{
    Action, Actor, Agent, Control, Decision, Event, FileOpType, FileOperation, FileOperationResult,
    HarnessClient, Observation, Prompt, ShellCommand, ShellCommandOutput, Started, ToolCall,
    ToolOutput, TrajectoryEvent, WebFetch, WebFetchOutput,
};
use tracing::{info, warn};

pub struct Hooks<H: HarnessClient> {
    harness: H,
    agent: Agent,
}

/// Map a Gemini CLI tool call to a Sondera [`Action`].
///
/// A tool with no specific mapping becomes a generic [`ToolCall`] rather than
/// being skipped. It still reaches Cedar only as
/// `Sondera::Action::"PreToolUse"`, which no file, shell, or web policy
/// applies to — but it is adjudicated and recorded, so the trajectory shows
/// what the agent did. Returning early instead left the call absent from the
/// record entirely, which reads as "the agent never called it".
///
/// Matching on [`normalize_tool_name`] covers every casing and separator
/// spelling of a tool name, and paths are read through [`file_path_arg`]
/// because Gemini CLI is not internally consistent: `read_file` takes
/// `absolute_path` while `write_file` and `replace` take `file_path`. A path
/// read from the wrong key comes back empty, and an empty path satisfies no
/// `context.path_normalized` condition — the policy typechecks and never
/// fires, which reads as a clean allow.
fn action_for(tool_name: &str, tool_input: &serde_json::Value, cwd: &str) -> Action {
    let call_id = || format!("tool-{}", uuid::Uuid::new_v4());
    match normalize_tool_name(tool_name).as_str() {
        "runshellcommand" | "runterminalcmd" | "shell" => Action::ShellCommand(ShellCommand {
            call_id: call_id(),
            command: string_arg(tool_input, &["command"])
                .unwrap_or("")
                .to_string(),
            working_dir: Some(
                string_arg(tool_input, &["cwd", "directory"])
                    .unwrap_or(cwd)
                    .to_string(),
            ),
        }),
        // `read_many_files` takes a `paths` glob list rather than one path; it
        // is modelled as a read of the first entry so the call is still
        // adjudicated rather than dropped.
        "readfile" | "readmanyfiles" => Action::FileOperation(FileOperation {
            call_id: call_id(),
            operation: FileOpType::Read,
            path: first_path(tool_input),
            content: None,
            old_content: None,
        }),
        // Gemini CLI registers its edit tool as `replace`; `edit_file` is kept
        // as an alias for older builds.
        "replace" | "editfile" | "edit" => Action::FileOperation(FileOperation {
            call_id: call_id(),
            operation: FileOpType::Edit,
            path: file_path_arg(tool_input).to_string(),
            content: string_arg(tool_input, &["new_string", "newString"]).map(str::to_string),
            old_content: string_arg(tool_input, &["old_string", "oldString"]).map(str::to_string),
        }),
        "writefile" => Action::FileOperation(FileOperation {
            call_id: call_id(),
            operation: FileOpType::Write,
            path: file_path_arg(tool_input).to_string(),
            content: string_arg(tool_input, &["content"]).map(str::to_string),
            old_content: None,
        }),
        "webfetch" => {
            let prompt = string_arg(tool_input, &["prompt"])
                .unwrap_or("")
                .to_string();
            // Gemini's web_fetch has no separate "url" field — the URL is
            // embedded in the prompt text. Try the explicit field first, then
            // extract from the prompt.
            let url = string_arg(tool_input, &["url"])
                .map(str::to_string)
                .unwrap_or_else(|| extract_url(&prompt));
            Action::WebFetch(WebFetch {
                call_id: call_id(),
                url,
                prompt,
            })
        }
        _ => Action::ToolCall(ToolCall {
            call_id: call_id(),
            tool: tool_name.to_string(),
            arguments: tool_input.clone(),
        }),
    }
}

/// Tool names, folded, whose result is a [`FileOperationResult`].
///
/// Must stay in step with the file arms of [`action_for`]: a call adjudicated
/// as a `FileOperation` whose result comes back as a generic `ToolOutput`
/// loses the content the post-execution policies scan.
const FILE_TOOLS: &[&str] = &[
    "readfile",
    "readmanyfiles",
    "replace",
    "editfile",
    "edit",
    "writefile",
];

/// Resolve the path a read targets, accepting either a single path argument or
/// the `paths` list `read_many_files` takes.
fn first_path(tool_input: &serde_json::Value) -> String {
    let single = file_path_arg(tool_input);
    if !single.is_empty() {
        return single.to_string();
    }
    tool_input
        .get("paths")
        .and_then(|v| v.as_array())
        .and_then(|paths| paths.first())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
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

impl<H: HarnessClient> Hooks<H> {
    /// Create a new Hooks instance
    pub fn new(harness: H, agent_id: String) -> Self {
        let agent = Agent {
            id: agent_id,
            provider: "gemini".to_string(),
            platform: "gemini".to_string(),
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
        let started = TrajectoryEvent::Control(Control::Started(Started::new(self.agent.clone())));

        let ev = self.event(&event.common.session_id, started);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => GeminiHookResponse::ok(),
            Decision::Deny => {
                let msg = adjudicated.deny_message("Session start blocked by policy");
                warn!("Session start denied: {}", msg);
                GeminiHookResponse::stop(msg)
            }
            Decision::Escalate => {
                let msg = adjudicated.deny_message("Session start escalated for review");
                warn!("Session start escalated: {}", msg);
                GeminiHookResponse::stop(msg)
            }
        };

        Ok(response)
    }

    /// Handle SessionEnd hook - finalize session
    pub async fn handle_session_end(
        &mut self,
        event: SessionEndEvent,
    ) -> Result<GeminiHookResponse> {
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
        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&event.prompt)));

        let ev = self
            .event(&event.common.session_id, prompt)
            .with_actor(Actor::human(&self.agent.id));

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
        // If a retry is already in progress, allow to prevent infinite loops.
        if event.stop_hook_active {
            info!("AfterAgent: stop_hook_active=true, allowing to prevent retry loop");
            return Ok(GeminiHookResponse::ok());
        }

        // Scan the complete agent response for policy violations.
        let observation = TrajectoryEvent::Observation(Observation::Prompt(Prompt::system(
            &event.prompt_response,
        )));

        let ev = self.event(&event.common.session_id, observation);

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

    pub async fn handle_before_model(
        &mut self,
        event: BeforeModelEvent,
    ) -> Result<GeminiHookResponse> {
        let content = extract_user_messages(&event.llm_request);
        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::system(&content)));
        let adjudicated = self
            .harness
            .adjudicate(self.event(&event.common.session_id, prompt))
            .await?;
        Ok(match adjudicated.decision {
            Decision::Allow => GeminiHookResponse::ok(),
            Decision::Deny | Decision::Escalate => GeminiHookResponse::deny(
                adjudicated.deny_message("Model request blocked by policy"),
            ),
        })
    }

    pub async fn handle_after_model(
        &mut self,
        event: AfterModelEvent,
    ) -> Result<GeminiHookResponse> {
        let content = serde_json::to_string(&event.llm_response).unwrap_or_default();
        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::assistant(&content)));
        let adjudicated = self
            .harness
            .adjudicate(self.event(&event.common.session_id, prompt))
            .await?;
        Ok(match adjudicated.decision {
            Decision::Allow => GeminiHookResponse::ok(),
            Decision::Deny | Decision::Escalate => GeminiHookResponse::deny(
                adjudicated.deny_message("Model response blocked by policy"),
            ),
        })
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
        // Extract user message content, filtering out Gemini CLI's auto-injected
        // <session_context> blocks to avoid false positive YARA signatures.
        let llm_content = extract_user_messages(&event.llm_request);
        let prompt =
            TrajectoryEvent::Observation(Observation::Prompt(Prompt::system(&llm_content)));

        let ev = self.event(&event.common.session_id, prompt);

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
        let tool_name = event.tool_name.clone();

        let action = action_for(&tool_name, &event.tool_input, &event.common.cwd);

        let ev = self.event(&event.common.session_id, TrajectoryEvent::Action(action));

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
        // Map tool response to appropriate observation type
        let tool_output = match normalize_tool_name(&event.tool_name).as_str() {
            "runshellcommand" | "runterminalcmd" | "shell" => {
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
            name if FILE_TOOLS.contains(&name) => {
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
                let path = Some(first_path(&event.tool_input)).filter(|p| !p.is_empty());
                TrajectoryEvent::Observation(Observation::FileOperationResult(
                    FileOperationResult {
                        call_id: format!("tool-{}", event.tool_name),
                        success,
                        path,
                        content,
                        error,
                    },
                ))
            }
            "webfetch" => {
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

        let ev = self.event(&event.common.session_id, tool_output);

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
    use serde_json::json;

    fn to_json(response: &GeminiHookResponse) -> String {
        serde_json::to_string(response).unwrap()
    }

    // ── Tool mapping ─────────────────────────────────────────────────────────

    #[test]
    fn read_file_takes_its_path_from_absolute_path() {
        // Gemini CLI's read_file argument is `absolute_path`, not `path`.
        let action = action_for(
            "read_file",
            &json!({"absolute_path": "/repo/.env"}),
            "/repo",
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.path, "/repo/.env");
                assert!(matches!(op.operation, FileOpType::Read));
            }
            other => panic!("Expected FileOperation(Read), got {other:?}"),
        }
    }

    #[test]
    fn replace_is_the_edit_tool() {
        let action = action_for(
            "replace",
            &json!({"file_path": "/repo/app.rs", "old_string": "a", "new_string": "b"}),
            "/repo",
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.path, "/repo/app.rs");
                assert!(matches!(op.operation, FileOpType::Edit));
                assert_eq!(op.old_content.as_deref(), Some("a"));
                assert_eq!(op.content.as_deref(), Some("b"));
            }
            other => panic!("Expected FileOperation(Edit), got {other:?}"),
        }
    }

    #[test]
    fn file_tools_never_lose_their_path() {
        // An empty path satisfies no `context.path_normalized` condition, so a
        // mis-keyed path is a silently unenforceable policy.
        let cases: &[(&str, serde_json::Value)] = &[
            ("read_file", json!({"absolute_path": "/repo/.env"})),
            ("read_many_files", json!({"paths": ["/repo/.env"]})),
            ("replace", json!({"file_path": "/repo/.env"})),
            ("write_file", json!({"file_path": "/repo/.env"})),
        ];
        for (tool, args) in cases {
            match action_for(tool, args, "/repo") {
                Action::FileOperation(op) => {
                    assert_eq!(op.path, "/repo/.env", "{tool}");
                }
                other => panic!("Expected FileOperation for {tool}, got {other:?}"),
            }
        }
    }

    #[test]
    fn shell_falls_back_to_the_session_cwd() {
        match action_for("run_shell_command", &json!({"command": "ls"}), "/repo") {
            Action::ShellCommand(cmd) => {
                assert_eq!(cmd.command, "ls");
                assert_eq!(cmd.working_dir.as_deref(), Some("/repo"));
            }
            other => panic!("Expected ShellCommand, got {other:?}"),
        }
    }

    #[test]
    fn unmapped_tools_are_recorded_as_generic_tool_calls() {
        // They reach Cedar only as `PreToolUse`, which no policy targets, but
        // they are adjudicated and land in the trajectory. Skipping the
        // round-trip left them absent from the record entirely.
        match action_for("save_memory", &json!({"fact": "x"}), "/repo") {
            Action::ToolCall(tc) => {
                assert_eq!(tc.tool, "save_memory");
                assert_eq!(tc.arguments, json!({"fact": "x"}));
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }
    }

    #[test]
    fn web_fetch_agrees_across_before_and_after_mapping() {
        // `webfetch` is matched by both mappers; the AfterTool arm keys on the
        // same folded name, so the fetched body reaches the webfetch-output
        // policies rather than arriving as a generic ToolOutput.
        assert_eq!(normalize_tool_name("web_fetch"), "webfetch");
        assert!(matches!(
            action_for(
                "web_fetch",
                &json!({"prompt": "read https://x.dev"}),
                "/repo"
            ),
            Action::WebFetch(_)
        ));
    }

    #[test]
    fn file_tools_agree_across_before_and_after_mapping() {
        for name in FILE_TOOLS {
            assert_eq!(&normalize_tool_name(name), name, "{name} is not folded");
            assert!(
                matches!(
                    action_for(name, &json!({"file_path": "f"}), "/repo"),
                    Action::FileOperation(_)
                ),
                "{name} is in FILE_TOOLS but does not map to a FileOperation"
            );
        }
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
