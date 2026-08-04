//! Hook handler implementations for OpenAI Codex CLI events.
//!
//! This module contains all the business logic for handling different types
//! of hook events from Codex CLI, including tool execution, prompt submission,
//! session management, and stop events.
//!
//! ## Error Degradation Strategy
//!
//! - **Adjudication hooks** (PreToolUse, UserPromptSubmit): FAIL-CLOSED.
//!   `?` propagates harness errors → non-zero exit → Codex falls back to its
//!   built-in permission system.
//! - **Observation hooks** (SessionStart, PostToolUse, Stop): DEGRADE
//!   GRACEFULLY. Log the error and return `{}` (passthrough) so the user's
//!   session is never interrupted for telemetry failures.

use super::types::*;
use crate::response::HookResponse;
use sondera_hooks::adjudication::warn_unenforceable_decision;
use sondera_hooks::error::Result;

use sondera_harness_client::{
    Action, Actor, Agent, Completed, Control, Decision, Event, FileOperationResult, HarnessClient,
    Observation, Prompt, ShellCommand, ShellCommandOutput, Started, Thought, ToolCall, ToolOutput,
    TrajectoryEvent, WebFetchOutput,
};
use sondera_hooks::tool::{
    file_operation_for, file_path_arg, is_file_operation, is_web_fetch, normalize_tool_name,
    string_arg, web_fetch_for, web_url_arg,
};
use tracing::{info, warn};

pub struct Hooks<H: HarnessClient> {
    harness: H,
    agent: Agent,
}

impl<H: HarnessClient> Hooks<H> {
    /// Create a new Hooks instance with a pre-built Agent.
    pub fn new(harness: H, agent: Agent) -> Self {
        Self { harness, agent }
    }

    /// Create an Event for the current Codex hook context.
    fn event(&self, trajectory_id: &str, event: TrajectoryEvent) -> Event {
        Event::new(self.agent.clone(), trajectory_id, event)
    }

    /// Derive a trajectory key from session_id (preferred) or cwd fallback.
    fn trajectory_key(common: &CommonInput) -> String {
        if !common.session_id.is_empty() {
            common.session_id.clone()
        } else {
            common.cwd.clone()
        }
    }

    // ========================================================================
    // Session lifecycle hooks
    // ========================================================================

    /// Handle SessionStart hook.
    ///
    /// Observation-only: degrades gracefully on harness error.
    pub async fn handle_session_start(&mut self, event: SessionStartEvent) -> Result<HookResponse> {
        let key = Self::trajectory_key(&event.common);

        let started = TrajectoryEvent::Control(Control::Started(Started::new(self.agent.clone())));

        let ev = self.event(&key, started);

        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => {
                warn_unenforceable_decision("Codex SessionStart observation", &adjudicated);
            }
            Err(err) => {
                warn!(
                    error = %err,
                    "SessionStart: harness error, degrading gracefully"
                );
            }
        }

        Ok(HookResponse::ok())
    }

    pub async fn handle_session_end(&mut self, event: SessionEndEvent) -> Result<HookResponse> {
        let key = Self::trajectory_key(&event.common);
        let completed = Completed::new().with_summary(event.reason);
        let ev = self.event(
            &key,
            TrajectoryEvent::Control(Control::Completed(completed)),
        );
        self.observe(ev, "Codex SessionEnd observation").await;
        Ok(HookResponse::ok())
    }

    pub async fn handle_subagent_start(
        &mut self,
        event: SubagentStartEvent,
    ) -> Result<HookResponse> {
        let key = Self::trajectory_key(&event.common);
        let mut started = Started::new(self.agent.clone());
        if !event.agent_type.trim().is_empty() {
            started = started.with_task(event.agent_type);
        }
        let ev = self.event(&key, TrajectoryEvent::Control(Control::Started(started)));
        self.observe(ev, "Codex SubagentStart observation").await;
        Ok(HookResponse::ok())
    }

    async fn observe(&self, event: Event, hook: &str) {
        match self.harness.adjudicate(event).await {
            Ok(adjudicated) => warn_unenforceable_decision(hook, &adjudicated),
            Err(err) => warn!(error = %err, hook, "Codex observation harness error"),
        }
    }

    // ========================================================================
    // Tool execution hooks
    // ========================================================================

    /// Handle PreToolUse hook.
    ///
    /// Maps Codex tool names to Sondera Action types and adjudicates.
    /// Currently Codex only sends `Bash`, but we handle any tool name
    /// for forward compatibility.
    ///
    /// SECURITY: `?` propagates harness errors = fail-closed.
    pub async fn handle_pre_tool_use(&mut self, event: PreToolUseEvent) -> Result<HookResponse> {
        let tool_name = event.tool_name.clone();
        let key = Self::trajectory_key(&event.common);

        let action = action_from_tool(
            &tool_name,
            &event.tool_input,
            &event.tool_use_id,
            &event.common.cwd,
        );

        let trajectory_event = TrajectoryEvent::Action(action);

        let ev = self.event(&key, trajectory_event);

        // FAIL-CLOSED: `?` propagates harness connection errors as bail,
        // which causes a non-zero exit code (blocking in Codex via exit != 0).
        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Tool '{}' execution allowed", tool_name);
                HookResponse::ok()
            }
            Decision::Deny => {
                let msg = adjudicated
                    .deny_message(&format!("Tool '{tool_name}' execution denied by policy"));
                warn!("Tool '{}' execution denied: {}", tool_name, msg);
                HookResponse::deny_tool(msg)
            }
            Decision::Escalate => {
                // Codex does not enforce "ask" (fails open), so escalated
                // commands must be denied. Revisit when Codex supports "ask".
                // Ref: https://developers.openai.com/codex/hooks
                let msg = adjudicated
                    .deny_message(&format!("Tool '{tool_name}' execution requires approval"));
                warn!(
                    "Tool '{}' escalated → denied (Codex 'ask' not enforced): {}",
                    tool_name, msg
                );
                HookResponse::deny_tool(msg)
            }
        };

        Ok(response)
    }

    pub async fn handle_permission_request(
        &mut self,
        event: PermissionRequestEvent,
    ) -> Result<HookResponse> {
        let key = Self::trajectory_key(&event.common);
        let action = action_from_tool(
            &event.tool_name,
            &event.tool_input,
            &event.turn_id,
            &event.common.cwd,
        );
        let adjudicated = self
            .harness
            .adjudicate(self.event(&key, TrajectoryEvent::Action(action)))
            .await?;
        Ok(match adjudicated.decision {
            Decision::Allow => HookResponse::allow_permission(),
            Decision::Deny | Decision::Escalate => HookResponse::deny_permission(
                adjudicated.deny_message("Permission request denied by policy"),
            ),
        })
    }

    /// Handle PostToolUse hook.
    ///
    /// Observes tool output and sends it to the harness for recording.
    /// Observation-only: degrades gracefully on harness error.
    pub async fn handle_post_tool_use(&mut self, event: PostToolUseEvent) -> Result<HookResponse> {
        let tool_name = event.tool_name.clone();
        let key = Self::trajectory_key(&event.common);

        let observation = if is_shell_tool(&tool_name) {
            let stdout = match &event.tool_response {
                serde_json::Value::String(s) => s.clone(),
                other => serde_json::to_string(other).unwrap_or_default(),
            };
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput {
                call_id: event.tool_use_id.clone(),
                exit_code: 0,
                stdout,
                stderr: String::new(),
            }))
        } else if is_file_operation(&tool_name, &event.tool_input) {
            // Gated on the same classifier as `action_from_tool`, so a call
            // adjudicated as a FileOperation reports a FileOperationResult and
            // keeps the content the post-execution policies scan.
            let path = file_path_arg(&event.tool_input);
            let content = match &event.tool_response {
                serde_json::Value::String(s) => s.clone(),
                other => string_arg(other, &["content", "output", "stdout", "text"])
                    .map(str::to_string)
                    .unwrap_or_else(|| serde_json::to_string(other).unwrap_or_default()),
            };
            TrajectoryEvent::Observation(Observation::FileOperationResult(FileOperationResult {
                call_id: event.tool_use_id.clone(),
                success: true,
                path: (!path.is_empty()).then(|| path.to_string()),
                content: (!content.is_empty()).then_some(content),
                error: None,
            }))
        } else if is_web_fetch(&tool_name, &event.tool_input) {
            // Same pairing as the file branch: the fetched body is what the
            // post-execution web policies scan.
            let body = match &event.tool_response {
                serde_json::Value::String(s) => s.clone(),
                other => string_arg(other, &["content", "output", "text", "body"])
                    .map(str::to_string)
                    .unwrap_or_else(|| serde_json::to_string(other).unwrap_or_default()),
            };
            TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
                event.tool_use_id.clone(),
                web_url_arg(&event.tool_input).unwrap_or_default(),
                status_from_response(&event.tool_response),
                body,
            )))
        } else {
            let output = serde_json::to_string(&event.tool_response).unwrap_or_default();
            TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput::success(
                event.tool_use_id.clone(),
                output,
            )))
        };

        let ev = self.event(&key, observation);

        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => match adjudicated.decision {
                Decision::Allow => Ok(HookResponse::ok()),
                Decision::Deny => {
                    let msg = adjudicated.deny_message("Tool output blocked by policy");
                    warn!("PostToolUse '{}' output blocked: {}", tool_name, msg);
                    Ok(HookResponse::block_post_tool(msg))
                }
                Decision::Escalate => {
                    let msg = adjudicated.deny_message("Tool output requires review");
                    info!("PostToolUse '{}' output escalated: {}", tool_name, msg);
                    Ok(HookResponse::block_post_tool(msg))
                }
            },
            Err(err) => {
                warn!(
                    error = %err,
                    "PostToolUse: harness error, degrading gracefully"
                );
                Ok(HookResponse::ok())
            }
        }
    }

    // ========================================================================
    // User prompt hook
    // ========================================================================

    /// Handle UserPromptSubmit hook.
    ///
    /// SECURITY: `?` propagates harness errors = fail-closed.
    pub async fn handle_user_prompt_submit(
        &mut self,
        event: UserPromptSubmitEvent,
    ) -> Result<HookResponse> {
        let key = Self::trajectory_key(&event.common);

        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&event.prompt)));

        let ev = self
            .event(&key, prompt)
            .with_actor(Actor::human(&self.agent.id));

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

    pub async fn handle_compact(
        &mut self,
        event: CompactEvent,
        hook_name: &str,
    ) -> Result<HookResponse> {
        let key = Self::trajectory_key(&event.common);
        let thought = format!("Codex {hook_name} trigger={}", event.trigger);
        let ev = self.event(
            &key,
            TrajectoryEvent::Observation(Observation::Thought(Thought::new(thought))),
        );
        self.observe(ev, hook_name).await;
        Ok(HookResponse::ok())
    }

    pub async fn handle_subagent_stop(&mut self, event: SubagentStopEvent) -> Result<HookResponse> {
        if event.stop_hook_active {
            return Ok(HookResponse::ok());
        }
        let key = Self::trajectory_key(&event.common);
        let message = event
            .last_assistant_message
            .unwrap_or_else(|| format!("Codex subagent {} completed", event.agent_type));
        let ev = self.event(
            &key,
            TrajectoryEvent::Observation(Observation::Prompt(Prompt::assistant(&message))),
        );
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => Ok(match adjudicated.decision {
                Decision::Allow => HookResponse::ok(),
                Decision::Deny | Decision::Escalate => HookResponse::continue_subagent(
                    adjudicated.deny_message("Subagent must continue working"),
                ),
            }),
            Err(err) => {
                warn!(error = %err, "SubagentStop harness error; degrading gracefully");
                Ok(HookResponse::ok())
            }
        }
    }

    // ========================================================================
    // Stop hook
    // ========================================================================

    /// Handle Stop hook.
    ///
    /// Codex Stop is a turn-end signal, not a session-end signal. Keep it
    /// observation-only so one Codex session maps to one Sondera trajectory.
    pub async fn handle_stop(&mut self, event: StopEvent) -> Result<HookResponse> {
        let key = Self::trajectory_key(&event.common);

        info!(
            "Session {} stop (active: {}, message: {:?})",
            key, event.stop_hook_active, event.last_assistant_message
        );

        if event.stop_hook_active {
            info!("Stop hook is already active. Allowing stop to prevent infinite loop");
            return Ok(HookResponse::ok());
        }

        // Record as a prompt observation with the last assistant message.
        if let Some(ref message) = event.last_assistant_message {
            let observation =
                TrajectoryEvent::Observation(Observation::Prompt(Prompt::assistant(message)));

            let ev = self.event(&key, observation);

            match self.harness.adjudicate(ev).await {
                Ok(adjudicated) => {
                    warn_unenforceable_decision("Codex Stop observation", &adjudicated);
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        "Stop: harness error, degrading gracefully"
                    );
                }
            }
        }

        Ok(HookResponse::ok())
    }
}

/// Map a Codex tool call to a Sondera [`Action`].
///
/// Reached from two hooks with different tool surfaces. `PreToolUse` fires
/// only for `Bash` (see [`crate::types::PreToolUseEvent`]), but
/// `PermissionRequest` is installed with a `*` matcher and carries whatever
/// tool needs approval — which is how a file operation reaches this adapter
/// today. Both route here, so a name missing from the arms below is
/// ungoverned on the approval path, not merely on a hypothetical future one.
fn action_from_tool(
    tool_name: &str,
    tool_input: &serde_json::Value,
    call_id: &str,
    cwd: &str,
) -> Action {
    if is_shell_tool(tool_name) {
        Action::ShellCommand(ShellCommand {
            call_id: call_id.to_string(),
            command: command_from_input(tool_input),
            working_dir: Some(cwd.to_string()),
        })
    } else if let Some(file_op) = file_operation_for(tool_name, tool_input, call_id.to_string()) {
        Action::FileOperation(file_op)
    } else if let Some(fetch) = web_fetch_for(tool_name, tool_input, call_id.to_string()) {
        Action::WebFetch(fetch)
    } else {
        Action::ToolCall(ToolCall {
            call_id: call_id.to_string(),
            tool: tool_name.to_string(),
            arguments: tool_input.clone(),
        })
    }
}

/// Read the HTTP status a fetch returned.
///
/// An absent status means the fetch succeeded, so this falls back to 200
/// rather than to a shell-style exit code of 0.
fn status_from_response(response: &serde_json::Value) -> i32 {
    for key in ["status_code", "statusCode", "status", "code"] {
        if let Some(code) = response.get(key).and_then(serde_json::Value::as_i64) {
            return i32::try_from(code).unwrap_or(200);
        }
    }
    200
}

fn is_shell_tool(tool_name: &str) -> bool {
    matches!(
        normalize_tool_name(tool_name).as_str(),
        "bash" | "shell" | "exec" | "localshell" | "runcommand"
    )
}

/// Read the command out of a Codex shell call.
///
/// Codex's `shell` tool takes an argv array (`["bash", "-lc", "…"]`) where the
/// `Bash` tool takes a `command` string; an argv array left unjoined would
/// reach the shell policies as an empty command.
fn command_from_input(tool_input: &serde_json::Value) -> String {
    if let Some(command) = string_arg(tool_input, &["command", "cmd", "script"]) {
        return command.to_string();
    }
    tool_input
        .get("command")
        .and_then(serde_json::Value::as_array)
        .map(|argv| {
            argv.iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_harness_client::{Adjudicated, FileOpType, PromptRole};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // ========================================================================
    // Mock harness client
    // ========================================================================

    /// Records adjudicate calls and returns a configurable response.
    #[derive(Clone)]
    struct MockHarnessClient {
        /// Pre-configured response for the next `adjudicate` call.
        response: Arc<Mutex<std::result::Result<Adjudicated, String>>>,
        /// Recorded events from `adjudicate` calls.
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl MockHarnessClient {
        fn allowing() -> Self {
            Self {
                response: Arc::new(Mutex::new(Ok(Adjudicated::allow()))),
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn denying(reason: &str) -> Self {
            Self {
                response: Arc::new(Mutex::new(Ok(
                    Adjudicated::deny().with_reason(reason.to_string())
                ))),
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn escalating(reason: &str) -> Self {
            Self {
                response: Arc::new(Mutex::new(Ok(
                    Adjudicated::escalate().with_reason(reason.to_string())
                ))),
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn failing(msg: &str) -> Self {
            Self {
                response: Arc::new(Mutex::new(Err(msg.to_string()))),
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn recorded_events(&self) -> Vec<Event> {
            self.events.lock().unwrap().clone()
        }
    }

    impl HarnessClient for MockHarnessClient {
        async fn adjudicate(
            &self,
            event: Event,
        ) -> std::result::Result<Adjudicated, sondera_types::HarnessClientError> {
            self.events.lock().unwrap().push(event);
            let response = self.response.lock().unwrap();
            match &*response {
                Ok(adj) => Ok(adj.clone()),
                Err(msg) => Err(sondera_types::HarnessClientError::Server(msg.clone())),
            }
        }
    }

    // ========================================================================
    // Helper factories
    // ========================================================================

    fn common(session_id: &str) -> CommonInput {
        CommonInput {
            session_id: session_id.to_string(),
            cwd: "/home/test/project".to_string(),
            hook_event_name: String::new(),
            model: "o3-mini".to_string(),
            permission_mode: PermissionMode::Default,
            transcript_path: None,
        }
    }

    fn common_no_session() -> CommonInput {
        CommonInput {
            session_id: String::new(),
            cwd: "/home/test/project".to_string(),
            hook_event_name: String::new(),
            model: "o3-mini".to_string(),
            permission_mode: PermissionMode::Default,
            transcript_path: None,
        }
    }

    fn test_agent() -> Agent {
        Agent {
            id: "codex-test".to_string(),
            provider: "openai".to_string(),
            platform: "codex".to_string(),
        }
    }

    fn to_json(response: &HookResponse) -> String {
        serde_json::to_string(response).unwrap()
    }

    // ========================================================================
    // Response serialization tests
    // ========================================================================

    // Guard against the bug where Allow responses bypass Codex's permission system.
    // HookResponse::ok() MUST serialize to "{}" (empty JSON).

    #[test]
    fn test_allow_response_serializes_to_empty_json() {
        let json = to_json(&HookResponse::ok());
        assert_eq!(
            json, "{}",
            "HookResponse::ok() must serialize to empty JSON, got: {json}"
        );
    }

    #[test]
    fn test_deny_tool_sets_hook_specific_output() {
        let json = to_json(&HookResponse::deny_tool("blocked by policy"));
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("\"deny\""));
        assert!(json.contains("blocked by policy"));
    }

    #[test]
    fn test_block_prompt_sets_flat_decision() {
        let json = to_json(&HookResponse::block_prompt("denied by policy"));
        assert!(json.contains("\"decision\""));
        assert!(json.contains("\"block\""));
        assert!(json.contains("denied by policy"));
    }

    // ========================================================================
    // Trajectory key / session ID tests
    // ========================================================================

    #[test]
    fn test_trajectory_key_uses_session_id_when_present() {
        let c = common("sess-abc123");
        assert_eq!(
            Hooks::<MockHarnessClient>::trajectory_key(&c),
            "sess-abc123"
        );
    }

    #[test]
    fn test_trajectory_key_falls_back_to_cwd() {
        let c = common_no_session();
        assert_eq!(
            Hooks::<MockHarnessClient>::trajectory_key(&c),
            "/home/test/project"
        );
    }

    // ========================================================================
    // SessionStart integration tests
    // ========================================================================

    #[tokio::test]
    async fn test_session_start_creates_session() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = SessionStartEvent {
            common: common("sess-001"),
            source: SessionStartSource::Startup,
            extra: HashMap::new(),
        };

        let response = hooks.handle_session_start(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
        assert_eq!(mock.recorded_events().len(), 1);
    }

    #[tokio::test]
    async fn test_session_start_harness_error_degrades_gracefully() {
        let mock = MockHarnessClient::failing("connection refused");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = SessionStartEvent {
            common: common("sess-001"),
            source: SessionStartSource::Startup,
            extra: HashMap::new(),
        };

        // Should NOT return an error -- observation hooks degrade gracefully.
        let response = hooks.handle_session_start(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
    }

    // ========================================================================
    // PreToolUse integration tests
    // ========================================================================

    #[tokio::test]
    async fn test_pre_tool_use_allow_flow() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PreToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "ls -la" }),
            extra: HashMap::new(),
        };

        let response = hooks.handle_pre_tool_use(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
    }

    #[tokio::test]
    async fn test_pre_tool_use_deny_flow() {
        let mock = MockHarnessClient::denying("dangerous command detected");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PreToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "rm -rf /" }),
            extra: HashMap::new(),
        };

        let response = hooks.handle_pre_tool_use(event).await.unwrap();
        let json = to_json(&response);
        assert!(json.contains("\"deny\""), "Expected deny, got: {json}");
        assert!(json.contains("dangerous command detected"));
    }

    #[tokio::test]
    async fn test_pre_tool_use_harness_error_fails_closed() {
        let mock = MockHarnessClient::failing("connection refused");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PreToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "echo hello" }),
            extra: HashMap::new(),
        };

        // MUST return an error (fail-closed) so Codex blocks via exit != 0.
        let result = hooks.handle_pre_tool_use(event).await;
        assert!(
            result.is_err(),
            "PreToolUse must fail-closed on harness error"
        );
    }

    #[tokio::test]
    async fn test_pre_tool_use_empty_command() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        // tool_input missing "command" field entirely.
        let event = PreToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({}),
            extra: HashMap::new(),
        };

        let response = hooks.handle_pre_tool_use(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
    }

    #[tokio::test]
    async fn test_pre_tool_use_unknown_tool_maps_to_tool_call() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PreToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "apply_patch".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "patch": "..." }),
            extra: HashMap::new(),
        };

        let response = hooks.handle_pre_tool_use(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
        assert_eq!(mock.recorded_events().len(), 1);
    }

    // ========================================================================
    // PostToolUse integration tests
    // ========================================================================

    #[tokio::test]
    async fn test_post_tool_use_observation_recorded() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PostToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "ls -la" }),
            tool_response: serde_json::json!(
                "total 48\ndrwxr-xr-x  12 user user 384 Mar 30 10:00 ."
            ),
            extra: HashMap::new(),
        };

        let response = hooks.handle_post_tool_use(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
        assert_eq!(mock.recorded_events().len(), 1);
    }

    #[tokio::test]
    async fn test_post_tool_use_harness_error_passthrough() {
        let mock = MockHarnessClient::failing("connection refused");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PostToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "ls" }),
            tool_response: serde_json::json!("output"),
            extra: HashMap::new(),
        };

        // Should NOT return an error -- observation hooks degrade gracefully.
        let response = hooks.handle_post_tool_use(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
    }

    #[tokio::test]
    async fn test_post_tool_use_json_object_response() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PostToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "cat file.json" }),
            tool_response: serde_json::json!({"key": "value", "nested": [1, 2, 3]}),
            extra: HashMap::new(),
        };

        let response = hooks.handle_post_tool_use(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
    }

    #[tokio::test]
    async fn test_post_tool_use_null_response() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PostToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "true" }),
            tool_response: serde_json::Value::Null,
            extra: HashMap::new(),
        };

        let response = hooks.handle_post_tool_use(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
    }

    #[tokio::test]
    async fn test_post_tool_use_deny_blocks_output() {
        let mock = MockHarnessClient::denying("sensitive output detected");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PostToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "cat /etc/passwd" }),
            tool_response: serde_json::json!("root:x:0:0:root:/root:/bin/bash"),
            extra: HashMap::new(),
        };

        let response = hooks.handle_post_tool_use(event).await.unwrap();
        let json = to_json(&response);
        assert!(
            json.contains("\"block\""),
            "PostToolUse deny should block: {json}"
        );
        assert!(json.contains("sensitive output detected"));
    }

    // ========================================================================
    // PreToolUse escalation test
    // ========================================================================

    #[tokio::test]
    async fn test_pre_tool_use_escalate_denies_because_ask_not_enforced() {
        // Codex does not enforce "ask" (fails open), so escalated commands
        // must be denied until Codex implements "ask" support.
        let mock = MockHarnessClient::escalating("requires approval");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PreToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "sudo rm -rf /tmp/data" }),
            extra: HashMap::new(),
        };

        let response = hooks.handle_pre_tool_use(event).await.unwrap();
        let json = to_json(&response);
        assert!(
            json.contains("\"deny\""),
            "Escalated PreToolUse should deny (Codex 'ask' fails open), got: {json}"
        );
        assert!(json.contains("requires approval"));
    }

    // ========================================================================
    // UserPromptSubmit integration tests
    // ========================================================================

    #[tokio::test]
    async fn test_user_prompt_submit_allow() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = UserPromptSubmitEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            prompt: "Fix the build".to_string(),
            extra: HashMap::new(),
        };

        let response = hooks.handle_user_prompt_submit(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
    }

    #[tokio::test]
    async fn test_user_prompt_submit_deny() {
        let mock = MockHarnessClient::denying("prompt contains prohibited content");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = UserPromptSubmitEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            prompt: "Delete all production data".to_string(),
            extra: HashMap::new(),
        };

        let response = hooks.handle_user_prompt_submit(event).await.unwrap();
        let json = to_json(&response);
        assert!(json.contains("\"block\""), "Expected block, got: {json}");
        assert!(json.contains("prompt contains prohibited content"));
    }

    #[tokio::test]
    async fn test_user_prompt_submit_harness_error_fails_closed() {
        let mock = MockHarnessClient::failing("connection refused");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = UserPromptSubmitEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            prompt: "Hello".to_string(),
            extra: HashMap::new(),
        };

        let result = hooks.handle_user_prompt_submit(event).await;
        assert!(
            result.is_err(),
            "UserPromptSubmit must fail-closed on harness error"
        );
    }

    #[tokio::test]
    async fn test_user_prompt_submit_empty_prompt() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = UserPromptSubmitEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            prompt: String::new(),
            extra: HashMap::new(),
        };

        let response = hooks.handle_user_prompt_submit(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
    }

    // ========================================================================
    // Stop integration tests
    // ========================================================================

    #[tokio::test]
    async fn test_stop_with_message() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = StopEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            stop_hook_active: false,
            last_assistant_message: Some("Task completed.".to_string()),
            extra: HashMap::new(),
        };

        let response = hooks.handle_stop(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
        let recorded = mock.recorded_events();
        assert_eq!(recorded.len(), 1);
        match &recorded[0].event {
            TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                assert_eq!(prompt.content, "Task completed.");
                assert_eq!(prompt.role, PromptRole::Assistant);
            }
            other => panic!("Stop must remain observational, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_stop_without_message() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = StopEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            stop_hook_active: false,
            last_assistant_message: None,
            extra: HashMap::new(),
        };

        let response = hooks.handle_stop(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
        // No message means no adjudicate call.
        assert_eq!(mock.recorded_events().len(), 0);
    }

    #[tokio::test]
    async fn test_stop_active_guard_records_nothing() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = StopEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            stop_hook_active: true,
            last_assistant_message: Some("Continue this turn.".to_string()),
            extra: HashMap::new(),
        };

        let response = hooks.handle_stop(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
        assert_eq!(mock.recorded_events().len(), 0);
    }

    #[tokio::test]
    async fn test_stop_harness_error_degrades_gracefully() {
        let mock = MockHarnessClient::failing("connection refused");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = StopEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            stop_hook_active: false,
            last_assistant_message: Some("Done.".to_string()),
            extra: HashMap::new(),
        };

        // Should NOT return an error -- observation hooks degrade gracefully.
        let response = hooks.handle_stop(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
    }

    // ========================================================================
    // Agent enrichment tests
    // ========================================================================

    #[tokio::test]
    async fn test_session_key_fallback_to_cwd() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = SessionStartEvent {
            common: common_no_session(),
            source: SessionStartSource::Startup,
            extra: HashMap::new(),
        };

        let _ = hooks.handle_session_start(event).await.unwrap();
        // Verify adjudicate was still called (using cwd as key).
        assert_eq!(mock.recorded_events().len(), 1);
    }

    // ========================================================================
    // Escalation tests (Codex "ask" fails open -- must deny)
    // ========================================================================

    #[tokio::test]
    async fn test_user_prompt_submit_escalate_blocks_because_ask_not_enforced() {
        let mock = MockHarnessClient::escalating("requires review");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = UserPromptSubmitEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            prompt: "Drop the production database".to_string(),
            extra: HashMap::new(),
        };

        let response = hooks.handle_user_prompt_submit(event).await.unwrap();
        let json = to_json(&response);
        assert!(
            json.contains("\"block\""),
            "Escalated UserPromptSubmit should block, got: {json}"
        );
        assert!(json.contains("requires review"));
    }

    #[tokio::test]
    async fn test_post_tool_use_escalate_blocks_output() {
        let mock = MockHarnessClient::escalating("output needs review");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PostToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "cat secrets.env" }),
            tool_response: serde_json::json!("API_KEY=sk-secret123"),
            extra: HashMap::new(),
        };

        let response = hooks.handle_post_tool_use(event).await.unwrap();
        let json = to_json(&response);
        assert!(
            json.contains("\"block\""),
            "Escalated PostToolUse should block output, got: {json}"
        );
        assert!(json.contains("output needs review"));
    }

    // ========================================================================
    // BypassPermissions mode tests
    // ========================================================================

    #[tokio::test]
    async fn test_pre_tool_use_deny_enforced_in_bypass_mode() {
        // Even when Codex is in bypassPermissions mode, our policy deny
        // must still be enforced because the hook exit code controls blocking.
        let mock = MockHarnessClient::denying("policy forbids this");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PreToolUseEvent {
            common: CommonInput {
                session_id: "sess-001".to_string(),
                cwd: "/home/test/project".to_string(),
                hook_event_name: String::new(),
                model: "o3-mini".to_string(),
                permission_mode: PermissionMode::BypassPermissions,
                transcript_path: None,
            },
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "rm -rf /" }),
            extra: HashMap::new(),
        };

        let response = hooks.handle_pre_tool_use(event).await.unwrap();
        let json = to_json(&response);
        assert!(
            json.contains("\"deny\""),
            "Deny must be enforced even in bypassPermissions mode, got: {json}"
        );
    }

    #[tokio::test]
    async fn test_pre_tool_use_harness_error_blocks_in_bypass_mode() {
        // In bypassPermissions mode, a harness error must still fail-closed.
        let mock = MockHarnessClient::failing("connection refused");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PreToolUseEvent {
            common: CommonInput {
                session_id: "sess-001".to_string(),
                cwd: "/home/test/project".to_string(),
                hook_event_name: String::new(),
                model: "o3-mini".to_string(),
                permission_mode: PermissionMode::BypassPermissions,
                transcript_path: None,
            },
            turn_id: "turn-001".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: "toolu_01XYZ".to_string(),
            tool_input: serde_json::json!({ "command": "echo hi" }),
            extra: HashMap::new(),
        };

        let result = hooks.handle_pre_tool_use(event).await;
        assert!(
            result.is_err(),
            "PreToolUse must fail-closed even in bypassPermissions mode"
        );
    }

    // ========================================================================
    // Malformed/edge-case input tests
    // ========================================================================

    #[tokio::test]
    async fn test_pre_tool_use_non_bash_tool_deny() {
        // Future tool types should also respect deny decisions.
        let mock = MockHarnessClient::denying("tool not allowed");
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PreToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "apply_patch".to_string(),
            tool_use_id: "toolu_02ABC".to_string(),
            tool_input: serde_json::json!({ "patch": "--- a/file\n+++ b/file" }),
            extra: HashMap::new(),
        };

        let response = hooks.handle_pre_tool_use(event).await.unwrap();
        let json = to_json(&response);
        assert!(
            json.contains("\"deny\""),
            "Non-Bash tool deny should work, got: {json}"
        );
    }

    #[tokio::test]
    async fn test_post_tool_use_non_bash_tool_observation() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), test_agent());

        let event = PostToolUseEvent {
            common: common("sess-001"),
            turn_id: "turn-001".to_string(),
            tool_name: "apply_patch".to_string(),
            tool_use_id: "toolu_02ABC".to_string(),
            tool_input: serde_json::json!({ "patch": "..." }),
            tool_response: serde_json::json!({ "applied": true }),
            extra: HashMap::new(),
        };

        let response = hooks.handle_post_tool_use(event).await.unwrap();
        assert_eq!(to_json(&response), "{}");
        assert_eq!(mock.recorded_events().len(), 1);
    }

    // ========================================================================
    // Tool mapping
    //
    // PreToolUse is Bash-only, but PermissionRequest is installed with a `*`
    // matcher and routes through the same mapper, so these arms are live on
    // the approval path rather than merely forward-compatible.
    // ========================================================================

    #[test]
    fn bash_still_maps_to_a_shell_command() {
        match action_from_tool(
            "Bash",
            &serde_json::json!({"command":"ls -la"}),
            "c",
            "/repo",
        ) {
            Action::ShellCommand(cmd) => {
                assert_eq!(cmd.command, "ls -la");
                assert_eq!(cmd.working_dir.as_deref(), Some("/repo"));
            }
            other => panic!("expected ShellCommand, got {other:?}"),
        }
    }

    #[test]
    fn argv_shell_calls_are_joined() {
        // Codex's `shell` tool takes an argv array; left unjoined it would
        // reach the shell policies as an empty command.
        match action_from_tool(
            "shell",
            &serde_json::json!({"command":["bash","-lc","cat .env"]}),
            "c",
            "/repo",
        ) {
            Action::ShellCommand(cmd) => assert_eq!(cmd.command, "bash -lc cat .env"),
            other => panic!("expected ShellCommand, got {other:?}"),
        }
    }

    #[test]
    fn apply_patch_maps_to_a_file_edit() {
        let patch = "--- a/.env\n+++ b/.env\n+TOKEN=abc\n";
        match action_from_tool(
            "apply_patch",
            &serde_json::json!({ "patch": patch }),
            "c",
            "/repo",
        ) {
            Action::FileOperation(op) => {
                assert_eq!(op.operation, FileOpType::Edit);
                // apply_patch names its targets inside the diff body, so the
                // content-driven policies are what adjudicate it.
                assert!(op.content.as_deref().unwrap().contains("TOKEN=abc"));
            }
            other => panic!("expected FileOperation(Edit), got {other:?}"),
        }
    }

    #[test]
    fn read_and_write_tools_map_to_file_operations() {
        match action_from_tool(
            "read_file",
            &serde_json::json!({"path":"/repo/.env"}),
            "c",
            "/repo",
        ) {
            Action::FileOperation(op) => {
                assert_eq!(op.operation, FileOpType::Read);
                assert_eq!(op.path, "/repo/.env");
            }
            other => panic!("expected FileOperation(Read), got {other:?}"),
        }
    }

    #[test]
    fn web_tools_map_to_a_web_fetch() {
        match action_from_tool(
            "fetch",
            &serde_json::json!({"url":"https://example.com/x"}),
            "c",
            "/repo",
        ) {
            Action::WebFetch(fetch) => assert_eq!(fetch.url, "https://example.com/x"),
            other => panic!("expected WebFetch, got {other:?}"),
        }
    }

    #[test]
    fn unrecognized_tools_still_fall_back_to_tool_call() {
        assert!(matches!(
            action_from_tool("update_plan", &serde_json::json!({"plan":[]}), "c", "/repo"),
            Action::ToolCall(_)
        ));
        // A web tool with no URL has nothing for url_parse to match, so it
        // keeps its arguments as a generic ToolCall rather than becoming a
        // WebFetch with an empty URL.
        assert!(matches!(
            action_from_tool("fetch", &serde_json::json!({"id":1}), "c", "/repo"),
            Action::ToolCall(_)
        ));
    }
}
