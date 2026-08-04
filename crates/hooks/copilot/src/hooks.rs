//! Hook handler implementations for GitHub Copilot CLI events.

use super::types::*;
use crate::response::HookResponse;
use serde_json::Value as JsonValue;
use sondera_harness_client::{
    Action, Actor, Agent, Completed, Control, Decision, Event, Failed, FileOpType, FileOperation,
    FileOperationResult, HarnessClient, Observation, Prompt, ShellCommand, ShellCommandOutput,
    Started, ToolCall, ToolOutput, TrajectoryEvent, WebFetchOutput,
};
use sondera_hooks::adjudication::warn_unenforceable_decision;
use sondera_hooks::agent_id;
use sondera_hooks::error::Result;
use sondera_hooks::tool::{is_web_fetch, web_fetch_for, web_url_arg};
use tracing::warn;

pub struct Hooks<H: HarnessClient> {
    harness: H,
    agent: Agent,
}

impl<H: HarnessClient> Hooks<H> {
    pub fn new(harness: H, _session_id: Option<&str>) -> Self {
        Self {
            harness,
            agent: Agent {
                id: agent_id("copilot"),
                provider: "github".to_string(),
                platform: "copilot-cli".to_string(),
            },
        }
    }

    fn event(&self, trajectory_id: &str, event: TrajectoryEvent) -> Event {
        Event::new(self.agent.clone(), trajectory_id, event)
    }

    pub async fn handle_session_start(&mut self, event: SessionStartEvent) -> Result<HookResponse> {
        let trajectory_id = session_key(&event.common);
        let started = TrajectoryEvent::Control(Control::Started(Started::new(self.agent.clone())));
        let ev = self.event(&trajectory_id, started);
        let adjudicated = self.harness.adjudicate(ev).await?;
        warn_unenforceable_decision("sessionStart", &adjudicated);
        Ok(HookResponse::ok())
    }

    pub async fn handle_session_end(&mut self, event: SessionEndEvent) -> Result<HookResponse> {
        let trajectory_id = session_key(&event.common);
        let completed = stop_control_from_end_reason(event.reason);
        let ev = self.event(&trajectory_id, completed);
        let adjudicated = self.harness.adjudicate(ev).await?;
        warn_unenforceable_decision("sessionEnd", &adjudicated);
        Ok(HookResponse::ok())
    }

    pub async fn handle_user_prompt_submitted(
        &mut self,
        event: UserPromptSubmittedEvent,
    ) -> Result<HookResponse> {
        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&event.prompt)));
        let ev = self
            .event(&session_key(&event.common), prompt)
            .with_actor(Actor::human(&self.agent.id));
        let adjudicated = self.harness.adjudicate(ev).await?;
        warn_unenforceable_decision("userPromptSubmitted", &adjudicated);
        Ok(HookResponse::ok())
    }

    pub async fn handle_user_prompt_transformed(
        &mut self,
        event: UserPromptTransformedEvent,
    ) -> Result<HookResponse> {
        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(
            &event.transformed_prompt,
        )));
        let ev = self
            .event(&session_key(&event.common), prompt)
            .with_actor(Actor::human(&self.agent.id));
        let adjudicated = self.harness.adjudicate(ev).await?;
        Ok(match adjudicated.decision {
            Decision::Allow => HookResponse::ok(),
            Decision::Deny | Decision::Escalate => {
                HookResponse::replace_transformed_prompt(format!(
                    "[Sondera policy withheld this prompt: {}]",
                    adjudicated.deny_message("Prompt blocked by policy")
                ))
            }
        })
    }

    pub async fn handle_pre_tool_use(&mut self, event: PreToolUseEvent) -> Result<HookResponse> {
        let action = action_from_tool(&event, &event.common.cwd);
        let ev = self.event(&session_key(&event.common), TrajectoryEvent::Action(action));
        let adjudicated = self.harness.adjudicate(ev).await?;
        Ok(match adjudicated.decision {
            Decision::Allow => HookResponse::ok(),
            Decision::Deny | Decision::Escalate => {
                HookResponse::block_tool(adjudicated.deny_message(&format!(
                    "Tool '{}' execution denied by policy",
                    event.tool_name
                )))
            }
        })
    }

    pub async fn handle_permission_request(
        &mut self,
        event: PermissionRequestEvent,
    ) -> Result<HookResponse> {
        let action = action_from_tool(&event, &event.common.cwd);
        let ev = self.event(&session_key(&event.common), TrajectoryEvent::Action(action));
        let adjudicated = self.harness.adjudicate(ev).await?;
        Ok(match adjudicated.decision {
            Decision::Allow => HookResponse::permission_allow("Allowed by Sondera policy"),
            Decision::Deny | Decision::Escalate => HookResponse::permission_deny(
                adjudicated.deny_message("Permission request denied by policy"),
            ),
        })
    }

    pub async fn handle_post_tool_use(&mut self, event: PostToolUseEvent) -> Result<HookResponse> {
        let output = output_from_tool(
            &event.tool,
            &event.tool_result,
            event.duration,
            true,
            int_field(&event.tool_result, &["exitCode", "exit_code", "code"]),
        );
        let ev = self.event(&session_key(&event.tool.common), output);

        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => warn_unenforceable_decision("postToolUse", &adjudicated),
            Err(err) => warn!(error = %err, "PostToolUse: harness error, degrading gracefully"),
        }
        Ok(HookResponse::ok())
    }

    pub async fn handle_post_tool_use_failure(
        &mut self,
        event: PostToolUseFailureEvent,
    ) -> Result<HookResponse> {
        let output = output_from_tool(
            &event.tool,
            &event.tool_error,
            0.0,
            false,
            event
                .exit_code
                .or_else(|| int_field(&event.tool_error, &["exitCode", "exit_code", "code"])),
        );
        let ev = self.event(&session_key(&event.tool.common), output);
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => Ok(match adjudicated.decision {
                Decision::Allow => HookResponse::additional_context(
                    "Tool failed; retry with safer arguments if appropriate.",
                ),
                Decision::Deny | Decision::Escalate => HookResponse::block_continuation(
                    adjudicated.deny_message("Tool failure recovery blocked by policy"),
                ),
            }),
            Err(err) => {
                warn!(error = %err, "PostToolUseFailure: harness error, degrading gracefully");
                Ok(HookResponse::additional_context(
                    "Tool failed; retry with safer arguments if appropriate.",
                ))
            }
        }
    }

    pub async fn handle_error_occurred(
        &mut self,
        event: ErrorOccurredEvent,
    ) -> Result<HookResponse> {
        warn!(error = %event.error, error_code = ?event.error_code, "Copilot error occurred");
        Ok(HookResponse::ok())
    }

    pub async fn handle_notification(&mut self, _event: NotificationEvent) -> Result<HookResponse> {
        Ok(HookResponse::ok())
    }

    pub async fn handle_pre_compact(&mut self, _event: PreCompactEvent) -> Result<HookResponse> {
        Ok(HookResponse::ok())
    }

    pub async fn handle_agent_stop(&mut self, event: AgentStopEvent) -> Result<HookResponse> {
        self.handle_stop_like(event, "agentStop").await
    }

    pub async fn handle_subagent_stop(&mut self, event: SubagentStopEvent) -> Result<HookResponse> {
        self.handle_stop_like(event, "subagentStop").await
    }

    async fn handle_stop_like(
        &mut self,
        event: AgentStopEvent,
        _hook_name: &str,
    ) -> Result<HookResponse> {
        let stop = stop_control_from_reason(event.reason.as_deref());
        let ev = self.event(&session_key(&event.common), stop);
        let adjudicated = self.harness.adjudicate(ev).await?;
        Ok(match adjudicated.decision {
            Decision::Allow => HookResponse::ok(),
            Decision::Deny | Decision::Escalate => HookResponse::block_continuation(
                adjudicated.deny_message("Continuation blocked by policy"),
            ),
        })
    }

    pub async fn handle_subagent_start(
        &mut self,
        event: SubagentStartEvent,
    ) -> Result<HookResponse> {
        let mut started = Started::new(self.agent.clone());
        if let Some(task) = event.task.clone() {
            started = started.with_task(task);
        }
        let ev = self.event(
            &session_key(&event.common),
            TrajectoryEvent::Control(Control::Started(started)),
        );
        let adjudicated = self.harness.adjudicate(ev).await?;
        warn_unenforceable_decision("subagentStart", &adjudicated);
        Ok(HookResponse::ok())
    }
}

fn action_from_tool(event: &ToolEvent, cwd: &str) -> Action {
    let call_id = format!("call-{}", uuid::Uuid::new_v4());
    match event.tool_name.as_str() {
        "bash" | "powershell" => Action::ShellCommand(ShellCommand {
            call_id,
            command: string_field(&event.tool_args, &["command", "script"]).unwrap_or_default(),
            working_dir: Some(cwd.to_string()),
        }),
        "view" | "read_file" => Action::FileOperation(FileOperation {
            call_id,
            operation: FileOpType::Read,
            path: string_field(&event.tool_args, &["path", "file"]).unwrap_or_default(),
            content: None,
            old_content: None,
        }),
        "edit" | "str_replace" => Action::FileOperation(FileOperation {
            call_id,
            operation: FileOpType::Edit,
            path: string_field(&event.tool_args, &["path", "file"]).unwrap_or_default(),
            content: string_field(&event.tool_args, &["new_str", "newString", "content"]),
            old_content: string_field(&event.tool_args, &["old_str", "oldString"]),
        }),
        "create" | "write_file" => Action::FileOperation(FileOperation {
            call_id,
            operation: FileOpType::Write,
            path: string_field(&event.tool_args, &["path", "file"]).unwrap_or_default(),
            content: string_field(&event.tool_args, &["content"]),
            old_content: None,
        }),
        _ => match web_fetch_for(&event.tool_name, &event.tool_args, call_id.clone()) {
            Some(fetch) => Action::WebFetch(fetch),
            None => Action::ToolCall(ToolCall {
                call_id,
                tool: event.tool_name.clone(),
                arguments: event.tool_args.clone(),
            }),
        },
    }
}

fn output_from_tool(
    event: &ToolEvent,
    result: &JsonValue,
    duration: f64,
    success: bool,
    exit_code: Option<i32>,
) -> TrajectoryEvent {
    let call_id = format!("call-{}", uuid::Uuid::new_v4());
    match event.tool_name.as_str() {
        "bash" | "powershell" => {
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput {
                call_id,
                exit_code: exit_code.unwrap_or(if success { 0 } else { 1 }),
                stdout: string_field(
                    result,
                    &[
                        "stdout",
                        "output",
                        "textResultForLlm",
                        "text_result_for_llm",
                    ],
                )
                .unwrap_or_else(|| result.to_string()),
                stderr: string_field(result, &["stderr", "error"]).unwrap_or_default(),
            }))
        }
        "view" | "read_file" => {
            let mut file_result = if success {
                FileOperationResult::success(call_id)
                    .with_content(string_field(result, &["content", "output"]).unwrap_or_default())
            } else {
                FileOperationResult::error(call_id, result.to_string())
            };
            if let Some(path) = string_field(&event.tool_args, &["file_path", "path", "file"]) {
                file_result = file_result.with_path(path);
            }
            TrajectoryEvent::Observation(Observation::FileOperationResult(file_result))
        }
        // Same pairing as the file branch: the fetched body is what the
        // post-execution web policies scan.
        name if is_web_fetch(name, &event.tool_args) => {
            TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
                call_id,
                web_url_arg(&event.tool_args).unwrap_or_default(),
                int_field(result, &["status_code", "statusCode", "status", "code"]).unwrap_or(200),
                string_field(result, &["content", "output", "text", "body"])
                    .unwrap_or_else(|| result.to_string()),
            )))
        }
        _ => TrajectoryEvent::Observation(Observation::ToolOutput(if success {
            ToolOutput::success(call_id, result.to_string())
        } else {
            ToolOutput::error(call_id, format!("duration={duration}; {result}"))
        })),
    }
}

fn string_field(value: &JsonValue, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(JsonValue::as_str))
        .map(ToString::to_string)
}

fn int_field(value: &JsonValue, keys: &[&str]) -> Option<i32> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(JsonValue::as_i64))
        .and_then(|value| i32::try_from(value).ok())
}

fn stop_control_from_reason(reason: Option<&str>) -> TrajectoryEvent {
    let reason = reason.unwrap_or("complete").trim();
    if matches!(
        reason.to_ascii_lowercase().as_str(),
        "" | "complete" | "completed" | "success" | "done"
    ) {
        TrajectoryEvent::Control(Control::Completed(Completed::new()))
    } else {
        TrajectoryEvent::Control(Control::Failed(Failed::new(reason.to_string())))
    }
}

fn stop_control_from_end_reason(reason: Option<EndReason>) -> TrajectoryEvent {
    match reason.unwrap_or_default() {
        EndReason::Complete | EndReason::Completed => {
            TrajectoryEvent::Control(Control::Completed(Completed::new()))
        }
        EndReason::Error => TrajectoryEvent::Control(Control::Failed(Failed::new("error"))),
        EndReason::Abort | EndReason::Aborted => {
            TrajectoryEvent::Control(Control::Failed(Failed::new("aborted")))
        }
        EndReason::Timeout => TrajectoryEvent::Control(Control::Failed(Failed::new("timeout"))),
        EndReason::UserExit => TrajectoryEvent::Control(Control::Failed(Failed::new("user_exit"))),
        EndReason::Unknown => TrajectoryEvent::Control(Control::Failed(Failed::new("unknown"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_harness_client::Adjudicated;
    use sondera_harness_client::types::HarnessClientError;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockHarness {
        response: Arc<Mutex<Adjudicated>>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl MockHarness {
        fn new(response: Adjudicated) -> Self {
            Self {
                response: Arc::new(Mutex::new(response)),
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl HarnessClient for MockHarness {
        async fn adjudicate(
            &self,
            event: Event,
        ) -> std::result::Result<Adjudicated, HarnessClientError> {
            self.events
                .lock()
                .map_err(|_| HarnessClientError::Unavailable("poisoned mutex".to_string()))?
                .push(event);
            Ok(self
                .response
                .lock()
                .map_err(|_| HarnessClientError::Unavailable("poisoned mutex".to_string()))?
                .clone())
        }
    }

    #[derive(Clone)]
    struct FailingHarness;

    impl HarnessClient for FailingHarness {
        async fn adjudicate(
            &self,
            _event: Event,
        ) -> std::result::Result<Adjudicated, HarnessClientError> {
            Err(HarnessClientError::Unavailable("offline".to_string()))
        }
    }

    #[tokio::test]
    async fn permission_request_returns_permission_model() {
        let harness = MockHarness::new(Adjudicated::deny().with_reason("too risky"));
        let mut hooks = Hooks::new(harness, None);
        let event: PermissionRequestEvent = serde_json::from_str(
            r#"{"cwd":"/repo","toolName":"bash","toolArgs":{"command":"rm -rf /"}}"#,
        )
        .unwrap();

        let response = hooks.handle_permission_request(event).await.unwrap();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"behavior\":\"deny\""));
        assert!(json.contains("too risky"));
    }

    #[tokio::test]
    async fn user_prompt_submitted_records_but_returns_no_output_on_deny() {
        let harness = MockHarness::new(Adjudicated::deny().with_reason("prompt blocked"));
        let events = harness.events.clone();
        let mut hooks = Hooks::new(harness, None);
        let event: UserPromptSubmittedEvent =
            serde_json::from_str(r#"{"cwd":"/repo","prompt":"delete everything"}"#).unwrap();

        let response = hooks.handle_user_prompt_submitted(event).await.unwrap();
        assert_eq!(serde_json::to_string(&response).unwrap(), "{}");

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0].event {
            TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                assert_eq!(prompt.content, "delete everything");
            }
            other => panic!("expected prompt observation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn user_prompt_transformed_rewrites_model_content_on_deny() {
        let harness = MockHarness::new(Adjudicated::deny().with_reason("contains a secret"));
        let events = harness.events.clone();
        let mut hooks = Hooks::new(harness, None);
        let event: UserPromptTransformedEvent = serde_json::from_str(
            r#"{"cwd":"/repo","prompt":"raw","transformedPrompt":"model-facing"}"#,
        )
        .unwrap();

        let response = hooks.handle_user_prompt_transformed(event).await.unwrap();
        let json = serde_json::to_value(response).unwrap();

        assert_eq!(
            json.get("modifiedTransformedPrompt")
                .and_then(serde_json::Value::as_str),
            Some("[Sondera policy withheld this prompt: contains a secret]")
        );
        let events = events.lock().unwrap();
        match &events[0].event {
            TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                assert_eq!(prompt.content, "model-facing");
            }
            other => panic!("expected transformed prompt observation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn agent_stop_uses_continuation_response_on_deny() {
        let harness = MockHarness::new(Adjudicated::deny().with_reason("not done"));
        let mut hooks = Hooks::new(harness, None);
        let event: AgentStopEvent =
            serde_json::from_str(r#"{"cwd":"/repo","reason":"complete"}"#).unwrap();

        let response = hooks.handle_agent_stop(event).await.unwrap();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"decision\":\"block\""));
        assert!(json.contains("not done"));
    }

    #[test]
    fn stop_reason_complete_maps_to_completed_control() {
        match stop_control_from_reason(Some("complete")) {
            TrajectoryEvent::Control(Control::Completed(_)) => {}
            other => panic!("expected completed control, got {other:?}"),
        }

        match stop_control_from_reason(Some("aborted")) {
            TrajectoryEvent::Control(Control::Failed(failed)) => {
                assert_eq!(failed.reason, "aborted");
            }
            other => panic!("expected failed control, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn session_end_error_maps_to_failed_control() {
        let harness = MockHarness::new(Adjudicated::allow());
        let events = harness.events.clone();
        let mut hooks = Hooks::new(harness, None);
        let event: SessionEndEvent =
            serde_json::from_str(r#"{"cwd":"/repo","reason":"error"}"#).unwrap();

        let _ = hooks.handle_session_end(event).await.unwrap();

        let events = events.lock().unwrap();
        match &events.last().unwrap().event {
            TrajectoryEvent::Control(Control::Failed(failed)) => {
                assert_eq!(failed.reason, "error");
            }
            other => panic!("expected failed control, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn post_tool_use_failure_blocks_continuation_on_deny() {
        let harness = MockHarness::new(Adjudicated::deny().with_reason("retry not allowed"));
        let mut hooks = Hooks::new(harness, None);
        let event: PostToolUseFailureEvent = serde_json::from_str(
            r#"{"cwd":"/repo","toolName":"bash","toolArgs":{"command":"missing-command"},"toolError":{"stderr":"not found"},"exitCode":127}"#,
        )
        .unwrap();

        let response = hooks.handle_post_tool_use_failure(event).await.unwrap();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"decision\":\"block\""));
        assert!(json.contains("retry not allowed"));
    }

    #[tokio::test]
    async fn post_tool_use_failure_degrades_when_harness_unavailable() {
        let mut hooks = Hooks::new(FailingHarness, None);
        let event: PostToolUseFailureEvent = serde_json::from_str(
            r#"{"cwd":"/repo","toolName":"bash","toolArgs":{"command":"missing-command"},"toolError":{"stderr":"not found"},"exitCode":127}"#,
        )
        .unwrap();

        let response = hooks.handle_post_tool_use_failure(event).await.unwrap();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("additionalContext"));
        assert!(json.contains("retry with safer arguments"));
    }

    #[test]
    fn shell_observation_preserves_reported_exit_code() {
        let event: ToolEvent = serde_json::from_str(
            r#"{"cwd":"/repo","toolName":"bash","toolArgs":{"command":"missing-command"}}"#,
        )
        .unwrap();
        let output = output_from_tool(
            &event,
            &serde_json::json!({"stderr":"not found"}),
            0.0,
            false,
            Some(127),
        );

        match output {
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(output)) => {
                assert_eq!(output.exit_code, 127);
                assert_eq!(output.stderr, "not found");
            }
            other => panic!("expected shell command output, got {other:?}"),
        }
    }
}
