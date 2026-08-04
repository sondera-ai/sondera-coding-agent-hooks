//! Hook handler implementations for Hermes Agent shell-hook events.
//!
//! Error strategy:
//! - `pre_tool_call` is blockable in Hermes and fails closed.
//! - Every other Hermes shell hook is advisory/observation-only and degrades
//!   gracefully when telemetry or adjudication is unavailable.

use super::types::*;
use crate::response::HookResponse;
use serde_json::Value;
use sondera_harness_client::{
    Action, Actor, Agent, Decision, Event, FileOperationResult, HarnessClient, Observation, Prompt,
    ShellCommand, ShellCommandOutput, Thought, ToolCall, ToolOutput, TrajectoryEvent,
    WebFetchOutput,
};
use sondera_hooks::adjudication::warn_unenforceable_decision;
use sondera_hooks::error::Result;
use sondera_hooks::tool::{
    file_operation_for, file_path_arg, is_file_operation, is_web_fetch, web_fetch_for, web_url_arg,
};
use tracing::warn;

pub struct Hooks<H: HarnessClient> {
    harness: H,
    agent: Agent,
}

impl<H: HarnessClient> Hooks<H> {
    pub fn new(harness: H, agent: Agent) -> Self {
        Self { harness, agent }
    }

    fn event(&self, trajectory_id: &str, event: TrajectoryEvent) -> Event {
        Event::new(self.agent.clone(), trajectory_id, event)
    }

    pub async fn handle_pre_tool_call(&mut self, event: HermesHookEvent) -> Result<HookResponse> {
        event.validate_tool_event()?;
        let tool_name = event.tool_name().unwrap_or_default().to_string();
        let key = event.trajectory_key();
        let call_id = event.call_id();
        let tool_input = event.tool_input();
        let action = if is_shell_tool(&tool_name) {
            Action::ShellCommand(ShellCommand {
                call_id,
                command: command_from_value(&tool_input).unwrap_or_else(|| tool_input.to_string()),
                working_dir: Some(event.working_dir_or_current()),
            })
        } else if let Some(file_op) = file_operation_for(&tool_name, &tool_input, call_id.clone()) {
            Action::FileOperation(file_op)
        } else if let Some(fetch) = web_fetch_for(&tool_name, &tool_input, call_id.clone()) {
            Action::WebFetch(fetch)
        } else {
            Action::ToolCall(ToolCall {
                call_id,
                tool: tool_name,
                arguments: tool_input,
            })
        };

        let ev = self.event(&key, TrajectoryEvent::Action(action));
        let adjudicated = self.harness.adjudicate(ev).await?;
        Ok(blocking_response(
            adjudicated,
            "Tool call blocked by policy",
            "Tool call requires review",
        ))
    }

    pub async fn handle_post_tool_call(&mut self, event: HermesHookEvent) -> Result<HookResponse> {
        self.record_tool_observation_inner(event, "post_tool_call")
            .await
    }

    pub async fn handle_transform_tool_result(
        &mut self,
        event: HermesHookEvent,
    ) -> Result<HookResponse> {
        self.record_tool_observation_inner(event, "transform_tool_result")
            .await
    }

    pub async fn handle_transform_terminal_output(
        &mut self,
        event: HermesHookEvent,
    ) -> Result<HookResponse> {
        let key = event.trajectory_key();
        let output = event.terminal_output();
        let observation =
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput {
                call_id: event.call_id(),
                exit_code: event.terminal_exit_code(),
                stdout: output.clone(),
                stderr: event.terminal_stderr(),
            }));
        let ev = self.event(&key, observation);
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => {
                warn_unenforceable_decision("transform_terminal_output", &adjudicated);
                Ok(HookResponse::ok())
            }
            Err(err) => {
                warn!(error = %err, "Hermes transform_terminal_output harness error; degrading gracefully");
                Ok(HookResponse::ok())
            }
        }
    }

    pub async fn handle_pre_llm_call(&mut self, event: HermesHookEvent) -> Result<HookResponse> {
        let Some(message) = event.user_message() else {
            return Ok(HookResponse::ok());
        };
        let key = event.trajectory_key();
        let observation = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&message)));
        let ev = self
            .event(&key, observation)
            .with_actor(Actor::human(&self.agent.id));
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => Ok(advisory_context_response(adjudicated)),
            Err(err) => {
                warn!(error = %err, "Hermes pre_llm_call harness error; degrading gracefully");
                Ok(HookResponse::ok())
            }
        }
    }

    pub async fn handle_post_llm_call(&mut self, event: HermesHookEvent) -> Result<HookResponse> {
        self.record_assistant_observation(event, "post_llm_call")
            .await
    }

    pub async fn handle_transform_llm_output(
        &mut self,
        event: HermesHookEvent,
    ) -> Result<HookResponse> {
        self.record_assistant_observation(event, "transform_llm_output")
            .await
    }

    pub async fn handle_pre_approval_request(
        &mut self,
        event: HermesHookEvent,
    ) -> Result<HookResponse> {
        self.record_approval_observation(event, "pre_approval_request")
            .await
    }

    pub async fn handle_post_approval_response(
        &mut self,
        event: HermesHookEvent,
    ) -> Result<HookResponse> {
        self.record_approval_observation(event, "post_approval_response")
            .await
    }

    pub async fn handle_pre_verify(&mut self, event: HermesHookEvent) -> Result<HookResponse> {
        let key = event.trajectory_key();
        let summary = event
            .extra_string("summary")
            .or_else(|| event.extra_string("verification"))
            .unwrap_or_else(|| "Hermes pre-verification checkpoint".to_string());
        let ev = self.event(
            &key,
            TrajectoryEvent::Observation(Observation::Thought(Thought::new(summary))),
        );
        let adjudicated = self.harness.adjudicate(ev).await?;
        Ok(match adjudicated.decision {
            Decision::Allow => HookResponse::ok(),
            Decision::Deny | Decision::Escalate => HookResponse::continue_turn(
                adjudicated.deny_message("Verification blocked; continue working"),
            ),
        })
    }

    pub async fn handle_pre_gateway_dispatch(
        &mut self,
        event: HermesHookEvent,
    ) -> Result<HookResponse> {
        let message = event
            .user_message()
            .or_else(|| event.extra_string("text"))
            .unwrap_or_default();
        if message.is_empty() {
            return Ok(HookResponse::ok());
        }
        let ev = self
            .event(
                &event.trajectory_key(),
                TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&message))),
            )
            .with_actor(Actor::human(&self.agent.id));
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => warn_unenforceable_decision("pre_gateway_dispatch", &adjudicated),
            Err(err) => warn!(error = %err, "Hermes gateway dispatch observation failed"),
        }
        Ok(HookResponse::ok())
    }

    pub async fn handle_lifecycle(&mut self, event: HermesHookEvent) -> Result<HookResponse> {
        let hook = if event.hook_event_name.is_empty() {
            "Hermes lifecycle event"
        } else {
            event.hook_event_name.as_str()
        };
        let ev = self.event(
            &event.trajectory_key(),
            TrajectoryEvent::Observation(Observation::Thought(Thought::new(hook))),
        );
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => warn_unenforceable_decision(hook, &adjudicated),
            Err(err) => warn!(error = %err, hook, "Hermes lifecycle observation failed"),
        }
        Ok(HookResponse::ok())
    }

    async fn record_tool_observation_inner(
        &mut self,
        event: HermesHookEvent,
        hook: &'static str,
    ) -> Result<HookResponse> {
        event.validate_tool_event()?;
        let tool_name = event.tool_name().unwrap_or_default().to_string();
        let result = event.tool_result().unwrap_or_default();
        let stderr = event.terminal_stderr();
        let observation = if is_shell_tool(&tool_name) {
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput {
                call_id: event.call_id(),
                exit_code: exit_code_from_result(&result),
                stdout: stdout_from_result(&result),
                stderr: if stderr.is_empty() {
                    stderr_from_result(&result)
                } else {
                    stderr
                },
            }))
        } else if is_file_operation(&tool_name, &event.tool_input()) {
            // Gated on the same classifier as `handle_pre_tool_call`, so a
            // call adjudicated as a FileOperation reports a
            // FileOperationResult and keeps the content the post-execution
            // policies scan.
            let tool_input = event.tool_input();
            let path = file_path_arg(&tool_input);
            let content = content_from_result(&result);
            let error = stderr_from_result(&result);
            TrajectoryEvent::Observation(Observation::FileOperationResult(FileOperationResult {
                call_id: event.call_id(),
                success: error.is_empty(),
                path: (!path.is_empty()).then(|| path.to_string()),
                content: (!content.is_empty()).then_some(content),
                error: (!error.is_empty()).then_some(error),
            }))
        } else if is_web_fetch(&tool_name, &event.tool_input()) {
            // Same pairing as the file branch: the fetched body is what the
            // post-execution web policies scan.
            let tool_input = event.tool_input();
            TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
                event.call_id(),
                web_url_arg(&tool_input).unwrap_or_default(),
                status_from_result(&result),
                content_from_result(&result),
            )))
        } else {
            TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput::success(
                event.call_id(),
                value_from_result(&result),
            )))
        };
        let key = event.trajectory_key();
        let ev = self.event(&key, observation);
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => {
                warn_unenforceable_decision(hook, &adjudicated);
                Ok(HookResponse::ok())
            }
            Err(err) => {
                warn!(error = %err, hook = hook, "Hermes tool observation harness error; degrading gracefully");
                Ok(HookResponse::ok())
            }
        }
    }

    async fn record_assistant_observation(
        &mut self,
        event: HermesHookEvent,
        hook: &'static str,
    ) -> Result<HookResponse> {
        let response = event.assistant_response().unwrap_or_default();
        if response.is_empty() {
            return Ok(HookResponse::ok());
        }
        let key = event.trajectory_key();
        let ev = self.event(
            &key,
            TrajectoryEvent::Observation(Observation::Prompt(Prompt::assistant(&response))),
        );
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => {
                warn_unenforceable_decision(hook, &adjudicated);
                Ok(HookResponse::ok())
            }
            Err(err) => {
                warn!(error = %err, hook = hook, "Hermes LLM observation harness error; degrading gracefully");
                Ok(HookResponse::ok())
            }
        }
    }

    async fn record_approval_observation(
        &mut self,
        event: HermesHookEvent,
        hook: &'static str,
    ) -> Result<HookResponse> {
        let key = event.trajectory_key();
        let summary = event
            .extra_string("command")
            .or_else(|| event.extra_string("message"))
            .unwrap_or_else(|| format!("Hermes {hook}"));
        let ev = self.event(
            &key,
            TrajectoryEvent::Observation(Observation::Thought(Thought::new(summary))),
        );
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => warn_unenforceable_decision(hook, &adjudicated),
            Err(err) => {
                warn!(error = %err, hook = hook, "Hermes approval observation harness error; degrading gracefully")
            }
        }
        Ok(HookResponse::ok())
    }
}

pub fn hermes_agent(session_id: Option<&str>) -> Agent {
    let id = session_id
        .filter(|session| !session.trim().is_empty())
        .map(|session| format!("hermes-{session}"))
        .unwrap_or_else(|| sondera_hooks::agent_id("hermes"));
    Agent {
        id,
        provider: "hermes".to_string(),
        platform: "hermes-agent".to_string(),
    }
}

fn blocking_response(
    adjudicated: sondera_harness_client::Adjudicated,
    deny: &str,
    escalate: &str,
) -> HookResponse {
    match adjudicated.decision {
        Decision::Allow => HookResponse::ok(),
        Decision::Deny => HookResponse::block(adjudicated.deny_message(deny)),
        Decision::Escalate => HookResponse::block(adjudicated.deny_message(escalate)),
    }
}

fn advisory_context_response(adjudicated: sondera_harness_client::Adjudicated) -> HookResponse {
    if let Some(context) = steering_context(&adjudicated) {
        return HookResponse::context(context);
    }
    match adjudicated.decision {
        Decision::Allow => HookResponse::ok(),
        Decision::Deny | Decision::Escalate => HookResponse::context(
            adjudicated
                .deny_message("Sondera policy advisory: adjust this turn before continuing."),
        ),
    }
}

fn steering_context(adjudicated: &sondera_harness_client::Adjudicated) -> Option<String> {
    let steering = adjudicated.steering.as_ref()?;
    let mut parts = Vec::new();
    if !steering.explanation.trim().is_empty() {
        parts.push(steering.explanation.clone());
    }
    if !steering.instructions.is_empty() {
        parts.push(steering.instructions.join("\n"));
    }
    (!parts.is_empty()).then(|| parts.join("\n"))
}

fn is_shell_tool(tool_name: &str) -> bool {
    matches!(
        tool_name.to_ascii_lowercase().as_str(),
        "terminal" | "bash" | "shell"
    )
}

fn value_from_result(result: &str) -> Value {
    serde_json::from_str(result).unwrap_or_else(|_| Value::String(result.to_string()))
}

fn exit_code_from_result(result: &str) -> i32 {
    serde_json::from_str::<Value>(result)
        .ok()
        .and_then(|value| {
            ["exit_code", "exitCode", "status"]
                .into_iter()
                .find_map(|key| value.get(key).and_then(Value::as_i64))
        })
        .and_then(|code| i32::try_from(code).ok())
        .unwrap_or(0)
}

fn stdout_from_result(result: &str) -> String {
    serde_json::from_str::<Value>(result)
        .ok()
        .and_then(|value| {
            ["stdout", "output"].into_iter().find_map(|key| {
                value
                    .get(key)
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
        })
        .unwrap_or_else(|| result.to_string())
}

/// Recover the file content a tool result carries.
///
/// Distinct from [`stdout_from_result`], which looks only at the shell keys: a
/// file result names its payload `content`. Falls back to the raw result so
/// the post-execution signature scan still has the bytes to work with even
/// when the shape is unrecognized.
fn content_from_result(result: &str) -> String {
    serde_json::from_str::<Value>(result)
        .ok()
        .and_then(|value| {
            ["content", "text", "stdout", "output"]
                .into_iter()
                .find_map(|key| {
                    value
                        .get(key)
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
        })
        .unwrap_or_else(|| result.to_string())
}

/// Read the HTTP status a fetch returned.
///
/// Distinct from [`exit_code_from_result`]: a fetch reports a status, not a
/// process exit code, and an absent status means the fetch succeeded, so it
/// falls back to 200 rather than 0.
fn status_from_result(result: &str) -> i32 {
    serde_json::from_str::<Value>(result)
        .ok()
        .and_then(|value| {
            ["status_code", "statusCode", "status", "code"]
                .into_iter()
                .find_map(|key| value.get(key).and_then(Value::as_i64))
        })
        .and_then(|code| i32::try_from(code).ok())
        .unwrap_or(200)
}

fn stderr_from_result(result: &str) -> String {
    serde_json::from_str::<Value>(result)
        .ok()
        .and_then(|value| {
            ["stderr", "error"].into_iter().find_map(|key| {
                value
                    .get(key)
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_harness_client::{Adjudicated, FileOpType, Steering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockHarnessClient {
        response: Arc<Mutex<std::result::Result<Adjudicated, String>>>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl MockHarnessClient {
        fn allowing() -> Self {
            Self::with_response(Ok(Adjudicated::allow()))
        }

        fn denying(reason: &str) -> Self {
            Self::with_response(Ok(Adjudicated::deny().with_reason(reason.to_string())))
        }

        fn escalating(reason: &str) -> Self {
            Self::with_response(Ok(Adjudicated::escalate().with_reason(reason.to_string())))
        }

        fn failing(reason: &str) -> Self {
            Self::with_response(Err(reason.to_string()))
        }

        fn with_response(response: std::result::Result<Adjudicated, String>) -> Self {
            Self {
                response: Arc::new(Mutex::new(response)),
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn events(&self) -> Vec<Event> {
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
                Ok(adjudicated) => Ok(adjudicated.clone()),
                Err(reason) => Err(sondera_types::HarnessClientError::Server(reason.clone())),
            }
        }
    }

    fn event() -> HermesHookEvent {
        HermesHookEvent {
            hook_event_name: "pre_tool_call".to_string(),
            tool_name: Some("terminal".to_string()),
            tool_input: Some(serde_json::json!({"command":"pwd"})),
            session_id: "sess-1".to_string(),
            cwd: "/tmp/project".to_string(),
            extra: serde_json::Map::from_iter([(
                "tool_call_id".to_string(),
                Value::String("call-1".to_string()),
            )]),
        }
    }

    fn json(response: &HookResponse) -> Value {
        serde_json::to_value(response).unwrap()
    }

    #[tokio::test]
    async fn pre_tool_call_allow_deny_escalate_and_fail_closed() {
        let mut hooks = Hooks::new(MockHarnessClient::allowing(), hermes_agent(Some("sess-1")));
        assert_eq!(
            json(&hooks.handle_pre_tool_call(event()).await.unwrap()),
            serde_json::json!({})
        );

        let mut hooks = Hooks::new(
            MockHarnessClient::denying("nope"),
            hermes_agent(Some("sess-1")),
        );
        assert_eq!(
            json(&hooks.handle_pre_tool_call(event()).await.unwrap()),
            serde_json::json!({"action":"block","message":"nope"})
        );

        let mut hooks = Hooks::new(
            MockHarnessClient::escalating("review"),
            hermes_agent(Some("sess-1")),
        );
        assert_eq!(
            json(&hooks.handle_pre_tool_call(event()).await.unwrap())["action"],
            "block"
        );

        let mut hooks = Hooks::new(
            MockHarnessClient::failing("down"),
            hermes_agent(Some("sess-1")),
        );
        assert!(hooks.handle_pre_tool_call(event()).await.is_err());
    }

    #[tokio::test]
    async fn tool_action_and_observation_share_correlation_id() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), hermes_agent(Some("sess-1")));
        let _ = hooks.handle_pre_tool_call(event()).await.unwrap();
        let mut post = event();
        post.hook_event_name = "post_tool_call".to_string();
        post.extra.insert(
            "result".to_string(),
            Value::String(r#"{"stdout":"ok","stderr":"warn","exit_code":0}"#.to_string()),
        );
        post.extra.insert(
            "stderr".to_string(),
            Value::String("warn-field".to_string()),
        );
        let _ = hooks.handle_post_tool_call(post).await.unwrap();

        let events = mock.events();
        let action_call_id = match &events[0].event {
            TrajectoryEvent::Action(Action::ShellCommand(cmd)) => &cmd.call_id,
            other => panic!("unexpected action: {other:?}"),
        };
        let observation_call_id = match &events[1].event {
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(output)) => {
                assert_eq!(output.stdout, "ok");
                assert_eq!(output.stderr, "warn-field");
                &output.call_id
            }
            other => panic!("unexpected observation: {other:?}"),
        };
        assert_eq!(action_call_id, observation_call_id);
        assert_eq!(action_call_id, "call-1");
    }

    #[tokio::test]
    async fn transform_terminal_output_preserves_stderr() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), hermes_agent(Some("sess-1")));
        let mut event = event();
        event.hook_event_name = "transform_terminal_output".to_string();
        event
            .extra
            .insert("output".to_string(), Value::String("out".to_string()));
        event
            .extra
            .insert("stderr".to_string(), Value::String("err".to_string()));
        event
            .extra
            .insert("exit_code".to_string(), Value::Number(2.into()));

        let _ = hooks.handle_transform_terminal_output(event).await.unwrap();

        let events = mock.events();
        let output = match &events[0].event {
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(output)) => output,
            other => panic!("unexpected observation: {other:?}"),
        };
        assert_eq!(output.stdout, "out");
        assert_eq!(output.stderr, "err");
        assert_eq!(output.exit_code, 2);
    }

    #[tokio::test]
    async fn observation_hooks_degrade_gracefully() {
        let mut hooks = Hooks::new(
            MockHarnessClient::failing("down"),
            hermes_agent(Some("sess-1")),
        );
        assert_eq!(
            json(&hooks.handle_post_tool_call(event()).await.unwrap()),
            serde_json::json!({})
        );
    }

    #[tokio::test]
    async fn pre_llm_is_advisory_context_only() {
        let mut adjudicated = Adjudicated::deny().with_reason("revise prompt");
        adjudicated.steering = Some(Steering {
            explanation: "policy context".to_string(),
            instructions: vec!["avoid secrets".to_string()],
        });
        let mut hooks = Hooks::new(
            MockHarnessClient::with_response(Ok(adjudicated)),
            hermes_agent(Some("sess-1")),
        );
        let mut event = event();
        event.hook_event_name = "pre_llm_call".to_string();
        event.tool_name = None;
        event.tool_input = None;
        event.extra.insert(
            "user_message".to_string(),
            Value::String("hello".to_string()),
        );
        let response = json(&hooks.handle_pre_llm_call(event).await.unwrap());
        assert_eq!(
            response,
            serde_json::json!({"context":"policy context\navoid secrets"})
        );
    }

    #[tokio::test]
    async fn transform_hook_is_observation_only_for_shell_transport() {
        let mut hooks = Hooks::new(
            MockHarnessClient::denying("secret"),
            hermes_agent(Some("sess-1")),
        );
        let response = json(&hooks.handle_transform_tool_result(event()).await.unwrap());

        assert_eq!(response, serde_json::json!({}));
    }

    async fn action_for_tool(tool_name: &str, tool_input: Value) -> Action {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), hermes_agent(Some("sess-1")));
        let mut ev = event();
        ev.tool_name = Some(tool_name.to_string());
        ev.tool_input = Some(tool_input);
        let _ = hooks.handle_pre_tool_call(ev).await.unwrap();
        match &mock.events()[0].event {
            TrajectoryEvent::Action(action) => action.clone(),
            other => panic!("expected an Action, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn file_tools_map_to_file_operations() {
        // Hermes mapped only shell commands, so every file call reached Cedar
        // as `PreToolUse` — an action no file policy applies to.
        match action_for_tool("read_file", serde_json::json!({"path":"/repo/.env"})).await {
            Action::FileOperation(op) => {
                assert_eq!(op.operation, FileOpType::Read);
                assert_eq!(op.path, "/repo/.env");
            }
            other => panic!("expected FileOperation(Read), got {other:?}"),
        }

        match action_for_tool(
            "write_file",
            serde_json::json!({"file_path":"/repo/.env","content":"TOKEN=abc"}),
        )
        .await
        {
            Action::FileOperation(op) => {
                assert_eq!(op.operation, FileOpType::Write);
                assert_eq!(op.content.as_deref(), Some("TOKEN=abc"));
            }
            other => panic!("expected FileOperation(Write), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn shell_and_unknown_tools_keep_their_mapping() {
        assert!(matches!(
            action_for_tool("terminal", serde_json::json!({"command":"pwd"})).await,
            Action::ShellCommand(_)
        ));
        assert!(matches!(
            action_for_tool("search_web", serde_json::json!({"q":"x"})).await,
            Action::ToolCall(_)
        ));
    }

    #[tokio::test]
    async fn web_tools_map_to_a_web_fetch() {
        match action_for_tool(
            "web_fetch",
            serde_json::json!({"url":"https://example.com/x"}),
        )
        .await
        {
            Action::WebFetch(fetch) => assert_eq!(fetch.url, "https://example.com/x"),
            other => panic!("expected WebFetch, got {other:?}"),
        }
    }
}
