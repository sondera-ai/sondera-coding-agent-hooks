//! Hook handler implementations for OpenHands SDK events.
//!
//! Error strategy:
//! - PreToolUse, UserPromptSubmit, and Stop are blocking hooks and fail closed
//!   (a harness error becomes a deny).
//! - PostToolUse, SessionStart, and SessionEnd are observation hooks and degrade
//!   gracefully on harness errors.

use super::types::*;
use serde_json::Value;
use sondera_harness_client::{
    Action, Actor, Agent, Completed, Control, Decision, Event, FileOperationResult, HarnessClient,
    Observation, Prompt, ShellCommand, ShellCommandOutput, Started, ToolCall, ToolOutput,
    TrajectoryEvent, WebFetchOutput,
};
use sondera_hooks::adjudication::warn_unenforceable_decision;
use sondera_hooks::error::Result;
use sondera_hooks::response::DecisionEnvelope as HookResponse;
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

    pub async fn handle_session_start(&mut self, event: SessionStartEvent) -> Result<HookResponse> {
        let key = event.common.trajectory_key();
        let trajectory_event =
            TrajectoryEvent::Control(Control::Started(Started::new(self.agent.clone())));
        let ev = self.event(&key, trajectory_event);

        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => {
                warn_unenforceable_decision("OpenHands SessionStart observation", &adjudicated);
            }
            Err(err) => {
                warn!(error = %err, "SessionStart harness error; degrading gracefully");
            }
        }

        Ok(HookResponse::ok())
    }

    pub async fn handle_pre_tool_use(&mut self, event: PreToolUseEvent) -> Result<HookResponse> {
        let tool_name = event.tool_name.clone();
        let key = event.common.trajectory_key();
        let call_id = event.call_id();
        let action = if is_shell_tool(&tool_name) {
            Action::ShellCommand(ShellCommand {
                call_id,
                command: command_from_input(&event.tool_input),
                working_dir: Some(event.common.working_dir_or_current()),
            })
        } else if let Some(file_op) =
            file_operation_for(&tool_name, &event.tool_input, call_id.clone())
        {
            // OpenHands' editor is one tool multiplexed over a `command`
            // argument, so the operation is read from the arguments rather
            // than the name — see `sondera_hooks::tool`.
            Action::FileOperation(file_op)
        } else if let Some(fetch) = web_fetch_for(&tool_name, &event.tool_input, call_id.clone()) {
            Action::WebFetch(fetch)
        } else {
            Action::ToolCall(ToolCall {
                call_id,
                tool: tool_name.clone(),
                arguments: event.tool_input.clone(),
            })
        };

        let ev = self.event(&key, TrajectoryEvent::Action(action));
        let adjudicated = self.harness.adjudicate(ev).await?;
        Ok(blocking_response(
            adjudicated,
            "Tool use blocked by policy",
            "Tool use requires review",
        ))
    }

    pub async fn handle_post_tool_use(&mut self, event: PostToolUseEvent) -> Result<HookResponse> {
        let tool_name = event.tool_name.clone();
        let key = event.common.trajectory_key();
        let call_id = event.call_id();
        let observation = if is_shell_tool(&tool_name) {
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput {
                call_id,
                exit_code: exit_code_from_response(&event.tool_response),
                stdout: string_field(&event.tool_response, &["stdout", "output", "content"]),
                stderr: string_field(&event.tool_response, &["stderr", "error"]),
            }))
        } else if is_file_operation(&tool_name, &event.tool_input) {
            // Gated on the same classifier as the pre-execution mapper: a call
            // adjudicated as a FileOperation whose result came back as a
            // generic ToolOutput would lose the content the post-execution
            // signature and sensitivity policies scan.
            let error = string_field(&event.tool_response, &["error"]);
            let path = file_path_arg(&event.tool_input);
            TrajectoryEvent::Observation(Observation::FileOperationResult(FileOperationResult {
                call_id,
                success: error.is_empty(),
                path: (!path.is_empty()).then(|| path.to_string()),
                content: {
                    let content = string_field(
                        &event.tool_response,
                        &["content", "output", "stdout", "text"],
                    );
                    (!content.is_empty()).then_some(content)
                },
                error: (!error.is_empty()).then_some(error),
            }))
        } else if is_web_fetch(&tool_name, &event.tool_input) {
            // Same pairing as the file branch: the fetched body is what the
            // post-execution web policies scan.
            TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
                call_id,
                web_url_arg(&event.tool_input).unwrap_or_default(),
                status_from_response(&event.tool_response),
                string_field(&event.tool_response, &["content", "output", "text", "body"]),
            )))
        } else {
            TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput::success(
                call_id,
                event.tool_response.clone(),
            )))
        };

        let ev = self.event(&key, observation);
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => {
                warn_unenforceable_decision("OpenHands PostToolUse observation", &adjudicated);
            }
            Err(err) => {
                warn!(error = %err, "PostToolUse harness error; degrading gracefully");
            }
        }
        Ok(HookResponse::ok())
    }

    pub async fn handle_user_prompt_submit(
        &mut self,
        event: UserPromptSubmitEvent,
    ) -> Result<HookResponse> {
        let key = event.common.trajectory_key();
        let observation =
            TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&event.message)));
        let ev = self
            .event(&key, observation)
            .with_actor(Actor::human(&self.agent.id));
        let adjudicated = self.harness.adjudicate(ev).await?;
        Ok(blocking_response(
            adjudicated,
            "Prompt blocked by policy",
            "Prompt requires review",
        ))
    }

    pub async fn handle_stop(&mut self, event: StopEvent) -> Result<HookResponse> {
        let key = event.common.trajectory_key();
        let summary = event
            .message
            .clone()
            .or_else(|| event.stop_reason())
            .unwrap_or_else(|| "OpenHands requested stop".to_string());
        let ev = self.event(
            &key,
            TrajectoryEvent::Control(Control::Completed(Completed::new().with_summary(summary))),
        );
        let adjudicated = self.harness.adjudicate(ev).await?;
        Ok(blocking_response(
            adjudicated,
            "Stop blocked by policy; continue working",
            "Stop requires review; continue working",
        ))
    }

    pub async fn handle_session_end(&mut self, event: SessionEndEvent) -> Result<HookResponse> {
        let key = event.common.trajectory_key();
        let mut completed = Completed::new();
        if let Some(reason) = event.end_reason() {
            completed = completed.with_summary(reason);
        }
        let ev = self.event(
            &key,
            TrajectoryEvent::Control(Control::Completed(completed)),
        );
        match self.harness.adjudicate(ev).await {
            Ok(adjudicated) => {
                warn_unenforceable_decision("OpenHands SessionEnd observation", &adjudicated);
            }
            Err(err) => {
                warn!(error = %err, "SessionEnd harness error; degrading gracefully");
            }
        }
        Ok(HookResponse::ok())
    }
}

fn blocking_response(
    adjudicated: sondera_harness_client::Adjudicated,
    deny: &str,
    escalate: &str,
) -> HookResponse {
    match adjudicated.decision {
        Decision::Allow => {
            if let Some(context) = steering_context(&adjudicated) {
                HookResponse::additional_context(context)
            } else {
                HookResponse::ok()
            }
        }
        Decision::Deny => deny_response(adjudicated, deny),
        Decision::Escalate => deny_response(adjudicated, escalate),
    }
}

fn deny_response(adjudicated: sondera_harness_client::Adjudicated, fallback: &str) -> HookResponse {
    let msg = adjudicated.deny_message(fallback);
    if let Some(context) = steering_context(&adjudicated) {
        HookResponse::deny_with_context(msg, context)
    } else {
        HookResponse::deny(msg)
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

fn command_from_input(input: &Value) -> String {
    if let Some(command) = input.as_str() {
        return command.to_string();
    }
    for key in ["command", "cmd", "input"] {
        if let Some(command) = input.get(key).and_then(Value::as_str) {
            return command.to_string();
        }
    }
    serde_json::to_string(input).unwrap_or_default()
}

fn exit_code_from_response(response: &Value) -> i32 {
    for key in ["exit_code", "exitCode", "status"] {
        if let Some(code) = response.get(key).and_then(Value::as_i64) {
            return code as i32;
        }
    }
    0
}

/// Read the HTTP status a fetch returned.
///
/// Distinct from [`exit_code_from_response`]: a fetch reports a status, not a
/// process exit code, and the two default differently — an absent status means
/// the fetch succeeded, so it falls back to 200 rather than 0.
fn status_from_response(response: &Value) -> i32 {
    for key in ["status_code", "statusCode", "status", "code"] {
        if let Some(code) = response.get(key).and_then(Value::as_i64) {
            return code as i32;
        }
    }
    200
}

fn string_field(response: &Value, keys: &[&str]) -> String {
    if let Some(text) = response.as_str() {
        return text.to_string();
    }
    for key in keys {
        if let Some(text) = response.get(*key).and_then(Value::as_str) {
            return text.to_string();
        }
    }
    if keys.contains(&"stdout") || keys.contains(&"output") {
        serde_json::to_string(response).unwrap_or_default()
    } else {
        String::new()
    }
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
            match &*self.response.lock().unwrap() {
                Ok(response) => Ok(response.clone()),
                Err(reason) => Err(sondera_types::HarnessClientError::Server(reason.clone())),
            }
        }
    }

    fn agent() -> Agent {
        super::super::get_agent()
    }

    fn common() -> CommonInput {
        CommonInput {
            event_type: String::new(),
            session_id: "sess-1".to_string(),
            working_dir: "/tmp/project".to_string(),
            model: None,
            metadata: Default::default(),
        }
    }

    fn json(response: &HookResponse) -> serde_json::Value {
        serde_json::to_value(response).unwrap()
    }

    #[tokio::test]
    async fn pre_tool_use_allow_deny_escalate_and_fail_closed() {
        let event = PreToolUseEvent {
            common: common(),
            tool_name: "terminal".to_string(),
            tool_input: serde_json::json!({"command":"ls"}),
            tool_call_id: "call-1".to_string(),
            extra: Default::default(),
        };

        let mut hooks = Hooks::new(MockHarnessClient::allowing(), agent());
        assert_eq!(
            json(&hooks.handle_pre_tool_use(event.clone()).await.unwrap()),
            serde_json::json!({})
        );

        let mut hooks = Hooks::new(MockHarnessClient::denying("nope"), agent());
        assert_eq!(
            json(&hooks.handle_pre_tool_use(event.clone()).await.unwrap())["decision"],
            "deny"
        );

        let mut hooks = Hooks::new(MockHarnessClient::escalating("review"), agent());
        assert_eq!(
            json(&hooks.handle_pre_tool_use(event.clone()).await.unwrap())["decision"],
            "deny"
        );

        let mut hooks = Hooks::new(MockHarnessClient::failing("down"), agent());
        assert!(hooks.handle_pre_tool_use(event).await.is_err());
    }

    #[tokio::test]
    async fn user_prompt_submit_supports_context_and_fails_closed() {
        let event = UserPromptSubmitEvent {
            common: common(),
            message: "hello".to_string(),
            extra: Default::default(),
        };
        let mut adjudicated = Adjudicated::deny().with_reason("blocked");
        adjudicated.steering = Some(Steering {
            explanation: "why".to_string(),
            instructions: vec!["do this".to_string()],
        });
        let mut hooks = Hooks::new(MockHarnessClient::with_response(Ok(adjudicated)), agent());
        let response = json(
            &hooks
                .handle_user_prompt_submit(event.clone())
                .await
                .unwrap(),
        );
        assert_eq!(response["decision"], "deny");
        assert_eq!(response["additionalContext"], "why\ndo this");

        let mut hooks = Hooks::new(MockHarnessClient::failing("down"), agent());
        assert!(hooks.handle_user_prompt_submit(event).await.is_err());
    }

    #[tokio::test]
    async fn stop_allow_deny_escalate_and_fail_closed() {
        let event = StopEvent {
            common: common(),
            reason: Some("done".to_string()),
            message: None,
            extra: Default::default(),
        };
        let mut hooks = Hooks::new(MockHarnessClient::allowing(), agent());
        assert_eq!(
            json(&hooks.handle_stop(event.clone()).await.unwrap()),
            serde_json::json!({})
        );

        let mut hooks = Hooks::new(MockHarnessClient::denying("continue"), agent());
        assert_eq!(
            json(&hooks.handle_stop(event.clone()).await.unwrap())["decision"],
            "deny"
        );

        let mut hooks = Hooks::new(MockHarnessClient::escalating("review"), agent());
        assert_eq!(
            json(&hooks.handle_stop(event.clone()).await.unwrap())["decision"],
            "deny"
        );

        let mut hooks = Hooks::new(MockHarnessClient::failing("down"), agent());
        assert!(hooks.handle_stop(event).await.is_err());
    }

    #[tokio::test]
    async fn observation_hooks_degrade_gracefully() {
        let mut hooks = Hooks::new(MockHarnessClient::failing("down"), agent());
        let session_start = SessionStartEvent {
            common: common(),
            extra: Default::default(),
        };
        assert_eq!(
            json(&hooks.handle_session_start(session_start).await.unwrap()),
            serde_json::json!({})
        );

        let mut hooks = Hooks::new(MockHarnessClient::failing("down"), agent());
        let end = SessionEndEvent {
            common: common(),
            reason: Some("done".to_string()),
            extra: Default::default(),
        };
        assert_eq!(
            json(&hooks.handle_session_end(end).await.unwrap()),
            serde_json::json!({})
        );
    }

    #[tokio::test]
    async fn post_tool_use_is_observation_only() {
        let event = PostToolUseEvent {
            common: common(),
            tool_name: "OtherTool".to_string(),
            tool_input: serde_json::json!({"x":1}),
            tool_response: serde_json::json!({"result":"secret"}),
            tool_call_id: "call-1".to_string(),
            extra: Default::default(),
        };
        for harness in [
            MockHarnessClient::denying("leak"),
            MockHarnessClient::escalating("review"),
            MockHarnessClient::failing("down"),
        ] {
            let mut hooks = Hooks::new(harness, agent());
            assert_eq!(
                json(&hooks.handle_post_tool_use(event.clone()).await.unwrap()),
                serde_json::json!({})
            );
        }
    }

    async fn action_for_tool(tool_name: &str, tool_input: serde_json::Value) -> Action {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), agent());
        let _ = hooks
            .handle_pre_tool_use(PreToolUseEvent {
                common: common(),
                tool_name: tool_name.to_string(),
                tool_input,
                tool_call_id: "call-1".to_string(),
                extra: Default::default(),
            })
            .await
            .unwrap();
        match &mock.events()[0].event {
            TrajectoryEvent::Action(action) => action.clone(),
            other => panic!("expected an Action, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn terminal_tools_map_to_shell_command() {
        assert!(matches!(
            action_for_tool("bash", serde_json::json!({"command":"pwd"})).await,
            Action::ShellCommand(_)
        ));
    }

    #[tokio::test]
    async fn file_tools_map_to_file_operations() {
        // Before these arms existed, every file call arrived as a generic
        // ToolCall — Cedar `PreToolUse`, which no file policy applies to.
        match action_for_tool("ReadFile", serde_json::json!({"path":"/repo/.env"})).await {
            Action::FileOperation(op) => {
                assert_eq!(op.operation, FileOpType::Read);
                assert_eq!(op.path, "/repo/.env");
            }
            other => panic!("expected FileOperation(Read), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_editor_tool_dispatches_on_its_command() {
        // OpenHands' str_replace_editor multiplexes read and write behind one
        // name; a `view` classified as an edit would miss the read policies.
        let view = action_for_tool(
            "str_replace_editor",
            serde_json::json!({"command":"view","path":"/repo/.env"}),
        )
        .await;
        match view {
            Action::FileOperation(op) => assert_eq!(op.operation, FileOpType::Read),
            other => panic!("expected FileOperation(Read), got {other:?}"),
        }

        let replace = action_for_tool(
            "str_replace_editor",
            serde_json::json!({"command":"str_replace","path":"/repo/.env","old_str":"a","new_str":"b"}),
        )
        .await;
        match replace {
            Action::FileOperation(op) => {
                assert_eq!(op.operation, FileOpType::Edit);
                assert_eq!(op.old_content.as_deref(), Some("a"));
                assert_eq!(op.content.as_deref(), Some("b"));
            }
            other => panic!("expected FileOperation(Edit), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn web_tools_map_to_a_web_fetch() {
        match action_for_tool("fetch", serde_json::json!({"url":"https://example.com/x"})).await {
            Action::WebFetch(fetch) => assert_eq!(fetch.url, "https://example.com/x"),
            other => panic!("expected WebFetch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unrecognized_tools_still_fall_back_to_tool_call() {
        assert!(matches!(
            action_for_tool("browse_web", serde_json::json!({"url":"https://x"})).await,
            Action::ToolCall(_)
        ));
    }

    #[tokio::test]
    async fn file_tool_results_are_file_operation_results() {
        let mock = MockHarnessClient::allowing();
        let mut hooks = Hooks::new(mock.clone(), agent());
        let _ = hooks
            .handle_post_tool_use(PostToolUseEvent {
                common: common(),
                tool_name: "read_file".to_string(),
                tool_input: serde_json::json!({"path":"/repo/.env"}),
                tool_response: serde_json::json!({"content":"TOKEN=abc"}),
                tool_call_id: "call-1".to_string(),
                extra: Default::default(),
            })
            .await
            .unwrap();
        match &mock.events()[0].event {
            TrajectoryEvent::Observation(Observation::FileOperationResult(result)) => {
                assert_eq!(result.path.as_deref(), Some("/repo/.env"));
                assert_eq!(result.content.as_deref(), Some("TOKEN=abc"));
                assert!(result.success);
            }
            other => panic!("expected FileOperationResult, got {other:?}"),
        }
    }
}
