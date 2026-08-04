//! OpenCode sidecar request handling.
//!
//! [`protocol`] holds the request/response types exchanged with the OpenCode
//! plugin; this module maps those requests onto trajectory events, adjudicates
//! them against the harness, and shapes the reply.

pub mod protocol;

pub use protocol::{
    HookCriticality, SidecarDecision, SidecarEvent, SidecarRequest, SidecarResponse,
};

use serde_json::Value;
use sondera_harness_client::{
    Action, Actor, Adjudicated, Agent, Completed, Control, Decision, Event, Failed,
    FileOperationResult, HarnessClient, Observation, Prompt, ShellCommand, ShellCommandOutput,
    Started, Thought, ToolCall, ToolOutput, TrajectoryEvent, WebFetchOutput,
};
use sondera_hooks::adjudication::warn_unenforceable_decision;
use sondera_hooks::error::{HookError, Result};
use sondera_hooks::tool::{
    file_operation_for, file_path_arg, is_file_operation, is_web_fetch, web_fetch_for, web_url_arg,
};
use std::collections::BTreeMap;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct OpenCodeSidecarState {
    agents: BTreeMap<String, Agent>,
    fallback_session_id: String,
}

impl Default for OpenCodeSidecarState {
    fn default() -> Self {
        Self {
            agents: BTreeMap::new(),
            fallback_session_id: format!("opencode-sidecar-{}", uuid::Uuid::new_v4()),
        }
    }
}

pub fn request_from_opencode_event(kind: &str, payload: Value) -> SidecarRequest {
    let session_id = string_at(&payload, &["session_id"])
        .or_else(|| string_at(&payload, &["sessionID"]))
        .or_else(|| string_at(&payload, &["session", "id"]))
        .or_else(|| string_at(&payload, &["info", "id"]))
        .or_else(|| string_at(&payload, &["properties", "sessionID"]))
        .or_else(|| string_at(&payload, &["properties", "info", "id"]));
    SidecarRequest {
        id: string_at(&payload, &["id"])
            .or_else(|| string_at(&payload, &["event_id"]))
            .unwrap_or_else(|| format!("{kind}:{}", chrono::Utc::now().timestamp_micros())),
        provider: crate::OPENCODE_PROVIDER.to_string(),
        platform: crate::OPENCODE_PLATFORM.to_string(),
        trajectory_id: session_id.clone(),
        session_id,
        criticality: criticality_for_event(kind),
        event: SidecarEvent {
            kind: kind.to_string(),
            payload,
        },
        metadata: Value::Null,
    }
}

pub async fn handle_sidecar_request<H: HarnessClient>(
    harness: &H,
    state: &mut OpenCodeSidecarState,
    request: SidecarRequest,
) -> Result<SidecarResponse> {
    debug!(kind = %request.event.kind, id = %request.id, "handling OpenCode sidecar request");
    if request.provider != crate::OPENCODE_PROVIDER {
        return Err(HookError::message(format!(
            "unsupported sidecar provider: {}",
            request.provider
        )));
    }

    let event = match map_request_to_event(state, &request).await {
        Ok(event) => event,
        Err(err) if request.criticality.is_blocking() => {
            return Ok(SidecarResponse::deny(
                request.id,
                format!("OpenCode event could not be mapped for policy enforcement: {err}"),
            )
            .with_error(err.to_string()));
        }
        Err(err) => {
            warn!(error = %err, kind = %request.event.kind, "OpenCode observation event could not be mapped");
            return Ok(SidecarResponse::allow(request.id).with_error(err.to_string()));
        }
    };

    match harness.adjudicate(event).await {
        Ok(adjudicated) => {
            if !request.criticality.is_blocking() {
                warn_unenforceable_decision(
                    &format!("OpenCode {} observation", request.event.kind),
                    &adjudicated,
                );
            }
            Ok(response_from_adjudication(request.id, adjudicated))
        }
        Err(err) if request.criticality.is_blocking() => Ok(SidecarResponse::deny(
            request.id,
            format!("Governance backend unavailable: {err}"),
        )
        .with_error(err.to_string())),
        Err(err) => {
            warn!(error = %err, kind = %request.event.kind, "OpenCode observation harness error; degrading gracefully");
            Ok(SidecarResponse::allow(request.id).with_error(err.to_string()))
        }
    }
}

async fn map_request_to_event(
    state: &mut OpenCodeSidecarState,
    request: &SidecarRequest,
) -> Result<Event> {
    let trajectory_id = request
        .trajectory_id
        .clone()
        .or_else(|| request.session_id.clone())
        .unwrap_or_else(|| state.fallback_session_id.clone());

    let event = match request.event.kind.as_str() {
        "session.created" => {
            let agent = build_agent();
            state.agents.insert(
                session_key(state, request.session_id.as_deref()),
                agent.clone(),
            );
            Event::new(
                agent.clone(),
                trajectory_id,
                TrajectoryEvent::Control(Control::Started(Started::new(agent))),
            )
        }
        "session.deleted" => {
            let agent = current_agent(state, request.session_id.as_deref());
            state
                .agents
                .remove(&session_key(state, request.session_id.as_deref()));
            Event::new(
                agent,
                trajectory_id,
                TrajectoryEvent::Control(Control::Completed(
                    Completed::new().with_summary(request.event.kind.clone()),
                )),
            )
        }
        "session.idle" => {
            let agent = current_agent(state, request.session_id.as_deref());
            Event::new(
                agent,
                trajectory_id,
                TrajectoryEvent::Observation(Observation::Thought(Thought::new(
                    "OpenCode session idle",
                ))),
            )
        }
        "session.error" => {
            let agent = current_agent(state, request.session_id.as_deref());
            state
                .agents
                .remove(&session_key(state, request.session_id.as_deref()));
            Event::new(
                agent,
                trajectory_id,
                TrajectoryEvent::Control(Control::Failed(Failed::new(
                    string_at(&request.event.payload, &["error"])
                        .or_else(|| string_at(&request.event.payload, &["message"]))
                        .unwrap_or_else(|| "OpenCode session error".to_string()),
                ))),
            )
        }
        "session.updated" => {
            let agent = current_agent(state, request.session_id.as_deref());
            Event::new(
                agent,
                trajectory_id,
                TrajectoryEvent::Observation(Observation::Thought(Thought::new(
                    "OpenCode session updated",
                ))),
            )
        }
        "chat.message" => {
            let agent = current_agent(state, request.session_id.as_deref());
            Event::new(
                agent.clone(),
                trajectory_id,
                TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(message_content(
                    &request.event.payload,
                )))),
            )
            .with_actor(Actor::human(agent.id))
        }
        "permission.ask" => {
            let agent = current_agent(state, request.session_id.as_deref());
            Event::new(
                agent,
                trajectory_id,
                TrajectoryEvent::Action(Action::ToolCall(ToolCall {
                    call_id: call_id(&request.event.payload),
                    tool: "opencode.permission.ask".to_string(),
                    arguments: request.event.payload.clone(),
                })),
            )
        }
        "tool.execute.before" => {
            let agent = current_agent(state, request.session_id.as_deref());
            Event::new(
                agent,
                trajectory_id,
                TrajectoryEvent::Action(action_from_tool_payload(&request.event.payload)),
            )
        }
        "tool.execute.after" => {
            let agent = current_agent(state, request.session_id.as_deref());
            Event::new(
                agent,
                trajectory_id,
                TrajectoryEvent::Observation(observation_from_tool_payload(&request.event.payload)),
            )
        }
        other => {
            let agent = current_agent(state, request.session_id.as_deref());
            Event::new(
                agent,
                trajectory_id,
                TrajectoryEvent::Observation(Observation::Thought(Thought::new(format!(
                    "OpenCode {other}: {}",
                    request.event.payload
                )))),
            )
        }
    };

    Ok(event)
}

fn build_agent() -> Agent {
    Agent {
        id: sondera_hooks::agent_id(crate::OPENCODE_PROVIDER),
        provider: crate::OPENCODE_PROVIDER.to_string(),
        platform: crate::OPENCODE_PLATFORM.to_string(),
    }
}

fn current_agent(state: &OpenCodeSidecarState, session_id: Option<&str>) -> Agent {
    state
        .agents
        .get(&session_key(state, session_id))
        .cloned()
        .unwrap_or_else(build_agent)
}

fn session_key(state: &OpenCodeSidecarState, session_id: Option<&str>) -> String {
    session_id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&state.fallback_session_id)
        .to_string()
}

fn action_from_tool_payload(payload: &Value) -> Action {
    let tool = tool_name(payload);
    if is_shell_tool(&tool) {
        Action::ShellCommand(ShellCommand {
            call_id: call_id(payload),
            command: command_from_payload(payload),
            working_dir: string_at(payload, &["cwd"])
                .or_else(|| string_at(payload, &["workspace"]))
                .or_else(|| {
                    std::env::current_dir()
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned())
                }),
        })
    } else if let Some(fetch) = web_fetch_for(&tool, &tool_arguments(payload), call_id(payload)) {
        Action::WebFetch(fetch)
    } else if let Some(file_op) =
        file_operation_for(&tool, &tool_arguments(payload), call_id(payload))
    {
        Action::FileOperation(file_op)
    } else {
        Action::ToolCall(ToolCall {
            call_id: call_id(payload),
            tool,
            arguments: tool_arguments(payload),
        })
    }
}

fn observation_from_tool_payload(payload: &Value) -> Observation {
    let tool = tool_name(payload);
    let call_id = call_id(payload);
    if let Some(error) = string_at(payload, &["error"]) {
        Observation::ToolOutput(ToolOutput::error(call_id, error))
    } else if is_shell_tool(&tool) {
        Observation::ShellCommandOutput(ShellCommandOutput::new(
            call_id,
            exit_code(payload),
            string_at(payload, &["stdout"])
                .or_else(|| string_at(payload, &["output"]))
                .or_else(|| string_at(payload, &["result", "stdout"]))
                .unwrap_or_default(),
            string_at(payload, &["stderr"])
                .or_else(|| string_at(payload, &["result", "stderr"]))
                .unwrap_or_default(),
        ))
    } else if is_file_operation(&tool, &tool_arguments(payload)) {
        // Gated on the same classifier as `action_from_tool_payload`, so a
        // call adjudicated as a FileOperation reports a FileOperationResult
        // and keeps the content the post-execution policies scan.
        let args = tool_arguments(payload);
        let path = file_path_arg(&args);
        Observation::FileOperationResult(FileOperationResult {
            call_id,
            success: true,
            path: (!path.is_empty()).then(|| path.to_string()),
            content: string_at(payload, &["output"])
                .or_else(|| string_at(payload, &["content"]))
                .or_else(|| string_at(payload, &["result", "output"])),
            error: None,
        })
    } else if is_web_fetch(&tool, &tool_arguments(payload)) {
        // Same pairing as the file branch: without it the fetched body
        // arrives as a generic ToolOutput and the webfetch-output policies
        // never see what came back.
        Observation::WebFetchOutput(WebFetchOutput::new(
            call_id,
            web_url_arg(&tool_arguments(payload)).unwrap_or_default(),
            status_code(payload),
            string_at(payload, &["output"])
                .or_else(|| string_at(payload, &["content"]))
                .or_else(|| string_at(payload, &["result", "output"]))
                .unwrap_or_default(),
        ))
    } else {
        Observation::ToolOutput(ToolOutput::success(
            call_id,
            payload
                .get("output")
                .cloned()
                .or_else(|| payload.get("result").cloned())
                .unwrap_or_else(|| payload.clone()),
        ))
    }
}

fn response_from_adjudication(id: String, adjudicated: Adjudicated) -> SidecarResponse {
    let additional_context = steering_context(&adjudicated);
    let reason = adjudicated
        .reason
        .clone()
        .or_else(|| adjudicated.format_policy_context());
    match adjudicated.decision {
        Decision::Allow => SidecarResponse {
            id,
            decision: SidecarDecision::Allow,
            reason,
            additional_context,
            error: None,
        },
        Decision::Deny => SidecarResponse {
            id,
            decision: SidecarDecision::Deny,
            reason: Some(adjudicated.deny_message("OpenCode action blocked by policy")),
            additional_context,
            error: None,
        },
        Decision::Escalate => SidecarResponse {
            id,
            decision: SidecarDecision::Escalate,
            reason: Some(adjudicated.deny_message("OpenCode action requires review")),
            additional_context,
            error: None,
        },
    }
}

fn steering_context(adjudicated: &Adjudicated) -> Option<String> {
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

/// Whether an OpenCode event kind is an enforcement gate.
///
/// This is the sidecar's copy of the same judgement `Commands::is_adjudication`
/// makes for the direct CLI path; a test in `lib.rs` asserts the two agree so
/// they cannot drift into a fail-open.
pub(crate) fn criticality_for_event(kind: &str) -> HookCriticality {
    match kind {
        "tool.execute.before" => HookCriticality::AdjudicationCritical,
        "permission.ask" => HookCriticality::AdjudicationCritical,
        "chat.message" => HookCriticality::ObservationOnly,
        _ => HookCriticality::ObservationOnly,
    }
}

fn message_content(payload: &Value) -> String {
    string_at(payload, &["message", "content"])
        .or_else(|| string_at(payload, &["content"]))
        .or_else(|| string_at(payload, &["text"]))
        .unwrap_or_else(|| serde_json::to_string(payload).unwrap_or_default())
}

fn tool_name(payload: &Value) -> String {
    string_at(payload, &["tool", "name"])
        .or_else(|| string_at(payload, &["tool"]))
        .or_else(|| string_at(payload, &["name"]))
        .unwrap_or_else(|| "tool".to_string())
}

fn tool_arguments(payload: &Value) -> Value {
    payload
        .get("args")
        .cloned()
        .or_else(|| payload.get("input").cloned())
        .or_else(|| payload.get("tool_input").cloned())
        .unwrap_or(Value::Null)
}

fn command_from_payload(payload: &Value) -> String {
    for path in [
        &["command"][..],
        &["cmd"][..],
        &["args", "command"][..],
        &["input", "command"][..],
        &["tool_input", "command"][..],
    ] {
        if let Some(command) = string_at(payload, path) {
            return command;
        }
    }
    tool_arguments(payload)
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| serde_json::to_string(&tool_arguments(payload)).unwrap_or_default())
}

fn call_id(payload: &Value) -> String {
    string_at(payload, &["call_id"])
        .or_else(|| string_at(payload, &["callId"]))
        .or_else(|| string_at(payload, &["tool_call_id"]))
        .or_else(|| string_at(payload, &["id"]))
        .unwrap_or_else(|| format!("call-{}", uuid::Uuid::new_v4()))
}

/// Read the HTTP status a fetch returned.
///
/// An absent status means the fetch succeeded, so this falls back to 200
/// rather than to a shell-style exit code of 0.
fn status_code(payload: &Value) -> i32 {
    for path in [
        &["status_code"][..],
        &["statusCode"][..],
        &["status"][..],
        &["code"][..],
        &["result", "status"][..],
    ] {
        let mut current = payload;
        let mut found = true;
        for key in path {
            match current.get(*key) {
                Some(next) => current = next,
                None => {
                    found = false;
                    break;
                }
            }
        }
        if found && let Some(code) = current.as_i64() {
            return i32::try_from(code).unwrap_or(200);
        }
    }
    200
}

fn exit_code(payload: &Value) -> i32 {
    for path in [
        &["exit_code"][..],
        &["exitCode"][..],
        &["code"][..],
        &["status"][..],
        &["result", "exit_code"][..],
    ] {
        if let Some(code) = int_at(payload, path) {
            return i32::try_from(code).unwrap_or(if code.is_negative() {
                i32::MIN
            } else {
                i32::MAX
            });
        }
    }
    0
}

fn is_shell_tool(tool_name: &str) -> bool {
    matches!(
        tool_name.to_ascii_lowercase().as_str(),
        "bash" | "shell" | "terminal" | "sh" | "run"
    )
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn int_at(value: &Value, path: &[&str]) -> Option<i64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_i64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_harness_client::types::HarnessClientError;
    use sondera_harness_client::{Adjudicated, Event, FileOpType};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FakeHarness {
        decision: Adjudicated,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl HarnessClient for FakeHarness {
        async fn adjudicate(
            &self,
            event: Event,
        ) -> std::result::Result<Adjudicated, HarnessClientError> {
            self.events.lock().unwrap().push(event);
            Ok(self.decision.clone())
        }
    }

    #[tokio::test]
    async fn before_tool_maps_shell_command_and_denies() {
        let harness = FakeHarness {
            decision: Adjudicated::deny().with_reason("blocked"),
            events: Arc::new(Mutex::new(Vec::new())),
        };
        let request = request_from_opencode_event(
            "tool.execute.before",
            serde_json::json!({
                "session_id": "s1",
                "tool": "bash",
                "args": {"command": "rm -rf ."},
                "cwd": "/tmp"
            }),
        );
        let mut state = OpenCodeSidecarState::default();

        let response = handle_sidecar_request(&harness, &mut state, request)
            .await
            .unwrap();

        assert_eq!(response.decision, SidecarDecision::Deny);
        let events = harness.events.lock().unwrap();
        assert!(matches!(
            events[0].event,
            TrajectoryEvent::Action(Action::ShellCommand(_))
        ));
    }

    #[tokio::test]
    async fn chat_message_is_observed_as_user_prompt() {
        let harness = FakeHarness {
            decision: Adjudicated::allow(),
            events: Arc::new(Mutex::new(Vec::new())),
        };
        let request = request_from_opencode_event(
            "chat.message",
            serde_json::json!({"session_id": "s1", "message": {"content": "review CUST001"}}),
        );
        let mut state = OpenCodeSidecarState::default();

        let response = handle_sidecar_request(&harness, &mut state, request)
            .await
            .unwrap();

        assert_eq!(response.decision, SidecarDecision::Allow);
        let events = harness.events.lock().unwrap();
        assert!(matches!(
            events[0].event,
            TrajectoryEvent::Observation(Observation::Prompt(_))
        ));
    }

    #[test]
    fn permission_ask_is_fail_closed_criticality() {
        let request = request_from_opencode_event(
            "permission.ask",
            serde_json::json!({"session_id": "s1", "tool": "bash"}),
        );

        assert_eq!(request.criticality, HookCriticality::AdjudicationCritical);
    }

    #[test]
    fn current_event_bus_payload_extracts_nested_session_id() {
        let request = request_from_opencode_event(
            "session.created",
            serde_json::json!({"info": {"id": "session-current"}}),
        );

        assert_eq!(request.session_id.as_deref(), Some("session-current"));
    }

    #[tokio::test]
    async fn cached_agents_are_scoped_by_session_id() {
        let mut state = OpenCodeSidecarState::default();
        let session_one = build_agent();
        let session_two = build_agent();
        state
            .agents
            .insert(session_key(&state, Some("s1")), session_one.clone());
        state
            .agents
            .insert(session_key(&state, Some("s2")), session_two.clone());

        assert_eq!(current_agent(&state, Some("s1")), session_one);
        assert_eq!(current_agent(&state, Some("s2")), session_two);
    }

    #[tokio::test]
    async fn completed_sessions_remove_cached_agents() {
        let mut state = OpenCodeSidecarState::default();
        state
            .agents
            .insert(session_key(&state, Some("s1")), build_agent());

        let request =
            request_from_opencode_event("session.deleted", serde_json::json!({"session_id": "s1"}));

        let _ = map_request_to_event(&mut state, &request).await.unwrap();

        assert!(!state.agents.contains_key(&session_key(&state, Some("s1"))));
    }

    #[tokio::test]
    async fn errored_sessions_remove_cached_agents() {
        let mut state = OpenCodeSidecarState::default();
        state
            .agents
            .insert(session_key(&state, Some("s1")), build_agent());

        let request = request_from_opencode_event(
            "session.error",
            serde_json::json!({"session_id": "s1", "error": "model failed"}),
        );

        let _ = map_request_to_event(&mut state, &request).await.unwrap();

        assert!(!state.agents.contains_key(&session_key(&state, Some("s1"))));
    }

    #[tokio::test]
    async fn idle_sessions_keep_cached_agents_and_emit_observation() {
        let mut state = OpenCodeSidecarState::default();
        state
            .agents
            .insert(session_key(&state, Some("s1")), build_agent());

        let request =
            request_from_opencode_event("session.idle", serde_json::json!({"session_id": "s1"}));

        let event = map_request_to_event(&mut state, &request).await.unwrap();

        assert!(state.agents.contains_key(&session_key(&state, Some("s1"))));
        assert!(matches!(
            event.event,
            TrajectoryEvent::Observation(Observation::Thought(_))
        ));
    }

    #[test]
    fn missing_session_ids_use_sidecar_scoped_fallback() {
        let state = OpenCodeSidecarState::default();

        let key = session_key(&state, None);

        assert!(key.starts_with("opencode-sidecar-"));
        assert_ne!(key, "default");
        assert_ne!(key, "opencode-session");
    }

    #[test]
    fn shell_tool_error_maps_to_failed_tool_output() {
        let payload = serde_json::json!({
            "id": "call-1",
            "tool": "bash",
            "error": "spawn failed"
        });

        let observation = observation_from_tool_payload(&payload);

        assert!(matches!(
            observation,
            Observation::ToolOutput(ToolOutput {
                success: false,
                error: Some(_),
                ..
            })
        ));
    }

    #[test]
    fn file_tools_map_to_file_operations() {
        // OpenCode mapped only shell and web tools, so `read`, `write`, and
        // `edit` reached Cedar as `PreToolUse` — an action no file policy
        // applies to.
        let cases: &[(&str, serde_json::Value, FileOpType)] = &[
            (
                "read",
                serde_json::json!({"filePath": "/repo/.env"}),
                FileOpType::Read,
            ),
            (
                "write",
                serde_json::json!({"filePath": "/repo/.env", "content": "TOKEN=abc"}),
                FileOpType::Write,
            ),
            (
                "edit",
                serde_json::json!({"filePath": "/repo/.env", "oldString": "a", "newString": "b"}),
                FileOpType::Edit,
            ),
        ];
        for (tool, args, expected) in cases {
            let payload = serde_json::json!({"id": "call-1", "tool": tool, "args": args});
            match action_from_tool_payload(&payload) {
                Action::FileOperation(op) => {
                    assert_eq!(op.operation, *expected, "{tool}");
                    assert_eq!(op.path, "/repo/.env", "{tool}");
                }
                other => panic!("expected FileOperation for {tool}, got {other:?}"),
            }
        }
    }

    #[test]
    fn file_tool_results_are_file_operation_results() {
        let payload = serde_json::json!({
            "id": "call-1",
            "tool": "read",
            "args": {"filePath": "/repo/.env"},
            "output": "TOKEN=abc"
        });

        match observation_from_tool_payload(&payload) {
            Observation::FileOperationResult(result) => {
                assert_eq!(result.path.as_deref(), Some("/repo/.env"));
                assert_eq!(result.content.as_deref(), Some("TOKEN=abc"));
            }
            other => panic!("expected FileOperationResult, got {other:?}"),
        }
    }

    #[test]
    fn shell_and_search_tools_keep_their_mapping() {
        for (tool, expected_shell) in [("bash", true), ("grep", false), ("glob", false)] {
            let payload = serde_json::json!({"id": "c", "tool": tool, "args": {"command": "ls", "pattern": "x"}});
            let action = action_from_tool_payload(&payload);
            assert_eq!(
                matches!(action, Action::ShellCommand(_)),
                expected_shell,
                "{tool}"
            );
        }
    }
}
