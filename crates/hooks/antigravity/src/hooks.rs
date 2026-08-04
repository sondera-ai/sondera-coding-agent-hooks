//! Hook handler implementations for Antigravity CLI events.
//!
//! The adjudicated event is `PreToolUse`: the proposed tool call is mapped to a
//! Sondera [`Action`], sent to the harness, and the [`Decision`] is mapped to
//! Antigravity's `decision` field (`allow`/`deny`/`ask`). `PostToolUse` records
//! the tool result as an observation and always returns `{}`. The advisory
//! events (`PreInvocation`/`PostInvocation`/`Stop`) are handled in `lib.rs`
//! without a harness round-trip.
//!
//! Reference: <https://antigravity.google/docs/hooks>

use super::types::*;
use crate::response::AntigravityHookResponse;
use sondera_hooks::error::Result;
use sondera_hooks::tool::normalize_tool_name;

use serde_json::Value;
use sondera_harness_client::{
    Action, Agent, Decision, Event, FileOpType, FileOperation, HarnessClient, Observation,
    ShellCommand, ToolCall, ToolOutput, TrajectoryEvent, WebFetch,
};
use tracing::{info, warn};

pub struct Hooks<H: HarnessClient> {
    harness: H,
    agent: Agent,
}

/// Extract a string argument from a tool-call `args` object. Antigravity tool
/// arguments use PascalCase keys (e.g. `CommandLine`, `TargetFile`).
fn str_arg(args: &Value, key: &str) -> String {
    args.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn opt_str_arg(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn call_id() -> String {
    format!("tool-{}", uuid::Uuid::new_v4())
}

/// Map a proposed Antigravity tool call to a Sondera [`Action`].
///
/// A tool with no specific mapping becomes a generic [`ToolCall`] rather than
/// being skipped. It still reaches Cedar only as
/// `Sondera::Action::"PreToolUse"`, which no file, shell, or web policy
/// applies to — but it is adjudicated and recorded, so the trajectory shows
/// what the agent did. Returning early instead left the call absent from the
/// record entirely, which reads as "the agent never called it".
fn action_for(tool_name: &str, args: &Value) -> Action {
    match normalize_tool_name(tool_name).as_str() {
        "runcommand" => Action::ShellCommand(ShellCommand {
            call_id: call_id(),
            command: str_arg(args, "CommandLine"),
            working_dir: opt_str_arg(args, "Cwd"),
        }),
        "viewfile" => Action::FileOperation(FileOperation {
            call_id: call_id(),
            operation: FileOpType::Read,
            path: str_arg(args, "AbsolutePath"),
            content: None,
            old_content: None,
        }),
        "writetofile" => Action::FileOperation(FileOperation {
            call_id: call_id(),
            operation: FileOpType::Write,
            path: str_arg(args, "TargetFile"),
            content: opt_str_arg(args, "CodeContent"),
            old_content: None,
        }),
        "replacefilecontent" => Action::FileOperation(FileOperation {
            call_id: call_id(),
            operation: FileOpType::Edit,
            path: str_arg(args, "TargetFile"),
            content: opt_str_arg(args, "ReplacementContent"),
            old_content: opt_str_arg(args, "TargetContent"),
        }),
        // Multi-edit: model as an Edit on the target file; individual chunks
        // are not surfaced to the policy layer.
        "multireplacefilecontent" => Action::FileOperation(FileOperation {
            call_id: call_id(),
            operation: FileOpType::Edit,
            path: str_arg(args, "TargetFile"),
            content: None,
            old_content: None,
        }),
        "readurlcontent" => Action::WebFetch(WebFetch {
            call_id: call_id(),
            url: str_arg(args, "Url"),
            prompt: String::new(),
        }),
        _ => Action::ToolCall(ToolCall {
            call_id: call_id(),
            tool: tool_name.to_string(),
            arguments: args.clone(),
        }),
    }
}

impl<H: HarnessClient> Hooks<H> {
    pub fn new(harness: H, agent_id: String) -> Self {
        let agent = Agent {
            id: agent_id,
            provider: "antigravity".to_string(),
            platform: "antigravity".to_string(),
        };
        Self { harness, agent }
    }

    fn event(&self, trajectory_id: &str, event: TrajectoryEvent) -> Event {
        Event::new(self.agent.clone(), trajectory_id, event)
    }

    /// Handle `PreToolUse` — adjudicate the proposed tool call.
    pub async fn handle_pre_tool_use(
        &mut self,
        event: PreToolUseEvent,
    ) -> Result<AntigravityHookResponse> {
        let tool_name = event.tool_call.name.clone();
        let action = action_for(&tool_name, &event.tool_call.args);

        let ev = self.event(
            &event.common.conversation_id,
            TrajectoryEvent::Action(action),
        );
        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("Tool '{tool_name}' execution allowed");
                AntigravityHookResponse::allow_tool()
            }
            Decision::Deny => {
                let msg = adjudicated
                    .deny_message(&format!("Tool '{tool_name}' execution denied by policy"));
                warn!("Tool '{tool_name}' execution denied: {msg}");
                AntigravityHookResponse::deny_tool(msg)
            }
            // Antigravity natively supports "ask", so an escalation maps to a
            // user prompt rather than a hard deny.
            Decision::Escalate => {
                let msg =
                    adjudicated.deny_message(&format!("Tool '{tool_name}' requires approval"));
                warn!("Tool '{tool_name}' escalated to user prompt: {msg}");
                AntigravityHookResponse::ask_tool(msg)
            }
        };

        Ok(response)
    }

    /// Handle `PostToolUse` — record the tool result as an observation. The
    /// payload only carries `stepIdx` + optional `error` (no tool name or
    /// output), so the observation is minimal. Output is always `{}`.
    pub async fn handle_post_tool_use(
        &mut self,
        event: PostToolUseEvent,
    ) -> Result<AntigravityHookResponse> {
        let error = event.error.filter(|e| !e.is_empty());
        let observation = TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput {
            call_id: format!("step-{}", event.step_idx),
            success: error.is_none(),
            output: Value::Object(Default::default()),
            error,
        }));

        let ev = self.event(&event.common.conversation_id, observation);
        let _ = self.harness.adjudicate(ev).await?;

        // PostToolUse output is always an empty object per the spec.
        Ok(AntigravityHookResponse::ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_run_command_to_shell_action() {
        let args = serde_json::json!({ "CommandLine": "npm test", "Cwd": "/wd" });
        match action_for("run_command", &args) {
            Action::ShellCommand(s) => {
                assert_eq!(s.command, "npm test");
                assert_eq!(s.working_dir.as_deref(), Some("/wd"));
            }
            other => panic!("expected ShellCommand, got {other:?}"),
        }
    }

    #[test]
    fn maps_replace_file_content_to_edit() {
        let args = serde_json::json!({
            "TargetFile": "/a.rs",
            "TargetContent": "old",
            "ReplacementContent": "new"
        });
        match action_for("replace_file_content", &args) {
            Action::FileOperation(f) => {
                assert!(matches!(f.operation, FileOpType::Edit));
                assert_eq!(f.path, "/a.rs");
                assert_eq!(f.old_content.as_deref(), Some("old"));
                assert_eq!(f.content.as_deref(), Some("new"));
            }
            other => panic!("expected FileOperation, got {other:?}"),
        }
    }

    #[test]
    fn maps_read_url_content_to_webfetch() {
        let args = serde_json::json!({ "Url": "https://example.com" });
        assert!(
            matches!(action_for("read_url_content", &args), Action::WebFetch(w) if w.url == "https://example.com")
        );
    }

    #[test]
    fn unmodeled_tool_is_recorded_as_a_generic_tool_call() {
        // It reaches Cedar only as `PreToolUse`, which no policy targets, but
        // it is adjudicated and lands in the trajectory. Skipping the harness
        // round-trip left the call absent from the record entirely.
        let args = serde_json::json!({ "query": "rust" });
        match action_for("search_web", &args) {
            Action::ToolCall(tc) => {
                assert_eq!(tc.tool, "search_web");
                assert_eq!(tc.arguments, args);
            }
            other => panic!("expected ToolCall, got {other:?}"),
        }
    }
}
