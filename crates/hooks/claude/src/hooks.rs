//! Hook handler implementations for Claude Code events.
//!
//! This module contains all the business logic for handling different types
//! of hook events from Claude Code, including tool use, notifications,
//! session management, and user prompt processing.

use super::types::*;
use crate::event::HookPlatform;
use crate::response::HookResponse;
use crate::truncate::{
    MAX_EVENT_TEXT_BYTES, cap_action_strings, cap_control_strings, cap_observation_strings,
    truncate_event_text,
};
use serde_json::Value;
use sondera_hooks::adjudication::{fail_closed_reason_post_tool, warn_unenforceable_decision};
use sondera_hooks::error::{HookError, Result};
use sondera_hooks::json_string_field;
use sondera_hooks::mention;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sondera_harness_client::{
    Action, Actor, Adjudicated, Agent, Completed, Control, Decision, Event, FileOpType,
    FileOperation, FileOperationResult, HarnessClient, Observation, Prompt, ShellCommand,
    ShellCommandOutput, Started, Terminated, ToolCall, ToolOutput, TrajectoryEvent, WebFetch,
    WebFetchOutput,
};
// `HarnessClient::adjudicate`'s error type is the trait-side
// `sondera_types::HarnessClientError`, not the gRPC-client-local variant
// re-exported by `sondera_harness_client::HarnessClientError`. Pull the
// trait-side one in directly so the wrapper's return type matches.
use sondera_types::HarnessClientError;
use tracing::{debug, info, warn};

// Stop must adjudicate only the final unadjudicated assistant tail. Missing or
// stale cursors seed to the start of the last assistant turn so resumed
// sessions never replay full transcripts through the hook budget, while still
// keeping the turn's thoughts (a `thinking` line that precedes the final `text`
// line is part of the same turn). A separate retry cursor preserves a failed
// tail without turning later Stops into full-session replay.
const STOP_TRANSCRIPT_ADJUDICATE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long `handle_stop` waits for Claude Code to finish writing the current
/// turn's reply to the transcript before giving up. Claude Code fires `Stop`
/// shortly before it writes the reply (I very roughly measured ~70ms on my
/// machine -jbrock), so reading immediately can beat the write and drop the
/// final message. We poll the transcript until its newest reply matches the Stop
/// payload's `last_assistant_message` instead of reading on faith.
///
/// This 2-second timeout is deliberately separate from the 30-second overall
/// hook timeout. We can't just rely on that one: when it expires it aborts the
/// whole hook, so the fallback that records the payload message would never run,
/// and those 30 seconds also have to cover connecting to the harness and the
/// 2-second adjudication step.
///
/// 2 seconds is comfortably longer than the write normally takes, so we rarely
/// wait the whole time, and it still leaves room under the 30-second limit for
/// the connect, the adjudication, and the fallback. It also stays well under the
/// host deadline, avoiding overlapping `Stop` hooks that would break the
/// assumption that only one `Stop` touches the cursor at a time.
const STOP_TRANSCRIPT_CATCHUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Sleep between transcript polls while waiting for the write. Small enough to
/// react promptly once the write lands, large enough not to spin.
const STOP_TRANSCRIPT_CATCHUP_POLL_INTERVAL: Duration = Duration::from_millis(10);

const STOP_TRANSCRIPT_ADJUDICATE_BATCH_SIZE: usize = 32;

struct PendingTranscriptEvent {
    event: Event,
    cursor_start: u64,
    cursor_after_line: u64,
}

/// How the Stop hook should read new assistant events from the transcript,
/// resolved once so the catch-up check and the read that follows it agree on a
/// single starting offset (see `handle_stop`).
enum StopReadPlan {
    /// The transcript has no extractable assistant events. Callers set the
    /// cursor to EOF so a resumed session never replays.
    NoAssistantTurn { transcript_len: u64 },
    /// Read forward from this byte offset.
    ReadFrom { cursor: u64 },
}

/// Choose the byte offset the next Stop read should start from, without touching
/// any persisted state.
///
/// Stop adjudication is intentionally final-tail only, so the offset follows a
/// fixed precedence:
///
/// 1. A retry cursor, if present and still inside the file — a previous batch
///    failed to adjudicate and we re-read from where it left off.
/// 2. Otherwise the stored cursor, but only if it already sits *inside* the
///    latest assistant turn and still points inside the file. If it has fallen
///    behind (absent, zeroed, or from an earlier turn), replaying the
///    intervening history could overrun the hook's time limit and flood the
///    scanning model with already-recorded turns; earlier turns were already
///    captured by their own Stops. If it points *past* EOF (the
///    transcript was replaced or truncated), it is stale — the same rule the
///    retry cursor gets — and reading from it would see nothing forever.
/// 3. Otherwise the start of the latest assistant turn. Starting at the turn
///    *start* (not its last line) keeps a `thinking` line that precedes the final
///    `text` line (see [`transcript::last_assistant_turn_start`]).
///
/// Resolving this once and threading the result into both the catch-up check and
/// the read is load-bearing: if the check validated one offset and the read then
/// started from another, we could re-emit already-recorded events or skip the
/// reply we just confirmed.
fn resolve_stop_read_plan(session_id: &str, transcript_path: &str) -> Result<StopReadPlan> {
    use super::transcript;

    let transcript_len = std::fs::metadata(transcript_path)?.len();
    let Some(last_turn_start) = transcript::last_assistant_turn_start(transcript_path)? else {
        return Ok(StopReadPlan::NoAssistantTurn { transcript_len });
    };

    let retry_cursor = transcript::read_retry_cursor_if_active(session_id, transcript_len);
    let stored_cursor = transcript::read_cursor_if_present(session_id);
    let cursor = if let Some(cursor) = retry_cursor {
        cursor
    } else {
        match stored_cursor {
            Some(cursor) if cursor > last_turn_start && cursor <= transcript_len => cursor,
            _ => last_turn_start,
        }
    };

    Ok(StopReadPlan::ReadFrom { cursor })
}

/// Errors seen while polling the transcript during the Stop catch-up wait.
///
/// This does two things. First, it limits log spam: the poll ticks every 10ms,
/// so a transcript that is unreadable for the whole wait would otherwise log
/// the same failure ~200 times in a single Stop. [`Self::note`] logs the first
/// failure at `warn` and demotes the rest to `debug`. Second, it remembers
/// what went wrong — how many polls failed, and the text of the most recent
/// failure — so that when the wait gives up, the timeout warning in
/// `handle_catch_up_timeout` can report whether the reply simply never
/// arrived (zero poll errors) or the transcript couldn't be read at all, and
/// why.
#[derive(Default)]
struct CatchUpPollErrors {
    count: u32,
    last: Option<String>,
}

impl CatchUpPollErrors {
    fn note(&mut self, message: std::fmt::Arguments<'_>) {
        if self.count == 0 {
            warn!("{message}");
        } else {
            debug!("{message}");
        }
        self.count += 1;
        self.last = Some(message.to_string());
    }
}

fn warn_stop_policy_finding(adjudicated: &Adjudicated) {
    if matches!(adjudicated.decision, Decision::Deny | Decision::Escalate) {
        let msg = adjudicated.deny_message("Stop produced a policy finding");
        warn!(
            "Stop produced a policy finding but is allowing because Claude Stop blocks continue the conversation: {}",
            msg
        );
    }
}

/// Check if a file path is under ~/.claude/plans/, which Claude Code uses for plan files.
/// Uses `fs::canonicalize` when the path exists on disk (resolves symlinks), falling
/// back to manual normalization for paths that don't exist yet (e.g. new plan files).
fn is_plan_file(file_path: &str) -> bool {
    if file_path.is_empty() {
        return false;
    }
    let Some(home) = std::env::var_os("HOME") else {
        return false;
    };
    let plans_dir = PathBuf::from(home).join(".claude").join("plans");
    let plans_dir = std::fs::canonicalize(&plans_dir).unwrap_or(plans_dir);
    let resolved = std::fs::canonicalize(file_path).unwrap_or_else(|_| {
        let path = Path::new(file_path);
        let absolute = if path.is_relative() {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        } else {
            path.to_path_buf()
        };
        // Lexical `.`/`..` collapse (shared with the @-mention resolver) blocks
        // traversal like `~/.claude/plans/../../etc/foo` for not-yet-created
        // plan files that `canonicalize` can't resolve.
        mention::lexically_normalize(&absolute)
    });
    resolved.starts_with(plans_dir)
}

fn lifecycle_block_response(
    adjudicated: &Adjudicated,
    deny_reason: &str,
    escalate_reason: &str,
    build_response: fn(String) -> HookResponse,
) -> Option<HookResponse> {
    match adjudicated.decision {
        Decision::Allow => None,
        Decision::Deny => Some(build_response(adjudicated.deny_message(deny_reason))),
        Decision::Escalate => Some(build_response(adjudicated.deny_message(escalate_reason))),
    }
}

fn lifecycle_response_reason(response: &HookResponse) -> &str {
    response
        .reason
        .as_deref()
        .or(response.stop_reason.as_deref())
        .unwrap_or("blocked by policy")
}

/// If args contain a file_path or notebook_path, derive is_plan_file and add it to the args.
fn enrich_with_plan_file_flag(mut args: serde_json::Value) -> serde_json::Value {
    if let serde_json::Value::Object(ref mut map) = args {
        let file_path = map
            .get("file_path")
            .or_else(|| map.get("notebook_path"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());

        if let Some(path_str) = file_path {
            map.insert(
                "is_plan_file".to_string(),
                serde_json::Value::Bool(is_plan_file(&path_str)),
            );
        }
    }
    args
}

fn tool_input_str<'a>(tool_input: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| tool_input.get(key).and_then(|value| value.as_str()))
}

fn normalize_pre_tool_action(
    tool_name: &str,
    tool_use_id: &str,
    cwd: &str,
    tool_input: &Value,
) -> Action {
    match tool_name {
        "Bash" | "Shell" => {
            let command = tool_input_str(tool_input, &["command"])
                .unwrap_or("")
                .to_string();
            Action::ShellCommand(ShellCommand {
                call_id: tool_use_id.to_string(),
                command,
                working_dir: Some(cwd.to_string()),
            })
        }
        "Read" => {
            let path = tool_input_str(tool_input, &["file_path", "path", "notebook_path"])
                .unwrap_or("")
                .to_string();
            Action::FileOperation(FileOperation {
                call_id: tool_use_id.to_string(),
                operation: FileOpType::Read,
                path,
                content: None,
                old_content: None,
            })
        }
        "Edit" => {
            let tool_input = enrich_with_plan_file_flag(tool_input.clone());
            let path = tool_input_str(&tool_input, &["file_path", "path", "notebook_path"])
                .unwrap_or("")
                .to_string();
            let old_content = tool_input_str(&tool_input, &["old_string", "old_content"])
                .map(std::string::ToString::to_string);
            let content = tool_input_str(&tool_input, &["new_string", "content", "new_content"])
                .map(std::string::ToString::to_string);
            Action::FileOperation(FileOperation {
                call_id: tool_use_id.to_string(),
                operation: FileOpType::Edit,
                path,
                content,
                old_content,
            })
        }
        "Write" => {
            let tool_input = enrich_with_plan_file_flag(tool_input.clone());
            let path = tool_input_str(&tool_input, &["file_path", "path", "notebook_path"])
                .unwrap_or("")
                .to_string();
            let content = tool_input_str(&tool_input, &["content", "new_string", "new_content"])
                .map(std::string::ToString::to_string);
            Action::FileOperation(FileOperation {
                call_id: tool_use_id.to_string(),
                operation: FileOpType::Write,
                path,
                content,
                old_content: None,
            })
        }
        "Glob" | "Grep" => {
            let path = tool_input_str(tool_input, &["path"])
                .unwrap_or(cwd)
                .to_string();
            let content =
                tool_input_str(tool_input, &["pattern"]).map(std::string::ToString::to_string);
            Action::FileOperation(FileOperation {
                call_id: tool_use_id.to_string(),
                operation: FileOpType::Read,
                path,
                content,
                old_content: None,
            })
        }
        "NotebookEdit" => {
            let tool_input = enrich_with_plan_file_flag(tool_input.clone());
            let path = tool_input_str(&tool_input, &["notebook_path", "file_path", "path"])
                .unwrap_or("")
                .to_string();
            let content = tool_input_str(&tool_input, &["new_source", "content", "new_content"])
                .map(std::string::ToString::to_string);
            Action::FileOperation(FileOperation {
                call_id: tool_use_id.to_string(),
                operation: FileOpType::Edit,
                path,
                content,
                old_content: None,
            })
        }
        "WebFetch" => {
            let url = tool_input_str(tool_input, &["url"])
                .unwrap_or("")
                .to_string();
            let prompt = tool_input_str(tool_input, &["prompt"])
                .unwrap_or("")
                .to_string();
            Action::WebFetch(WebFetch {
                call_id: tool_use_id.to_string(),
                url,
                prompt,
            })
        }
        _ => Action::ToolCall(ToolCall {
            call_id: tool_use_id.to_string(),
            tool: tool_name.to_string(),
            arguments: tool_input.clone(),
        }),
    }
}

/// Synthesize a stable `call_id` for a re-derived `@`-mention file read.
///
/// A real tool call carries Claude Code's `tool_use_id`; an `@`-mention has
/// none, so we derive one from the session and the resolved path. Keying on the
/// path (not a per-prompt counter) keeps distinct files distinct across the
/// prompts of one session, so an audit or correlation that indexes by `call_id`
/// cannot conflate two different reads.
fn at_mention_call_id(session_id: &str, path: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    format!("atmention-{session_id}-{:016x}", hasher.finish())
}

pub struct Hooks<H: HarnessClient> {
    harness: H,
    agent: Agent,
    /// Which Claude surface these hooks serve. The typed source of truth for
    /// this instance's identity labels — the agent/actor platform name derives
    /// from it.
    platform: HookPlatform,
    /// How long `handle_stop` waits for the current turn's transcript write to
    /// land before falling back to the Stop payload. Defaults to
    /// [`STOP_TRANSCRIPT_CATCHUP_TIMEOUT`]; tests shrink it to keep timeout-path
    /// cases fast.
    stop_catchup_timeout: Duration,
}

impl<H: HarnessClient> Hooks<H> {
    /// Create a new Hooks instance.
    pub fn new(harness: H, agent: Agent, platform: HookPlatform) -> Self {
        Self {
            harness,
            agent,
            platform,
            stop_catchup_timeout: STOP_TRANSCRIPT_CATCHUP_TIMEOUT,
        }
    }

    /// Adjudicate a single event through the harness.
    async fn adjudicate(
        &self,
        event: Event,
    ) -> std::result::Result<Adjudicated, HarnessClientError> {
        self.harness.adjudicate(event).await
    }

    /// Adjudicate one bounded Stop transcript batch through the transport batch
    /// RPC. Callers chunk before reaching this helper, so this never receives
    /// an unbounded retry tail.
    async fn adjudicate_stop_batch(
        &self,
        events: Vec<Event>,
    ) -> std::result::Result<Vec<Adjudicated>, HarnessClientError> {
        let event_count = events.len();
        let adjudications = self.harness.adjudicates(events).await?;
        if adjudications.len() != event_count {
            return Err(HarnessClientError::Decode(format!(
                "Expected {event_count} Stop transcript adjudications, received {}",
                adjudications.len()
            )));
        }
        Ok(adjudications)
    }

    /// Create an Event with the current agent identity.
    fn event(&self, session_id: &str, event: TrajectoryEvent) -> Event {
        Event::new(self.agent.clone(), session_id, event)
    }

    /// Return the parent agent identity for subagent events.
    ///
    /// Subagents are ephemeral (Explore, Plan, specialist agents) and run
    /// within the parent session. Their events roll up under the parent
    /// agent rather than creating separate agent registrations.
    fn subagent(&self, _agent_type: &str) -> Agent {
        self.agent.clone()
    }

    // ============================================================================
    // Session lifecycle hooks
    // ============================================================================

    /// Handle sessionStart hook
    pub async fn handle_session_start(&mut self, event: SessionStartEvent) -> Result<HookResponse> {
        let session_agent = self.agent.clone();
        let started =
            TrajectoryEvent::Control(Control::Started(Started::new(session_agent.clone())));

        let ev = Event::new(session_agent, &event.session_id, started);

        let adjudicated = self.adjudicate(ev).await?;

        match adjudicated.decision {
            Decision::Allow => Ok(HookResponse::allow()),
            Decision::Deny => {
                let msg = adjudicated.deny_message("Session start blocked by policy");
                warn!("Session start denied: {}", msg);
                Ok(HookResponse::stop(msg))
            }
            Decision::Escalate => {
                let msg = adjudicated.deny_message("Session start escalated for review");
                warn!("Session start escalated: {}", msg);
                Ok(HookResponse::stop(msg))
            }
        }
    }

    /// Handle sessionEnd hook
    pub async fn handle_session_end(&mut self, event: SessionEndEvent) -> Result<HookResponse> {
        info!(
            "Session {} ended (reason: {:?})",
            event.session_id, event.reason
        );

        let terminal_control = match event.reason {
            SessionEndReason::Clear => Some(Control::Terminated(Terminated::new(
                "session cleared",
                "user",
            ))),
            SessionEndReason::Logout => Some(Control::Terminated(Terminated::new(
                "user logged out",
                "user",
            ))),
            SessionEndReason::BypassPermissionsDisabled => Some(Control::Terminated(
                Terminated::new("bypass permissions disabled", "system"),
            )),
            SessionEndReason::PromptInputExit | SessionEndReason::Other => {
                info!(
                    "Session {} ended with resumable reason {:?}; preserving non-terminal trajectory state",
                    event.session_id, event.reason
                );
                None
            }
        };

        if let Some(control) = terminal_control {
            let ev = self.event(&event.session_id, TrajectoryEvent::Control(control));

            let adjudicated = self.adjudicate(ev).await?;
            warn_unenforceable_decision("non-blocking hook", &adjudicated);
        }

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // Tool execution hooks
    // ============================================================================

    /// Handle preToolUse hook
    pub async fn handle_pre_tool_use(&mut self, event: PreToolUseEvent) -> Result<HookResponse> {
        let tool_name = event.tool_name.clone();
        let mut action = normalize_pre_tool_action(
            &tool_name,
            &event.tool_use_id,
            &event.cwd,
            &event.tool_input,
        );

        if cap_action_strings(&mut action, MAX_EVENT_TEXT_BYTES) {
            warn!(
                cap_bytes = MAX_EVENT_TEXT_BYTES,
                tool_name = tool_name.as_str(),
                tool_use_id = event.tool_use_id.as_str(),
                "Truncated preToolUse action to fit gRPC message limit"
            );
        }

        let trajectory_event = TrajectoryEvent::Action(action);

        let ev = self.event(&event.session_id, trajectory_event);

        let adjudicated = self.adjudicate(ev).await?;

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
        let tool_name = event.tool_name.clone();

        // Use _permission suffix so the Cedar harness can map to PermissionRequest action
        let mut action = Action::ToolCall(ToolCall {
            call_id: event.tool_use_id.clone(),
            tool: format!("{}_permission", tool_name),
            arguments: event.tool_input.clone(),
        });

        if cap_action_strings(&mut action, MAX_EVENT_TEXT_BYTES) {
            warn!(
                cap_bytes = MAX_EVENT_TEXT_BYTES,
                tool_name = tool_name.as_str(),
                tool_use_id = event.tool_use_id.as_str(),
                "Truncated permissionRequest tool_input to fit gRPC message limit"
            );
        }

        let ev = self.event(&event.session_id, TrajectoryEvent::Action(action));

        let adjudicated = self.adjudicate(ev).await?;

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
        let mut observation = match event.tool_name.as_str() {
            "Bash" | "Shell" => {
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
                if let Some(path) = json_string_field(&event.tool_input, &["file_path", "path"]) {
                    result = result.with_path(path);
                }
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

        if cap_observation_strings(&mut observation, MAX_EVENT_TEXT_BYTES) {
            warn!(
                cap_bytes = MAX_EVENT_TEXT_BYTES,
                tool_name = event.tool_name.as_str(),
                tool_use_id = event.tool_use_id.as_str(),
                "Truncated postToolUse observation to fit gRPC message limit"
            );
        }

        let tool_output = TrajectoryEvent::Observation(observation);

        let ev = self.event(&event.session_id, tool_output);

        match self.adjudicate(ev).await {
            Ok(adjudicated) => match adjudicated.decision {
                Decision::Allow => Ok(HookResponse::allow()),
                Decision::Deny => {
                    let msg = adjudicated.deny_message("Tool output blocked by policy");
                    warn!("PostToolUse '{}' output blocked: {}", event.tool_name, msg);
                    // PostToolUse `decision: "block"` alone still leaves the original
                    // tool result visible to Claude. Replace it with shape-compatible
                    // redacted output per https://code.claude.com/docs/en/hooks.
                    Ok(HookResponse::post_tool_block_with_redacted_output(
                        msg,
                        &event.tool_response,
                    ))
                }
                Decision::Escalate => {
                    let msg = adjudicated.deny_message("Tool output requires review");
                    info!(
                        "PostToolUse '{}' output escalated: {}",
                        event.tool_name, msg
                    );
                    // See the deny arm above: PostToolUse must use updatedToolOutput
                    // to prevent Claude from seeing blocked tool output.
                    Ok(HookResponse::post_tool_block_with_redacted_output(
                        msg,
                        &event.tool_response,
                    ))
                }
            },
            Err(err) => {
                warn!(
                    error = %err,
                    "PostToolUse: harness error, blocking tool output by fail-closed enforcement"
                );
                // Vary the block reason by failure class so server-side
                // rejections and timeouts are not mislabeled as connectivity
                // problems. Enforcement stays fail-closed regardless.
                let msg = fail_closed_reason_post_tool(&HookError::from(err)).to_string();
                // Use updatedToolOutput here too; otherwise a degraded PostToolUse
                // block would still expose the original result to Claude.
                Ok(HookResponse::post_tool_block_with_redacted_output(
                    msg,
                    &event.tool_response,
                ))
            }
        }
    }

    // ============================================================================
    // Notification hook
    // ============================================================================

    /// Handle notification events
    pub async fn handle_notification(&mut self, event: NotificationEvent) -> Result<HookResponse> {
        info!(
            "Processing notification: {:?} (session: {})",
            event.notification_type, event.session_id
        );

        let mut system_prompt = Observation::Prompt(Prompt::system(format!(
            "[notification:{:?}] {}",
            event.notification_type, event.message
        )));

        if cap_observation_strings(&mut system_prompt, MAX_EVENT_TEXT_BYTES) {
            warn!(
                cap_bytes = MAX_EVENT_TEXT_BYTES,
                notification_type = ?event.notification_type,
                "Truncated notification message to fit gRPC message limit"
            );
        }

        let ev = self
            .event(
                &event.session_id,
                TrajectoryEvent::Observation(system_prompt),
            )
            .with_actor(Actor::system(self.platform.as_str()));

        let adjudicated = self.adjudicate(ev).await?;
        warn_unenforceable_decision("non-blocking hook", &adjudicated);

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // User prompt hook
    // ============================================================================

    /// Adjudicate the files mentioned with `@` in the prompt, one at a time, in
    /// order of appearance and before the prompt itself.
    ///
    /// Files mentioned with `@` are inlined into the prompt by Claude Code
    /// without ever issuing a `Read` tool call, so no `PreToolUse` hook fires
    /// for them. This re-derives those reads: each `@`-mention that resolves to
    /// a readable local file is sent as a `Read` [`FileOperation`] carrying the
    /// file's content, so both path- and content-based policy still govern `@`
    /// access.
    ///
    /// Returns `Some(block_response)` as soon as a mention is denied or
    /// escalated; the caller returns it and never adjudicates the prompt.
    /// Returns `None` when every mention is allowed. Enforcement mode is applied
    /// by the harness (a `Deny` reaching a hook is already a governing
    /// decision), so no mode check happens here. `Escalate` requests human
    /// approval, which cannot be obtained at prompt-submit time and the file
    /// content is already inlined into the turn, so it fails closed and blocks.
    /// Directory mentions, MCP `@server:resource` mentions, and dangling paths
    /// are skipped.
    async fn adjudicate_at_mention_reads(
        &self,
        event: &UserPromptSubmitEvent,
    ) -> Result<Option<HookResponse>> {
        let mentioned =
            mention::resolve_mentioned_files(&event.prompt, &event.cwd, MAX_EVENT_TEXT_BYTES);
        for (path, content) in mentioned {
            let mut action = Action::FileOperation(FileOperation {
                call_id: at_mention_call_id(&event.session_id, &path),
                operation: FileOpType::Read,
                path: path.to_string_lossy().into_owned(),
                content,
                old_content: None,
            });
            // `read_file_text` already bounds the read for memory; this is the
            // same wire cap every other handler applies to the built action.
            if cap_action_strings(&mut action, MAX_EVENT_TEXT_BYTES) {
                warn!(
                    cap_bytes = MAX_EVENT_TEXT_BYTES,
                    path = %path.display(),
                    session_id = event.session_id.as_str(),
                    "Truncated @-mention file read to fit gRPC message limit"
                );
            }

            let ev = self.event(&event.session_id, TrajectoryEvent::Action(action));
            let adjudicated = self.adjudicate(ev).await?;

            match adjudicated.decision {
                Decision::Allow => {}
                Decision::Deny => {
                    let msg = adjudicated.deny_message(&format!(
                        "@-mentioned file '{}' blocked by policy",
                        path.display()
                    ));
                    warn!("@-mention read denied: {}", msg);
                    return Ok(Some(HookResponse::prompt_block(msg)));
                }
                Decision::Escalate => {
                    let msg = adjudicated.deny_message(&format!(
                        "@-mentioned file '{}' requires approval that cannot be granted at prompt submit",
                        path.display()
                    ));
                    warn!("@-mention read escalated; failing closed: {}", msg);
                    return Ok(Some(HookResponse::prompt_block(msg)));
                }
            }
        }
        Ok(None)
    }

    /// Handle userPromptSubmit hook
    pub async fn handle_user_prompt_submit(
        &mut self,
        event: UserPromptSubmitEvent,
    ) -> Result<HookResponse> {
        // `@`-mentioned files are inlined into the prompt without a Read tool
        // call, so govern them here before the prompt itself: a deny on any
        // mentioned file blocks the whole prompt (the file content is already
        // assembled into the turn, so there is no later tool hook to block on).
        if let Some(block) = self.adjudicate_at_mention_reads(&event).await? {
            return Ok(block);
        }

        let mut prompt_obs = Observation::Prompt(Prompt::user(&event.prompt));
        if cap_observation_strings(&mut prompt_obs, MAX_EVENT_TEXT_BYTES) {
            warn!(
                cap_bytes = MAX_EVENT_TEXT_BYTES,
                session_id = event.session_id.as_str(),
                "Truncated user prompt to fit gRPC message limit"
            );
        }

        let ev = self
            .event(&event.session_id, TrajectoryEvent::Observation(prompt_obs))
            .with_actor(Actor::human(&self.agent.id));

        let adjudicated = self.adjudicate(ev).await?;

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
                warn!("User prompt escalated; failing closed: {}", msg);
                HookResponse::prompt_block(msg)
            }
        };
        Ok(response)
    }

    // ============================================================================
    // Stop hooks
    // ============================================================================

    /// Handle stop hook
    pub async fn handle_stop(&mut self, event: StopEvent) -> Result<HookResponse> {
        info!(
            "Processing stop event (session: {}, stop_hook_active: {})",
            event.session_id, event.stop_hook_active
        );

        if event.stop_hook_active {
            info!("Stop hook is already active. Allowing stop to prevent infinite loop");
            return Ok(HookResponse::allow());
        }

        let events = self.collect_stop_events(&event).await?;

        // Claude Code treats a Stop block/exit-2 response as "continue the
        // conversation". Adjudicate the current assistant tail for trajectory
        // visibility, but never return a blocking Stop response.
        self.adjudicate_stop_transcript_events(&event.session_id, events)
            .await?;

        Ok(HookResponse::allow())
    }

    /// Gather the current assistant tail from the transcript for adjudication.
    ///
    /// When the Stop payload carries the reply the user saw
    /// (`last_assistant_message`), Claude Code may not have written that reply to
    /// the transcript yet. Wait for it to land, then read the transcript from
    /// where the reply starts; reading the transcript rather than the payload
    /// alone preserves the turn's thinking. If the reply never lands before the
    /// wait times out, record the payload message directly as a best-effort
    /// fallback and return no events. With no payload reply to wait on, read whatever the
    /// transcript already holds. A parse failure is logged and treated as no
    /// events so it never blocks the stop.
    async fn collect_stop_events(&self, event: &StopEvent) -> Result<Vec<PendingTranscriptEvent>> {
        // The reply the user actually saw, per the Stop payload. Kept as-is (not
        // trimmed): the transcript stores the reply verbatim, so the catch-up
        // check trims both sides itself, and the fallback records this raw text
        // to match what a transcript read would have recorded.
        let expected = event
            .last_assistant_message
            .as_deref()
            .filter(|reply| !reply.trim().is_empty());

        if event.transcript_path.is_empty() {
            // Claude Code always supplies a transcript path, so an empty one is
            // itself worth surfacing. There is no transcript to read or wait on;
            // if the payload still carries the reply the user saw, record it
            // directly rather than dropping the turn's final message — the
            // payload is the only copy.
            warn!(
                session_id = event.session_id.as_str(),
                recording_payload = expected.is_some(),
                "Stop event carried no transcript path"
            );
            if let Some(reply) = expected {
                self.record_last_assistant_message(event, reply).await;
            }
            return Ok(Vec::new());
        }

        let extracted = match expected {
            Some(reply) => {
                // Claude Code fires `Stop` before it finishes writing this turn's
                // reply to the transcript. Wait for the reply to land in the
                // file, then read the transcript from where the reply starts.
                match self
                    .wait_for_transcript_catch_up(&event.session_id, &event.transcript_path, reply)
                    .await
                {
                    Ok(cursor) => self.read_stop_events_from(
                        &event.session_id,
                        &event.transcript_path,
                        cursor,
                    ),
                    Err(poll_errors) => {
                        self.handle_catch_up_timeout(event, reply, &poll_errors)
                            .await;
                        return Ok(Vec::new());
                    }
                }
            }
            // No payload reply to wait on (e.g. a Stop with no assistant output).
            None => self.extract_transcript_events(&event.session_id, &event.transcript_path),
        };

        match extracted {
            Ok(events) => {
                if !events.is_empty() {
                    info!(
                        "Extracted {} assistant trajectory events from Stop transcript",
                        events.len()
                    );
                }
                Ok(events)
            }
            Err(err) => {
                warn!(
                    "Failed to parse Stop transcript at {}: {err}",
                    event.transcript_path
                );
                Ok(Vec::new())
            }
        }
    }

    /// Poll the transcript until its newest assistant reply matches `expected`
    /// (the Stop payload's `last_assistant_message`), and return the byte offset
    /// to read from. If the reply never lands within `stop_catchup_timeout`,
    /// returns the errors seen while polling so the timeout warning can say
    /// whether the wait failed cleanly (the write just never came) or the
    /// transcript itself was unreadable.
    ///
    /// Because the returned offset is resolved on the same iteration that
    /// observed the match, the caller can read from exactly the span the check
    /// validated (see [`resolve_stop_read_plan`]). The transcript is stable
    /// during the wait: a `Stop` hook blocks Claude Code from continuing, so the
    /// next turn — and the only other writer of this cursor's state — cannot
    /// start until we return.
    async fn wait_for_transcript_catch_up(
        &self,
        session_id: &str,
        transcript_path: &str,
        expected: &str,
    ) -> std::result::Result<u64, CatchUpPollErrors> {
        use super::transcript;

        // Compare against the same truncation `parse_transcript` applies, so a
        // reply large enough to be capped still matches itself. Trim both sides:
        // the payload and the transcript block can differ only in surrounding
        // whitespace (e.g. a trailing newline), which shouldn't defeat the match.
        let expected = truncate_event_text(expected, MAX_EVENT_TEXT_BYTES);
        let expected = expected.as_ref().trim();

        let deadline = Instant::now() + self.stop_catchup_timeout;
        // The transcript is append-only and this hook blocks the only other
        // writer of its cursor state, so a poll can only observe something new
        // after the file has grown. Remember the length we last inspected and
        // skip the re-parse when it hasn't changed — resolving the read plan
        // scans the whole file, so re-running it every tick would turn a slow
        // write on a large transcript into two seconds of back-to-back
        // full-file scans.
        let mut checked_len: Option<u64> = None;
        // Read errors are expected while Claude Code is still creating or
        // swapping the file, so keep polling through them; `poll_errors`
        // deduplicates the logging and carries the summary into the timeout
        // warning.
        let mut poll_errors = CatchUpPollErrors::default();
        loop {
            match std::fs::metadata(transcript_path).map(|meta| meta.len()) {
                Ok(len) if checked_len == Some(len) => {}
                Ok(len) => {
                    checked_len = Some(len);
                    match resolve_stop_read_plan(session_id, transcript_path) {
                        Ok(StopReadPlan::ReadFrom { cursor }) => {
                            match transcript::newest_assistant_reply(transcript_path, cursor) {
                                Ok(Some(reply)) if reply.trim() == expected => return Ok(cursor),
                                // Reply not present past the cursor yet (or only a
                                // thinking line so far) — keep waiting.
                                Ok(_) => {}
                                Err(err) => {
                                    // The error may be transient, so re-check next
                                    // tick even if the file doesn't grow again.
                                    checked_len = None;
                                    poll_errors.note(format_args!(
                                        "Failed to read Claude transcript while waiting for Stop reply: {err}"
                                    ));
                                }
                            }
                        }
                        // No assistant turn on disk yet; keep waiting for the write.
                        Ok(StopReadPlan::NoAssistantTurn { .. }) => {}
                        Err(err) => {
                            checked_len = None;
                            poll_errors.note(format_args!(
                                "Failed to resolve Claude Stop read offset while waiting: {err}"
                            ));
                        }
                    }
                }
                // Not statable (not created yet, or mid-swap) — keep waiting.
                Err(err) => {
                    checked_len = None;
                    poll_errors.note(format_args!(
                        "Failed to stat Claude transcript while waiting for Stop reply: {err}"
                    ));
                }
            }

            if Instant::now() >= deadline {
                return Err(poll_errors);
            }
            tokio::time::sleep(STOP_TRANSCRIPT_CATCHUP_POLL_INTERVAL).await;
        }
    }

    /// Handle the case where the wait for the transcript timed out before the
    /// reply appeared.
    ///
    /// If a retry cursor is pending, a later `Stop` will re-read this turn from
    /// the transcript (with its thinking) via that cursor, so recording the
    /// payload now would double-record it once the harness recovers — leave it to
    /// the retry path. Otherwise record the payload directly so the reply the user
    /// saw isn't lost; the transcript is the only source of thinking, so this
    /// turn's thinking is lost either way.
    ///
    /// Two edge cases in the retry-cursor check:
    ///
    /// * The transcript holds no assistant events at all. A pending retry cursor
    ///   then has nothing to re-read and can never drain; left alone it would
    ///   skip the fallback on this and every later Stop, losing each turn's
    ///   reply. Clear it and set the stored cursor to EOF (exactly what the
    ///   no-payload read path does), then record the payload. With nothing
    ///   extractable on disk, the recording cannot duplicate a retry re-read.
    /// * The transcript's metadata can't be read, so the retry cursor can't be
    ///   validated against the file length. The skip exists to prevent a double
    ///   record, so err on that side and treat any retry cursor that exists as
    ///   pending. Defaulting the length to zero would do the opposite: every
    ///   retry cursor would look stale, and the fallback would record a message
    ///   that a later retry re-read may record again.
    async fn handle_catch_up_timeout(
        &self,
        event: &StopEvent,
        reply: &str,
        poll_errors: &CatchUpPollErrors,
    ) {
        use super::transcript;

        let retry_pending = match std::fs::metadata(&event.transcript_path).map(|meta| meta.len()) {
            Ok(transcript_len) => {
                match transcript::last_assistant_turn_start(&event.transcript_path) {
                    Ok(None) => {
                        if let Err(err) =
                            transcript::write_cursor(&event.session_id, transcript_len)
                        {
                            warn!(
                                session_id = event.session_id.as_str(),
                                "Failed to set Claude transcript cursor to EOF after Stop catch-up timeout: {err}"
                            );
                        }
                        transcript::remove_retry_cursor(&event.session_id);
                        info!(
                            session_id = event.session_id.as_str(),
                            transcript_len,
                            "Stop transcript has no assistant events; cleared any retry cursor and set the cursor to EOF before recording the payload"
                        );
                        false
                    }
                    _ => transcript::read_retry_cursor_if_active(&event.session_id, transcript_len)
                        .is_some(),
                }
            }
            Err(_) => transcript::read_retry_cursor_if_present(&event.session_id).is_some(),
        };

        if retry_pending {
            warn!(
                session_id = event.session_id.as_str(),
                timeout_ms = self.stop_catchup_timeout.as_millis() as u64,
                poll_errors = poll_errors.count,
                last_poll_error = poll_errors.last.as_deref(),
                "Stop transcript did not catch up in time; a retry cursor is pending, so leaving this turn for the retry path rather than recording the payload"
            );
            return;
        }
        warn!(
            session_id = event.session_id.as_str(),
            timeout_ms = self.stop_catchup_timeout.as_millis() as u64,
            poll_errors = poll_errors.count,
            last_poll_error = poll_errors.last.as_deref(),
            "Stop transcript did not catch up to last_assistant_message in time; recording payload message directly (thinking for this turn is lost)"
        );
        self.record_last_assistant_message(event, reply).await;
    }

    /// Record the Stop payload's `last_assistant_message` (`message`) as a single
    /// assistant prompt event, adjudicated directly — no transcript cursor is
    /// touched. `message` must be non-empty.
    ///
    /// This is the fallback when the wait for the transcript times out before the
    /// reply appears, or when the Stop event carries no transcript path at all
    /// (see `handle_stop`). Not advancing the cursor can't double-record: the
    /// caller only reaches this path when no retry cursor can re-read this turn —
    /// none is pending, the transcript holds nothing extractable, or there is no
    /// transcript to read — so the next `Stop` starts its read at the *latest*
    /// assistant turn (skipping this one), and `handle_stop` always allows the
    /// stop, so no later `Stop` re-reads this turn.
    async fn record_last_assistant_message(&self, event: &StopEvent, message: &str) {
        // `truncate_event_text` borrows when the message already fits and only
        // allocates the shortened copy when it must. Do not replace it with
        // `cap_string`, which would copy the whole payload before truncating.
        let body = truncate_event_text(message, MAX_EVENT_TEXT_BYTES);
        if matches!(body, std::borrow::Cow::Owned(_)) {
            warn!(
                original_bytes = message.len(),
                cap_bytes = MAX_EVENT_TEXT_BYTES,
                session_id = event.session_id.as_str(),
                "Truncated Stop last_assistant_message to fit gRPC message limit"
            );
        }
        let ev = self.event(
            &event.session_id,
            TrajectoryEvent::Observation(Observation::Prompt(Prompt::assistant(body.as_ref()))),
        );
        // Bound this the same way the batch path is bounded. Without it the call
        // relies only on the outer 30s hook timeout, which is mostly spent by the
        // time we reach the fallback (connect + the catch-up wait); if the harness
        // is slow, that outer timeout would drop the call mid-flight and lose the
        // message with no trace. On timeout or error we warn and allow the stop
        // (the message is lost, but it is never dropped silently).
        match tokio::time::timeout(STOP_TRANSCRIPT_ADJUDICATE_TIMEOUT, self.adjudicate(ev)).await {
            Ok(Ok(adjudicated)) => warn_stop_policy_finding(&adjudicated),
            Ok(Err(err)) => warn!(
                session_id = event.session_id.as_str(),
                "Failed to adjudicate Stop fallback message; final message not recorded: {err}"
            ),
            Err(_) => warn!(
                session_id = event.session_id.as_str(),
                timeout_ms = STOP_TRANSCRIPT_ADJUDICATE_TIMEOUT.as_millis() as u64,
                "Timed out adjudicating Stop fallback message; final message not recorded"
            ),
        }
    }

    /// Resolve the Stop read offset and read new assistant events from it in one
    /// step, for callers that don't first wait for a specific reply to land.
    /// `handle_stop` uses this only when the Stop payload carries no
    /// `last_assistant_message` to wait on; otherwise it drives
    /// [`resolve_stop_read_plan`] and [`Self::read_stop_events_from`] separately so
    /// the catch-up check and the read share a single offset.
    fn extract_transcript_events(
        &self,
        session_id: &str,
        transcript_path: &str,
    ) -> Result<Vec<PendingTranscriptEvent>> {
        use super::transcript;

        match resolve_stop_read_plan(session_id, transcript_path)? {
            StopReadPlan::NoAssistantTurn { transcript_len } => {
                transcript::write_cursor(session_id, transcript_len)?;
                transcript::remove_retry_cursor(session_id);
                info!(
                    session_id,
                    transcript_path,
                    transcript_len,
                    "Set missing Claude transcript cursor to EOF for transcript with no assistant events"
                );
                Ok(Vec::new())
            }
            StopReadPlan::ReadFrom { cursor } => {
                self.read_stop_events_from(session_id, transcript_path, cursor)
            }
        }
    }

    /// Parse new assistant messages from the transcript starting at the
    /// already-resolved `cursor`, build trajectory events, and return the cursor
    /// offsets that are safe to commit once those events have been adjudicated.
    ///
    /// On an empty read the stored cursor is advanced past any skipped lines and
    /// the retry cursor is cleared, so the caller records nothing. The offset is
    /// passed in (not resolved here) so the wait's catch-up check and this read
    /// operate on the same span — see [`resolve_stop_read_plan`].
    fn read_stop_events_from(
        &self,
        session_id: &str,
        transcript_path: &str,
        cursor: u64,
    ) -> Result<Vec<PendingTranscriptEvent>> {
        use super::transcript;

        let (extracted, new_cursor) = transcript::parse_transcript(transcript_path, cursor)?;

        if extracted.is_empty() {
            if new_cursor != cursor {
                transcript::write_cursor(session_id, new_cursor)?;
            }
            transcript::remove_retry_cursor(session_id);
            return Ok(vec![]);
        }

        let events = extracted
            .into_iter()
            .map(|e| PendingTranscriptEvent {
                event: self.event(session_id, e.event).with_timestamp(e.timestamp),
                cursor_start: cursor,
                cursor_after_line: e.cursor_after_line,
            })
            .collect();

        Ok(events)
    }

    async fn adjudicate_stop_transcript_events(
        &self,
        session_id: &str,
        events: Vec<PendingTranscriptEvent>,
    ) -> Result<()> {
        let retry_cursor = events.first().map(|event| event.cursor_start);
        let Some(cursor_after_line) = events.last().map(|event| event.cursor_after_line) else {
            return Ok(());
        };

        let adjudicate = async {
            // Use bounded batches: the transport batch RPC avoids one
            // round-trip per event, while the cap prevents a retry tail from
            // becoming one unbounded gRPC request/response.
            let mut batch = Vec::with_capacity(STOP_TRANSCRIPT_ADJUDICATE_BATCH_SIZE);
            for pending in events {
                batch.push(pending.event);
                if batch.len() == STOP_TRANSCRIPT_ADJUDICATE_BATCH_SIZE {
                    for adjudicated in self
                        .adjudicate_stop_batch(std::mem::take(&mut batch))
                        .await?
                    {
                        warn_stop_policy_finding(&adjudicated);
                    }
                }
            }
            if !batch.is_empty() {
                for adjudicated in self.adjudicate_stop_batch(batch).await? {
                    warn_stop_policy_finding(&adjudicated);
                }
            }
            Ok::<(), HarnessClientError>(())
        };

        match tokio::time::timeout(STOP_TRANSCRIPT_ADJUDICATE_TIMEOUT, adjudicate).await {
            Ok(Ok(())) => {
                super::transcript::write_cursor(session_id, cursor_after_line)?;
                super::transcript::remove_retry_cursor(session_id);
            }
            Ok(Err(err)) => {
                if let Some(retry_cursor) = retry_cursor
                    && let Err(cursor_err) =
                        super::transcript::write_retry_cursor(session_id, retry_cursor)
                {
                    warn!(
                        "Failed to persist Stop transcript retry cursor after adjudication error: {cursor_err}"
                    );
                }
                warn!(
                    "Stop transcript adjudication failed; allowing Stop and leaving cursor retryable: {err}"
                );
            }
            Err(_) => {
                if let Some(retry_cursor) = retry_cursor
                    && let Err(cursor_err) =
                        super::transcript::write_retry_cursor(session_id, retry_cursor)
                {
                    warn!(
                        "Failed to persist Stop transcript retry cursor after adjudication timeout: {cursor_err}"
                    );
                }
                warn!(
                    timeout_ms = STOP_TRANSCRIPT_ADJUDICATE_TIMEOUT.as_millis() as u64,
                    "Stop transcript adjudication timed out; allowing Stop and leaving cursor retryable"
                );
            }
        }

        Ok(())
    }

    /// Handle subagentStart hook
    pub async fn handle_subagent_start(
        &mut self,
        event: SubagentStartEvent,
    ) -> Result<HookResponse> {
        info!(
            "Processing subagent start (session: {}, agent_id: {}, agent_type: {})",
            event.session_id, event.agent_id, event.agent_type
        );

        // Record the subagent start as a Control::Started event for the subagent.
        // Use agent_type (not agent_id) to derive a human-readable, deduplicated identity.
        let subagent = self.subagent(&event.agent_type);
        let started = TrajectoryEvent::Control(Control::Started(Started::new(subagent.clone())));

        let ev = Event::new(subagent, &event.session_id, started);

        let adjudicated = self.adjudicate(ev).await?;
        warn_unenforceable_decision("non-blocking hook", &adjudicated);

        // SubagentStart hooks cannot block subagent creation, but can inject context
        Ok(HookResponse::allow())
    }

    /// Handle subagentStop hook
    pub async fn handle_subagent_stop(&mut self, event: SubagentStopEvent) -> Result<HookResponse> {
        info!(
            "Processing subagent stop (session: {}, agent_id: {}, agent_type: {}, stop_hook_active: {})",
            event.session_id, event.agent_id, event.agent_type, event.stop_hook_active
        );

        if event.stop_hook_active {
            info!("Subagent stop hook is already active. Allowing stop to prevent infinite loop");
            return Ok(HookResponse::allow());
        }

        // Emit Control::Completed for the subagent to match the Control::Started from SubagentStart.
        // agent_type is optional on stop events (#[serde(default)]), so fall back to agent_id
        // to avoid emitting a broken "{parent}/" identity.
        let subagent_key = if event.agent_type.is_empty() {
            &event.agent_id
        } else {
            &event.agent_type
        };
        let subagent = self.subagent(subagent_key);
        let completed = TrajectoryEvent::Control(Control::Completed(Completed::new()));

        let ev = Event::new(subagent, &event.session_id, completed);

        let adjudicated = self.adjudicate(ev).await?;
        if let Some(response) = lifecycle_block_response(
            &adjudicated,
            "Subagent stop blocked by policy",
            "Subagent stop escalated for review",
            HookResponse::subagent_stop_block,
        ) {
            warn!(
                "Subagent stop blocked: {}",
                response.reason.as_deref().unwrap_or("blocked by policy")
            );
            return Ok(response);
        }

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // Team hooks (TeammateIdle, TaskCompleted)
    // ============================================================================

    /// Handle teammateIdle hook
    ///
    /// This fires when an agent team teammate is about to go idle after finishing its turn.
    /// Exit code 2 (blocking error) causes the teammate to receive feedback and continue working.
    pub async fn handle_teammate_idle(&mut self, event: TeammateIdleEvent) -> Result<HookResponse> {
        info!(
            "Processing teammate idle (session: {}, teammate: {}, team: {})",
            event.session_id, event.teammate_name, event.team_name
        );

        let teammate = self.subagent(&event.teammate_name);
        let suspended = TrajectoryEvent::Control(Control::Suspended(
            sondera_harness_client::Suspended::new("teammate idle"),
        ));

        let ev = Event::new(teammate, &event.session_id, suspended);

        let adjudicated = self.adjudicate(ev).await?;
        if let Some(response) = lifecycle_block_response(
            &adjudicated,
            "Teammate idle blocked by policy",
            "Teammate idle escalated for review",
            HookResponse::stop,
        ) {
            warn!(
                "Teammate idle blocked: {}",
                lifecycle_response_reason(&response)
            );
            return Ok(response);
        }

        Ok(HookResponse::allow())
    }

    /// Handle taskCompleted hook
    ///
    /// This fires when a task is being marked as completed. Exit code 2 blocks
    /// the task from being marked complete and provides feedback to the model.
    pub async fn handle_task_completed(
        &mut self,
        event: TaskCompletedEvent,
    ) -> Result<HookResponse> {
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

        let mut control = Control::Completed(Completed::new().with_summary(&event.task_subject));
        if cap_control_strings(&mut control, MAX_EVENT_TEXT_BYTES) {
            warn!(
                cap_bytes = MAX_EVENT_TEXT_BYTES,
                task_id = event.task_id.as_str(),
                "Truncated taskCompleted summary to fit gRPC message limit"
            );
        }

        let ev = self.event(&event.session_id, TrajectoryEvent::Control(control));

        let adjudicated = self.adjudicate(ev).await?;
        if let Some(response) = lifecycle_block_response(
            &adjudicated,
            "Task completion blocked by policy",
            "Task completion escalated for review",
            HookResponse::stop,
        ) {
            warn!(
                "Task completion blocked: {}",
                lifecycle_response_reason(&response)
            );
            return Ok(response);
        }

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
        let tool_name = event.tool_name.clone();
        let error = event.error.clone();

        info!(
            "Tool '{}' failed with error: {} (session: {})",
            tool_name, error, event.session_id
        );

        // Record the tool failure as an observation
        let mut observation =
            Observation::ToolOutput(ToolOutput::error(&event.tool_use_id, &error));
        if cap_observation_strings(&mut observation, MAX_EVENT_TEXT_BYTES) {
            warn!(
                cap_bytes = MAX_EVENT_TEXT_BYTES,
                tool_name = tool_name.as_str(),
                tool_use_id = event.tool_use_id.as_str(),
                "Truncated postToolUseFailure error to fit gRPC message limit"
            );
        }

        let ev = self.event(&event.session_id, TrajectoryEvent::Observation(observation));

        let adjudicated = self.adjudicate(ev).await?;
        warn_unenforceable_decision("non-blocking hook", &adjudicated);

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // Config change hook
    // ============================================================================

    /// Handle configChange hook.
    ///
    /// When settings change mid-session, record the configuration transition as
    /// a system observation and adjudicate it so policy can react to the change.
    pub async fn handle_config_change(&mut self, event: ConfigChangeEvent) -> Result<HookResponse> {
        info!(
            "Config change detected (session: {}, type: {:?})",
            event.session_id, event.config_type
        );

        let context = format!("Configuration changed ({:?})", event.config_type);

        // Emit a system observation so the harness records the configuration transition.
        let mut observation = Observation::Prompt(Prompt::system(&context));
        if cap_observation_strings(&mut observation, MAX_EVENT_TEXT_BYTES) {
            warn!(
                cap_bytes = MAX_EVENT_TEXT_BYTES,
                session_id = event.session_id.as_str(),
                "Truncated configChange observation to fit gRPC message limit"
            );
        }
        let ev = self
            .event(&event.session_id, TrajectoryEvent::Observation(observation))
            .with_actor(Actor::system(self.platform.as_str()));

        let adjudicated = self.adjudicate(ev).await?;
        if event.config_type == ConfigChangeType::PolicySettings {
            warn_unenforceable_decision(
                "policy_settings config changes cannot be blocked by Claude",
                &adjudicated,
            );
            return Ok(HookResponse::allow().with_system_message(context));
        }

        if let Some(response) = lifecycle_block_response(
            &adjudicated,
            "Configuration change blocked by policy",
            "Configuration change escalated for review",
            HookResponse::block,
        ) {
            warn!(
                "Configuration change blocked: {}",
                response.reason.as_deref().unwrap_or("blocked by policy")
            );
            return Ok(response);
        }

        Ok(HookResponse::allow().with_system_message(context))
    }

    // ============================================================================
    // Instructions loaded hook
    // ============================================================================

    /// Handle instructionsLoaded hook.
    ///
    /// Fires when CLAUDE.md or `.claude/rules/*.md` files are loaded. These
    /// instructions constrain agent behavior and may affect Cedar policy scope.
    pub fn handle_instructions_loaded(
        &self,
        event: InstructionsLoadedEvent,
    ) -> Result<HookResponse> {
        info!(
            "Instructions loaded (session: {}, file: {}, type: {}, reason: {})",
            event.session_id, event.file_path, event.memory_type, event.load_reason
        );

        Ok(HookResponse::allow())
    }

    /// Handle worktreeRemove hook.
    pub fn handle_worktree_remove(&self, event: WorktreeRemoveEvent) -> Result<HookResponse> {
        info!(
            "Worktree removed (session: {}, path: {})",
            event.session_id, event.worktree_path
        );

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // Pre-compact hook
    // ============================================================================

    /// Handle preCompact hook
    pub async fn handle_pre_compact(&mut self, event: PreCompactEvent) -> Result<HookResponse> {
        let trigger = event.trigger;
        let session_id = &event.session_id;
        let custom_instructions = &event.custom_instructions;

        info!(?trigger, %session_id, "Processing pre-compact event");

        match trigger {
            CompactTrigger::Auto => {
                info!("Auto-compaction triggered");
            }
            CompactTrigger::Manual => {
                info!(
                    instruction_bytes = custom_instructions.len(),
                    "Manual compaction requested"
                );
            }
            CompactTrigger::Unknown => {
                warn!("Unknown compaction trigger received");
            }
        }

        let context = format!(
            "Compaction requested ({trigger:?}){}",
            if custom_instructions.is_empty() {
                String::new()
            } else {
                format!(" with instructions: {custom_instructions}")
            }
        );
        let mut observation = Observation::Prompt(Prompt::system(&context));
        if cap_observation_strings(&mut observation, MAX_EVENT_TEXT_BYTES) {
            warn!(
                cap_bytes = MAX_EVENT_TEXT_BYTES,
                session_id = event.session_id.as_str(),
                "Truncated preCompact observation to fit gRPC message limit"
            );
        }

        let ev = self
            .event(&event.session_id, TrajectoryEvent::Observation(observation))
            .with_actor(Actor::system(self.platform.as_str()));

        let adjudicated = self.adjudicate(ev).await?;
        if let Some(response) = lifecycle_block_response(
            &adjudicated,
            "Compaction blocked by policy",
            "Compaction escalated for review",
            HookResponse::block,
        ) {
            warn!(
                "Compaction blocked: {}",
                response.reason.as_deref().unwrap_or("blocked by policy")
            );
            return Ok(response);
        }

        Ok(HookResponse::allow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::{BlockDecision, HookSpecificOutput};
    use serde_json::json;
    use std::collections::VecDeque;
    use std::io::Write;
    use std::sync::Mutex;

    fn to_json(response: &HookResponse) -> String {
        serde_json::to_string(response).unwrap()
    }

    struct HandlerHarness {
        responses: Mutex<VecDeque<std::result::Result<Adjudicated, HarnessClientError>>>,
        adjudicated_events: Mutex<Vec<Event>>,
        adjudication_batches: Mutex<Vec<usize>>,
    }

    impl HandlerHarness {
        fn new(responses: Vec<std::result::Result<Adjudicated, HarnessClientError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                adjudicated_events: Mutex::new(Vec::new()),
                adjudication_batches: Mutex::new(Vec::new()),
            }
        }

        fn with_adjudicated_events<R>(&self, f: impl FnOnce(&[Event]) -> R) -> R {
            let events = self.adjudicated_events.lock().unwrap();
            f(&events)
        }

        fn with_adjudication_batches<R>(&self, f: impl FnOnce(&[usize]) -> R) -> R {
            let batches = self.adjudication_batches.lock().unwrap();
            f(&batches)
        }
    }

    impl HarnessClient for HandlerHarness {
        async fn adjudicate(
            &self,
            event: Event,
        ) -> std::result::Result<Adjudicated, HarnessClientError> {
            let mut results = self.adjudicates(vec![event]).await?;
            results
                .pop()
                .ok_or_else(|| HarnessClientError::Decode("empty adjudicates response".into()))
        }

        async fn adjudicates(
            &self,
            events: Vec<Event>,
        ) -> std::result::Result<Vec<Adjudicated>, HarnessClientError> {
            self.adjudication_batches.lock().unwrap().push(events.len());
            let mut results = Vec::with_capacity(events.len());
            let mut responses = self.responses.lock().unwrap();
            let mut adjudicated_events = self.adjudicated_events.lock().unwrap();
            for event in events {
                adjudicated_events.push(event);
                results.push(
                    responses
                        .pop_front()
                        .expect("scripted adjudication response")?,
                );
            }
            Ok(results)
        }
    }

    fn handler_agent() -> Agent {
        Agent {
            id: "agent-handler-test".to_string(),
            provider: "anthropic".to_string(),
            platform: "claude-code".to_string(),
        }
    }

    fn hooks_with_decision(decision: Adjudicated) -> Hooks<HandlerHarness> {
        stop_hooks(vec![Ok(decision)], STOP_TRANSCRIPT_CATCHUP_TIMEOUT)
    }

    /// A `ClaudeCode` `Hooks` whose harness replays `responses`, one per
    /// adjudicated event. `stop_catchup_timeout` bounds `handle_stop`'s wait for
    /// the transcript write: timeout-path tests pass a small value so they don't
    /// sit for the full production timeout.
    fn stop_hooks(
        responses: Vec<std::result::Result<Adjudicated, HarnessClientError>>,
        stop_catchup_timeout: Duration,
    ) -> Hooks<HandlerHarness> {
        let mut hooks = Hooks::new(
            HandlerHarness::new(responses),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );
        hooks.stop_catchup_timeout = stop_catchup_timeout;
        hooks
    }

    #[test]
    fn session_start_records_started_event_without_returning_model_context() {
        let project_root = tempfile::tempdir().expect("temp project root");
        std::fs::create_dir_all(project_root.path().join(".claude"))
            .expect("create claude settings dir");

        let session_id = unique_session_id("session-start-no-context");
        let start_event = SessionStartEvent {
            session_id: session_id.clone(),
            transcript_path: String::new(),
            cwd: project_root.path().display().to_string(),
            permission_mode: PermissionMode::Default,
            hook_event_name: "SessionStart".to_string(),
            source: SessionStartSource::Startup,
            model: Some("claude-sonnet-4-20250514".to_string()),
        };
        let mut hooks = Hooks::new(
            HandlerHarness::new(vec![Ok(Adjudicated::allow())]),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime");
        let response = runtime
            .block_on(hooks.handle_session_start(start_event))
            .expect("SessionStart should allow");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(adjudicated.len(), 1);
            assert_eq!(adjudicated[0].trajectory_id, session_id);
            match &adjudicated[0].event {
                TrajectoryEvent::Control(Control::Started(started)) => {
                    assert_eq!(started.agent.platform, "claude-code");
                }
                other => panic!("expected started event, got {other:?}"),
            }
        });
    }

    fn assert_block(response: HookResponse, expected_reason: &str) {
        let value = serde_json::to_value(response).expect("serialize response");
        assert_eq!(value["decision"], "block");
        assert!(
            value["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains(expected_reason)),
            "unexpected block response: {value}"
        );
    }

    fn assert_stop(response: HookResponse, expected_reason: &str) {
        let value = serde_json::to_value(response).expect("serialize response");
        assert_eq!(value["continue"], false);
        assert!(
            value["decision"].is_null(),
            "unexpected decision field: {value}"
        );
        assert!(
            value["stopReason"]
                .as_str()
                .is_some_and(|reason| reason.contains(expected_reason)),
            "unexpected stop response: {value}"
        );
    }

    fn unique_session_id(prefix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        format!("{prefix}-{}-{nanos}", std::process::id())
    }

    fn assistant_transcript_line(ts: &str, uuid: &str, text: &str) -> String {
        format!(
            r#"{{"type":"assistant","timestamp":"{ts}","uuid":"{uuid}","message":{{"role":"assistant","content":[{{"type":"text","text":"{text}"}}]}}}}"#
        )
    }

    fn assistant_thinking_transcript_line(ts: &str, uuid: &str, thinking: &str) -> String {
        format!(
            r#"{{"type":"assistant","timestamp":"{ts}","uuid":"{uuid}","message":{{"role":"assistant","content":[{{"type":"thinking","thinking":"{thinking}"}}]}}}}"#
        )
    }

    fn user_transcript_line(ts: &str, uuid: &str, text: &str) -> String {
        format!(
            r#"{{"type":"user","timestamp":"{ts}","uuid":"{uuid}","message":{{"role":"user","content":"{text}"}}}}"#
        )
    }

    fn write_transcript(dir: &std::path::Path, lines: &[String]) -> String {
        let path = dir.join("transcript.jsonl");
        let mut file = std::fs::File::create(&path).expect("create transcript");
        for line in lines {
            writeln!(file, "{line}").expect("write transcript line");
        }
        path.to_string_lossy().into_owned()
    }

    /// Append one JSONL line to an existing transcript, mimicking Claude Code
    /// writing a turn's reply after the Stop hook has already fired.
    fn append_transcript_line(path: &str, line: &str) {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open transcript for append");
        writeln!(file, "{line}").expect("append transcript line");
    }

    /// A `StopEvent` with the fields the Stop tests always hold constant; only
    /// the session, transcript path, and payload message vary.
    fn stop_event(
        session_id: &str,
        transcript_path: &str,
        last_assistant_message: Option<&str>,
    ) -> StopEvent {
        StopEvent {
            session_id: session_id.to_string(),
            transcript_path: transcript_path.to_string(),
            cwd: "/tmp".to_string(),
            permission_mode: PermissionMode::Default,
            hook_event_name: "Stop".to_string(),
            stop_hook_active: false,
            last_assistant_message: last_assistant_message.map(str::to_string),
        }
    }

    fn session_end_event(session_id: &str) -> SessionEndEvent {
        SessionEndEvent {
            session_id: session_id.to_string(),
            transcript_path: String::new(),
            cwd: String::new(),
            permission_mode: PermissionMode::Default,
            hook_event_name: "SessionEnd".to_string(),
            reason: SessionEndReason::Other,
        }
    }

    fn session_end_event_with_reason(
        session_id: &str,
        reason: SessionEndReason,
    ) -> SessionEndEvent {
        SessionEndEvent {
            reason,
            ..session_end_event(session_id)
        }
    }

    async fn assert_post_tool_use_timeout_blocks_with_redacted_output_without_doctor_steer() {
        let mut hooks = Hooks::new(
            HandlerHarness::new(vec![Err(HarnessClientError::Timeout)]),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );
        let response = hooks
            .handle_post_tool_use(PostToolUseEvent {
                session_id: unique_session_id("post-tool-timeout"),
                transcript_path: String::new(),
                cwd: "/tmp".to_string(),
                permission_mode: PermissionMode::Default,
                hook_event_name: "PostToolUse".to_string(),
                tool_name: "Bash".to_string(),
                tool_input: json!({"command": "cat secret.txt"}),
                tool_response: json!({
                    "stdout": "secret output",
                    "stderr": "secret error",
                    "interrupted": true,
                }),
                tool_use_id: "toolu_timeout".to_string(),
            })
            .await
            .expect("post-tool timeout should fail closed");

        assert_eq!(response.decision, Some(BlockDecision::Block));
        let reason = response.reason.as_deref().expect("block reason");
        assert!(
            reason.contains("timed out"),
            "timeout reason should name timeout cause: {reason}"
        );
        assert!(
            reason.contains("latency/load"),
            "timeout reason should point at latency/load: {reason}"
        );
        assert!(
            !reason.contains("sondera serve"),
            "timeout reason must not steer toward doctor: {reason}"
        );
        assert!(
            !reason.contains("connectivity"),
            "timeout reason must not steer toward connectivity: {reason}"
        );

        match response.hook_specific_output.as_ref() {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                let updated = output
                    .updated_tool_output
                    .as_ref()
                    .expect("post-tool timeout should replace tool output");
                assert_eq!(
                    updated["stdout"],
                    "Output withheld by Sondera policy. See hook block reason."
                );
                assert_eq!(updated["interrupted"], false);
            }
            other => panic!("expected PostToolUse block output, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn session_end_preserves_transcript_cursor_for_resume() {
        let session_id = unique_session_id("session-end-cursor");
        super::super::transcript::write_cursor(&session_id, 42).expect("write cursor");

        let mut hooks = Hooks::new(
            HandlerHarness::new(vec![]),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );
        let _ = hooks
            .handle_session_end(session_end_event_with_reason(
                &session_id,
                SessionEndReason::PromptInputExit,
            ))
            .await
            .expect("session end should allow");

        assert_eq!(
            super::super::transcript::read_cursor(&session_id),
            42,
            "SessionEnd must not delete the transcript cursor; Claude resume reuses the transcript"
        );
        super::super::transcript::remove_cursor(&session_id);
    }

    #[tokio::test]
    async fn resumable_session_end_does_not_terminalize_trajectory() {
        for reason in [SessionEndReason::PromptInputExit, SessionEndReason::Other] {
            let session_id = unique_session_id("session-end-resumable");
            let mut hooks = Hooks::new(
                HandlerHarness::new(vec![]),
                handler_agent(),
                HookPlatform::ClaudeCode,
            );

            let response = hooks
                .handle_session_end(session_end_event_with_reason(&session_id, reason))
                .await
                .expect("resumable session end should allow");

            assert_eq!(to_json(&response), "{}");
            hooks.harness.with_adjudicated_events(|events| {
                assert!(
                    events.is_empty(),
                    "{reason:?} must not emit terminal lifecycle events for a resumable session: {events:?}"
                );
            });
        }
    }

    #[tokio::test]
    async fn terminal_session_end_reasons_emit_terminated_not_completed() {
        let cases = [
            (SessionEndReason::Clear, "session cleared", "user"),
            (SessionEndReason::Logout, "user logged out", "user"),
            (
                SessionEndReason::BypassPermissionsDisabled,
                "bypass permissions disabled",
                "system",
            ),
        ];

        for (reason, expected_reason, expected_actor) in cases {
            let session_id = unique_session_id("session-end-terminal");
            let mut hooks = hooks_with_decision(Adjudicated::allow());

            let response = hooks
                .handle_session_end(session_end_event_with_reason(&session_id, reason))
                .await
                .expect("terminal session end should allow");

            assert_eq!(to_json(&response), "{}");
            hooks.harness.with_adjudicated_events(|events| {
                assert_eq!(events.len(), 1);
                match &events[0].event {
                    TrajectoryEvent::Control(Control::Terminated(terminated)) => {
                        assert_eq!(terminated.reason, expected_reason);
                        assert_eq!(terminated.terminated_by, expected_actor);
                    }
                    other => panic!(
                        "{reason:?} must terminate without marking completed, got: {other:?}"
                    ),
                }
            });
        }
    }

    #[tokio::test]
    async fn stop_adjudicates_only_latest_assistant_tail_when_cursor_is_zero() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-latest-tail-only");
        super::super::transcript::remove_cursor(&session_id);
        super::super::transcript::write_cursor(&session_id, 0).expect("write stepped-on cursor");

        let old = assistant_transcript_line("2026-02-11T19:08:42.000Z", "uuid-old", "old answer");
        // A real transcript separates distinct assistant responses with a user
        // line (prompt or tool_result); without it the two would be one turn.
        let between = user_transcript_line("2026-02-11T19:08:42.500Z", "uuid-user", "next");
        let current =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-current", "final answer");
        let path = write_transcript(dir.path(), &[old, between, current]);
        let final_cursor = std::fs::metadata(&path).expect("transcript metadata").len();
        let mut hooks = Hooks::new(
            HandlerHarness::new(vec![Ok(Adjudicated::allow())]),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, None))
            .await
            .expect("Stop should allow after tail adjudication");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                1,
                "Stop must adjudicate only the latest assistant tail, not replay the full transcript"
            );
            match &adjudicated[0].event {
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                    assert_eq!(prompt.content, "final answer");
                }
                other => panic!("expected assistant prompt event, got {other:?}"),
            }
        });
        assert_eq!(
            super::super::transcript::read_cursor(&session_id),
            final_cursor,
            "Stop should commit the cursor after the latest assistant tail is adjudicated"
        );

        super::super::transcript::remove_cursor(&session_id);
    }

    #[tokio::test]
    async fn stop_captures_thoughts_when_final_turn_splits_thinking_and_text() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-final-turn-thoughts");
        super::super::transcript::remove_cursor(&session_id);

        // Claude Code writes the final turn's thinking and text as separate
        // JSONL lines. Seeding to the turn start (not the last line) must keep
        // the thought, so Stop records both the thought and the assistant text.
        let prior = user_transcript_line("2026-02-11T19:08:41.000Z", "uuid-user", "go");
        let thinking =
            assistant_thinking_transcript_line("2026-02-11T19:08:42.000Z", "uuid-think", "reason");
        let answer =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-text", "final answer");
        let path = write_transcript(dir.path(), &[prior, thinking, answer]);

        let mut hooks = Hooks::new(
            HandlerHarness::new(vec![Ok(Adjudicated::allow()), Ok(Adjudicated::allow())]),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, None))
            .await
            .expect("Stop should allow after tail adjudication");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                2,
                "Stop must capture the final turn's thought and its assistant text"
            );
            match &adjudicated[0].event {
                TrajectoryEvent::Observation(Observation::Thought(t)) => {
                    assert_eq!(t.thought, "reason");
                }
                other => panic!("expected leading Thought event, got {other:?}"),
            }
            match &adjudicated[1].event {
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                    assert_eq!(prompt.content, "final answer");
                }
                other => panic!("expected assistant prompt event, got {other:?}"),
            }
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    // ------------------------------------------------------------------------
    // Stop wait-then-read timing and race tests.
    //
    // Each test drives `handle_stop` with a scripted harness and a temp
    // transcript. Timeout-path tests pass a small `stop_catchup_timeout` so they
    // don't sit for the full 2s production wait; catch-up-path tests keep a
    // small timeout purely as a guard so a fixture mistake fails fast instead of
    // hanging.
    // ------------------------------------------------------------------------

    /// The common case: the reply is already on disk when Stop fires. We read
    /// the transcript (thought + reply) and record the final message exactly
    /// once — never an extra copy from the payload.
    #[tokio::test]
    async fn stop_records_final_message_once_when_transcript_already_current() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-already-current");
        super::super::transcript::remove_cursor(&session_id);

        let prior = user_transcript_line("2026-02-11T19:08:41.000Z", "uuid-user", "go");
        let thinking =
            assistant_thinking_transcript_line("2026-02-11T19:08:42.000Z", "uuid-think", "reason");
        let answer =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-text", "final answer");
        let path = write_transcript(dir.path(), &[prior, thinking, answer]);

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow()), Ok(Adjudicated::allow())],
            std::time::Duration::from_millis(200),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, Some("final answer")))
            .await
            .expect("Stop should allow");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                2,
                "final message must be recorded once (transcript read), not duplicated by the payload"
            );
            assert!(matches!(
                &adjudicated[0].event,
                TrajectoryEvent::Observation(Observation::Thought(t)) if t.thought == "reason"
            ));
            match &adjudicated[1].event {
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                    assert_eq!(prompt.content, "final answer");
                }
                other => panic!("expected assistant prompt event, got {other:?}"),
            }
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    /// The write lands while we're waiting: `handle_stop` must block until the
    /// reply appears, then read it — not read stale content and return early.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_waits_for_write_that_lands_mid_wait() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-write-mid-wait");
        super::super::transcript::remove_cursor(&session_id);

        // At Stop-fire time the transcript has only the prompt — the assistant
        // reply has not been written yet.
        let prior = user_transcript_line("2026-02-11T19:08:41.000Z", "uuid-user", "go");
        let path = write_transcript(dir.path(), &[prior]);

        let answer =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-text", "final answer");
        let append_path = path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            append_transcript_line(&append_path, &answer);
        });

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow())],
            std::time::Duration::from_secs(2),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, Some("final answer")))
            .await
            .expect("Stop should allow");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(adjudicated.len(), 1, "must read the reply once it lands");
            match &adjudicated[0].event {
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                    assert_eq!(prompt.content, "final answer");
                }
                other => panic!("expected assistant prompt event, got {other:?}"),
            }
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    /// The transcript never catches up before the wait times out: we warn and
    /// fall back to the payload's final message. That records the reply but drops
    /// the turn's thinking — the accepted degraded path.
    #[tokio::test]
    async fn stop_falls_back_to_payload_when_transcript_never_catches_up() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-timeout-fallback");
        super::super::transcript::remove_cursor(&session_id);

        // The transcript holds a thought and a *different* reply than the
        // payload, so the catch-up check never matches.
        let prior = user_transcript_line("2026-02-11T19:08:41.000Z", "uuid-user", "go");
        let thinking =
            assistant_thinking_transcript_line("2026-02-11T19:08:42.000Z", "uuid-think", "reason");
        let stale =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-text", "stale reply");
        let path = write_transcript(dir.path(), &[prior, thinking, stale]);

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow())],
            std::time::Duration::from_millis(30),
        );
        let response = hooks
            .handle_stop(stop_event(
                &session_id,
                &path,
                Some("the reply the user saw"),
            ))
            .await
            .expect("Stop should allow via fallback");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                1,
                "fallback records only the payload message (no transcript thought)"
            );
            match &adjudicated[0].event {
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                    assert_eq!(prompt.content, "the reply the user saw");
                }
                other => panic!("expected payload assistant prompt event, got {other:?}"),
            }
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    /// A turn's thinking line is flushed before its text line. A lone thought is
    /// not a match, so we keep waiting; once the text lands we read both.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_waits_when_only_thinking_written_then_reads_both() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-thinking-first");
        super::super::transcript::remove_cursor(&session_id);

        let prior = user_transcript_line("2026-02-11T19:08:41.000Z", "uuid-user", "go");
        let thinking =
            assistant_thinking_transcript_line("2026-02-11T19:08:42.000Z", "uuid-think", "reason");
        let path = write_transcript(dir.path(), &[prior, thinking]);

        let answer =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-text", "final answer");
        let append_path = path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            append_transcript_line(&append_path, &answer);
        });

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow()), Ok(Adjudicated::allow())],
            std::time::Duration::from_secs(2),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, Some("final answer")))
            .await
            .expect("Stop should allow");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                2,
                "once the text lands we read the whole turn: thought + reply"
            );
            assert!(matches!(
                &adjudicated[0].event,
                TrajectoryEvent::Observation(Observation::Thought(t)) if t.thought == "reason"
            ));
            assert!(matches!(
                &adjudicated[1].event,
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) if prompt.content == "final answer"
            ));
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    /// A reply identical to an earlier turn's ("Done." twice): the earlier copy
    /// sits *behind* the cursor, so it must not satisfy the check. We wait for
    /// the new copy to be written past the cursor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_waits_past_identical_earlier_reply_behind_cursor() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-repeated-reply");
        super::super::transcript::remove_cursor(&session_id);

        // Turn A already recorded: an assistant "Done." followed by the next
        // prompt. Park the cursor at EOF so turn A's "Done." is behind it.
        let turn_a = assistant_transcript_line("2026-02-11T19:08:41.000Z", "uuid-a", "Done.");
        let between = user_transcript_line("2026-02-11T19:08:42.000Z", "uuid-user", "again");
        let path = write_transcript(dir.path(), &[turn_a, between]);
        let cursor_at_eof = std::fs::metadata(&path).expect("metadata").len();
        super::super::transcript::write_cursor(&session_id, cursor_at_eof).expect("write cursor");

        // Turn B's identical "Done." is written mid-wait.
        let turn_b = assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-b", "Done.");
        let append_path = path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            append_transcript_line(&append_path, &turn_b);
        });

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow())],
            std::time::Duration::from_secs(2),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, Some("Done.")))
            .await
            .expect("Stop should allow");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                1,
                "must record only turn B's new reply, not re-match the behind-cursor copy"
            );
            match &adjudicated[0].event {
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                    assert_eq!(prompt.content, "Done.");
                }
                other => panic!("expected assistant prompt event, got {other:?}"),
            }
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    /// The catch-up check and the read must start from the same offset. A retry
    /// cursor set before an earlier turn wins offset resolution, so the read must
    /// begin there too — re-emitting the earlier turn (retry semantics), not
    /// silently skipping forward and dropping it.
    #[tokio::test]
    async fn stop_check_and_read_share_offset_under_retry_cursor() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-offset-consistency");
        super::super::transcript::remove_cursor(&session_id);

        let first =
            assistant_transcript_line("2026-02-11T19:08:41.000Z", "uuid-first", "first reply");
        let between = user_transcript_line("2026-02-11T19:08:42.000Z", "uuid-user", "again");
        let second =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-second", "second reply");
        let path = write_transcript(dir.path(), &[first, between, second]);

        // A prior batch failed at offset 0, so both turns should be re-read.
        super::super::transcript::write_retry_cursor(&session_id, 0).expect("write retry cursor");

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow()), Ok(Adjudicated::allow())],
            std::time::Duration::from_millis(200),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, Some("second reply")))
            .await
            .expect("Stop should allow");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                2,
                "read must start at the retry cursor the check validated, re-emitting both turns"
            );
            assert!(matches!(
                &adjudicated[0].event,
                TrajectoryEvent::Observation(Observation::Prompt(p)) if p.content == "first reply"
            ));
            assert!(matches!(
                &adjudicated[1].event,
                TrajectoryEvent::Observation(Observation::Prompt(p)) if p.content == "second reply"
            ));
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    // The truncation-matched compare (an oversized reply still matches because
    // both sides are truncated the same way) is proven precisely and cheaply by
    // `transcript::tests::newest_reply_truncates_like_the_parser`, so it is not
    // repeated as a heavier end-to-end case here.

    /// The concern behind the timeout fallback: after a Stop times out and
    /// records the payload, the *next* Stop must not re-read that turn from the
    /// transcript. Its next read starts at the latest turn, which skips the
    /// earlier one, so the timed-out turn is recorded exactly once overall.
    #[tokio::test]
    async fn stop_timeout_fallback_not_double_recorded_on_next_stop() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-fallback-no-dup");
        super::super::transcript::remove_cursor(&session_id);

        // Stop N: only the prompt is on disk, so the wait times out and we fall
        // back to recording turn N's payload reply directly.
        let prior = user_transcript_line("2026-02-11T19:08:41.000Z", "uuid-user", "go");
        let path = write_transcript(dir.path(), &[prior]);

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow()), Ok(Adjudicated::allow())],
            std::time::Duration::from_millis(30),
        );
        let _ = hooks
            .handle_stop(stop_event(&session_id, &path, Some("answer N")))
            .await
            .expect("Stop N should allow via fallback");

        // Turn N's text lands late, then turn N+1 completes.
        append_transcript_line(
            &path,
            &assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-n", "answer N"),
        );
        append_transcript_line(
            &path,
            &user_transcript_line("2026-02-11T19:08:44.000Z", "uuid-user2", "next"),
        );
        append_transcript_line(
            &path,
            &assistant_transcript_line("2026-02-11T19:08:45.000Z", "uuid-n1", "answer N plus one"),
        );

        let _ = hooks
            .handle_stop(stop_event(&session_id, &path, Some("answer N plus one")))
            .await
            .expect("Stop N+1 should allow");

        hooks.harness.with_adjudicated_events(|adjudicated| {
            let contents: Vec<&str> = adjudicated
                .iter()
                .filter_map(|e| match &e.event {
                    TrajectoryEvent::Observation(Observation::Prompt(p)) => Some(p.content.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                contents,
                vec!["answer N", "answer N plus one"],
                "turn N recorded once (fallback), turn N+1 once; the next Stop must not re-read turn N"
            );
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    /// The transcript stores the reply verbatim while the payload may differ only
    /// in surrounding whitespace (e.g. a trailing newline). That must still catch
    /// up and read the transcript, not fall back — the compare trims both sides.
    #[tokio::test]
    async fn stop_matches_reply_despite_surrounding_whitespace() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-whitespace-match");
        super::super::transcript::remove_cursor(&session_id);

        let prior = user_transcript_line("2026-02-11T19:08:41.000Z", "uuid-user", "go");
        let thinking =
            assistant_thinking_transcript_line("2026-02-11T19:08:42.000Z", "uuid-think", "reason");
        // The transcript block carries trailing spaces the payload lacks.
        let answer =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-text", "final answer   ");
        let path = write_transcript(dir.path(), &[prior, thinking, answer]);

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow()), Ok(Adjudicated::allow())],
            std::time::Duration::from_millis(200),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, Some("final answer")))
            .await
            .expect("Stop should allow");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                2,
                "a whitespace-only difference must still catch up and read the transcript"
            );
            assert!(matches!(
                &adjudicated[0].event,
                TrajectoryEvent::Observation(Observation::Thought(t)) if t.thought == "reason"
            ));
            match &adjudicated[1].event {
                // The transcript's verbatim text (with trailing spaces) is recorded.
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                    assert_eq!(prompt.content, "final answer   ");
                }
                other => panic!("expected assistant prompt event, got {other:?}"),
            }
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    /// With a retry cursor pending, the timeout fallback is skipped: the retry
    /// path will re-read this turn (with its thinking) from the transcript on a
    /// later Stop, so recording the payload now would double-record it.
    #[tokio::test]
    async fn stop_skips_payload_fallback_when_retry_cursor_pending() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-retry-skip-fallback");
        super::super::transcript::remove_cursor(&session_id);

        let old = assistant_transcript_line("2026-02-11T19:08:41.000Z", "uuid-old", "old reply");
        let path = write_transcript(dir.path(), &[old]);
        // A prior adjudication failed and left a retry cursor at the start.
        super::super::transcript::write_retry_cursor(&session_id, 0).expect("write retry cursor");

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow())],
            std::time::Duration::from_millis(30),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, Some("current reply")))
            .await
            .expect("Stop should allow");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                0,
                "fallback must be skipped while a retry cursor is pending so the turn isn't double-recorded"
            );
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    /// If the fallback adjudication errors, the Stop is still allowed and the
    /// failure is logged — never propagated up or dropped silently.
    #[tokio::test]
    async fn stop_fallback_adjudication_error_still_allows() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-fallback-error");
        super::super::transcript::remove_cursor(&session_id);

        // A reply that never matches the payload forces the timeout fallback.
        let stale =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-text", "stale reply");
        let path = write_transcript(dir.path(), &[stale]);

        let mut hooks = stop_hooks(
            vec![Err(HarnessClientError::Server("boom".into()))],
            std::time::Duration::from_millis(30),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, Some("the visible reply")))
            .await
            .expect("Stop should allow even when the fallback adjudication fails");

        assert_eq!(to_json(&response), "{}");

        super::super::transcript::remove_cursor(&session_id);
    }

    /// A Stop with no transcript path but a payload reply must still record the
    /// reply. There is no transcript to read or wait on, so the payload is the
    /// only copy of the turn's final message.
    #[tokio::test]
    async fn stop_records_payload_when_transcript_path_missing() {
        let session_id = unique_session_id("stop-no-transcript-path");
        super::super::transcript::remove_cursor(&session_id);

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow())],
            std::time::Duration::from_millis(30),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, "", Some("standalone reply")))
            .await
            .expect("Stop should allow");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                1,
                "the payload reply must be recorded even without a transcript path"
            );
            match &adjudicated[0].event {
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                    assert_eq!(prompt.content, "standalone reply");
                }
                other => panic!("expected payload assistant prompt event, got {other:?}"),
            }
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    /// A retry cursor pointing into a transcript with no assistant events can
    /// never drain — there is nothing to re-read. The timeout path must clear it,
    /// set the stored cursor to EOF, and record the payload, instead of skipping
    /// the fallback on this and every later Stop.
    #[tokio::test]
    async fn stop_timeout_clears_undrainable_retry_cursor_and_records_payload() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-undrainable-retry");
        super::super::transcript::remove_cursor(&session_id);

        // Only a user line on disk: no assistant events, so the wait can never
        // match and the retry cursor has nothing to recover.
        let prior = user_transcript_line("2026-02-11T19:08:41.000Z", "uuid-user", "go");
        let path = write_transcript(dir.path(), &[prior]);
        let transcript_len = std::fs::metadata(&path).expect("metadata").len();
        super::super::transcript::write_retry_cursor(&session_id, 0).expect("write retry cursor");

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow())],
            std::time::Duration::from_millis(30),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, Some("current reply")))
            .await
            .expect("Stop should allow via fallback");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                1,
                "the payload must be recorded; an undrainable retry cursor must not suppress the fallback"
            );
            match &adjudicated[0].event {
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                    assert_eq!(prompt.content, "current reply");
                }
                other => panic!("expected payload assistant prompt event, got {other:?}"),
            }
        });
        assert_eq!(
            super::super::transcript::read_retry_cursor_if_present(&session_id),
            None,
            "the undrainable retry cursor must be cleared"
        );
        assert_eq!(
            super::super::transcript::read_cursor_if_present(&session_id),
            Some(transcript_len),
            "the stored cursor must be set to EOF so later Stops don't replay"
        );

        super::super::transcript::remove_cursor(&session_id);
    }

    /// A stored cursor pointing past EOF (the transcript was replaced or
    /// truncated) is stale. Offset resolution must fall back to the latest
    /// assistant turn and read the reply that is on disk, not wait behind an
    /// unreachable offset until the timeout fires.
    #[tokio::test]
    async fn stop_reads_transcript_when_stored_cursor_is_past_eof() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-cursor-past-eof");
        super::super::transcript::remove_cursor(&session_id);

        let prior = user_transcript_line("2026-02-11T19:08:41.000Z", "uuid-user", "go");
        let thinking =
            assistant_thinking_transcript_line("2026-02-11T19:08:42.000Z", "uuid-think", "reason");
        let answer =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-text", "final answer");
        let path = write_transcript(dir.path(), &[prior, thinking, answer]);
        let transcript_len = std::fs::metadata(&path).expect("metadata").len();
        super::super::transcript::write_cursor(&session_id, transcript_len + 4096)
            .expect("write stale cursor past EOF");

        let mut hooks = stop_hooks(
            vec![Ok(Adjudicated::allow()), Ok(Adjudicated::allow())],
            std::time::Duration::from_millis(200),
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, Some("final answer")))
            .await
            .expect("Stop should allow");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|adjudicated| {
            assert_eq!(
                adjudicated.len(),
                2,
                "a stale past-EOF cursor must not hide the turn that is on disk"
            );
            assert!(matches!(
                &adjudicated[0].event,
                TrajectoryEvent::Observation(Observation::Thought(t)) if t.thought == "reason"
            ));
            assert!(matches!(
                &adjudicated[1].event,
                TrajectoryEvent::Observation(Observation::Prompt(prompt)) if prompt.content == "final answer"
            ));
        });

        super::super::transcript::remove_cursor(&session_id);
    }

    #[tokio::test]
    async fn stop_adjudication_failure_allows_and_leaves_tail_retryable() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-tail-retry");
        super::super::transcript::remove_cursor(&session_id);

        let current =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-current", "final answer");
        let path = write_transcript(dir.path(), &[current]);
        let mut hooks = Hooks::new(
            HandlerHarness::new(vec![Err(HarnessClientError::Server("boom".into()))]),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );
        let response = hooks
            .handle_stop(stop_event(&session_id, &path, None))
            .await
            .expect("Stop should allow even when tail adjudication fails");

        assert_eq!(to_json(&response), "{}");
        hooks
            .harness
            .with_adjudicated_events(|adjudicated| assert_eq!(adjudicated.len(), 1));
        assert_eq!(
            super::super::transcript::read_cursor_if_present(&session_id),
            None,
            "failed Stop tail adjudication must leave the cursor retryable"
        );
        assert_eq!(
            super::super::transcript::read_retry_cursor_if_present(&session_id),
            Some(0),
            "failed Stop tail adjudication should persist the tail start separately from the committed cursor"
        );

        super::super::transcript::remove_cursor(&session_id);
    }

    #[tokio::test]
    async fn stop_retry_cursor_preserves_failed_tail_when_new_assistant_arrives() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-tail-retry-next-assistant");
        super::super::transcript::remove_cursor(&session_id);

        let first =
            assistant_transcript_line("2026-02-11T19:08:43.000Z", "uuid-first", "first answer");
        let path = write_transcript(dir.path(), &[first]);
        let mut failing_hooks = Hooks::new(
            HandlerHarness::new(vec![Err(HarnessClientError::Server("boom".into()))]),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );
        let first_response = failing_hooks
            .handle_stop(stop_event(&session_id, &path, None))
            .await
            .expect("Stop should allow even when tail adjudication fails");

        assert_eq!(to_json(&first_response), "{}");
        assert_eq!(
            super::super::transcript::read_retry_cursor_if_present(&session_id),
            Some(0)
        );

        append_transcript_line(
            &path,
            &user_transcript_line("2026-02-11T19:08:44.000Z", "uuid-user", "next prompt"),
        );
        append_transcript_line(
            &path,
            &assistant_transcript_line("2026-02-11T19:08:45.000Z", "uuid-second", "second answer"),
        );
        let final_cursor = std::fs::metadata(&path).expect("transcript metadata").len();

        let mut retry_hooks = Hooks::new(
            HandlerHarness::new(vec![Ok(Adjudicated::allow()), Ok(Adjudicated::allow())]),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );
        let retry_response = retry_hooks
            .handle_stop(stop_event(&session_id, &path, None))
            .await
            .expect("retry Stop should adjudicate from failed tail");

        assert_eq!(to_json(&retry_response), "{}");
        retry_hooks.harness.with_adjudicated_events(|adjudicated| {
            let contents = adjudicated
                .iter()
                .map(|event| match &event.event {
                    TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                        prompt.content.as_str()
                    }
                    other => panic!("expected assistant prompt event, got {other:?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(contents, ["first answer", "second answer"]);
        });
        assert_eq!(
            super::super::transcript::read_cursor(&session_id),
            final_cursor
        );
        assert_eq!(
            super::super::transcript::read_retry_cursor_if_present(&session_id),
            None,
            "successful retry should clear the retry cursor"
        );

        super::super::transcript::remove_cursor(&session_id);
    }

    #[tokio::test]
    async fn stop_retry_tail_adjudicates_in_bounded_batches() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-tail-batched");
        super::super::transcript::remove_cursor(&session_id);
        super::super::transcript::write_retry_cursor(&session_id, 0).expect("write retry cursor");

        let event_count = STOP_TRANSCRIPT_ADJUDICATE_BATCH_SIZE + 3;
        let lines = (0..event_count)
            .map(|idx| {
                assistant_transcript_line(
                    &format!("2026-02-11T19:08:{idx:02}.000Z"),
                    &format!("uuid-{idx}"),
                    &format!("answer {idx}"),
                )
            })
            .collect::<Vec<_>>();
        let path = write_transcript(dir.path(), &lines);
        let final_cursor = std::fs::metadata(&path).expect("transcript metadata").len();
        let responses = (0..event_count)
            .map(|_| Ok(Adjudicated::allow()))
            .collect::<Vec<_>>();
        let mut hooks = Hooks::new(
            HandlerHarness::new(responses),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );

        let response = hooks
            .handle_stop(stop_event(&session_id, &path, None))
            .await
            .expect("Stop should allow after batched tail adjudication");

        assert_eq!(to_json(&response), "{}");
        hooks
            .harness
            .with_adjudicated_events(|adjudicated| assert_eq!(adjudicated.len(), event_count));
        hooks.harness.with_adjudication_batches(|batches| {
            assert_eq!(
                batches,
                &[STOP_TRANSCRIPT_ADJUDICATE_BATCH_SIZE, 3],
                "Stop should use bounded adjudicates batches instead of singleton RPCs or one unbounded batch"
            );
        });
        assert_eq!(
            super::super::transcript::read_cursor(&session_id),
            final_cursor
        );
        assert_eq!(
            super::super::transcript::read_retry_cursor_if_present(&session_id),
            None,
            "successful batched Stop should clear the retry cursor"
        );

        super::super::transcript::remove_cursor(&session_id);
    }

    #[tokio::test]
    async fn stop_without_assistant_events_allows_and_seeds_cursor_to_eof() {
        let dir = tempfile::tempdir().expect("temp transcript dir");
        let session_id = unique_session_id("stop-no-assistant");
        super::super::transcript::remove_cursor(&session_id);

        let user_line =
            user_transcript_line("2026-02-11T19:08:43.000Z", "uuid-user", "just a prompt");
        let path = write_transcript(dir.path(), &[user_line]);
        let final_cursor = std::fs::metadata(&path).expect("transcript metadata").len();
        let mut hooks = Hooks::new(
            HandlerHarness::new(vec![]),
            handler_agent(),
            HookPlatform::ClaudeCode,
        );

        let response = hooks
            .handle_stop(stop_event(&session_id, &path, None))
            .await
            .expect("Stop should allow when transcript has no assistant events");

        assert_eq!(to_json(&response), "{}");
        hooks
            .harness
            .with_adjudicated_events(|adjudicated| assert!(adjudicated.is_empty()));
        assert_eq!(
            super::super::transcript::read_cursor(&session_id),
            final_cursor,
            "Stop should seed the cursor to EOF when there are no assistant events to adjudicate"
        );

        super::super::transcript::remove_cursor(&session_id);
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

    #[test]
    fn test_normalize_pre_tool_action_maps_bash_to_shell_command() {
        let action =
            normalize_pre_tool_action("Bash", "call-123", "/tmp/ws", &json!({"command": "ls -la"}));

        match action {
            Action::ShellCommand(shell) => {
                assert_eq!(shell.call_id, "call-123");
                assert_eq!(shell.command, "ls -la");
                assert_eq!(shell.working_dir.as_deref(), Some("/tmp/ws"));
            }
            other => panic!("Expected Action::ShellCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_pre_tool_action_maps_unknown_mcp_tool_to_tool_call() {
        let args = json!({
            "repo": "example-org/example-repo",
            "options": { "open": true, "limit": 25 }
        });
        let action = normalize_pre_tool_action(
            "mcp__github__list_pull_requests",
            "call-mcp-1",
            "/tmp/ws",
            &args,
        );

        match action {
            Action::ToolCall(tool_call) => {
                assert_eq!(tool_call.call_id, "call-mcp-1");
                assert_eq!(tool_call.tool, "mcp__github__list_pull_requests");
                assert_eq!(tool_call.arguments, args);
            }
            other => panic!("Expected Action::ToolCall, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_pre_tool_action_preserves_plugin_slack_search_channels() {
        let args = json!({
            "query": "security",
            "limit": 20
        });
        let action = normalize_pre_tool_action(
            "mcp__plugin_slack_slack__slack_search_channels",
            "call-slack-search-channels",
            "/tmp/ws",
            &args,
        );

        match action {
            Action::ToolCall(tool_call) => {
                assert_eq!(tool_call.call_id, "call-slack-search-channels");
                assert_eq!(
                    tool_call.tool,
                    "mcp__plugin_slack_slack__slack_search_channels"
                );
                assert_eq!(tool_call.arguments, args);
            }
            other => panic!("Expected Action::ToolCall for Slack MCP tool, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_pre_tool_action_maps_read_to_file_operation() {
        let action = normalize_pre_tool_action(
            "Read",
            "call-read-1",
            "/tmp/ws",
            &json!({"file_path": "/etc/hosts"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.call_id, "call-read-1");
                assert_eq!(op.path, "/etc/hosts");
                assert!(matches!(op.operation, FileOpType::Read));
                assert!(op.content.is_none());
            }
            other => panic!("Expected FileOperation(Read), got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_pre_tool_action_maps_edit_to_file_operation() {
        let action = normalize_pre_tool_action(
            "Edit",
            "call-edit-1",
            "/tmp/ws",
            &json!({"file_path": "/tmp/foo.py", "old_string": "x = 1", "new_string": "x = 2"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.call_id, "call-edit-1");
                assert_eq!(op.path, "/tmp/foo.py");
                assert!(matches!(op.operation, FileOpType::Edit));
                assert_eq!(op.old_content.as_deref(), Some("x = 1"));
                assert_eq!(op.content.as_deref(), Some("x = 2"));
            }
            other => panic!("Expected FileOperation(Edit), got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_pre_tool_action_maps_write_to_file_operation() {
        let action = normalize_pre_tool_action(
            "Write",
            "call-write-1",
            "/tmp/ws",
            &json!({"file_path": "/tmp/new.py", "content": "print('hello')"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.call_id, "call-write-1");
                assert_eq!(op.path, "/tmp/new.py");
                assert!(matches!(op.operation, FileOpType::Write));
                assert_eq!(op.content.as_deref(), Some("print('hello')"));
                assert!(op.old_content.is_none());
            }
            other => panic!("Expected FileOperation(Write), got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_pre_tool_action_maps_web_fetch() {
        let action = normalize_pre_tool_action(
            "WebFetch",
            "call-wf-1",
            "/tmp/ws",
            &json!({"url": "https://example.com", "prompt": "summarize"}),
        );
        match action {
            Action::WebFetch(wf) => {
                assert_eq!(wf.call_id, "call-wf-1");
                assert_eq!(wf.url, "https://example.com");
                assert_eq!(wf.prompt, "summarize");
            }
            other => panic!("Expected WebFetch, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_pre_tool_action_shell_alias() {
        let action =
            normalize_pre_tool_action("Shell", "call-sh", "/home", &json!({"command": "echo hi"}));
        match action {
            Action::ShellCommand(shell) => {
                assert_eq!(shell.command, "echo hi");
            }
            other => panic!("Expected ShellCommand for Shell alias, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_glob_to_file_read() {
        let action = normalize_pre_tool_action(
            "Glob",
            "call-glob-1",
            "/tmp/ws",
            &json!({"pattern": "**/*.rs", "path": "/src"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.call_id, "call-glob-1");
                assert_eq!(op.path, "/src");
                assert!(matches!(op.operation, FileOpType::Read));
                assert_eq!(op.content.as_deref(), Some("**/*.rs"));
                assert!(op.old_content.is_none());
            }
            other => panic!("Expected FileOperation(Read) for Glob, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_glob_defaults_to_cwd() {
        let action = normalize_pre_tool_action(
            "Glob",
            "call-glob-2",
            "/my/project",
            &json!({"pattern": "*.txt"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.path, "/my/project");
            }
            other => panic!("Expected FileOperation for Glob, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_glob_includes_pattern_in_content() {
        let action = normalize_pre_tool_action(
            "Glob",
            "call-glob-3",
            "/tmp",
            &json!({"pattern": "src/**/*.tsx"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.content.as_deref(), Some("src/**/*.tsx"));
            }
            other => panic!("Expected FileOperation for Glob, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_grep_to_file_read() {
        let action = normalize_pre_tool_action(
            "Grep",
            "call-grep-1",
            "/tmp/ws",
            &json!({"pattern": "TODO", "path": "/src/main.rs"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.call_id, "call-grep-1");
                assert_eq!(op.path, "/src/main.rs");
                assert!(matches!(op.operation, FileOpType::Read));
                assert_eq!(op.content.as_deref(), Some("TODO"));
                assert!(op.old_content.is_none());
            }
            other => panic!("Expected FileOperation(Read) for Grep, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_grep_defaults_to_cwd() {
        let action = normalize_pre_tool_action(
            "Grep",
            "call-grep-2",
            "/workspace",
            &json!({"pattern": "fn main"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.path, "/workspace");
            }
            other => panic!("Expected FileOperation for Grep, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_grep_includes_pattern_in_content() {
        let action = normalize_pre_tool_action(
            "Grep",
            "call-grep-3",
            "/tmp",
            &json!({"pattern": "log.*Error"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.content.as_deref(), Some("log.*Error"));
            }
            other => panic!("Expected FileOperation for Grep, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_notebook_edit_to_file_edit() {
        let action = normalize_pre_tool_action(
            "NotebookEdit",
            "call-nb-1",
            "/tmp/ws",
            &json!({"notebook_path": "/tmp/analysis.ipynb", "new_source": "import pandas as pd"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.call_id, "call-nb-1");
                assert_eq!(op.path, "/tmp/analysis.ipynb");
                assert!(matches!(op.operation, FileOpType::Edit));
                assert_eq!(op.content.as_deref(), Some("import pandas as pd"));
                assert!(op.old_content.is_none());
            }
            other => panic!("Expected FileOperation(Edit) for NotebookEdit, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_unknown_mcp_stays_toolcall() {
        let args = json!({"itemId": "ITEM-123"});
        let action = normalize_pre_tool_action(
            "mcp__tracker__get_item",
            "call-mcp-tracker",
            "/tmp/ws",
            &args,
        );
        match action {
            Action::ToolCall(tc) => {
                assert_eq!(tc.tool, "mcp__tracker__get_item");
                assert_eq!(tc.arguments, args);
            }
            other => panic!("Expected ToolCall for MCP tracker tool, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_mcp_filesystem_stays_toolcall() {
        let args = json!({"path": "/etc/passwd"});
        let action = normalize_pre_tool_action(
            "mcp__filesystem__read_file",
            "call-mcp-fs",
            "/tmp/ws",
            &args,
        );
        match action {
            Action::ToolCall(tc) => {
                assert_eq!(tc.tool, "mcp__filesystem__read_file");
                assert_eq!(tc.arguments, args);
            }
            other => {
                panic!("Expected ToolCall for mcp__filesystem (security boundary), got {other:?}")
            }
        }
    }

    #[test]
    fn test_normalize_web_search_stays_toolcall() {
        let args = json!({"query": "rust async"});
        let action = normalize_pre_tool_action("WebSearch", "call-ws-1", "/tmp/ws", &args);
        match action {
            Action::ToolCall(tc) => {
                assert_eq!(tc.tool, "WebSearch");
                assert_eq!(tc.arguments, args);
            }
            other => panic!("Expected ToolCall for WebSearch, got {other:?}"),
        }
    }

    #[test]
    fn test_normalize_agent_stays_toolcall() {
        let args = json!({"prompt": "do something", "subagent_type": "general-purpose"});
        let action = normalize_pre_tool_action("Agent", "call-agent-1", "/tmp/ws", &args);
        match action {
            Action::ToolCall(tc) => {
                assert_eq!(tc.tool, "Agent");
                assert_eq!(tc.arguments, args);
            }
            other => panic!("Expected ToolCall for Agent, got {other:?}"),
        }
    }

    // ============================================================================
    // Blockable Claude lifecycle/config handler coverage
    // ============================================================================
    mod wrapper_arms {
        use super::*;
        use sondera_harness_client::{Adjudicated, Event};
        use sondera_types::HarnessClientError;

        /// Mock harness whose `adjudicate` walks a scripted response
        /// sequence. Each call dequeues the next outcome; once
        /// exhausted, returns a "no more" error so a test that calls
        /// too often gets a loud failure instead of silent reuse.
        struct ScriptedHarness {
            responses: std::sync::Mutex<
                std::collections::VecDeque<std::result::Result<Adjudicated, HarnessClientError>>,
            >,
        }

        impl ScriptedHarness {
            fn new(responses: Vec<std::result::Result<Adjudicated, HarnessClientError>>) -> Self {
                Self {
                    responses: std::sync::Mutex::new(responses.into()),
                }
            }
        }

        impl HarnessClient for ScriptedHarness {
            async fn adjudicate(
                &self,
                _event: Event,
            ) -> std::result::Result<Adjudicated, HarnessClientError> {
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| {
                        Err(HarnessClientError::Server(
                            "ScriptedHarness ran out of responses".into(),
                        ))
                    })
            }
        }

        fn fake_agent() -> Agent {
            Agent {
                id: "agent-test".to_string(),
                provider: "anthropic".to_string(),
                platform: "claude-code".to_string(),
            }
        }

        fn fake_event(agent: &Agent) -> Event {
            Event::new(
                agent.clone(),
                "sess-test",
                TrajectoryEvent::Control(Control::Started(Started::new(agent.clone()))),
            )
        }

        /// Drive `Hooks::adjudicate` and the blockable Claude
        /// lifecycle/config handlers through scripted allow/deny/error
        /// outcomes, asserting each handler fails closed the way its
        /// surface requires (block, stop, or unenforceable-but-allowed).
        #[tokio::test]
        async fn blockable_lifecycle_handlers_fail_closed() {
            super::assert_post_tool_use_timeout_blocks_with_redacted_output_without_doctor_steer()
                .await;

            let agent = fake_agent();
            let hooks = Hooks::new(
                ScriptedHarness::new(vec![
                    Ok(Adjudicated::allow()),
                    Ok(Adjudicated::deny()),
                    Err(HarnessClientError::Server("transport reset".into())),
                ]),
                agent.clone(),
                HookPlatform::ClaudeCode,
            );

            let r1 = hooks.adjudicate(fake_event(&agent)).await;
            assert!(r1.is_ok());
            assert_eq!(r1.unwrap().decision, Decision::Allow);

            let r2 = hooks.adjudicate(fake_event(&agent)).await;
            assert!(r2.is_ok());
            assert_eq!(r2.unwrap().decision, Decision::Deny);

            let r3 = hooks.adjudicate(fake_event(&agent)).await;
            assert!(r3.is_err());

            // ============== blockable Claude lifecycle/config handlers ==============
            let mut hooks =
                hooks_with_decision(Adjudicated::deny().with_reason("subagent must continue"));
            let response = hooks
                .handle_subagent_stop(SubagentStopEvent {
                    session_id: unique_session_id("subagent-stop"),
                    transcript_path: String::new(),
                    cwd: String::new(),
                    permission_mode: PermissionMode::Default,
                    hook_event_name: "SubagentStop".to_string(),
                    stop_hook_active: false,
                    agent_id: "agent-1".to_string(),
                    agent_type: "Explore".to_string(),
                    agent_transcript_path: String::new(),
                })
                .await
                .expect("subagent stop response");
            assert_block(response, "subagent must continue");

            let mut hooks =
                hooks_with_decision(Adjudicated::deny().with_reason("teammate must continue"));
            let response = hooks
                .handle_teammate_idle(TeammateIdleEvent {
                    session_id: unique_session_id("teammate-idle"),
                    transcript_path: String::new(),
                    cwd: String::new(),
                    permission_mode: PermissionMode::Default,
                    hook_event_name: "TeammateIdle".to_string(),
                    teammate_name: "Planner".to_string(),
                    team_name: "Team".to_string(),
                })
                .await
                .expect("teammate idle response");
            assert_stop(response, "teammate must continue");

            let mut hooks =
                hooks_with_decision(Adjudicated::deny().with_reason("task is incomplete"));
            let response = hooks
                .handle_task_completed(TaskCompletedEvent {
                    session_id: unique_session_id("task-completed"),
                    transcript_path: String::new(),
                    cwd: String::new(),
                    permission_mode: PermissionMode::Default,
                    hook_event_name: "TaskCompleted".to_string(),
                    task_id: "task-1".to_string(),
                    task_subject: "Finish rollout".to_string(),
                    task_description: None,
                    teammate_name: None,
                    team_name: None,
                })
                .await
                .expect("task completed response");
            assert_stop(response, "task is incomplete");

            let mut hooks = hooks_with_decision(Adjudicated::deny().with_reason("keep context"));
            let response = hooks
                .handle_pre_compact(PreCompactEvent {
                    session_id: unique_session_id("pre-compact"),
                    transcript_path: String::new(),
                    cwd: String::new(),
                    permission_mode: PermissionMode::Default,
                    hook_event_name: "PreCompact".to_string(),
                    trigger: CompactTrigger::Manual,
                    custom_instructions: "preserve audit evidence".to_string(),
                })
                .await
                .expect("pre compact response");
            assert_block(response, "keep context");

            let config_cwd = tempfile::tempdir().expect("temp config cwd");
            let mut hooks =
                hooks_with_decision(Adjudicated::deny().with_reason("config violates policy"));
            let response = hooks
                .handle_config_change(ConfigChangeEvent {
                    session_id: unique_session_id("config-change"),
                    transcript_path: String::new(),
                    cwd: config_cwd.path().display().to_string(),
                    permission_mode: PermissionMode::Default,
                    hook_event_name: "ConfigChange".to_string(),
                    config_type: ConfigChangeType::LocalSettings,
                    file_path: String::new(),
                })
                .await
                .expect("config change response");
            assert_block(response, "config violates policy");

            let policy_cwd = tempfile::tempdir().expect("temp policy cwd");
            let mut hooks =
                hooks_with_decision(Adjudicated::deny().with_reason("managed policy changed"));
            let response = hooks
                .handle_config_change(ConfigChangeEvent {
                    session_id: unique_session_id("policy-settings"),
                    transcript_path: String::new(),
                    cwd: policy_cwd.path().display().to_string(),
                    permission_mode: PermissionMode::Default,
                    hook_event_name: "ConfigChange".to_string(),
                    config_type: ConfigChangeType::PolicySettings,
                    file_path: String::new(),
                })
                .await
                .expect("policy settings config response");
            let response = serde_json::to_value(response).expect("serialize response");
            assert!(
                response.get("decision").is_none(),
                "policy_settings changes cannot be blocked by Claude: {response}"
            );
        }
    }

    #[tokio::test]
    async fn denied_local_settings_config_change_blocks() {
        let session_id = unique_session_id("denied-config");

        let mut hooks =
            hooks_with_decision(Adjudicated::deny().with_reason("config violates policy"));

        let response = hooks
            .handle_config_change(ConfigChangeEvent {
                session_id: session_id.clone(),
                transcript_path: String::new(),
                cwd: String::new(),
                permission_mode: PermissionMode::Default,
                hook_event_name: "ConfigChange".to_string(),
                config_type: ConfigChangeType::LocalSettings,
                file_path: String::new(),
            })
            .await
            .expect("config change response");

        assert_block(response, "config violates policy");
    }

    // ========================================================================
    // `@`-reference file adjudication (UserPromptSubmit)
    // ========================================================================

    fn hooks_with_responses(
        responses: Vec<std::result::Result<Adjudicated, HarnessClientError>>,
    ) -> Hooks<HandlerHarness> {
        Hooks::new(
            HandlerHarness::new(responses),
            handler_agent(),
            HookPlatform::ClaudeCode,
        )
    }

    fn user_prompt_event(session_id: &str, cwd: &str, prompt: &str) -> UserPromptSubmitEvent {
        UserPromptSubmitEvent {
            session_id: session_id.to_string(),
            transcript_path: String::new(),
            cwd: cwd.to_string(),
            permission_mode: PermissionMode::Default,
            hook_event_name: "UserPromptSubmit".to_string(),
            prompt: prompt.to_string(),
        }
    }

    #[tokio::test]
    async fn user_prompt_deny_on_at_mention_blocks_before_prompt() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("secret.rs"), "const KEY: &str = \"x\";")
            .expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();
        let session_id = unique_session_id("atref-deny");

        let mut hooks = hooks_with_responses(vec![Ok(
            Adjudicated::deny().with_reason("secret file blocked")
        )]);

        let response = hooks
            .handle_user_prompt_submit(user_prompt_event(&session_id, &cwd, "explain @secret.rs"))
            .await
            .expect("handler result");

        assert_block(response, "secret file blocked");
        // Only the file read was adjudicated; the prompt itself never was.
        hooks.harness.with_adjudicated_events(|events| {
            assert_eq!(events.len(), 1);
            assert!(matches!(
                &events[0].event,
                TrajectoryEvent::Action(Action::FileOperation(_))
            ));
        });
    }

    #[tokio::test]
    async fn user_prompt_allowed_at_mention_reads_file_then_adjudicates_prompt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = "fn main() { println!(\"hi\"); }";
        std::fs::write(dir.path().join("a.rs"), body).expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();
        let session_id = unique_session_id("atmention-allow");
        // The adjudicated path is lexically normalized (symlinks unresolved),
        // matching the cwd's shape rather than the canonical target.
        let expected_path = std::path::Path::new(&cwd)
            .join("a.rs")
            .to_string_lossy()
            .into_owned();

        let mut hooks =
            hooks_with_responses(vec![Ok(Adjudicated::allow()), Ok(Adjudicated::allow())]);

        let response = hooks
            .handle_user_prompt_submit(user_prompt_event(&session_id, &cwd, "explain @a.rs"))
            .await
            .expect("handler result");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|events| {
            assert_eq!(events.len(), 2);
            match &events[0].event {
                TrajectoryEvent::Action(Action::FileOperation(op)) => {
                    assert_eq!(op.operation, FileOpType::Read);
                    assert_eq!(op.path, expected_path);
                    assert_eq!(op.content.as_deref(), Some(body));
                }
                other => panic!("first event must be the @-mention read, got {other:?}"),
            }
            assert!(
                matches!(
                    &events[1].event,
                    TrajectoryEvent::Observation(Observation::Prompt(_))
                ),
                "the prompt must be adjudicated after the @-mention read"
            );
        });
    }

    #[tokio::test]
    async fn user_prompt_escalate_on_at_mention_fails_closed_and_blocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.rs"), "fn main() {}").expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();
        let session_id = unique_session_id("atmention-escalate");

        // Escalate requests approval that cannot be obtained at prompt submit,
        // and the content is already inlined, so the read fails closed and
        // blocks; the prompt itself is never adjudicated.
        let mut hooks = hooks_with_responses(vec![Ok(Adjudicated::escalate())]);

        let response = hooks
            .handle_user_prompt_submit(user_prompt_event(&session_id, &cwd, "explain @a.rs"))
            .await
            .expect("handler result");

        assert_block(response, "requires approval");
        hooks
            .harness
            .with_adjudicated_events(|events| assert_eq!(events.len(), 1));
    }

    #[tokio::test]
    async fn user_prompt_escalate_fails_closed_and_blocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cwd = dir.path().to_string_lossy().into_owned();
        let session_id = unique_session_id("prompt-escalate");

        // No `@`-mentions, so this exercises the top-level prompt adjudication
        // match directly rather than `adjudicate_at_mention_reads`.
        let mut hooks = hooks_with_responses(vec![Ok(Adjudicated::escalate())]);

        let response = hooks
            .handle_user_prompt_submit(user_prompt_event(&session_id, &cwd, "no @mentions"))
            .await
            .expect("handler result");

        assert_block(response, "escalated");
    }

    #[tokio::test]
    async fn user_prompt_deduplicates_repeated_at_mention() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.rs"), "fn main() {}").expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();
        let session_id = unique_session_id("atref-dedupe");

        let mut hooks =
            hooks_with_responses(vec![Ok(Adjudicated::allow()), Ok(Adjudicated::allow())]);

        let response = hooks
            .handle_user_prompt_submit(user_prompt_event(
                &session_id,
                &cwd,
                "compare @a.rs with @a.rs",
            ))
            .await
            .expect("handler result");

        assert_eq!(to_json(&response), "{}");
        // One file read (the duplicate is deduped) plus the prompt.
        hooks
            .harness
            .with_adjudicated_events(|events| assert_eq!(events.len(), 2));
    }

    #[tokio::test]
    async fn user_prompt_without_at_mention_adjudicates_only_prompt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cwd = dir.path().to_string_lossy().into_owned();
        let session_id = unique_session_id("atref-none");

        let mut hooks = hooks_with_responses(vec![Ok(Adjudicated::allow())]);

        let response = hooks
            .handle_user_prompt_submit(user_prompt_event(
                &session_id,
                &cwd,
                "no references in this prompt",
            ))
            .await
            .expect("handler result");

        assert_eq!(to_json(&response), "{}");
        hooks.harness.with_adjudicated_events(|events| {
            assert_eq!(events.len(), 1);
            assert!(matches!(
                &events[0].event,
                TrajectoryEvent::Observation(Observation::Prompt(_))
            ));
        });
    }
}
