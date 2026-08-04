//! Hook handler implementations for VS Code Copilot Chat events.
//!
//! This module contains all the business logic for handling the 8 VS Code
//! Copilot Chat hook events: SessionStart, UserPromptSubmit, PreToolUse,
//! PostToolUse, PreCompact, SubagentStart, SubagentStop, Stop.
//!
//! ## VS Code tool name mapping
//!
//! VS Code Copilot has shipped both snake_case (`read_file`) and camelCase
//! (`readFile`) names for the same call, so every arm below matches on
//! [`normalize_tool_name`] rather than the literal string. Both spellings —
//! and any future one that differs only in casing or separators — fold to the
//! same key.
//!
//! | VS Code tool name                                | Action type             |
//! |--------------------------------------------------|-------------------------|
//! | `run_in_terminal`, `runTerminalCommand`           | `ShellCommand`          |
//! | `read_file`, `readFile`, `readFiles`              | `FileOperation(Read)`   |
//! | `create_file`, `createFile`, `writeFile`          | `FileOperation(Write)`  |
//! | `insert_edit_into_file`, `replace_string_in_file`, |                        |
//! | `apply_patch`, `edit_notebook_file`, `editFiles`  | `FileOperation(Edit)`   |
//! | `delete_file`, `deleteFile`                       | `FileOperation(Delete)` |
//! | `fetch_webpage`                                   | `WebFetch`              |
//! | *(everything else)*                               | `ToolCall`              |
//!
//! Anything that falls through to `ToolCall` reaches Cedar as
//! `Sondera::Action::"PreToolUse"`, which no file, shell, or web policy
//! applies to — so a name missing from this table is a name that cannot be
//! governed. Enumeration tools (`list_dir`, `file_search`, `grep_search`) are
//! deliberately left generic: they surface paths rather than file contents.
//!
//! Reference: <https://code.visualstudio.com/docs/agent-customization/hooks#_frequently-asked-questions>

use super::types::*;
use crate::mention;
use crate::response::HookResponse;
use sondera_hooks::adjudication::warn_unenforceable_decision;
use sondera_hooks::error::Result;

use sondera_hooks::tool::{file_path_arg, normalize_tool_name, string_arg, web_url_arg};

use std::path::Path;

use sondera_harness_client::{
    Action, Actor, Agent, Control, Decision, Event, FileOpType, FileOperation, FileOperationResult,
    HarnessClient, Observation, Prompt, ShellCommand, ShellCommandOutput, Started, ToolCall,
    ToolOutput, TrajectoryEvent, WebFetch, WebFetchOutput,
};
use tracing::{info, warn};

// ============================================================================
// Tool name normalization
// ============================================================================

/// Tool names that carry a file operation, in their folded form.
///
/// Shared by the pre- and post-execution mappers so an addition to one cannot
/// drift from the other: a tool adjudicated as a `FileOperation` must report
/// its result as a `FileOperationResult`, or the harness never sees the
/// content the read actually returned.
const FILE_TOOLS: &[&str] = &[
    "readfile",
    "readfiles",
    "createfile",
    "writefile",
    "inserteditintofile",
    "replacestringinfile",
    "applypatch",
    "editnotebookfile",
    "editfiles",
    "editfile",
    "deletefile",
];

/// Tool names, folded, that carry a web fetch.
///
/// Paired with `FILE_TOOLS` above: the pre- and post-execution mappers gate on
/// the same list so a call adjudicated as a `WebFetch` reports a
/// `WebFetchOutput`.
const WEB_TOOLS: &[&str] = &["fetchwebpage", "webfetch", "fetch"];

/// Map a VS Code tool name and its input to the canonical `Action` type.
///
/// Matches on the folded name, so each arm covers every casing and separator
/// spelling VS Code has shipped for that tool.
fn normalize_pre_tool_action(
    tool_name: &str,
    call_id: &str,
    cwd: &str,
    args: &serde_json::Value,
) -> Action {
    match normalize_tool_name(tool_name).as_str() {
        // ── Terminal / shell ─────────────────────────────────────────────────
        // VS Code current: run_in_terminal  |  legacy: runTerminalCommand, terminal
        "runinterminal" | "runterminalcommand" | "terminal" => {
            let command = string_arg(args, &["command", "commandLine"])
                .unwrap_or("")
                .to_string();
            Action::ShellCommand(ShellCommand {
                call_id: call_id.to_string(),
                command,
                working_dir: Some(cwd.to_string()),
            })
        }

        // ── File edits ───────────────────────────────────────────────────────
        // VS Code current: insert_edit_into_file, replace_string_in_file,
        // edit_notebook_file  |  legacy: editFiles, editFile
        "inserteditintofile"
        | "replacestringinfile"
        | "editnotebookfile"
        | "editfiles"
        | "editfile" => {
            // Input shapes differ per tool; `files[]` is the editFiles legacy
            // form, which names the target without carrying the new content.
            let path = string_arg(args, &["filePath", "file_path", "path"])
                .or_else(|| {
                    args.get("files")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("")
                .to_string();
            let old_content = string_arg(
                args,
                &[
                    "oldString",
                    "oldStr",
                    "old_str",
                    "oldContent",
                    "old_content",
                ],
            )
            .map(str::to_string);
            let content = string_arg(
                args,
                &[
                    "newString",
                    "newStr",
                    "new_str",
                    "newContent",
                    "content",
                    "code",
                ],
            )
            .map(str::to_string);
            Action::FileOperation(FileOperation {
                call_id: call_id.to_string(),
                operation: FileOpType::Edit,
                path,
                content,
                old_content,
            })
        }

        // ── Patch application ────────────────────────────────────────────────
        // CONTEXT: apply_patch carries its target paths inside the patch body
        // rather than in a path argument, so `path` stays empty and only the
        // content-driven policies (signature categories, sensitivity label)
        // can adjudicate it. Modelling it as an Edit still beats a generic
        // ToolCall, which no file policy reaches at all.
        "applypatch" => Action::FileOperation(FileOperation {
            call_id: call_id.to_string(),
            operation: FileOpType::Edit,
            path: file_path_arg(args).to_string(),
            content: string_arg(args, &["input", "patch", "content"]).map(str::to_string),
            old_content: None,
        }),

        // ── File creation ────────────────────────────────────────────────────
        // VS Code current: create_file  |  legacy: createFile, writeFile
        "createfile" | "writefile" => Action::FileOperation(FileOperation {
            call_id: call_id.to_string(),
            operation: FileOpType::Write,
            path: file_path_arg(args).to_string(),
            content: string_arg(args, &["content", "code"]).map(str::to_string),
            old_content: None,
        }),

        // ── File reads ───────────────────────────────────────────────────────
        // VS Code current: read_file  |  legacy: readFile, readFiles
        "readfile" | "readfiles" => Action::FileOperation(FileOperation {
            call_id: call_id.to_string(),
            operation: FileOpType::Read,
            path: file_path_arg(args).to_string(),
            content: None,
            old_content: None,
        }),

        // ── File deletion ────────────────────────────────────────────────────
        // VS Code current: delete_file  |  legacy: deleteFile
        "deletefile" => Action::FileOperation(FileOperation {
            call_id: call_id.to_string(),
            operation: FileOpType::Delete,
            path: file_path_arg(args).to_string(),
            content: None,
            old_content: None,
        }),

        // ── Web fetch ────────────────────────────────────────────────────────
        // VS Code current: fetch_webpage, whose input is { urls: [...], query }.
        name if WEB_TOOLS.contains(&name) => {
            let url = string_arg(args, &["url"])
                .or_else(|| {
                    args.get("urls")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("")
                .to_string();
            let prompt = string_arg(args, &["query", "prompt"])
                .unwrap_or("")
                .to_string();
            Action::WebFetch(WebFetch {
                call_id: call_id.to_string(),
                url,
                prompt,
            })
        }

        // ── Everything else → generic tool call ──────────────────────────────
        _ => Action::ToolCall(ToolCall {
            call_id: call_id.to_string(),
            tool: tool_name.to_string(),
            arguments: args.clone(),
        }),
    }
}

// ============================================================================
// `@`-mention reads
// ============================================================================

/// Upper bound on how much of an `@`-mentioned file is read for adjudication.
///
/// Matches the per-event text budget the Claude adapter applies on the same
/// path: the content rides on the re-derived `Read` action, and a file past the
/// cap is truncated rather than dropped so content-keyed policy still sees its
/// head.
const MAX_MENTION_READ_BYTES: usize = 15 * 1024 * 1024;

/// Synthesize a stable `call_id` for a re-derived `@`-mention file read.
///
/// A real tool call carries VS Code's `toolUseId`; an `@`-mention has none, so
/// one is derived from the session key and the resolved path. Keying on the
/// path rather than a per-prompt counter keeps two different files distinct
/// across the prompts of one session, so anything correlating by `call_id`
/// cannot conflate them.
fn at_mention_call_id(session_key: &str, path: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    format!("atmention-{session_key}-{:016x}", hasher.finish())
}

pub struct Hooks<H: HarnessClient> {
    harness: H,
    agent: Agent,
}

impl<H: HarnessClient> Hooks<H> {
    /// Create a new Hooks instance.
    ///
    /// `agent` should be built via [`crate::get_agent`].
    pub fn new(harness: H, agent: Agent) -> Self {
        Self { harness, agent }
    }

    /// Create an Event with the current agent
    fn event(&self, trajectory_id: &str, event: TrajectoryEvent) -> Event {
        Event::new(self.agent.clone(), trajectory_id, event)
    }

    /// Get a session key from the event. Uses session_id if present, otherwise falls back to cwd.
    fn get_session_key(session_id: &Option<String>, cwd: &str) -> String {
        session_id
            .as_ref()
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| cwd.to_string())
    }

    // ============================================================================
    // Session lifecycle hooks
    // ============================================================================

    /// Handle sessionStart hook
    pub async fn handle_session_start(&mut self, event: SessionStartEvent) -> Result<HookResponse> {
        let session_key = Self::get_session_key(&event.common.session_id, &event.common.cwd);

        let started = TrajectoryEvent::Control(Control::Started(Started::new(self.agent.clone())));

        let ev = self.event(&session_key, started);

        let adjudicated = self.harness.adjudicate(ev).await?;
        warn_unenforceable_decision("non-blocking hook", &adjudicated);

        let context = format!(
            "Session {} started (source: {:?})",
            session_key, event.source
        );
        Ok(HookResponse::session_start_context(context))
    }

    // ============================================================================
    // User prompt hook
    // ============================================================================

    /// Adjudicate the files mentioned with `@` in the prompt, one at a time, in
    /// order of appearance and before the prompt itself.
    ///
    /// Copilot Chat inlines a mentioned file's content while assembling the
    /// prompt and never issues a read tool call, so no `PreToolUse` hook fires
    /// for it. This re-derives those reads: every mention that
    /// [`crate::mention`] resolves to a readable local file is sent as a `Read`
    /// [`FileOperation`] carrying the content, so both path- and content-keyed
    /// policy govern `@` access.
    ///
    /// Returns `Some(block)` as soon as a mention is denied or escalated; the
    /// caller returns it and never adjudicates the prompt. Returns `None` when
    /// every mention is allowed. Enforcement mode is applied by the harness (a
    /// `Deny` reaching a hook is already a governing decision), so no mode check
    /// happens here. `Escalate` asks for an approval that cannot be obtained at
    /// prompt-submit time, and the content is already assembled into the turn,
    /// so it fails closed and blocks.
    async fn adjudicate_at_mention_reads(
        &self,
        session_key: &str,
        event: &UserPromptSubmitEvent,
    ) -> Result<Option<HookResponse>> {
        let mentioned = mention::resolve_prompt_mentions(
            &event.prompt,
            &event.common.cwd,
            MAX_MENTION_READ_BYTES,
        );
        for (path, content) in mentioned {
            // `read_file_text` already bounds the read, so the action carries at
            // most `MAX_MENTION_READ_BYTES` of content.
            let action = Action::FileOperation(FileOperation {
                call_id: at_mention_call_id(session_key, &path),
                operation: FileOpType::Read,
                path: path.to_string_lossy().into_owned(),
                content,
                old_content: None,
            });

            let ev = self.event(session_key, TrajectoryEvent::Action(action));
            let adjudicated = self.harness.adjudicate(ev).await?;

            match adjudicated.decision {
                Decision::Allow => {}
                Decision::Deny => {
                    let msg = adjudicated.deny_message(&format!(
                        "@-mentioned file '{}' blocked by policy",
                        path.display()
                    ));
                    warn!("@-mention read denied: {}", msg);
                    return Ok(Some(HookResponse::user_prompt_deny(msg)));
                }
                Decision::Escalate => {
                    let msg = adjudicated.deny_message(&format!(
                        "@-mentioned file '{}' requires approval that cannot be granted at prompt submit",
                        path.display()
                    ));
                    warn!("@-mention read escalated; failing closed: {}", msg);
                    return Ok(Some(HookResponse::user_prompt_deny(msg)));
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
        let session_key = Self::get_session_key(&event.common.session_id, &event.common.cwd);

        // `@`-mentioned files are inlined into the prompt without a read tool
        // call, so govern them here, before the prompt itself: a deny on any
        // mentioned file blocks the whole prompt, since the content is already
        // assembled into the turn and no later tool hook will fire for it.
        if let Some(block) = self
            .adjudicate_at_mention_reads(&session_key, &event)
            .await?
        {
            return Ok(block);
        }

        let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(&event.prompt)));

        let ev = self
            .event(&session_key, prompt)
            .with_actor(Actor::human(&self.agent.id));

        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => {
                info!("User prompt allowed");
                HookResponse::allow()
            }
            Decision::Deny => {
                let msg = adjudicated.deny_message("Prompt blocked by policy");
                warn!("User prompt denied: {}", msg);
                HookResponse::user_prompt_deny(msg)
            }
            Decision::Escalate => {
                let msg = adjudicated.deny_message("Prompt escalated for review");
                warn!("User prompt escalated: {}", msg);
                HookResponse::user_prompt_deny(msg)
            }
        };
        Ok(response)
    }

    // ============================================================================
    // Tool execution hooks
    // ============================================================================

    /// Handle preToolUse hook
    pub async fn handle_pre_tool_use(&mut self, event: PreToolUseEvent) -> Result<HookResponse> {
        let session_key = Self::get_session_key(&event.common.session_id, &event.common.cwd);
        let tool_name = event.tool_name.clone();
        let args = &event.tool_input;

        let action =
            normalize_pre_tool_action(&tool_name, &event.tool_use_id, &event.common.cwd, args);

        let trajectory_event = TrajectoryEvent::Action(action);

        let ev = self.event(&session_key, trajectory_event);

        let adjudicated = self.harness.adjudicate(ev).await?;

        // Map the adjudication to a hook response.
        //
        // IMPORTANT: For Allow we return HookResponse::allow() which
        // serializes to `{}`. We must NOT set permissionDecision: "allow"
        // explicitly unless we want to bypass VS Code's normal permission system.
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

    /// Handle postToolUse hook
    pub async fn handle_post_tool_use(&mut self, event: PostToolUseEvent) -> Result<HookResponse> {
        let session_key = Self::get_session_key(&event.common.session_id, &event.common.cwd);
        let tool_name = event.tool_name.clone();

        let folded = normalize_tool_name(&tool_name);
        let observation = match folded.as_str() {
            // Terminal command output
            "runinterminal" | "runterminalcommand" | "terminal" => {
                let output = string_arg(&event.tool_response, &["output", "stdout"])
                    .unwrap_or("")
                    .to_string();
                let exit_code = event
                    .tool_response
                    .get("exitCode")
                    .or_else(|| event.tool_response.get("exit_code"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32;
                Observation::ShellCommandOutput(ShellCommandOutput::new(
                    &event.tool_use_id,
                    exit_code,
                    output,
                    "",
                ))
            }
            // File operation results (read, edit, create, delete). The content
            // recovered here is what the post-execution signature and
            // sensitivity policies scan — a read demoted to a generic
            // ToolOutput loses it.
            name if FILE_TOOLS.contains(&name) => {
                let content = string_arg(&event.tool_response, &["content", "text", "output"])
                    .map(str::to_string)
                    .or_else(|| {
                        event
                            .tool_response
                            .get("file")
                            .and_then(|f| f.get("content"))
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    });

                let mut result = FileOperationResult::success(&event.tool_use_id);
                let path = file_path_arg(&event.tool_input);
                if !path.is_empty() {
                    result = result.with_path(path);
                }
                if let Some(content) = content {
                    result = result.with_content(content);
                }
                Observation::FileOperationResult(result)
            }
            // Same pairing as the file branch: without it the fetched body
            // arrives as a generic ToolOutput and the webfetch-output
            // policies never see what came back.
            name if WEB_TOOLS.contains(&name) => Observation::WebFetchOutput(WebFetchOutput::new(
                &event.tool_use_id,
                web_url_arg(&event.tool_input).unwrap_or_default(),
                event
                    .tool_response
                    .get("statusCode")
                    .or_else(|| event.tool_response.get("status"))
                    .and_then(|v| v.as_i64())
                    .and_then(|code| i32::try_from(code).ok())
                    .unwrap_or(200),
                string_arg(&event.tool_response, &["content", "text", "output", "body"])
                    .unwrap_or("")
                    .to_string(),
            )),
            _ => Observation::ToolOutput(ToolOutput::success(
                &event.tool_use_id,
                event.tool_response.clone(),
            )),
        };

        let tool_output = TrajectoryEvent::Observation(observation);

        let ev = self.event(&session_key, tool_output);

        let adjudicated = self.harness.adjudicate(ev).await?;

        let response = match adjudicated.decision {
            Decision::Allow => HookResponse::allow(),
            Decision::Deny | Decision::Escalate => {
                let msg = adjudicated.deny_message("Tool output blocked by policy");
                HookResponse::post_tool_block(msg)
            }
        };

        Ok(response)
    }

    // ============================================================================
    // Pre-compact hook
    // ============================================================================

    /// Handle preCompact hook — observation only
    pub fn handle_pre_compact(&self, event: PreCompactEvent) -> Result<HookResponse> {
        let trigger = event.trigger;
        let session_key = Self::get_session_key(&event.common.session_id, &event.common.cwd);

        info!(
            "Processing pre-compact event: {:?} (session: {})",
            trigger, session_key
        );

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // Subagent hooks
    // ============================================================================

    /// Handle subagentStart hook — context injection
    pub fn handle_subagent_start(&self, event: SubagentStartEvent) -> Result<HookResponse> {
        let session_key = Self::get_session_key(&event.common.session_id, &event.common.cwd);

        info!(
            "Subagent started: id={}, type={} (session: {})",
            event.agent_id, event.agent_type, session_key
        );

        Ok(HookResponse::allow())
    }

    /// Handle subagentStop hook
    pub fn handle_subagent_stop(&self, event: SubagentStopEvent) -> Result<HookResponse> {
        let session_key = Self::get_session_key(&event.common.session_id, &event.common.cwd);

        info!(
            "Processing subagent stop: id={}, type={} (session: {}, stop_hook_active: {})",
            event.agent_id, event.agent_type, session_key, event.stop_hook_active
        );

        if event.stop_hook_active {
            info!("Subagent stop hook is already active. Allowing stop to prevent infinite loop");
            return Ok(HookResponse::allow());
        }

        Ok(HookResponse::allow())
    }

    // ============================================================================
    // Stop hook
    // ============================================================================

    /// Handle stop hook — task completion.
    ///
    /// VS Code's `Stop` hook fires when the agent finishes a task. This is the
    /// closest lifecycle event to a session end in VS Code (there is no SessionEnd
    /// hook).
    pub fn handle_stop(&self, event: StopEvent) -> Result<HookResponse> {
        let session_key = Self::get_session_key(&event.common.session_id, &event.common.cwd);

        info!(
            "Processing stop event (session: {}, stop_hook_active: {})",
            session_key, event.stop_hook_active
        );

        if event.stop_hook_active {
            info!("Stop hook is already active. Allowing stop to prevent infinite loop");
            return Ok(HookResponse::allow());
        }

        Ok(HookResponse::allow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn to_json(response: &HookResponse) -> String {
        serde_json::to_string(response).unwrap()
    }

    // Guard: allow() must serialize to "{}" — not to permissionDecision: "allow"
    // which would bypass VS Code's normal permission system.
    #[test]
    fn test_allow_response_serializes_to_empty_json() {
        let json = to_json(&HookResponse::allow());
        assert_eq!(
            json, "{}",
            "HookResponse::allow() must serialize to empty JSON, got: {json}"
        );
    }

    #[test]
    fn test_pre_tool_deny_in_hook_specific_output() {
        let response = HookResponse::pre_tool_deny("blocked by policy".to_string());
        let json = to_json(&response);
        // permissionDecision must be INSIDE hookSpecificOutput per VS Code spec
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("PreToolUse"));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("\"deny\""));
        assert!(json.contains("blocked by policy"));
        assert!(response.is_deny());
    }

    #[test]
    fn test_pre_tool_ask_in_hook_specific_output() {
        let response = HookResponse::pre_tool_ask("needs approval".to_string());
        let json = to_json(&response);
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("PreToolUse"));
        assert!(json.contains("\"ask\""));
        assert!(json.contains("needs approval"));
        assert!(!response.is_deny());
    }

    #[test]
    fn test_post_tool_block_sets_decision_at_top_level() {
        let response = HookResponse::post_tool_block("output blocked by policy".to_string());
        let json = to_json(&response);
        // PostToolUse block: decision/reason at top level per VS Code spec
        assert!(json.contains("\"decision\":\"block\""));
        assert!(json.contains("output blocked by policy"));
        assert!(response.is_deny());
    }

    // ── normalize_pre_tool_action tests ──────────────────────────────────────

    #[test]
    fn test_run_terminal_command() {
        let action = normalize_pre_tool_action(
            "runTerminalCommand",
            "call-1",
            "/workspace",
            &json!({"command": "npm test"}),
        );
        match action {
            Action::ShellCommand(cmd) => {
                assert_eq!(cmd.command, "npm test");
                assert_eq!(cmd.working_dir.as_deref(), Some("/workspace"));
            }
            other => panic!("Expected ShellCommand, got {other:?}"),
        }
    }

    #[test]
    fn test_terminal_legacy_name() {
        let action =
            normalize_pre_tool_action("terminal", "call-2", "/ws", &json!({"command": "ls"}));
        assert!(matches!(action, Action::ShellCommand(_)));
    }

    #[test]
    fn test_edit_files_with_file_path() {
        let action = normalize_pre_tool_action(
            "editFiles",
            "call-3",
            "/ws",
            &json!({"filePath": "src/main.rs", "newContent": "fn main() {}"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.path, "src/main.rs");
                assert!(matches!(op.operation, FileOpType::Edit));
                assert_eq!(op.content.as_deref(), Some("fn main() {}"));
            }
            other => panic!("Expected FileOperation(Edit), got {other:?}"),
        }
    }

    #[test]
    fn test_edit_files_with_files_array() {
        let action = normalize_pre_tool_action(
            "editFiles",
            "call-4",
            "/ws",
            &json!({"files": ["src/lib.rs"]}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.path, "src/lib.rs");
                assert!(matches!(op.operation, FileOpType::Edit));
            }
            other => panic!("Expected FileOperation(Edit), got {other:?}"),
        }
    }

    #[test]
    fn test_replace_string_in_file() {
        let action = normalize_pre_tool_action(
            "replace_string_in_file",
            "call-5",
            "/ws",
            &json!({"filePath": "app.rs", "oldStr": "hello", "newStr": "world"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.path, "app.rs");
                assert!(matches!(op.operation, FileOpType::Edit));
                assert_eq!(op.old_content.as_deref(), Some("hello"));
                assert_eq!(op.content.as_deref(), Some("world"));
            }
            other => panic!("Expected FileOperation(Edit), got {other:?}"),
        }
    }

    #[test]
    fn test_create_file() {
        let action = normalize_pre_tool_action(
            "createFile",
            "call-6",
            "/ws",
            &json!({"filePath": "new.rs", "content": "// new file"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.path, "new.rs");
                assert!(matches!(op.operation, FileOpType::Write));
                assert_eq!(op.content.as_deref(), Some("// new file"));
            }
            other => panic!("Expected FileOperation(Write), got {other:?}"),
        }
    }

    #[test]
    fn test_write_file_legacy_name() {
        let action = normalize_pre_tool_action(
            "writeFile",
            "call-7",
            "/ws",
            &json!({"path": "/tmp/out.txt", "content": "data"}),
        );
        assert!(matches!(action, Action::FileOperation(_)));
    }

    #[test]
    fn test_read_file() {
        let action = normalize_pre_tool_action(
            "readFile",
            "call-8",
            "/ws",
            &json!({"filePath": "README.md"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.path, "README.md");
                assert!(matches!(op.operation, FileOpType::Read));
            }
            other => panic!("Expected FileOperation(Read), got {other:?}"),
        }
    }

    #[test]
    fn test_read_files_plural() {
        let action = normalize_pre_tool_action(
            "readFiles",
            "call-9",
            "/ws",
            &json!({"filePath": "src/lib.rs"}),
        );
        assert!(matches!(action, Action::FileOperation(_)));
    }

    #[test]
    fn test_delete_file() {
        let action = normalize_pre_tool_action(
            "deleteFile",
            "call-10",
            "/ws",
            &json!({"filePath": "old.rs"}),
        );
        match action {
            Action::FileOperation(op) => {
                assert_eq!(op.path, "old.rs");
                assert!(matches!(op.operation, FileOpType::Delete));
            }
            other => panic!("Expected FileOperation(Delete), got {other:?}"),
        }
    }

    #[test]
    fn test_unknown_tool_falls_back_to_tool_call() {
        let args = json!({"query": "find all TODOs"});
        let action = normalize_pre_tool_action("mcp__github__search", "call-11", "/ws", &args);
        match action {
            Action::ToolCall(tc) => {
                assert_eq!(tc.tool, "mcp__github__search");
                assert_eq!(tc.arguments, args);
            }
            other => panic!("Expected ToolCall, got {other:?}"),
        }
    }

    // ── Snake_case names, as VS Code actually emits them ─────────────────────
    //
    // The camelCase names above came from the toolset groups in the hooks
    // docs; the tool names on the wire are snake_case. Matching only the
    // former demoted every file call to a generic ToolCall, which reaches
    // Cedar as `PreToolUse` — an action no file policy applies to.

    #[test]
    fn snake_case_read_file_is_a_file_read() {
        let action = normalize_pre_tool_action(
            "read_file",
            "call-12",
            "/ws",
            &json!({"filePath": "/repo/.env", "startLine": 1, "endLine": 200}),
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
    fn snake_case_names_map_like_their_camel_case_spellings() {
        let cases: &[(&str, serde_json::Value, FileOpType)] = &[
            (
                "create_file",
                json!({"filePath": "new.rs", "content": "// new"}),
                FileOpType::Write,
            ),
            (
                "insert_edit_into_file",
                json!({"filePath": "app.rs", "code": "fn main() {}"}),
                FileOpType::Edit,
            ),
            (
                "edit_notebook_file",
                json!({"filePath": "nb.ipynb", "newCode": ""}),
                FileOpType::Edit,
            ),
            (
                "delete_file",
                json!({"filePath": "old.rs"}),
                FileOpType::Delete,
            ),
        ];
        for (tool, args, expected) in cases {
            match normalize_pre_tool_action(tool, "call-13", "/ws", args) {
                Action::FileOperation(op) => {
                    assert_eq!(op.operation, *expected, "{tool}");
                    assert!(!op.path.is_empty(), "{tool} lost its path");
                }
                other => panic!("Expected FileOperation for {tool}, got {other:?}"),
            }
        }
    }

    #[test]
    fn run_in_terminal_is_a_shell_command() {
        let action = normalize_pre_tool_action(
            "run_in_terminal",
            "call-14",
            "/workspace",
            &json!({"command": "cat .env", "isBackground": false}),
        );
        match action {
            Action::ShellCommand(cmd) => {
                assert_eq!(cmd.command, "cat .env");
                assert_eq!(cmd.working_dir.as_deref(), Some("/workspace"));
            }
            other => panic!("Expected ShellCommand, got {other:?}"),
        }
    }

    #[test]
    fn fetch_webpage_is_a_web_fetch() {
        let action = normalize_pre_tool_action(
            "fetch_webpage",
            "call-15",
            "/ws",
            &json!({"urls": ["https://example.com/x"], "query": "api key"}),
        );
        match action {
            Action::WebFetch(fetch) => {
                assert_eq!(fetch.url, "https://example.com/x");
                assert_eq!(fetch.prompt, "api key");
            }
            other => panic!("Expected WebFetch, got {other:?}"),
        }
    }

    #[test]
    fn enumeration_tools_stay_generic() {
        // list_dir and the search tools surface paths rather than file
        // contents, so they are deliberately not modelled as FileRead.
        for tool in ["list_dir", "file_search", "grep_search", "semantic_search"] {
            let action = normalize_pre_tool_action(tool, "call-16", "/ws", &json!({"path": "/ws"}));
            assert!(
                matches!(action, Action::ToolCall(_)),
                "{tool} should stay a generic ToolCall"
            );
        }
    }

    #[test]
    fn every_web_tool_name_is_folded_and_maps_both_ways() {
        // WEB_TOOLS gates both mappers; an unfolded entry never matches, and a
        // name that maps to a WebFetch must report a WebFetchOutput or the
        // fetched body never reaches the webfetch-output policies.
        for name in WEB_TOOLS {
            assert_eq!(&normalize_tool_name(name), name, "{name} is not folded");
            assert!(
                matches!(
                    normalize_pre_tool_action(name, "c", "/ws", &json!({"url": "https://x"})),
                    Action::WebFetch(_)
                ),
                "{name} is in WEB_TOOLS but does not map to a WebFetch"
            );
        }
    }

    #[test]
    fn every_file_tool_name_is_folded() {
        // FILE_TOOLS gates the post-execution mapper; an entry that is not
        // already folded silently never matches.
        for name in FILE_TOOLS {
            assert_eq!(&normalize_tool_name(name), name, "{name} is not folded");
        }
    }

    #[test]
    fn file_tools_agree_across_pre_and_post_mapping() {
        // A tool adjudicated as a FileOperation must report its result as a
        // FileOperationResult, or the content the call returned never reaches
        // the post-execution policies.
        for name in FILE_TOOLS {
            let action = normalize_pre_tool_action(name, "call-17", "/ws", &json!({"path": "f"}));
            assert!(
                matches!(action, Action::FileOperation(_)),
                "{name} is in FILE_TOOLS but does not map to a FileOperation"
            );
        }
    }
}
