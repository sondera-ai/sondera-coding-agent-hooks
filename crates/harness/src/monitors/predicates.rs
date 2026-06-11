//! Event predicates for the untrusted-read / protected-write monitor.
//!
//! Each predicate evaluates intrinsic, typed fields of a [`TrajectoryEvent`]
//! variant only: no `event.raw`, no IFC label, no clock. The predicates are
//! pure functions over the event plus injected configuration, so JSONL-order
//! replay of the same event list yields identical results.
//!
//! Arming happens on *output* observations, not actions: a `WebFetch` action
//! does not arm, but its `WebFetchOutput` does. `ShellCommandOutput` and
//! `ToolOutput` do not carry the originating command/tool name, so the caller
//! maintains a `call_id → name` side-table populated via
//! [`populate_pending_call`] from prior `Action` events.

use crate::monitors::config::MonitorConfig;
use crate::types::{Action, Control, Event, FileOpType, Observation, TrajectoryEvent};
use globset::GlobSet;
use std::collections::HashMap;

/// True when the event is an untrusted-read *output* observation.
///
/// - Any `WebFetchOutput` is unconditionally untrusted.
/// - `ShellCommandOutput` is untrusted when its `call_id` resolves (via the
///   `pending_calls` side-table) to a command binary in
///   `config.shell_untrusted_commands`.
/// - `ToolOutput` is untrusted when its `call_id` resolves to a tool name in
///   `config.tool_untrusted_names`.
/// - Everything else (including the `WebFetch` *action*) is not an untrusted
///   read.
pub fn is_untrusted_read(
    event: &Event,
    config: &MonitorConfig,
    pending_calls: &HashMap<String, String>,
) -> bool {
    match &event.event {
        // Any web fetch output is unconditionally untrusted.
        TrajectoryEvent::Observation(Observation::WebFetchOutput(_)) => true,
        // ShellCommandOutput does not carry the command text: resolve the
        // originating binary through the side-table.
        TrajectoryEvent::Observation(Observation::ShellCommandOutput(sco)) => pending_calls
            .get(&sco.call_id)
            .is_some_and(|cmd| is_untrusted_command(cmd, config)),
        // ToolOutput does not carry the tool name: same side-table lookup.
        TrajectoryEvent::Observation(Observation::ToolOutput(to)) => pending_calls
            .get(&to.call_id)
            .is_some_and(|tool| config.tool_untrusted_names.contains(tool)),
        // Think, Prompt, FileOperationResult, all Actions, Control::*,
        // State::Snapshot: not untrusted reads.
        _ => false,
    }
}

/// True when a command binary name is in the configured untrusted set.
fn is_untrusted_command(command: &str, config: &MonitorConfig) -> bool {
    config.shell_untrusted_commands.contains(command)
}

/// Extract a `call_id → tool-or-command-name` side-table entry from an
/// `Action` event, if any.
///
/// - `Action::ToolCall` maps `call_id → tool`.
/// - `Action::ShellCommand` maps `call_id → first shlex token` (the command
///   binary). Returns `None` on malformed (unbalanced-quote) commands.
/// - All other events return `None`.
pub fn populate_pending_call(event: &Event) -> Option<(String, String)> {
    match &event.event {
        TrajectoryEvent::Action(Action::ToolCall(tc)) => {
            Some((tc.call_id.clone(), tc.tool.clone()))
        }
        TrajectoryEvent::Action(Action::ShellCommand(sc)) => {
            let tokens = shlex::split(&sc.command)?;
            let binary = tokens.first()?.clone();
            Some((sc.call_id.clone(), binary))
        }
        _ => None,
    }
}

/// True when the event is an approval signal that clears the armed
/// obligation.
///
/// Double allowlist: ONLY `Control::Resumed` matches, and ONLY when its
/// `resumed_by` is in `config.resume_approved_by` (exact, case-sensitive —
/// default `["user"]`). Anything else — `"system"`, `"agent"`, an empty
/// string, a case mismatch — fails closed. In particular
/// `Control::Adjudicated` — which the harness writes after every non-Control
/// event — must never clear the obligation.
pub fn is_approval(event: &Event, config: &MonitorConfig) -> bool {
    matches!(
        &event.event,
        TrajectoryEvent::Control(Control::Resumed(r))
            if config.resume_approved_by.contains(&r.resumed_by)
    )
}

/// True when the event writes to a protected path.
///
/// - `Action::FileOperation` with `Write` or `Edit` on a path matching the
///   protected glob set. `Read` and `Delete` are NOT writes.
/// - `Action::ShellCommand` via the best-effort
///   [`shell_command_touches_protected_path`] heuristic.
pub fn is_protected_write(event: &Event, _config: &MonitorConfig, glob_set: &GlobSet) -> bool {
    match &event.event {
        TrajectoryEvent::Action(Action::FileOperation(fo)) => {
            // Read and Delete must NOT match.
            matches!(fo.operation, FileOpType::Write | FileOpType::Edit)
                && glob_set.is_match(&fo.path)
        }
        TrajectoryEvent::Action(Action::ShellCommand(sc)) => {
            shell_command_touches_protected_path(&sc.command, glob_set)
        }
        _ => false,
    }
}

/// Shell command binaries whose positional path arguments are treated as
/// write targets by the best-effort heuristic. Redirect targets
/// (`>`, `>>`, `tee`) are always checked regardless of the binary, so a
/// read-only command like `cat .env` does not false-positive.
const WRITE_CAPABLE_COMMANDS: &[&str] = &[
    "cp", "mv", "tee", "dd", "install", "rsync", "truncate", "ln",
];

/// Best-effort heuristic: tokenize the shell command with shlex (same
/// pattern as `cedar::transform::parse_file_paths`) and glob-match redirect
/// targets — plus positional path arguments of write-capable binaries —
/// against the protected glob set.
///
/// A heuristic, not a full shell parser. Returns `false` (never panics) on
/// unbalanced-quote input.
fn shell_command_touches_protected_path(command: &str, glob_set: &GlobSet) -> bool {
    let tokens = match shlex::split(command) {
        Some(t) => t,
        None => return false,
    };
    let binary_writes_path_args = tokens
        .first()
        .is_some_and(|binary| WRITE_CAPABLE_COMMANDS.contains(&binary.as_str()));

    let mut prev_was_redirect = false;
    for (index, token) in tokens.iter().enumerate() {
        if matches!(token.as_str(), ">" | ">>" | "tee") {
            prev_was_redirect = true;
            continue;
        }
        let is_candidate =
            prev_was_redirect || (binary_writes_path_args && index > 0 && looks_like_path(token));
        if is_candidate && glob_set.is_match(token) {
            return true;
        }
        prev_was_redirect = false;
    }
    false
}

/// Cheap path-shaped token check.
fn looks_like_path(token: &str) -> bool {
    token.contains('/') || token.starts_with('.') || token.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        Adjudicated, Agent, FileOperation, Resumed, ShellCommand, ShellCommandOutput, Started,
        ToolCall, ToolOutput, WebFetch, WebFetchOutput,
    };

    fn make_event(event: TrajectoryEvent) -> Event {
        let agent = Agent {
            id: "agent-1".to_string(),
            provider_id: "test".to_string(),
        };
        Event::new(agent, "traj-1", event)
    }

    fn no_pending() -> HashMap<String, String> {
        HashMap::new()
    }

    fn default_glob_set() -> GlobSet {
        MonitorConfig::default().build_glob_set().unwrap()
    }

    #[test]
    fn web_fetch_output_is_untrusted() {
        let config = MonitorConfig::default();
        let event = make_event(TrajectoryEvent::Observation(Observation::WebFetchOutput(
            WebFetchOutput::new("call-1", "https://example.com", 200, "body"),
        )));
        assert!(is_untrusted_read(&event, &config, &no_pending()));
    }

    #[test]
    fn web_fetch_action_is_not_untrusted() {
        // Arm on the OUTPUT observation, not the action.
        let config = MonitorConfig::default();
        let event = make_event(TrajectoryEvent::Action(Action::WebFetch(WebFetch::new(
            "https://example.com",
            "fetch it",
        ))));
        assert!(!is_untrusted_read(&event, &config, &no_pending()));
    }

    #[test]
    fn shell_output_untrusted_via_side_table() {
        let config = MonitorConfig::default();
        let mut pending = HashMap::new();
        pending.insert("call-1".to_string(), "curl".to_string());
        let event = make_event(TrajectoryEvent::Observation(
            Observation::ShellCommandOutput(ShellCommandOutput::new("call-1", 0, "body", "")),
        ));
        assert!(is_untrusted_read(&event, &config, &pending));
    }

    #[test]
    fn shell_output_not_untrusted_safe_command() {
        let config = MonitorConfig::default();
        let mut pending = HashMap::new();
        pending.insert("call-1".to_string(), "ls".to_string());
        let event = make_event(TrajectoryEvent::Observation(
            Observation::ShellCommandOutput(ShellCommandOutput::new("call-1", 0, "files", "")),
        ));
        assert!(!is_untrusted_read(&event, &config, &pending));
    }

    #[test]
    fn tool_output_untrusted_via_side_table() {
        let config = MonitorConfig::default();
        let mut pending = HashMap::new();
        pending.insert("call-1".to_string(), "mcp_fetch".to_string());
        let event = make_event(TrajectoryEvent::Observation(Observation::ToolOutput(
            ToolOutput::success("call-1", serde_json::json!({"ok": true})),
        )));
        assert!(is_untrusted_read(&event, &config, &pending));
    }

    #[test]
    fn populate_pending_call_tool_call() {
        let event = make_event(TrajectoryEvent::Action(Action::ToolCall(ToolCall {
            call_id: "call-1".to_string(),
            tool: "mcp_fetch".to_string(),
            arguments: serde_json::json!({}),
        })));
        assert_eq!(
            populate_pending_call(&event),
            Some(("call-1".to_string(), "mcp_fetch".to_string()))
        );
    }

    #[test]
    fn populate_pending_call_shell_command() {
        let event = make_event(TrajectoryEvent::Action(Action::ShellCommand(
            ShellCommand {
                call_id: "call-2".to_string(),
                command: "curl https://example.com".to_string(),
                working_dir: None,
            },
        )));
        assert_eq!(
            populate_pending_call(&event),
            Some(("call-2".to_string(), "curl".to_string()))
        );
    }

    #[test]
    fn populate_pending_call_noop_for_other_events() {
        let event = make_event(TrajectoryEvent::Control(Control::Resumed(Resumed::new(
            "user",
        ))));
        assert_eq!(populate_pending_call(&event), None);
    }

    #[test]
    fn approval_is_resumed_only() {
        let config = MonitorConfig::default();
        let resumed = make_event(TrajectoryEvent::Control(Control::Resumed(Resumed::new(
            "user",
        ))));
        let adjudicated = make_event(TrajectoryEvent::Control(Control::Adjudicated(
            Adjudicated::allow(),
        )));
        let started = make_event(TrajectoryEvent::Control(Control::Started(Started::new(
            "agent-1",
        ))));
        assert!(is_approval(&resumed, &config));
        assert!(!is_approval(&adjudicated, &config));
        assert!(!is_approval(&started, &config));
    }

    #[test]
    fn approval_default_allowlist_accepts_user() {
        // The default allowlist is exactly ["user"].
        let config = MonitorConfig::default();
        let resumed = make_event(TrajectoryEvent::Control(Control::Resumed(Resumed::new(
            "user",
        ))));
        assert!(is_approval(&resumed, &config));
    }

    #[test]
    fn approval_fail_closed_on_unlisted_resumed_by() {
        // Unknown, empty, and case-mismatched resumed_by values are NOT
        // approvals (fail-closed) — including "User" (case-sensitive).
        let config = MonitorConfig::default();
        for resumed_by in ["system", "agent", "", "User"] {
            let event = make_event(TrajectoryEvent::Control(Control::Resumed(Resumed::new(
                resumed_by,
            ))));
            assert!(
                !is_approval(&event, &config),
                "resumed_by={resumed_by:?} must fail closed"
            );
        }
    }

    #[test]
    fn approval_allowlist_is_config_extensible() {
        // The allowlist is configurable — a custom config can accept
        // additional resumed_by values, and only those values.
        let config = MonitorConfig {
            resume_approved_by: ["reviewer"].iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        let reviewer = make_event(TrajectoryEvent::Control(Control::Resumed(Resumed::new(
            "reviewer",
        ))));
        let user = make_event(TrajectoryEvent::Control(Control::Resumed(Resumed::new(
            "user",
        ))));
        assert!(is_approval(&reviewer, &config));
        assert!(!is_approval(&user, &config));
    }

    #[test]
    fn protected_write_file_op_write() {
        let config = MonitorConfig::default();
        let event = make_event(TrajectoryEvent::Action(Action::FileOperation(
            FileOperation::write(".env", "X=1"),
        )));
        assert!(is_protected_write(&event, &config, &default_glob_set()));
    }

    #[test]
    fn protected_write_file_op_read_is_not_write() {
        let config = MonitorConfig::default();
        let event = make_event(TrajectoryEvent::Action(Action::FileOperation(
            FileOperation::read(".env"),
        )));
        assert!(!is_protected_write(&event, &config, &default_glob_set()));
    }

    #[test]
    fn protected_write_file_op_delete_is_not_write() {
        // Delete is not a write to a protected path.
        let config = MonitorConfig::default();
        let event = make_event(TrajectoryEvent::Action(Action::FileOperation(
            FileOperation::delete(".env"),
        )));
        assert!(!is_protected_write(&event, &config, &default_glob_set()));
    }

    #[test]
    fn protected_write_shell_redirect() {
        let config = MonitorConfig::default();
        let event = make_event(TrajectoryEvent::Action(Action::ShellCommand(
            ShellCommand::new("echo X > .env"),
        )));
        assert!(is_protected_write(&event, &config, &default_glob_set()));
    }

    #[test]
    fn protected_write_shell_cat_is_not_write() {
        // A read-only command touching a protected path is not a write.
        let config = MonitorConfig::default();
        let event = make_event(TrajectoryEvent::Action(Action::ShellCommand(
            ShellCommand::new("cat .env"),
        )));
        assert!(!is_protected_write(&event, &config, &default_glob_set()));
    }

    #[test]
    fn protected_write_shell_write_capable_path_arg() {
        // "path arg" coverage: a write-capable binary with a protected
        // positional path argument trips even without a redirect.
        let config = MonitorConfig::default();
        let event = make_event(TrajectoryEvent::Action(Action::ShellCommand(
            ShellCommand::new("cp config.json .env"),
        )));
        assert!(is_protected_write(&event, &config, &default_glob_set()));
    }

    #[test]
    fn shell_heuristic_unbalanced_quotes() {
        // shlex::split returns None on unbalanced quotes; predicate must be
        // graceful (false), not panic.
        let config = MonitorConfig::default();
        let event = make_event(TrajectoryEvent::Action(Action::ShellCommand(
            ShellCommand::new("echo 'unterminated"),
        )));
        assert!(!is_protected_write(&event, &config, &default_glob_set()));
    }
}
