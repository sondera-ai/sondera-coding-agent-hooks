//! Sondera hook adapter for VS Code Copilot Chat.
//!
//! Exposes the `sondera hook vscode` subtree: `install` / `uninstall` write
//! `.github/hooks/sondera.json` (local) or `~/.sondera/vscode/hooks/sondera.json`
//! (user) — see [`install`] — and one subcommand per hook event reads that
//! event's JSON on stdin and writes a [`response::HookResponse`] on stdout.
//! [`event`] holds the event matrix.
//!
//! Like the Claude adapter, this crate owns its stdin read, budget, and
//! degraded mapping rather than delegating the whole loop to
//! [`sondera_hooks::runner::resolve_hook`]; every failure still resolves to a
//! degraded response rather than a bare non-zero exit, and preventive events
//! fail closed.
//!
//! Events are attributed to `provider = "microsoft"`, `platform = "vscode"`.

pub mod event;
pub mod hooks;
pub mod install;
pub mod mention;
pub mod response;
pub mod types;

pub use hooks::Hooks;
pub use types::*;

use crate::install::{InstallScope, install_hooks, uninstall_hooks};
use crate::response::HookResponse;
use clap::{Args, Subcommand};
use sondera_harness_client::{Agent, connect_harness_for_hook};
use sondera_hooks::adjudication::fail_closed_reason;
use sondera_hooks::error::{HookError, Result};
use sondera_hooks::event::HookEvent;
use sondera_hooks::runner::resolve_hook;
use sondera_hooks::{agent_id, flush_output, output_response};
use tracing::debug;

/// Build the Agent registration for VS Code Copilot Chat.
///
/// The agent is identified purely by its id, provider, and platform. Hooks
/// normalize raw VS Code events into trajectory tool actions rather than
/// collecting agent capability documents, so no per-session state is loaded.
pub fn get_agent(_session_id: Option<&str>) -> Agent {
    Agent {
        id: agent_id("vscode"),
        provider: "microsoft".to_string(),
        platform: "vscode".to_string(),
    }
}

#[derive(Args, Debug)]
pub struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Install {
        #[arg(short = 'u', long)]
        user: bool,
    },
    Uninstall {
        #[arg(short = 'u', long)]
        user: bool,
    },
    SessionStart,
    UserPromptSubmit,
    PreToolUse,
    PostToolUse,
    PreCompact,
    SubagentStart,
    SubagentStop,
    Stop,
}

/// Build the degraded-mode response when the harness is unavailable,
/// adjudication fails, or the hook times out.
///
/// Adjudication gates fail **closed** with the matching VS Code block shape
/// (enforcement rides on the stdout JSON; the caller still exits 0). SessionStart
/// injects fallback context. Hooks VS Code cannot block (SubagentStart,
/// PreCompact) and the stop hooks — which would loop the agent if forced to
/// block while the harness is down — degrade open.
///
/// The denial text varies with `error` so a timeout or a server-side rejection
/// is not described to the user as a connectivity problem.
fn degraded_response(command: &Commands, error: &HookError) -> HookResponse {
    let reason = fail_closed_reason(error);
    match command {
        Commands::SessionStart => {
            debug!(
                error = %error,
                category = error.category(),
                "VS Code SessionStart fallback suppressed raw harness error from user-facing output"
            );
            HookResponse::session_start_context(error.fallback_context().to_string())
        }
        Commands::PreToolUse => HookResponse::pre_tool_deny(reason.to_string()),
        Commands::UserPromptSubmit => HookResponse::user_prompt_deny(reason.to_string()),
        Commands::PostToolUse => HookResponse::post_tool_block(reason.to_string()),
        Commands::Install { .. }
        | Commands::Uninstall { .. }
        | Commands::SubagentStart
        | Commands::SubagentStop
        | Commands::PreCompact
        | Commands::Stop => HookResponse::allow(),
    }
}

impl HookEvent for Commands {
    fn is_adjudication(&self) -> bool {
        // `SubagentStop` is deliberately absent: `handle_subagent_stop` never
        // calls the harness, so it can never produce a deny. Claiming it as an
        // adjudication gate only made it *block* while the harness was down —
        // enforcement that exists solely in the failure path — and blocking a
        // *stop* forces the subagent to continue rather than preventing an
        // action, the same loop hazard `Stop` degrades open to avoid.
        matches!(
            self,
            Commands::PreToolUse | Commands::UserPromptSubmit | Commands::PostToolUse
        )
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    // Handle install/uninstall early — these don't need stdin or the harness.
    match &cli.command {
        Commands::Install { user } => {
            let scope = if *user {
                InstallScope::User
            } else {
                InstallScope::Local
            };
            return install_hooks(scope, cli.verbose);
        }
        Commands::Uninstall { user } => {
            let scope = if *user {
                InstallScope::User
            } else {
                InstallScope::Local
            };
            return uninstall_hooks(scope);
        }
        _ => {}
    }

    // `resolve_hook` owns the stdin read, the single wall-clock budget, the
    // panic guard, and the error -> `degraded_response` funnel, so a hook VS
    // Code kills never writes an empty decision (which it reads as "no
    // opinion"). The harness connect happens inside dispatch because the agent
    // identity is keyed on the event's `sessionId`.
    let response = resolve_hook(
        cli.command,
        degraded_response,
        || async { Ok::<(), HookError>(()) },
        |(), command, raw_event| async move {
            let session_id: Option<String> = raw_event
                .get("sessionId")
                .or_else(|| raw_event.get("session_id"))
                .and_then(|v| v.as_str())
                .map(String::from);

            let agent = get_agent(session_id.as_deref());
            let harness = connect_harness_for_hook(&agent, "vscode").await?;
            let mut hooks = Hooks::new(harness, agent);

            match command {
                Commands::Install { .. } | Commands::Uninstall { .. } => {
                    unreachable!("install/uninstall handled before dispatch")
                }
                Commands::SessionStart => {
                    let event: SessionStartEvent = serde_json::from_value(raw_event)?;
                    event.validate()?;
                    Ok(hooks.handle_session_start(event).await?)
                }
                Commands::UserPromptSubmit => {
                    let event: UserPromptSubmitEvent = serde_json::from_value(raw_event)?;
                    event.validate()?;
                    Ok(hooks.handle_user_prompt_submit(event).await?)
                }
                Commands::PreToolUse => {
                    let event: PreToolUseEvent = serde_json::from_value(raw_event)?;
                    event.validate()?;
                    Ok(hooks.handle_pre_tool_use(event).await?)
                }
                Commands::PostToolUse => {
                    let event: PostToolUseEvent = serde_json::from_value(raw_event)?;
                    event.validate()?;
                    Ok(hooks.handle_post_tool_use(event).await?)
                }
                Commands::PreCompact => {
                    let event: PreCompactEvent = serde_json::from_value(raw_event)?;
                    event.validate()?;
                    Ok(hooks.handle_pre_compact(event)?)
                }
                Commands::SubagentStart => {
                    let event: SubagentStartEvent = serde_json::from_value(raw_event)?;
                    event.validate()?;
                    Ok(hooks.handle_subagent_start(event)?)
                }
                Commands::SubagentStop => {
                    let event: SubagentStopEvent = serde_json::from_value(raw_event)?;
                    event.validate()?;
                    Ok(hooks.handle_subagent_stop(event)?)
                }
                Commands::Stop => {
                    let event: StopEvent = serde_json::from_value(raw_event)?;
                    event.validate()?;
                    Ok(hooks.handle_stop(event)?)
                }
            }
        },
    )
    .await;

    output_response(response)?;
    flush_output();

    // Always exit 0, even for denials: VS Code only parses the stdout JSON
    // (continue:false / permissionDecision:deny / decision:block) on exit
    // code 0. Exit code 2 makes it discard stdout and surface raw stderr —
    // the tracing WARN lines, including configured endpoint URLs — instead of
    // the sanitized deny message. Worse, on Windows VS Code spawns hooks via
    // Windows PowerShell 5.1, whose `-Command` collapses a native exit code 2
    // to 1, which VS Code treats as a NON-blocking warning — silently ignoring
    // actual policy denials (observed against vscode-copilot-chat hookExecutor.ts).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_harness_client::HarnessClientError;
    use sondera_hooks::runner::assert_fail_closed_matrix;

    fn all_commands() -> Vec<Commands> {
        vec![
            Commands::SessionStart,
            Commands::UserPromptSubmit,
            Commands::PreToolUse,
            Commands::PostToolUse,
            Commands::PreCompact,
            Commands::SubagentStart,
            Commands::SubagentStop,
            Commands::Stop,
        ]
    }

    #[test]
    fn every_adjudication_command_degrades_to_a_deny_for_every_failure_mode() {
        assert_fail_closed_matrix(
            all_commands(),
            Commands::is_adjudication,
            degraded_response,
            HookResponse::is_deny,
        );
    }

    #[test]
    fn a_server_rejection_points_at_the_admin_not_at_connectivity() {
        // The harness answered, so the service is reachable;
        // steering the user at connectivity would waste their time.
        let error = HookError::from(HarnessClientError::Server("schema mismatch".into()));
        let response = degraded_response(&Commands::SessionStart, &error);
        let context = response.hook_specific_output.as_ref().expect("context")["additionalContext"]
            .to_string();

        assert!(context.contains("server-side"));
        assert!(!context.contains("temporarily unavailable"));
    }

    #[test]
    fn stop_degrades_open_to_avoid_loops() {
        // Forcing a block on every degraded Stop would prevent the agent from
        // ever stopping while the harness is down.
        let error = HookError::Unreachable("transport unavailable".into());
        assert!(!degraded_response(&Commands::Stop, &error).is_deny());
    }

    #[test]
    fn degraded_session_start_injects_context() {
        let response = degraded_response(
            &Commands::SessionStart,
            &HookError::Unreachable("down".into()),
        );

        assert!(!response.is_deny());
        let output = response
            .hook_specific_output
            .as_ref()
            .expect("session start should carry guarded degraded context");
        assert_eq!(output["hookEventName"], "SessionStart");
        assert!(output.get("additionalContext").is_some());
    }
}
