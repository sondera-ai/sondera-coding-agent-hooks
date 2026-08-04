//! Sondera hook adapter for the Antigravity CLI (`agy`).
//!
//! Antigravity ships its own Claude-Code-style hook protocol (verified against
//! the `agy` binary + official docs), distinct from the Gemini-CLI hooks:
//!
//! | Event | Sondera handling |
//! |-------|------------------|
//! | `PreToolUse` | Adjudicated. Tool call → [`Action`](sondera_harness_client::Action) → harness; decision maps to `allow`/`deny`/`ask`. Fail-closed to `deny`. |
//! | `PostToolUse` | Observation only; records the step result, returns `{}`. |
//! | `PreInvocation` / `PostInvocation` | Advisory no-op (`{}`); no harness round-trip. |
//! | `Stop` | Advisory; allows the stop (`{"decision":"stop"}`). |
//!
//! Reference: <https://antigravity.google/docs/hooks>

pub mod hooks;
pub mod install;
pub mod response;
pub mod types;

pub use hooks::Hooks;
pub use types::*;

use crate::install::{InstallScope, install_hooks, uninstall_hooks};
use crate::response::AntigravityHookResponse;
use clap::{Args, Subcommand};
use sondera_harness_client::connect_harness_for_hook_agent_id;
use sondera_hooks::adjudication::fail_closed_reason;
use sondera_hooks::error::{HookError, Result};
use sondera_hooks::event::HookEvent;
use sondera_hooks::runner::resolve_hook;
use sondera_hooks::{agent_id, flush_output, output_response, read_stdin};

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
        /// Install global user hooks (`~/.gemini/config/hooks.json`).
        #[arg(short = 'u', long, conflicts_with = "workspace")]
        user: bool,
        /// Install workspace hooks for the active project
        /// (`.agents/hooks.json`). This is the default.
        #[arg(short = 'w', long, conflicts_with = "user")]
        workspace: bool,
    },
    Uninstall {
        #[arg(short = 'u', long, conflicts_with = "workspace")]
        user: bool,
        #[arg(short = 'w', long, conflicts_with = "user")]
        workspace: bool,
    },
    PreToolUse,
    PostToolUse,
    PreInvocation,
    PostInvocation,
    Stop,
}

impl HookEvent for Commands {
    fn is_adjudication(&self) -> bool {
        matches!(self, Commands::PreToolUse)
    }
}

/// Workspace is the default when neither `--user` nor `--workspace` is passed,
/// since workspace hooks take precedence over the global file.
fn scope_from_flags(user: bool) -> InstallScope {
    if user {
        InstallScope::User
    } else {
        InstallScope::Workspace
    }
}

/// Fail closed when the harness is unreachable, adjudication errors, or the hook
/// times out: `PreToolUse` is the only enforcement point; `PostToolUse` is
/// observation and degrades open.
fn degraded_response(command: &Commands, error: &HookError) -> AntigravityHookResponse {
    let reason = fail_closed_reason(error);
    match command {
        Commands::PreToolUse => AntigravityHookResponse::deny_tool(reason),
        _ => AntigravityHookResponse::ok(),
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Install { user, .. } => {
            return install_hooks(scope_from_flags(user), cli.verbose);
        }
        Commands::Uninstall { user, .. } => return uninstall_hooks(scope_from_flags(user)),

        // Advisory events: respond without a harness round-trip.
        Commands::PreInvocation => {
            let _e: PreInvocationEvent = read_stdin()?;
            output_response(AntigravityHookResponse::ok())?;
            flush_output();
            return Ok(());
        }
        Commands::PostInvocation => {
            let _e: PostInvocationEvent = read_stdin()?;
            output_response(AntigravityHookResponse::ok())?;
            flush_output();
            return Ok(());
        }
        Commands::Stop => {
            let _e: StopEvent = read_stdin()?;
            // Allow termination; Sondera does not force the loop to continue.
            output_response(AntigravityHookResponse::allow_stop())?;
            flush_output();
            return Ok(());
        }

        // Harness-backed events handled below.
        Commands::PreToolUse | Commands::PostToolUse => {}
    }

    let command = cli.command;
    let response = resolve_hook(
        command,
        degraded_response,
        || async {
            let agent_id = agent_id("antigravity");
            let harness = connect_harness_for_hook_agent_id(&agent_id, "antigravity").await?;
            Ok::<_, HookError>(Hooks::new(harness, agent_id))
        },
        |mut hooks, command, raw| async move {
            let response = match command {
                Commands::PreToolUse => {
                    let e: PreToolUseEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_pre_tool_use(e).await?
                }
                Commands::PostToolUse => {
                    let e: PostToolUseEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_post_tool_use(e).await?
                }
                _ => unreachable!("advisory/install commands handled before dispatch"),
            };
            Ok::<_, HookError>(response)
        },
    )
    .await;

    output_response(response)?;
    flush_output();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_tool_use_degraded_response_fails_closed() {
        assert!(
            degraded_response(
                &Commands::PreToolUse,
                &HookError::Unreachable("harness down".into())
            )
            .is_deny()
        );
    }

    #[test]
    fn post_tool_use_degrades_open() {
        assert!(
            !degraded_response(
                &Commands::PostToolUse,
                &HookError::Unreachable("harness down".into())
            )
            .is_deny()
        );
    }
}
