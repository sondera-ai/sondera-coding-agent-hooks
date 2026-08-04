//! Sondera hook adapter for Codex.
//!
//! Exposes the `sondera hook codex` subtree: `install` / `uninstall` write the
//! hook wiring (see [`install`]), and one subcommand per hook event reads that
//! event's JSON on stdin and writes a [`response::HookResponse`] on stdout.
//!
//! Adjudication runs through [`sondera_hooks::runner::resolve_hook`], so every
//! failure — unreachable harness, malformed event, panic, budget overrun —
//! resolves to this provider's degraded response rather than a bare non-zero
//! exit. Preventive events fail closed.
//!
//! Reference: <https://developers.openai.com/codex/>

pub mod hooks;
pub mod install;
pub mod response;
pub mod types;

pub use hooks::Hooks;
pub use types::*;

use crate::install::{install_hooks, uninstall_hooks};
use crate::response::HookResponse;
use clap::{Args, Subcommand};
use sondera_harness_client::{Agent, connect_harness_for_hook};
use sondera_hooks::adjudication::fail_closed_reason;
use sondera_hooks::error::{HookError, Result};
use sondera_hooks::event::HookEvent;
use sondera_hooks::runner::resolve_hook;
use sondera_hooks::{agent_id, flush_output, output_response};

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
        /// Install to user-level ~/.codex/hooks.json (default)
        #[arg(long, conflicts_with = "project")]
        user: bool,
        /// Install to project-level .codex/hooks.json instead of user-level
        #[arg(short = 'p', long)]
        project: bool,
    },
    Uninstall {
        /// Uninstall from user-level ~/.codex/hooks.json (default)
        #[arg(long, conflicts_with = "project")]
        user: bool,
        /// Uninstall from project-level .codex/hooks.json instead of user-level
        #[arg(short = 'p', long)]
        project: bool,
    },
    SessionStart,
    SessionEnd,
    SubagentStart,
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    PreCompact,
    PostCompact,
    UserPromptSubmit,
    SubagentStop,
    Stop,
}

impl HookEvent for Commands {
    fn is_adjudication(&self) -> bool {
        matches!(
            self,
            Commands::PreToolUse | Commands::PermissionRequest | Commands::UserPromptSubmit
        )
    }
}

/// Build the degraded-mode response when the harness is unavailable or
/// adjudication fails. Adjudication hooks fail closed with a structured deny
/// that Codex enforces; observation hooks degrade gracefully to passthrough.
///
/// `is_adjudication()` is the single source of truth for which commands are
/// adjudication-critical: the guarded catch-all denies any such command that
/// lacks an explicit arm above, so adding a new adjudication command can never
/// silently fall through to passthrough (fail open).
fn degraded_response(command: &Commands, error: &HookError) -> HookResponse {
    let reason = fail_closed_reason(error);
    match command {
        Commands::PreToolUse => HookResponse::deny_tool(reason),
        Commands::PermissionRequest => HookResponse::deny_permission(reason),
        Commands::UserPromptSubmit => HookResponse::block_prompt(reason),
        other if other.is_adjudication() => HookResponse::block_prompt(reason),
        _ => HookResponse::ok(),
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Commands::Install { project, user } => {
            let _ = user;
            return install_hooks(*project);
        }
        Commands::Uninstall { project, user } => {
            let _ = user;
            return uninstall_hooks(*project);
        }
        _ => {}
    }

    // `resolve_hook` reads stdin, connects, and dispatches, funneling every
    // failure (malformed event, connect error, handler error, or the harness
    // client's connect/RPC timeout) into `degraded_response` so an adjudication
    // hook never escapes as a bare non-zero exit that Codex would treat as a
    // no-op (fail open).
    let command = cli.command;
    let response = resolve_hook(
        command,
        degraded_response,
        || async {
            let agent = Agent {
                id: agent_id("codex"),
                provider: "openai".to_string(),
                platform: "codex".to_string(),
            };
            let harness = connect_harness_for_hook(&agent, "codex").await?;
            Ok::<_, HookError>(Hooks::new(harness, agent))
        },
        |mut hooks, command, raw| async move {
            let response = match command {
                Commands::Install { .. } | Commands::Uninstall { .. } => {
                    unreachable!("install/uninstall handled before dispatch")
                }
                Commands::SessionStart => {
                    let event: SessionStartEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_session_start(event).await?
                }
                Commands::SessionEnd => {
                    let event: SessionEndEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_session_end(event).await?
                }
                Commands::SubagentStart => {
                    let event: SubagentStartEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_subagent_start(event).await?
                }
                Commands::PreToolUse => {
                    let event: PreToolUseEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_pre_tool_use(event).await?
                }
                Commands::PermissionRequest => {
                    let event: PermissionRequestEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_permission_request(event).await?
                }
                Commands::PostToolUse => {
                    let event: PostToolUseEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_post_tool_use(event).await?
                }
                Commands::PreCompact => {
                    let event: PreCompactEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_compact(event, "PreCompact").await?
                }
                Commands::PostCompact => {
                    let event: PostCompactEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_compact(event, "PostCompact").await?
                }
                Commands::UserPromptSubmit => {
                    let event: UserPromptSubmitEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_user_prompt_submit(event).await?
                }
                Commands::SubagentStop => {
                    let event: SubagentStopEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_subagent_stop(event).await?
                }
                Commands::Stop => {
                    let event: StopEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_stop(event).await?
                }
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
    use crate::response::HookResponse;

    #[test]
    fn degraded_pre_tool_use_fails_closed() {
        assert!(matches!(
            degraded_response(
                &Commands::PreToolUse,
                &HookError::Unreachable("harness down".into())
            ),
            HookResponse::PreToolUse(_)
        ));
    }
}
