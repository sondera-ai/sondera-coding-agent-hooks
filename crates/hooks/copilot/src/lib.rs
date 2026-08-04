//! Sondera hook adapter for the GitHub Copilot CLI.
//!
//! Exposes the `sondera hook copilot` subtree: `install` / `uninstall` write
//! the hook wiring (see [`install`]), and one subcommand per hook event reads
//! that event's JSON on stdin and writes a [`response::HookResponse`] on
//! stdout. [`event`] holds the event matrix.
//!
//! Adjudication runs through [`sondera_hooks::runner::resolve_hook`], so every
//! failure — unreachable harness, malformed event, panic, budget overrun —
//! resolves to this provider's degraded response rather than a bare non-zero
//! exit. Preventive events fail closed.
//!
//! Reference: <https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks>

pub mod event;
pub mod hooks;
pub mod install;
pub mod response;
pub mod types;

pub use hooks::Hooks;
pub use types::*;

use crate::install::{InstallScope, install_hooks, uninstall_hooks};
use crate::response::HookResponse;
use clap::{Args, Subcommand};
use sondera_harness_client::{HarnessGrpcClient, connect_harness_for_hook_agent_id};
use sondera_hooks::adjudication::fail_closed_reason;
use sondera_hooks::error::{HookError, Result};
use sondera_hooks::event::HookEvent;
use sondera_hooks::runner::resolve_hook;
use sondera_hooks::{flush_output, output_response};

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
        #[arg(short = 'u', long, conflicts_with = "project")]
        user: bool,
        #[arg(short = 'p', long, conflicts_with = "user")]
        project: bool,
    },
    Uninstall {
        #[arg(short = 'u', long, conflicts_with = "project")]
        user: bool,
        #[arg(short = 'p', long, conflicts_with = "user")]
        project: bool,
    },
    SessionStart,
    SessionEnd,
    UserPromptSubmitted,
    UserPromptTransformed,
    PreToolUse,
    PostToolUse,
    PermissionRequest,
    PostToolUseFailure,
    AgentStop,
    Notification,
    PreCompact,
    SubagentStart,
    SubagentStop,
    ErrorOccurred,
}

impl HookEvent for Commands {
    fn is_adjudication(&self) -> bool {
        matches!(
            self,
            Commands::PreToolUse | Commands::PermissionRequest | Commands::UserPromptTransformed
        )
    }
}

/// Fail-closed response for a command when the harness is unavailable,
/// adjudication errors, or the hook times out.
///
/// `preToolUse` and `permissionRequest` deny with their matching response
/// shapes. `userPromptTransformed` fails closed by replacing model-facing
/// content. Every other event degrades to a passthrough `{}`.
fn degraded_response(command: &Commands, error: &HookError) -> HookResponse {
    let reason = fail_closed_reason(error);
    match command {
        Commands::PreToolUse => HookResponse::block_tool(reason),
        Commands::PermissionRequest => HookResponse::permission_deny(reason),
        Commands::UserPromptTransformed => HookResponse::replace_transformed_prompt(format!(
            "[Sondera policy withheld this prompt because governance was unavailable: {reason}]"
        )),
        _ => HookResponse::ok(),
    }
}

async fn connect_harness() -> Result<HarnessGrpcClient> {
    let agent_id = sondera_hooks::agent_id("copilot");
    Ok(connect_harness_for_hook_agent_id(&agent_id, "copilot").await?)
}

pub async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Commands::Install { user, project: _ } => {
            let scope = if *user {
                InstallScope::User
            } else {
                InstallScope::Project
            };
            return install_hooks(scope, cli.verbose);
        }
        Commands::Uninstall { user, project: _ } => {
            let scope = if *user {
                InstallScope::User
            } else {
                InstallScope::Project
            };
            return uninstall_hooks(scope);
        }
        _ => {}
    }

    let command = cli.command;
    let response = resolve_hook(
        command,
        degraded_response,
        connect_harness,
        |harness, command, raw| async move {
            let response = match command {
                Commands::Install { .. } | Commands::Uninstall { .. } => {
                    unreachable!("install/uninstall handled before dispatch")
                }
                Commands::SessionStart => {
                    let event: SessionStartEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_session_start(event).await?
                }
                Commands::SessionEnd => {
                    let event: SessionEndEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_session_end(event).await?
                }
                Commands::UserPromptSubmitted => {
                    let event: UserPromptSubmittedEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_user_prompt_submitted(event).await?
                }
                Commands::UserPromptTransformed => {
                    let event: UserPromptTransformedEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_user_prompt_transformed(event).await?
                }
                Commands::PreToolUse => {
                    let event: PreToolUseEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_pre_tool_use(event).await?
                }
                Commands::PostToolUse => {
                    let event: PostToolUseEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.tool.common.session_id.as_deref());
                    hooks.handle_post_tool_use(event).await?
                }
                Commands::PermissionRequest => {
                    let event: PermissionRequestEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_permission_request(event).await?
                }
                Commands::PostToolUseFailure => {
                    let event: PostToolUseFailureEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.tool.common.session_id.as_deref());
                    hooks.handle_post_tool_use_failure(event).await?
                }
                Commands::AgentStop => {
                    let event: AgentStopEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_agent_stop(event).await?
                }
                Commands::Notification => {
                    let event: NotificationEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_notification(event).await?
                }
                Commands::PreCompact => {
                    let event: PreCompactEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_pre_compact(event).await?
                }
                Commands::SubagentStart => {
                    let event: SubagentStartEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_subagent_start(event).await?
                }
                Commands::SubagentStop => {
                    let event: SubagentStopEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_subagent_stop(event).await?
                }
                Commands::ErrorOccurred => {
                    let event: ErrorOccurredEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    let mut hooks = Hooks::new(harness, event.common.session_id.as_deref());
                    hooks.handle_error_occurred(event).await?
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
    use sondera_hooks::runner::assert_fail_closed_matrix;

    fn all_commands() -> Vec<Commands> {
        vec![
            Commands::SessionStart,
            Commands::SessionEnd,
            Commands::UserPromptSubmitted,
            Commands::UserPromptTransformed,
            Commands::PreToolUse,
            Commands::PostToolUse,
            Commands::PermissionRequest,
            Commands::PostToolUseFailure,
            Commands::AgentStop,
            Commands::Notification,
            Commands::PreCompact,
            Commands::SubagentStart,
            Commands::SubagentStop,
            Commands::ErrorOccurred,
        ]
    }

    #[test]
    fn every_adjudication_command_degrades_to_a_deny() {
        assert_fail_closed_matrix(
            all_commands(),
            Commands::is_adjudication,
            degraded_response,
            HookResponse::is_deny,
        );
    }
}
