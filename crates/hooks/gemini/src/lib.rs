//! Sondera hook adapter for the Gemini CLI.
//!
//! Exposes the `sondera hook gemini` subtree: `install` / `uninstall` write the
//! hook block into `settings.json` at user, project, or local scope (see
//! [`install`]), and one subcommand per hook event reads that event's JSON on
//! stdin and writes a [`response::GeminiHookResponse`] on stdout.
//!
//! Distinct from the Antigravity CLI, which ships a Claude-Code-style protocol
//! and has its own adapter in `sondera-antigravity`.
//!
//! Adjudication runs through [`sondera_hooks::runner::resolve_hook`], so every
//! failure — unreachable harness, malformed event, panic, budget overrun —
//! resolves to this provider's degraded response rather than a bare non-zero
//! exit. Preventive events fail closed.
//!
//! Reference: <https://geminicli.com/docs/hooks/>

pub mod hooks;
pub mod install;
pub mod response;
pub mod types;

pub use hooks::Hooks;
pub use types::*;

use crate::install::{InstallScope, install_hooks, uninstall_hooks};
use crate::response::GeminiHookResponse;
use clap::{Args, Subcommand};
use sondera_harness_client::connect_harness_for_hook_agent_id;
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
    BeforeAgent,
    AfterAgent,
    BeforeModel,
    AfterModel,
    BeforeToolSelection,
    BeforeTool,
    AfterTool,
    PreCompress,
    Notification,
}

impl HookEvent for Commands {
    fn is_adjudication(&self) -> bool {
        matches!(
            self,
            Commands::BeforeAgent
                | Commands::BeforeModel
                | Commands::AfterModel
                | Commands::BeforeToolSelection
                | Commands::BeforeTool
        )
    }
}

/// Fail-closed response for a command when the harness is unavailable,
/// adjudication errors, or the hook times out.
///
/// Enforcement gates deny with the matching Gemini shape: `BeforeAgent` /
/// `BeforeTool` set `decision: deny`, while `BeforeToolSelection` — which has no
/// `decision` field — fails closed by forcing tool mode `NONE` (no tool may
/// run). Advisory/retrospective hooks degrade to a passthrough `{}`.
fn degraded_response(command: &Commands, error: &HookError) -> GeminiHookResponse {
    let reason = fail_closed_reason(error);
    match command {
        Commands::BeforeAgent
        | Commands::BeforeModel
        | Commands::AfterModel
        | Commands::BeforeTool => GeminiHookResponse::deny(reason),
        Commands::BeforeToolSelection => GeminiHookResponse::disable_all_tools(reason),
        _ => GeminiHookResponse::ok(),
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Commands::Install { user, project } => {
            let scope = match (*user, *project) {
                (true, _) => InstallScope::User,
                (_, true) => InstallScope::Project,
                _ => InstallScope::Local,
            };
            return install_hooks(scope, cli.verbose);
        }
        Commands::Uninstall { user, project } => {
            let scope = match (*user, *project) {
                (true, _) => InstallScope::User,
                (_, true) => InstallScope::Project,
                _ => InstallScope::Local,
            };
            return uninstall_hooks(scope);
        }
        _ => {}
    }

    let command = cli.command;
    let response = resolve_hook(
        command,
        degraded_response,
        || async {
            let agent_id = agent_id("gemini");
            let harness = connect_harness_for_hook_agent_id(&agent_id, "gemini").await?;
            Ok::<_, HookError>(Hooks::new(harness, agent_id))
        },
        |mut hooks, command, raw| async move {
            let response = match command {
                Commands::Install { .. } | Commands::Uninstall { .. } => {
                    unreachable!("install/uninstall handled before dispatch")
                }
                Commands::SessionStart => {
                    let e: SessionStartEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_session_start(e).await?
                }
                Commands::SessionEnd => {
                    let e: SessionEndEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_session_end(e).await?
                }
                Commands::BeforeAgent => {
                    let e: BeforeAgentEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_before_agent(e).await?
                }
                Commands::AfterAgent => {
                    let e: AfterAgentEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_after_agent(e).await?
                }
                Commands::BeforeModel => {
                    let e: BeforeModelEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_before_model(e).await?
                }
                Commands::AfterModel => {
                    let e: AfterModelEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_after_model(e).await?
                }
                Commands::BeforeToolSelection => {
                    let e: BeforeToolSelectionEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_before_tool_selection(e).await?
                }
                Commands::BeforeTool => {
                    let e: BeforeToolEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_before_tool(e).await?
                }
                Commands::AfterTool => {
                    let e: AfterToolEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_after_tool(e).await?
                }
                Commands::PreCompress => {
                    let e: PreCompressEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_pre_compress(e)?
                }
                Commands::Notification => {
                    let e: NotificationEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_notification(e)?
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
            Commands::BeforeAgent,
            Commands::AfterAgent,
            Commands::BeforeModel,
            Commands::AfterModel,
            Commands::BeforeToolSelection,
            Commands::BeforeTool,
            Commands::AfterTool,
            Commands::PreCompress,
            Commands::Notification,
        ]
    }

    #[test]
    fn every_adjudication_command_degrades_to_a_deny() {
        assert_fail_closed_matrix(
            all_commands(),
            Commands::is_adjudication,
            degraded_response,
            GeminiHookResponse::is_deny,
        );
    }
}
