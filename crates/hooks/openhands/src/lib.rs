//! Sondera hook adapter for OpenHands.
//!
//! Exposes the `sondera hook openhands` subtree: `install` / `uninstall` write
//! project-level `.openhands/hooks.json` (see [`install`]), and one subcommand
//! per hook event reads that event's JSON on stdin and writes the minimal
//! allow/deny/context
//! [`DecisionEnvelope`](sondera_hooks::response::DecisionEnvelope) on stdout.
//! This adapter has no `response` module of its own — it uses the shared
//! envelope directly.
//!
//! Adjudication runs through [`sondera_hooks::runner::resolve_hook`], so every
//! failure — unreachable harness, malformed event, panic, budget overrun —
//! resolves to a degraded response rather than a bare non-zero exit. Preventive
//! events fail closed.
//!
//! Reference: <https://docs.openhands.dev/>

pub mod hooks;
pub mod install;
pub mod types;

pub use hooks::Hooks;
pub use types::*;

use crate::install::{install_hooks, uninstall_hooks};
use clap::{Args, Subcommand};
use sondera_harness_client::{Agent, connect_harness_for_hook};
use sondera_hooks::adjudication::fail_closed_reason;
use sondera_hooks::error::{HookError, Result};
use sondera_hooks::event::HookEvent;
use sondera_hooks::response::DecisionEnvelope as HookResponse;
use sondera_hooks::runner::resolve_hook;
use sondera_hooks::{agent_id, flush_output, output_response};

/// Build the OpenHands agent identity for this hook invocation.
pub fn get_agent() -> Agent {
    Agent {
        id: agent_id("openhands"),
        provider: "openhands".to_string(),
        platform: "openhands".to_string(),
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
    Install,
    Uninstall,
    SessionStart,
    PreToolUse,
    PostToolUse,
    UserPromptSubmit,
    Stop,
    SessionEnd,
}

impl HookEvent for Commands {
    fn is_adjudication(&self) -> bool {
        matches!(
            self,
            Commands::PreToolUse | Commands::UserPromptSubmit | Commands::Stop
        )
    }
}

/// Fail closed for adjudication hooks when the harness is unavailable, the
/// payload is invalid, adjudication errors, or the hook times out; observation
/// hooks degrade to a passthrough `{}`.
fn degraded_response(command: &Commands, error: &HookError) -> HookResponse {
    let reason = fail_closed_reason(error);
    if command.is_adjudication() {
        HookResponse::deny(reason)
    } else {
        HookResponse::ok()
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Commands::Install => return install_hooks(),
        Commands::Uninstall => return uninstall_hooks(),
        _ => {}
    }

    let command = cli.command;
    let response = resolve_hook(
        command,
        degraded_response,
        || async {
            let agent = get_agent();
            let harness = connect_harness_for_hook(&agent, "openhands").await?;
            Ok::<_, HookError>(Hooks::new(harness, agent))
        },
        |mut hooks, command, raw| async move {
            let response = match command {
                Commands::Install | Commands::Uninstall => {
                    unreachable!("install/uninstall handled before dispatch")
                }
                Commands::SessionStart => {
                    let event: SessionStartEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_session_start(event).await?
                }
                Commands::PreToolUse => {
                    let event: PreToolUseEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_pre_tool_use(event).await?
                }
                Commands::PostToolUse => {
                    let event: PostToolUseEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_post_tool_use(event).await?
                }
                Commands::UserPromptSubmit => {
                    let event: UserPromptSubmitEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_user_prompt_submit(event).await?
                }
                Commands::Stop => {
                    let event: StopEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_stop(event).await?
                }
                Commands::SessionEnd => {
                    let event: SessionEndEvent = serde_json::from_value(raw)?;
                    event.validate()?;
                    hooks.handle_session_end(event).await?
                }
            };
            Ok::<_, HookError>(response)
        },
    )
    .await;

    // OpenHands enforces a block via exit code 2 with the decision JSON on stdout.
    let denied = response.is_deny();
    output_response(response)?;
    flush_output();
    if denied {
        std::process::exit(2);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_hooks::runner::assert_fail_closed_matrix;

    fn all_commands() -> Vec<Commands> {
        vec![
            Commands::SessionStart,
            Commands::PreToolUse,
            Commands::PostToolUse,
            Commands::UserPromptSubmit,
            Commands::Stop,
            Commands::SessionEnd,
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
