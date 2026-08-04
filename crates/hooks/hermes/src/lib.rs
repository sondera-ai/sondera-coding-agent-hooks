//! Sondera hook adapter for the Hermes agent.
//!
//! Exposes the `sondera hook hermes` subtree: `install` / `uninstall` add and
//! remove Sondera-managed entries in the `hooks:` block of
//! `~/.hermes/config.yaml` (see [`install`]), leaving third-party entries
//! alone. One subcommand per hook event reads that event's JSON on stdin and
//! writes a [`response::HookResponse`] on stdout.
//!
//! Hermes shell hooks run with the user's full OS credentials, so that `hooks:`
//! block is privileged configuration — review it like CI or cron. Hermes also
//! prompts for consent per `(event, command)` pair on first use; non-interactive
//! gateway sessions need `--auto-accept-all-hooks` at install time, or Hermes'
//! own `--accept-hooks` / `HERMES_ACCEPT_HOOKS=1`.
//!
//! Enforcement is uneven across the event surface, so read
//! `crates/hooks/README.md` before relying on a given hook to block:
//! `pre_tool_call` blocks for real, `pre_llm_call` can only inject steering
//! context, and the transform hooks emit a forward-compatible replacement shape
//! that current Hermes builds do not yet consume.
//!
//! Adjudication runs through [`sondera_hooks::runner::resolve_hook`], so every
//! failure — unreachable harness, malformed event, panic, budget overrun —
//! resolves to a degraded response rather than a bare non-zero exit. Blockable
//! events fail closed.

pub mod hooks;
pub mod install;
pub mod response;
pub mod types;

pub use hooks::Hooks;
pub use types::*;

use crate::install::{install_hooks, uninstall_hooks};
use crate::response::HookResponse;
use clap::{Args, Subcommand};
use hooks::hermes_agent;
use sondera_harness_client::connect_harness_for_hook;
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
        /// Write Hermes-global hooks_auto_accept=true, trusting all shell hooks in the config.
        #[arg(long = "auto-accept-all-hooks", alias = "auto-accept")]
        auto_accept_all_hooks: bool,
    },
    Uninstall,
    #[command(name = "pre_tool_call", alias = "pre-tool-call")]
    PreToolCall,
    #[command(name = "post_tool_call", alias = "post-tool-call")]
    PostToolCall,
    #[command(name = "transform_tool_result", alias = "transform-tool-result")]
    TransformToolResult,
    #[command(name = "pre_llm_call", alias = "pre-llm-call")]
    PreLlmCall,
    #[command(name = "post_llm_call", alias = "post-llm-call")]
    PostLlmCall,
    #[command(name = "transform_llm_output", alias = "transform-llm-output")]
    TransformLlmOutput,
    #[command(
        name = "transform_terminal_output",
        alias = "transform-terminal-output"
    )]
    TransformTerminalOutput,
    #[command(name = "pre_approval_request", alias = "pre-approval-request")]
    PreApprovalRequest,
    #[command(name = "post_approval_response", alias = "post-approval-response")]
    PostApprovalResponse,
    #[command(name = "pre_verify", alias = "pre-verify")]
    PreVerify,
    #[command(name = "on_session_start", alias = "on-session-start")]
    OnSessionStart,
    #[command(name = "on_session_end", alias = "on-session-end")]
    OnSessionEnd,
    #[command(name = "on_session_finalize", alias = "on-session-finalize")]
    OnSessionFinalize,
    #[command(name = "on_session_reset", alias = "on-session-reset")]
    OnSessionReset,
    #[command(name = "subagent_start", alias = "subagent-start")]
    SubagentStart,
    #[command(name = "subagent_stop", alias = "subagent-stop")]
    SubagentStop,
    #[command(name = "pre_gateway_dispatch", alias = "pre-gateway-dispatch")]
    PreGatewayDispatch,
}

impl HookEvent for Commands {
    fn is_adjudication(&self) -> bool {
        matches!(self, Commands::PreToolCall | Commands::PreVerify)
    }
}

/// Fail closed when the harness is unavailable, the payload is invalid,
/// adjudication errors, or the hook times out. `pre_tool_call` blocks the tool;
/// `pre_verify` keeps the turn running. Other shell hooks degrade to `{}`.
fn degraded_response(command: &Commands, error: &HookError) -> HookResponse {
    let reason = fail_closed_reason(error);
    match command {
        Commands::PreToolCall => HookResponse::block(reason),
        Commands::PreVerify => HookResponse::continue_turn(reason),
        _ => HookResponse::ok(),
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Commands::Install {
            auto_accept_all_hooks,
        } => return install_hooks(*auto_accept_all_hooks, cli.verbose),
        Commands::Uninstall => return uninstall_hooks(),
        _ => {}
    }

    let command = cli.command;
    // Hermes derives the agent identity from the parsed event's session id, so
    // the connection happens inside dispatch; `resolve_hook` still enforces the
    // stdin-read, timeout, and error → fail-closed contract around it.
    let response = resolve_hook(
        command,
        degraded_response,
        || async { Ok::<(), HookError>(()) },
        |(), command, raw| async move {
            let event: HermesHookEvent = serde_json::from_value(raw)?;
            let session_id =
                (!event.session_id.trim().is_empty()).then(|| event.session_id.clone());
            let agent = hermes_agent(session_id.as_deref());
            let harness = connect_harness_for_hook(&agent, "hermes").await?;
            let mut hooks = Hooks::new(harness, agent);

            let response = match command {
                Commands::Install { .. } | Commands::Uninstall => {
                    unreachable!("install/uninstall handled before dispatch")
                }
                Commands::PreToolCall => hooks.handle_pre_tool_call(event).await?,
                Commands::PostToolCall => hooks.handle_post_tool_call(event).await?,
                Commands::TransformToolResult => hooks.handle_transform_tool_result(event).await?,
                Commands::PreLlmCall => hooks.handle_pre_llm_call(event).await?,
                Commands::PostLlmCall => hooks.handle_post_llm_call(event).await?,
                Commands::TransformLlmOutput => hooks.handle_transform_llm_output(event).await?,
                Commands::TransformTerminalOutput => {
                    hooks.handle_transform_terminal_output(event).await?
                }
                Commands::PreApprovalRequest => hooks.handle_pre_approval_request(event).await?,
                Commands::PostApprovalResponse => {
                    hooks.handle_post_approval_response(event).await?
                }
                Commands::PreVerify => hooks.handle_pre_verify(event).await?,
                Commands::PreGatewayDispatch => hooks.handle_pre_gateway_dispatch(event).await?,
                Commands::OnSessionStart
                | Commands::OnSessionEnd
                | Commands::OnSessionFinalize
                | Commands::OnSessionReset
                | Commands::SubagentStart
                | Commands::SubagentStop => hooks.handle_lifecycle(event).await?,
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
            Commands::PreToolCall,
            Commands::PostToolCall,
            Commands::TransformToolResult,
            Commands::PreLlmCall,
            Commands::PostLlmCall,
            Commands::TransformLlmOutput,
            Commands::TransformTerminalOutput,
            Commands::PreApprovalRequest,
            Commands::PostApprovalResponse,
            Commands::PreVerify,
            Commands::OnSessionStart,
            Commands::OnSessionEnd,
            Commands::OnSessionFinalize,
            Commands::OnSessionReset,
            Commands::SubagentStart,
            Commands::SubagentStop,
            Commands::PreGatewayDispatch,
        ]
    }

    #[test]
    fn every_adjudication_command_degrades_to_a_deny() {
        assert_fail_closed_matrix(
            all_commands(),
            Commands::is_adjudication,
            degraded_response,
            HookResponse::is_enforcing,
        );
    }
}
