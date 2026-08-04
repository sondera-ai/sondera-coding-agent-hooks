//! Sondera hook adapter for Cursor.
//!
//! Exposes the `sondera hook cursor` subtree: `install` / `uninstall` write
//! `hooks.json` at user or project scope (see [`install`]), and one subcommand
//! per hook event reads that event's JSON on stdin and writes a
//! [`response::HookResponse`] on stdout.
//!
//! Adjudication runs through [`sondera_hooks::runner::resolve_hook`], so every
//! failure — unreachable harness, malformed event, panic, budget overrun —
//! resolves to this provider's degraded response rather than a bare non-zero
//! exit. Preventive events fail closed; Cursor reads a denial from the process
//! exiting `2`, not from the response body alone.
//!
//! Reference: <https://cursor.com/docs/agent/hooks>

pub mod hooks;
pub mod install;
pub mod response;
pub mod types;

pub use hooks::{Hooks, handle_workspace_open};
pub use types::*;

use crate::install::{InstallScope, install_hooks, uninstall_hooks};
use crate::response::HookResponse;
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
    PreToolUse,
    PostToolUse,
    PostToolUseFailure,
    SubagentStart,
    SubagentStop,
    BeforeShellExecution,
    AfterShellExecution,
    BeforeMCPExecution,
    AfterMCPExecution,
    BeforeReadFile,
    AfterFileEdit,
    BeforeSubmitPrompt,
    AfterAgentResponse,
    AfterAgentThought,
    PreCompact,
    Stop,
    BeforeTabFileRead,
    AfterTabFileEdit,
    WorkspaceOpen,
}

impl HookEvent for Commands {
    fn is_adjudication(&self) -> bool {
        matches!(
            self,
            Commands::PreToolUse
                | Commands::BeforeShellExecution
                | Commands::BeforeMCPExecution
                | Commands::BeforeReadFile
                | Commands::BeforeSubmitPrompt
                | Commands::BeforeTabFileRead
                | Commands::SubagentStart
        )
    }
}

/// Fail-closed response for a command when the harness is unavailable,
/// adjudication errors, or the hook times out.
///
/// Enforcement gates (`is_adjudication`) deny with the matching Cursor response
/// variant so the deny is well-formed for that hook; observation and lifecycle
/// hooks degrade to a passthrough `{}` because Cursor cannot block them.
fn degraded_response(command: &Commands, error: &HookError) -> HookResponse {
    let reason = fail_closed_reason(error);
    match command {
        Commands::PreToolUse => HookResponse::deny_tool_use(reason),
        Commands::BeforeShellExecution | Commands::BeforeMCPExecution => {
            HookResponse::deny_execution(reason)
        }
        Commands::BeforeReadFile => HookResponse::deny_read_file(reason),
        Commands::BeforeSubmitPrompt => HookResponse::block_prompt(reason),
        Commands::BeforeTabFileRead => HookResponse::deny_tab_read(),
        Commands::SubagentStart => HookResponse::subagent_start_deny(reason),
        // Observation / lifecycle hooks Cursor cannot block: degrade to passthrough.
        _ => HookResponse::ok(),
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Commands::Install { user, .. } => {
            let scope = if *user {
                InstallScope::User
            } else {
                InstallScope::Project
            };
            return install_hooks(scope, cli.verbose);
        }
        Commands::Uninstall { user, .. } => {
            let scope = if *user {
                InstallScope::User
            } else {
                InstallScope::Project
            };
            return uninstall_hooks(scope);
        }
        // WorkspaceOpen is not an adjudication hook and connects to no harness;
        // handle it directly.
        Commands::WorkspaceOpen => {
            let e: WorkspaceOpenEvent = read_stdin()?;
            e.validate()?;
            output_response(handle_workspace_open(e))?;
            flush_output();
            return Ok(());
        }
        _ => {}
    }

    let command = cli.command;
    let response = resolve_hook(
        command,
        degraded_response,
        || async {
            let agent_id = agent_id("cursor");
            let harness = connect_harness_for_hook_agent_id(&agent_id, "cursor").await?;
            Ok::<_, HookError>(Hooks::new(harness, agent_id))
        },
        |mut hooks, command, raw| async move {
            let response = match command {
                Commands::Install { .. } | Commands::Uninstall { .. } | Commands::WorkspaceOpen => {
                    unreachable!("install/uninstall/workspace-open handled before dispatch")
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
                Commands::PostToolUseFailure => {
                    let e: PostToolUseFailureEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_post_tool_use_failure(e).await?
                }
                Commands::SubagentStart => {
                    let e: SubagentStartEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_subagent_start(e).await?
                }
                Commands::SubagentStop => {
                    let e: SubagentStopEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_subagent_stop(e).await?
                }
                Commands::BeforeShellExecution => {
                    let e: BeforeShellExecutionEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_before_shell_execution(e).await?
                }
                Commands::AfterShellExecution => {
                    let e: AfterShellExecutionEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_after_shell_execution(e).await?
                }
                Commands::BeforeMCPExecution => {
                    let e: BeforeMCPExecutionEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_before_mcp_execution(e).await?
                }
                Commands::AfterMCPExecution => {
                    let e: AfterMCPExecutionEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_after_mcp_execution(e).await?
                }
                Commands::BeforeReadFile => {
                    let e: BeforeReadFileEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_before_read_file(e).await?
                }
                Commands::AfterFileEdit => {
                    let e: AfterFileEditEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_after_file_edit(e).await?
                }
                Commands::BeforeSubmitPrompt => {
                    let e: BeforeSubmitPromptEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_before_submit_prompt(e).await?
                }
                Commands::AfterAgentResponse => {
                    let e: AfterAgentResponseEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_after_agent_response(e).await?
                }
                Commands::AfterAgentThought => {
                    let e: AfterAgentThoughtEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_after_agent_thought(e).await?
                }
                Commands::PreCompact => {
                    let e: PreCompactEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_pre_compact(e).await?
                }
                Commands::Stop => {
                    let e: StopEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_stop(e).await?
                }
                Commands::BeforeTabFileRead => {
                    let e: BeforeTabFileReadEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_before_tab_file_read(e).await?
                }
                Commands::AfterTabFileEdit => {
                    let e: AfterTabFileEditEvent = serde_json::from_value(raw)?;
                    e.validate()?;
                    hooks.handle_after_tab_file_edit(e).await?
                }
            };
            Ok::<_, HookError>(response)
        },
    )
    .await;

    // Cursor enforces a block via process exit code 2 (with the decision JSON on
    // stdout); a successful allow exits 0.
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
            Commands::SessionEnd,
            Commands::PreToolUse,
            Commands::PostToolUse,
            Commands::PostToolUseFailure,
            Commands::SubagentStart,
            Commands::SubagentStop,
            Commands::BeforeShellExecution,
            Commands::AfterShellExecution,
            Commands::BeforeMCPExecution,
            Commands::AfterMCPExecution,
            Commands::BeforeReadFile,
            Commands::AfterFileEdit,
            Commands::BeforeSubmitPrompt,
            Commands::AfterAgentResponse,
            Commands::AfterAgentThought,
            Commands::PreCompact,
            Commands::Stop,
            Commands::BeforeTabFileRead,
            Commands::AfterTabFileEdit,
            Commands::WorkspaceOpen,
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
