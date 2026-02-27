//! Cursor hooks CLI for Sondera governance platform.

use anyhow::Result;
use clap::{Parser, Subcommand};
use sondera_hooks_common::{
    agent_id, connect_harness, flush_output, init_tracing, load_sondera_env, output_response,
    read_stdin,
};

mod app;
use app::*;

#[derive(Parser, Debug)]
#[command(name = "sondera-cursor", version, about = "Cursor hooks for Sondera")]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing("sondera_cursor", cli.verbose);

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
        _ => {}
    }

    load_sondera_env()?;
    let harness = connect_harness().await?;
    let mut hooks = Hooks::new(harness, agent_id("cursor"));

    let response = match cli.command {
        Commands::Install { .. } | Commands::Uninstall { .. } => unreachable!(),
        Commands::SessionStart => {
            let e: SessionStartEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_session_start(e).await?
        }
        Commands::SessionEnd => {
            let e: SessionEndEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_session_end(e).await?
        }
        Commands::PreToolUse => {
            let e: PreToolUseEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_pre_tool_use(e).await?
        }
        Commands::PostToolUse => {
            let e: PostToolUseEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_post_tool_use(e).await?
        }
        Commands::PostToolUseFailure => {
            let e: PostToolUseFailureEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_post_tool_use_failure(e).await?
        }
        Commands::SubagentStart => {
            let e: SubagentStartEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_subagent_start(e).await?
        }
        Commands::SubagentStop => {
            let e: SubagentStopEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_subagent_stop(e).await?
        }
        Commands::BeforeShellExecution => {
            let e: BeforeShellExecutionEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_before_shell_execution(e).await?
        }
        Commands::AfterShellExecution => {
            let e: AfterShellExecutionEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_after_shell_execution(e).await?
        }
        Commands::BeforeMCPExecution => {
            let e: BeforeMCPExecutionEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_before_mcp_execution(e).await?
        }
        Commands::AfterMCPExecution => {
            let e: AfterMCPExecutionEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_after_mcp_execution(e).await?
        }
        Commands::BeforeReadFile => {
            let e: BeforeReadFileEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_before_read_file(e).await?
        }
        Commands::AfterFileEdit => {
            let e: AfterFileEditEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_after_file_edit(e).await?
        }
        Commands::BeforeSubmitPrompt => {
            let e: BeforeSubmitPromptEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_before_submit_prompt(e).await?
        }
        Commands::AfterAgentResponse => {
            let e: AfterAgentResponseEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_after_agent_response(e).await?
        }
        Commands::AfterAgentThought => {
            let e: AfterAgentThoughtEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_after_agent_thought(e).await?
        }
        Commands::PreCompact => {
            let e: PreCompactEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_pre_compact(e).await?
        }
        Commands::Stop => {
            let e: StopEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_stop(e).await?
        }
        Commands::BeforeTabFileRead => {
            let e: BeforeTabFileReadEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_before_tab_file_read(e).await?
        }
        Commands::AfterTabFileEdit => {
            let e: AfterTabFileEditEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_after_tab_file_edit(e).await?
        }
    };

    let denied = response.is_deny();
    output_response(response)?;
    flush_output();

    // Cursor uses exit code 2 to enforce blocks/denials.
    if denied {
        std::process::exit(2);
    }

    Ok(())
}
