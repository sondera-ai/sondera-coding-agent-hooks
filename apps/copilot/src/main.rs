//! GitHub Copilot hooks CLI for Sondera governance platform.

use anyhow::Result;
use clap::{Parser, Subcommand};
use sondera_hooks_common::{
    agent_id, connect_harness, flush_output, init_tracing, load_sondera_env, output_response,
    read_stdin,
};

mod app;
use app::*;

#[derive(Parser, Debug)]
#[command(
    name = "sondera-copilot",
    version,
    about = "GitHub Copilot hooks for Sondera"
)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Install {
        #[arg(short = 'p', long)]
        project: bool,
    },
    Uninstall {
        #[arg(short = 'p', long)]
        project: bool,
    },
    SessionStart,
    SessionEnd,
    UserPromptSubmitted,
    PreToolUse,
    PostToolUse,
    ErrorOccurred,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing("sondera_copilot", cli.verbose);

    match &cli.command {
        Commands::Install { project: _ } => return install_hooks(cli.verbose),
        Commands::Uninstall { project: _ } => return uninstall_hooks(),
        _ => {}
    }

    load_sondera_env()?;
    let harness = connect_harness().await?;
    let mut hooks = Hooks::new(harness, agent_id("copilot"));

    let response = match cli.command {
        Commands::Install { .. } | Commands::Uninstall { .. } => unreachable!(),
        Commands::SessionStart => {
            let event: SessionStartEvent = read_stdin()?;
            event.validate()?;
            hooks.handle_session_start(event).await?
        }
        Commands::SessionEnd => {
            let event: SessionEndEvent = read_stdin()?;
            event.validate()?;
            hooks.handle_session_end(event).await?
        }
        Commands::UserPromptSubmitted => {
            let event: UserPromptSubmittedEvent = read_stdin()?;
            event.validate()?;
            hooks.handle_user_prompt_submitted(event).await?
        }
        Commands::PreToolUse => {
            let event: PreToolUseEvent = read_stdin()?;
            event.validate()?;
            hooks.handle_pre_tool_use(event).await?
        }
        Commands::PostToolUse => {
            let event: PostToolUseEvent = read_stdin()?;
            event.validate()?;
            hooks.handle_post_tool_use(event).await?
        }
        Commands::ErrorOccurred => {
            let event: ErrorOccurredEvent = read_stdin()?;
            event.validate()?;
            hooks.handle_error_occurred(event).await?
        }
    };

    output_response(response)?;
    flush_output();
    Ok(())
}
