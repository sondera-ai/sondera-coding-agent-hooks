//! Claude Code hooks CLI for Sondera governance platform.

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
    name = "sondera-claude",
    version,
    about = "Claude Code hooks for Sondera"
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
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    PostToolUseFailure,
    Notification,
    UserPromptSubmit,
    Stop,
    SubagentStart,
    SubagentStop,
    TeammateIdle,
    TaskCompleted,
    PreCompact,
    SessionStart,
    SessionEnd,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing("sondera_claude", cli.verbose);

    // Handle install/uninstall early — these don't need the harness
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

    load_sondera_env()?;
    let harness = connect_harness().await?;
    let mut hooks = Hooks::new(harness, agent_id("claude"));

    let response = match cli.command {
        Commands::Install { .. } | Commands::Uninstall { .. } => unreachable!(),
        Commands::PreToolUse => hooks.handle_pre_tool_use(read_stdin()?).await?,
        Commands::PermissionRequest => hooks.handle_permission_request(read_stdin()?).await?,
        Commands::PostToolUse => hooks.handle_post_tool_use(read_stdin()?).await?,
        Commands::PostToolUseFailure => hooks.handle_post_tool_use_failure(read_stdin()?).await?,
        Commands::Notification => hooks.handle_notification(read_stdin()?)?,
        Commands::UserPromptSubmit => hooks.handle_user_prompt_submit(read_stdin()?).await?,
        Commands::Stop => hooks.handle_stop(read_stdin()?)?,
        Commands::SubagentStart => hooks.handle_subagent_start(read_stdin()?).await?,
        Commands::SubagentStop => hooks.handle_subagent_stop(read_stdin()?)?,
        Commands::TeammateIdle => hooks.handle_teammate_idle(read_stdin()?)?,
        Commands::TaskCompleted => hooks.handle_task_completed(read_stdin()?)?,
        Commands::PreCompact => hooks.handle_pre_compact(read_stdin()?)?,
        Commands::SessionStart => hooks.handle_session_start(read_stdin()?).await?,
        Commands::SessionEnd => hooks.handle_session_end(read_stdin()?).await?,
    };

    output_response(response)?;
    flush_output();
    Ok(())
}
