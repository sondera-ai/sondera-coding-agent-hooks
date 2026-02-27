//! Gemini CLI hooks for Sondera governance platform.

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
    name = "sondera-gemini",
    version,
    about = "Gemini CLI hooks for Sondera"
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

/// Run the hook adjudication pipeline.
///
/// Connects to the harness, reads the event from stdin, adjudicates it,
/// and writes the response to stdout.
async fn run_hook(cli: Cli) -> Result<()> {
    load_sondera_env()?;
    let harness = connect_harness().await?;
    let mut hooks = Hooks::new(harness, agent_id("gemini"));

    let response = match cli.command {
        Commands::Install { .. }
        | Commands::Uninstall { .. }
        | Commands::BeforeModel
        | Commands::AfterModel => unreachable!(),
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
        Commands::BeforeAgent => {
            let e: BeforeAgentEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_before_agent(e).await?
        }
        Commands::AfterAgent => {
            let e: AfterAgentEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_after_agent(e).await?
        }
        Commands::BeforeToolSelection => {
            let e: BeforeToolSelectionEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_before_tool_selection(e).await?
        }
        Commands::BeforeTool => {
            let e: BeforeToolEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_before_tool(e).await?
        }
        Commands::AfterTool => {
            let e: AfterToolEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_after_tool(e).await?
        }
        Commands::PreCompress => {
            let e: PreCompressEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_pre_compress(e)?
        }
        Commands::Notification => {
            let e: NotificationEvent = read_stdin()?;
            e.validate()?;
            hooks.handle_notification(e)?
        }
    };

    output_response(response)?;
    flush_output();
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing("sondera_gemini", cli.verbose);

    match &cli.command {
        Commands::Install { user, project } => {
            let scope = match (*user, *project) {
                (true, _) => InstallScope::User,
                (_, true) => InstallScope::Project,
                _ => InstallScope::Local,
            };
            if let Err(e) = install_hooks(scope, cli.verbose) {
                eprintln!("{e:#}");
                std::process::exit(1);
            }
            return;
        }
        Commands::Uninstall { user, project } => {
            let scope = match (*user, *project) {
                (true, _) => InstallScope::User,
                (_, true) => InstallScope::Project,
                _ => InstallScope::Local,
            };
            if let Err(e) = uninstall_hooks(scope) {
                eprintln!("{e:#}");
                std::process::exit(1);
            }
            return;
        }
        // BeforeModel/AfterModel are not adjudicated — pass through immediately
        // without connecting to the harness to avoid unnecessary overhead.
        Commands::BeforeModel | Commands::AfterModel => {
            if let Err(e) = output_response(GeminiHookResponse::ok()) {
                eprintln!("{e:#}");
                std::process::exit(2);
            }
            flush_output();
            return;
        }
        _ => {}
    }

    // Fail-closed: any error in the adjudication pipeline aborts the action.
    // Exit code 2 tells Gemini CLI to block the target action and use stderr
    // as the rejection reason.
    if let Err(e) = run_hook(cli).await {
        eprintln!("{e:#}");
        std::process::exit(2);
    }
}
