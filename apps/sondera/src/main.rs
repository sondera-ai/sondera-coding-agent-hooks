//! Unified Sondera CLI.
//!
//! Top-level subcommands:
//! - `hook` — one nested subcommand per coding-agent provider (`claude`,
//!   `copilot`, `cursor`, …), each forwarding to that provider crate's
//!   `run(Cli)`. The invocation is `sondera hook <provider> <event>`, matching
//!   the command the installer bakes into the host IDE's settings.
//! - `serve` — runs both gRPC surfaces on one port: the `sondera.harness.v1`
//!   service backed by the Cedar policy engine, and the `sondera.console.v1`
//!   read surface over the same store.
//! - `mcp` — runs Cedar authoring and unary console tools over MCP stdio,
//!   reading the console over gRPC rather than opening the store.
//! - `tui` — the terminal reading view over a running `serve`'s console
//!   surface: the trajectory feed and one run's event transcript.

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Parser, Debug)]
#[command(
    name = "sondera",
    bin_name = "sondera",
    version,
    about = "Unified Sondera CLI: coding-agent hook adapters and the Sondera server"
)]
struct Cli {
    /// Increase output detail.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Coding-agent hook CLI entrypoints.
    Hook {
        #[command(subcommand)]
        provider: HookCommand,
    },
    /// Run the harness and console gRPC services on one address.
    Serve(ServeArgs),
    /// Run the Cedar policy and console MCP server on stdio.
    Mcp(McpArgs),
    /// Browse trajectories and their event transcripts in the terminal.
    ///
    /// Reads the console gRPC surface of a running `sondera serve`; start one
    /// first, or point `--endpoint` at an existing instance.
    Tui(sondera_tui::TuiArgs),
}

/// Per-provider hook CLIs. Each variant wraps that provider crate's `Cli`.
#[derive(Subcommand, Debug)]
enum HookCommand {
    /// Antigravity hooks.
    Antigravity(sondera_antigravity::Cli),
    /// Claude Code hooks.
    Claude(sondera_claude::Cli),
    /// Codex hooks.
    Codex(sondera_codex::Cli),
    /// GitHub Copilot CLI hooks.
    Copilot(sondera_copilot::Cli),
    /// Cursor hooks.
    Cursor(sondera_cursor::Cli),
    /// Gemini CLI hooks.
    Gemini(sondera_gemini::Cli),
    /// Hermes agent shell-hook commands.
    Hermes(sondera_hermes::Cli),
    /// OpenCode hooks.
    Opencode(sondera_opencode::Cli),
    /// OpenHands hooks.
    Openhands(sondera_openhands::Cli),
    /// VS Code hooks.
    Vscode(sondera_vscode::Cli),
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// Address to bind both services to.
    ///
    /// Falls back to `harness.addr` in `sondera.toml`, then
    /// `SONDERA_HARNESS_ADDR`, then 127.0.0.1:50051 — the endpoint hook clients
    /// already dial.
    ///
    /// Neither service authenticates its caller: every caller adjudicates
    /// against the same policies and reads the whole local store. Keep it on a
    /// loopback address.
    #[arg(short, long)]
    addr: Option<SocketAddr>,

    /// Config directory holding `ifc.toml`, `policies.toml`, and
    /// `policies/cedar/`.
    ///
    /// Defaults to the nearest `.sondera` at or above the working directory,
    /// falling back per asset to `~/.sondera`.
    #[arg(short, long)]
    config_dir: Option<PathBuf>,

    /// Trajectory database the harness writes and the console reads.
    ///
    /// Defaults to `~/.sondera/trajectories/trajectories.db`.
    #[arg(short, long)]
    db: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct McpArgs {
    /// Console gRPC endpoint backing the agent and trajectory tools.
    ///
    /// This is the address `sondera serve` binds. Like the TUI, the MCP server
    /// is a read-only client of it and opens no database of its own: the store
    /// takes an exclusive per-process lock, so a second opener could not start
    /// while the harness was running.
    ///
    /// The console is dialed lazily. Cedar authoring needs none of it, so the
    /// server starts — and those tools work — whether or not anything is
    /// listening here.
    #[arg(short, long, env = "SONDERA_CONSOLE_ENDPOINT", default_value = sondera_mcp::console::DEFAULT_ENDPOINT)]
    endpoint: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Hook { provider } => {
            // Hooks speak JSON on stdout to the host IDE; keep logs on stderr.
            sondera_hooks::init_tracing("sondera", cli.verbose);
            // A timed-out stdin read remains blocked on Tokio's blocking pool,
            // so dropping the runtime would wait indefinitely on any return path.
            match run_hook(provider).await {
                Ok(()) => std::process::exit(0),
                Err(error) => {
                    eprintln!("Error: {error:#}");
                    std::process::exit(1);
                }
            }
        }
        Command::Serve(args) => run_serve(args, cli.verbose).await?,
        Command::Mcp(args) => run_mcp(args, cli.verbose).await?,
        // No tracing setup: the TUI owns the alternate screen, and a subscriber
        // writing to stdout or stderr would paint over it. Errors surface in the
        // UI's own status line, and the fatal ones print after the terminal is
        // restored.
        Command::Tui(args) => sondera_tui::run(args)
            .await
            .map_err(|error| anyhow::anyhow!("{error:#}"))?,
    }

    Ok(())
}

async fn run_hook(provider: HookCommand) -> Result<()> {
    match provider {
        HookCommand::Antigravity(cli) => sondera_antigravity::run(cli).await?,
        HookCommand::Claude(cli) => sondera_claude::run(cli).await?,
        HookCommand::Codex(cli) => sondera_codex::run(cli).await?,
        HookCommand::Copilot(cli) => sondera_copilot::run(cli).await?,
        HookCommand::Cursor(cli) => sondera_cursor::run(cli).await?,
        HookCommand::Gemini(cli) => sondera_gemini::run(cli).await?,
        HookCommand::Hermes(cli) => sondera_hermes::run(cli).await?,
        HookCommand::Opencode(cli) => sondera_opencode::run(cli).await?,
        HookCommand::Openhands(cli) => sondera_openhands::run(cli).await?,
        HookCommand::Vscode(cli) => sondera_vscode::run(cli).await?,
    }
    Ok(())
}

/// Logging setup for the long-running gRPC server.
///
/// `RUST_LOG` wins when set — the convention for a server an operator attaches
/// to; `-v` only moves the fallback.
fn init_server_tracing(verbose: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if verbose {
            EnvFilter::new("info,sondera=debug")
        } else {
            EnvFilter::new("warn")
        }
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_span_events(FmtSpan::CLOSE)
        .init();
}

/// Run both gRPC surfaces on one listener.
///
/// The two used to be separate commands on separate ports. They are folded into
/// one because they are one deployment: the console reads exactly what the
/// harness writes. Running them together also lets the console share the
/// harness's open store rather than opening the same database a second time —
/// both sides go through the store traits, so the console sees each event as
/// soon as it is committed. They never contend for a route either, since gRPC
/// dispatches on `/<package>.<Service>/<Method>`.
async fn run_serve(args: ServeArgs, verbose: bool) -> Result<()> {
    init_server_tracing(verbose);

    // Read the unified config once and hand it to the engine, so the CLI and
    // the guardrails cannot end up with two different views of the same files.
    // `--config-dir` pins the project scope; `~/.sondera` still applies under
    // it, per asset. Precedence for each setting: CLI flag, then `sondera.toml`,
    // then default.
    let settings =
        sondera_cedar_policy::Settings::load_with_config_dir(args.config_dir.as_deref())?;
    if !settings.sources.is_empty() {
        tracing::info!(sources = ?settings.sources, "Loaded configuration");
    }
    tracing::info!(config_dirs = ?settings.config_dirs, "Resolved config directories");

    let addr = args
        .addr
        .or(settings.harness.addr)
        .unwrap_or_else(sondera_harness::rpc::default_addr);

    let db_path = match args.db {
        Some(path) => path,
        None => sondera_storage::get_default_db_path()
            .context("Failed to resolve the default trajectory database path")?,
    };
    let store = Arc::new(
        sondera_storage::TrajectoryStore::open(&db_path)
            .await
            .with_context(|| format!("Failed to open trajectory store: {}", db_path.display()))?,
    );

    // Built before `settings` moves into the engine. Off unless `[scanner]
    // enabled` says otherwise: it is one model call per event, so it is not
    // something a deployment should acquire by upgrading.
    let scans = scan_dispatcher(&settings.scanner, store.clone())?;

    let harness =
        sondera_cedar_policy::CedarPolicyHarness::from_settings_with_store(settings, store.clone())
            .await?;

    let mut harness_service = sondera_harness::rpc::HarnessGrpcService::new(Arc::new(harness));
    if let Some(scans) = scans {
        harness_service = harness_service.with_scans(scans);
    }

    tracing::info!(
        db = %db_path.display(),
        "Serving harness and console gRPC on {addr}"
    );

    // No graceful shutdown: the console's trajectory tails poll until the
    // consumer goes away, so draining them would turn Ctrl-C into a hang. The
    // process exits on the signal instead, which is what the separate servers
    // did before.
    tonic::transport::Server::builder()
        .add_service(sondera_harness::rpc::wrap(harness_service))
        .add_service(sondera_console::grpc_service(store))
        .serve(addr)
        .await
        // The address belongs in the message: the common failure here is
        // another `sondera serve` already holding the port, and tonic's own
        // error says only "transport error".
        .with_context(|| format!("Server on {addr} stopped"))?;

    Ok(())
}

/// Build the background trajectory scanner, when `[scanner]` asks for one.
///
/// Returns `None` when the scanner is disabled — the default — in which case
/// the harness enforces exactly the same policy and simply records no
/// summaries.
///
/// A provider that cannot be built is a hard startup failure rather than a
/// warning. Scanning is optional, but *silently* not scanning after an operator
/// explicitly enabled it is worse than not starting: they would see a running
/// server and an empty console and have nothing to look at to explain it.
fn scan_dispatcher(
    settings: &sondera_cedar_policy::ScannerSettings,
    store: Arc<sondera_storage::TrajectoryStore>,
) -> Result<Option<Arc<dyn sondera_harness::scan::ScanDispatch>>> {
    if !settings.enabled {
        tracing::debug!(
            "Trajectory scanner disabled; set `[scanner] enabled = true` to turn it on"
        );
        return Ok(None);
    }

    let scanner = sondera_trajectory::TrajectoryScanner::new(settings.model.clone())
        .context("Failed to build the trajectory scanner from `[scanner]` in sondera.toml")?;

    tracing::info!(
        provider = scanner.provider_name(),
        model = scanner.model(),
        "Trajectory scanner enabled"
    );

    Ok(Some(Arc::new(sondera_harness::scan::ScanDispatcher::new(
        Arc::new(scanner),
        store,
    ))))
}

/// Serve the Cedar policy authoring MCP server on stdio.
///
/// An MCP client launches this as a subprocess and speaks JSON-RPC over
/// **stdout**, so logging goes to stderr — anything else on stdout corrupts the
/// protocol stream. `RUST_LOG` wins when set, which is the convention MCP
/// clients expect for a stdio server; `-v` only moves the fallback.
///
/// This is its own command rather than an endpoint on [`run_serve`]'s listener:
/// policy authoring is a per-client editing session, not a shared server
/// surface, and every MCP client here launches its server as a subprocess.
///
/// It opens no database. The console tools dial [`run_serve`]'s gRPC endpoint
/// instead, because the store admits one process at a time and this one is
/// launched alongside a running harness, not instead of it.
async fn run_mcp(args: McpArgs, verbose: bool) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(if verbose { "debug" } else { "info" }));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_ansi(false)
        .init();

    let console = sondera_mcp::console::ConsoleClient::new(&args.endpoint)
        .with_context(|| format!("Failed to configure the console client: {}", args.endpoint))?;

    tracing::info!(
        endpoint = %args.endpoint,
        "Starting Cedar and console MCP server on stdio"
    );
    sondera_mcp::serve_stdio(console).await?;

    Ok(())
}
