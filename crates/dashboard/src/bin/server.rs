//! Sondera Dashboard Server
//!
//! Read-only trajectory dashboard API: fail-closed startup,
//! loopback-by-construction bind, config via clap + env fallbacks with
//! `~/.sondera/env` loaded first.

use anyhow::Result;
use clap::Parser;
use sondera_dashboard::config::{self, Args};
use sondera_dashboard::storage::ReadOnlyStore;
use sondera_dashboard::{AppState, build_router_with_ui, cors::cors_layer};

/// Best-effort cleanup of snapshot copies left behind by dead dashboard
/// processes (the copy filenames are process-unique, so leftovers are
/// never reused). Errors are warnings only — a missing or unreadable
/// cache dir is not a startup failure.
fn clean_stale_copies(copy_dir: &std::path::Path) {
    let entries = match std::fs::read_dir(copy_dir) {
        Ok(entries) => entries,
        Err(_) => return, // dir does not exist yet — nothing to clean
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if (name.ends_with(".db") || name.ends_with(".db-wal"))
            && let Err(e) = std::fs::remove_file(entry.path())
        {
            tracing::warn!(file = %name, error = %e, "failed to remove stale snapshot copy");
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load ~/.sondera/env BEFORE Args::parse() so clap's env fallback sees
    // SONDERA_DASHBOARD_TOKEN / SONDERA_DASHBOARD_PORT from the env file.
    sondera_hooks_common::load_sondera_env()?;
    let args = Args::parse();

    // Initialize logging (stderr, workspace convention).
    let filter = if args.verbose {
        tracing_subscriber::EnvFilter::new("info,sondera=debug")
    } else {
        tracing_subscriber::EnvFilter::new("warn")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    // Fail-closed startup: missing/empty token is fatal.
    let token = config::validate_token(args.token)?;

    // CORS origins: explicit allowlist; '*'/empty/malformed is fatal.
    let origin_strings: Vec<String> = if args.cors_origin.is_empty() {
        config::DEFAULT_CORS_ORIGINS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        args.cors_origin
    };
    let origins = config::parse_origins(&origin_strings)?;

    // Default paths resolved via the harness's own functions so harness and
    // dashboard can never disagree. The DB path is stat-only here — the
    // dashboard never opens the live file.
    let db_path = match args.db_path {
        Some(path) => path,
        None => sondera_harness::get_default_db_path()?,
    };
    let trajectories_dir = match args.trajectories_dir {
        Some(path) => path,
        None => sondera_harness::storage::file::get_storage_dir()?.join("trajectories"),
    };

    // Fail-closed static-UI validation: a --ui-dir without an index.html is
    // a fatal startup error, never a silently-broken fallback. Absent flag
    // => None => no static UI.
    let ui_dir = config::validate_ui_dir(args.ui_dir)?;
    if let Some(dir) = &ui_dir {
        tracing::info!(dir = %dir.display(), "serving static UI (unauthenticated assets, D-75)");
    }

    // Snapshot copies live next to the source (~/.sondera/dashboard-cache):
    // same volume, same permissions posture, no tmpfs eviction surprises.
    // Constructing the store performs no I/O on the live DB path — the first
    // stat/copy happens lazily on first read, so startup never opens turso
    // when the DB is absent.
    let copy_dir = sondera_harness::storage::file::get_storage_dir()?.join("dashboard-cache");
    clean_stale_copies(&copy_dir);
    let store = std::sync::Arc::new(ReadOnlyStore::new(db_path.clone(), copy_dir));

    let state = AppState {
        token,
        db_path,
        trajectories_dir,
        store,
        stream_tx: tokio::sync::broadcast::channel(sondera_dashboard::stream::BROADCAST_CAPACITY).0,
    };

    // Live-feed source: notify JSONL tail primary, Turso-poll fallback on
    // watcher failure. Chosen once at startup — no mid-flight switching;
    // either way the adjudication hot path is never touched and the live DB
    // is never opened.
    match sondera_dashboard::stream::tail::spawn_tail(
        state.trajectories_dir.clone(),
        state.stream_tx.clone(),
    ) {
        Ok(()) => tracing::info!("live feed source: notify JSONL tail"),
        Err(err) => {
            tracing::warn!(
                error = %err,
                "notify watcher unavailable; falling back to Turso polling"
            );
            sondera_dashboard::stream::poll::spawn_poll(
                state.store.clone(),
                state.stream_tx.clone(),
            );
        }
    }

    let app = build_router_with_ui(state, cors_layer(&origins), ui_dir);

    // Loopback by construction: hardcoded 127.0.0.1 literal; no flag for the
    // bind address exists. The assert documents the invariant at runtime.
    let addr = config::bind_addr(args.port);
    assert!(
        addr.ip().is_loopback(),
        "dashboard must bind loopback only (D-52)"
    );

    tracing::info!("sondera-dashboard listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
