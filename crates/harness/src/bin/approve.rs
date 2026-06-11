//! `sondera-approve` — out-of-band human-approval actuator for the multi-hop
//! monitor.
//!
//! `UntrustedThenProtectedWrite` denies protected writes "until approval"
//! (`multi_hop.cedar`), where approval is a `Control::Resumed` event from the
//! `resume_approved_by` allowlist (default `["user"]`). No hook adapter emits
//! one, so this binary is that channel: it injects the approval over the same
//! RPC the hooks use, clearing the trajectory's obligation (`Armed -> Clean`).
//!
//! Two modes: a one-shot CLI (`sondera-approve <trajectory_id>`) and an HTTP
//! endpoint (`--serve`, `POST /approve`) for a web UI — a separate write
//! surface, so the dashboard stays read-only.
//!
//! Approval is a pre-write gate: it clears an `Armed` trajectory, but a
//! `Violated` one is terminal and is not recovered.

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sondera_harness::{
    Agent, Control, Decision, Event, Harness, HarnessClient, Resumed, TrajectoryEvent,
};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use tower_http::cors::CorsLayer;

#[derive(Parser, Debug)]
#[command(name = "sondera-approve")]
#[command(about = "Approve a multi-hop monitor's armed obligation for a trajectory")]
#[command(version)]
struct Args {
    /// Trajectory (session) id to approve (one-shot mode). Omit with --serve.
    trajectory_id: Option<String>,

    /// Approver identity written as `resumed_by`. Must be in the monitor's
    /// `resume_approved_by` allowlist (default `["user"]`) to count as approval.
    #[arg(long, default_value = "user")]
    by: String,

    /// Path to the harness Unix socket (defaults to the standard location).
    #[arg(short, long)]
    socket: Option<PathBuf>,

    /// Run as an HTTP control-plane endpoint instead of a one-shot CLI.
    #[arg(long)]
    serve: bool,

    /// Address to bind in --serve mode (localhost only by default).
    #[arg(long, default_value = "127.0.0.1:8799")]
    bind: String,

    /// Bearer token required on every request in --serve mode.
    #[arg(long, env = "SONDERA_APPROVE_TOKEN")]
    token: Option<String>,

    /// Allowed CORS origin(s) in --serve mode (repeatable). Defaults to common
    /// localhost dev origins. Never a wildcard.
    #[arg(long = "cors-origin")]
    cors_origins: Vec<String>,

    /// Enable verbose logging.
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if args.verbose {
        tracing_subscriber::EnvFilter::new("info,tarpc=warn,sondera=debug")
    } else {
        tracing_subscriber::EnvFilter::new("info")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    if args.serve {
        let token = args.token.filter(|t| !t.is_empty()).context(
            "--token (or SONDERA_APPROVE_TOKEN) is required and must be non-empty in --serve mode",
        )?;
        return serve(&args.bind, token, args.socket, &args.cors_origins).await;
    }

    let trajectory_id = args
        .trajectory_id
        .context("a trajectory_id is required (or pass --serve to run the HTTP endpoint)")?;
    let decision = approve(&trajectory_id, &args.by, args.socket.as_deref()).await?;

    println!(
        "Approval sent for trajectory {} (resumed_by={}). Decision: {:?}.",
        trajectory_id, args.by, decision
    );
    println!(
        "An Armed obligation is now cleared; protected writes are permitted again. \
         (A trajectory already in the Violated state is terminal and is NOT recovered.)"
    );
    Ok(())
}

/// Inject a user-originated `Control::Resumed` approval over the harness RPC.
/// Shared by the CLI and the `serve` handler. Returns the harness decision
/// (always `Allow` for a Control event — it confirms acceptance, not the FSM
/// transition).
async fn approve(trajectory_id: &str, resumed_by: &str, socket: Option<&Path>) -> Result<Decision> {
    let client = match socket {
        Some(path) => HarnessClient::connect(path).await,
        None => HarnessClient::connect_default().await,
    }
    .context("connecting to harness socket (is sondera-harness-server running?)")?;

    let agent = Agent {
        id: "sondera-approve".to_string(),
        provider_id: "sondera-approve".to_string(),
    };
    let event = Event::new(
        agent,
        trajectory_id.to_string(),
        TrajectoryEvent::Control(Control::Resumed(Resumed::new(resumed_by))),
    );

    let adjudicated = client
        .adjudicate(event)
        .await
        .context("harness rejected the approval event")?;
    Ok(adjudicated.decision)
}

// ── HTTP serve mode ────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    token: String,
    socket: Option<PathBuf>,
}

#[derive(Deserialize)]
struct ApproveRequest {
    trajectory_id: String,
    #[serde(default)]
    by: Option<String>,
}

#[derive(Serialize)]
struct ApproveResponse {
    trajectory_id: String,
    resumed_by: String,
    decision: String,
}

async fn serve(
    bind: &str,
    token: String,
    socket: Option<PathBuf>,
    cors_origins: &[String],
) -> Result<()> {
    let default_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ];
    let raw: Vec<&str> = if cors_origins.is_empty() {
        default_origins.to_vec()
    } else {
        cors_origins.iter().map(String::as_str).collect()
    };
    let origins = raw
        .iter()
        .map(|o| {
            o.parse()
                .with_context(|| format!("invalid CORS origin: {o}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    let state = AppState { token, socket };

    let app = Router::new()
        .route("/approve", post(approve_handler))
        .route("/health", get(|| async { "ok" }))
        // Auth is inner; CORS is outer so preflight OPTIONS is answered first.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!("sondera-approve HTTP endpoint listening on http://{bind} (POST /approve)");
    axum::serve(listener, app).await.context("serving")?;
    Ok(())
}

/// Constant-time bearer-token gate, mirroring the dashboard's auth posture.
async fn require_bearer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match presented {
        Some(t) if bool::from(t.as_bytes().ct_eq(state.token.as_bytes())) => {
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn approve_handler(
    State(state): State<AppState>,
    Json(req): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, (StatusCode, String)> {
    if req.trajectory_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "trajectory_id is required".to_string(),
        ));
    }
    let resumed_by = req.by.unwrap_or_else(|| "user".to_string());
    let decision = approve(&req.trajectory_id, &resumed_by, state.socket.as_deref())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("{e:#}")))?;

    Ok(Json(ApproveResponse {
        trajectory_id: req.trajectory_id,
        resumed_by,
        decision: format!("{decision:?}"),
    }))
}
