//! Server configuration: clap derive + env fallbacks, with fail-closed
//! validation and a loopback-by-construction bind address.

use axum::http::HeaderValue;
use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Default CORS allowlist: the Vite dev-server origins.
pub const DEFAULT_CORS_ORIGINS: [&str; 2] = ["http://localhost:5173", "http://127.0.0.1:5173"];

/// CLI arguments for `sondera-dashboard`.
//
// There is deliberately NO bind-address flag and no address field of any
// kind: a non-loopback bind is unrepresentable by construction. Only the
// port is configurable.
#[derive(Parser, Debug)]
#[command(name = "sondera-dashboard")]
#[command(about = "Read-only trajectory dashboard API server")]
#[command(version)]
pub struct Args {
    /// Port to bind on 127.0.0.1 (the address itself is not configurable)
    #[arg(long, env = "SONDERA_DASHBOARD_PORT", default_value_t = 8787)]
    pub port: u16,

    /// Bearer token required on every route (missing/empty is fatal)
    #[arg(long, env = "SONDERA_DASHBOARD_TOKEN")]
    pub token: Option<String>,

    /// Path to the live trajectories database (stat-only; never opened)
    #[arg(long)]
    pub db_path: Option<PathBuf>,

    /// Directory containing per-trajectory JSONL files
    #[arg(long)]
    pub trajectories_dir: Option<PathBuf>,

    /// Allowed CORS origin (repeatable); defaults to the Vite dev origins
    #[arg(long, action = clap::ArgAction::Append)]
    pub cors_origin: Vec<String>,

    /// Directory of built SPA assets to serve as an unauthenticated static fallback
    //
    // Non-doc comment so clap does not leak it into --help: only STATIC
    // ASSETS are served without a token. Every data route stays bearer-gated
    // by the auth layer regardless of this flag, and when the flag is absent
    // the default 401-on-unmatched behavior is preserved.
    #[arg(long)]
    pub ui_dir: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(long, short)]
    pub verbose: bool,
}

/// Validate the configured token: `None`, empty, or whitespace-only is a
/// fatal startup error naming `SONDERA_DASHBOARD_TOKEN`.
pub fn validate_token(token: Option<String>) -> anyhow::Result<String> {
    match token {
        Some(t) if !t.trim().is_empty() => Ok(t),
        _ => anyhow::bail!(
            "no dashboard token configured: set SONDERA_DASHBOARD_TOKEN in ~/.sondera/env \
             (or pass --token) to a high-entropy secret — the server refuses to start \
             without one"
        ),
    }
}

/// Validate the optional `--ui-dir`: `None` passes through unchanged;
/// `Some(dir)` must be an existing directory containing `index.html`,
/// otherwise startup is a fatal error (fail-closed, same shape as
/// [`validate_token`]).
pub fn validate_ui_dir(ui_dir: Option<PathBuf>) -> anyhow::Result<Option<PathBuf>> {
    let Some(dir) = ui_dir else {
        return Ok(None);
    };
    if !dir.is_dir() {
        anyhow::bail!(
            "--ui-dir '{}' is not an existing directory — build the SPA first \
             (cd web && npm run build) and point --ui-dir at the build output",
            dir.display()
        );
    }
    if !dir.join("index.html").is_file() {
        anyhow::bail!(
            "--ui-dir '{}' contains no index.html — point it at the built SPA \
             output (cd web && npm run build)",
            dir.display()
        );
    }
    Ok(Some(dir))
}

/// Parse and validate the CORS origin list: each origin must be non-empty,
/// must not be `*`, and must parse as a `HeaderValue`.
pub fn parse_origins(origins: &[String]) -> anyhow::Result<Vec<HeaderValue>> {
    origins
        .iter()
        .map(|origin| {
            if origin.trim().is_empty() {
                anyhow::bail!("CORS origin must not be empty");
            }
            if origin == "*" {
                anyhow::bail!(
                    "CORS origin '*' is not allowed — pass explicit origins via --cors-origin"
                );
            }
            HeaderValue::from_str(origin)
                .map_err(|e| anyhow::anyhow!("invalid CORS origin '{origin}': {e}"))
        })
        .collect()
}

/// Construct the bind address from the hardcoded loopback literal. Only the
/// port is configurable; the address is `127.0.0.1` by construction — there
/// is no flag to change it.
pub fn bind_addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_token_rejects_none() {
        let err = validate_token(None).unwrap_err().to_string();
        assert!(err.contains("SONDERA_DASHBOARD_TOKEN"));
    }

    #[test]
    fn validate_token_rejects_empty() {
        let err = validate_token(Some(String::new())).unwrap_err().to_string();
        assert!(err.contains("SONDERA_DASHBOARD_TOKEN"));
    }

    #[test]
    fn validate_token_rejects_whitespace_only() {
        let err = validate_token(Some("   ".to_string()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("SONDERA_DASHBOARD_TOKEN"));
    }

    #[test]
    fn validate_token_accepts_real_token() {
        assert_eq!(
            validate_token(Some("a-real-token".to_string())).unwrap(),
            "a-real-token"
        );
    }

    #[test]
    fn parse_origins_rejects_wildcard() {
        assert!(parse_origins(&["*".to_string()]).is_err());
    }

    #[test]
    fn parse_origins_rejects_empty_string() {
        assert!(parse_origins(&[String::new()]).is_err());
    }

    #[test]
    fn parse_origins_rejects_header_invalid_value() {
        assert!(parse_origins(&["http://bad\norigin".to_string()]).is_err());
    }

    #[test]
    fn parse_origins_accepts_vite_defaults() {
        let parsed = parse_origins(
            &DEFAULT_CORS_ORIGINS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], "http://localhost:5173");
        assert_eq!(parsed[1], "http://127.0.0.1:5173");
    }

    #[test]
    fn bind_addr_is_loopback_on_127_0_0_1() {
        let addr = bind_addr(8787);
        assert!(addr.ip().is_loopback());
        assert!(addr.to_string().starts_with("127.0.0.1:"));
    }

    #[test]
    fn validate_ui_dir_passes_none_through() {
        assert!(validate_ui_dir(None).unwrap().is_none());
    }

    #[test]
    fn validate_ui_dir_rejects_missing_dir() {
        let missing = std::env::temp_dir().join("sondera-no-such-ui-dir");
        let err = validate_ui_dir(Some(missing.clone()))
            .unwrap_err()
            .to_string();
        assert!(err.contains(&missing.display().to_string()));
        assert!(err.contains("npm run build"));
    }

    #[test]
    fn validate_ui_dir_rejects_dir_without_index_html() {
        let dir = tempfile::tempdir().unwrap();
        let err = validate_ui_dir(Some(dir.path().to_path_buf()))
            .unwrap_err()
            .to_string();
        assert!(err.contains(&dir.path().display().to_string()));
        assert!(err.contains("npm run build"));
    }

    #[test]
    fn validate_ui_dir_accepts_dir_with_index_html() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<!doctype html>").unwrap();
        let validated = validate_ui_dir(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(validated, Some(dir.path().to_path_buf()));
    }
}
