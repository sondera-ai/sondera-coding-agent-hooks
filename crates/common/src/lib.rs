//! Shared utilities for Sondera coding agent hooks (Claude, Cursor, Copilot, Gemini).
//!
//! Provides the common I/O plumbing that every hook binary needs:
//! - JSON stdin/stdout for communicating with the host IDE
//! - Tracing initialization (logs to stderr to keep stdout clean for JSON)
//! - Environment loading from `~/.sondera/env`
//! - Agent identity construction
//! - Harness client connection via default Unix socket

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::PathBuf;

pub use sondera_harness::HarnessClient;

/// Read JSON data from stdin and deserialize into the specified type.
pub fn read_stdin<T>() -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .context("Failed to read from stdin")?;

    serde_json::from_str(&buffer).with_context(|| {
        format!(
            "Failed to parse JSON from stdin. Input was: {}",
            buffer.chars().take(500).collect::<String>()
        )
    })
}

/// Output a response as JSON to stdout, ensuring proper flushing.
pub fn output_response<T: Serialize>(response: T) -> Result<()> {
    let _ = io::stderr().flush();
    let json = serde_json::to_string(&response)?;
    println!("{}", json);
    let _ = io::stdout().flush();
    Ok(())
}

/// Flush all output streams before exiting.
pub fn flush_output() {
    let _ = io::stderr().flush();
    let _ = io::stdout().flush();
}

/// Initialize tracing for hooks (logs to stderr to keep stdout clean for JSON).
pub fn init_tracing(crate_name: &str, verbose: bool) {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::new(format!("warn,{crate_name}=debug,sondera_harness=debug"))
    } else {
        tracing_subscriber::EnvFilter::new("warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_ansi(false)
        .compact()
        .try_init()
        .ok();
}

/// Load environment from ~/.sondera/env if it exists.
pub fn load_sondera_env() -> Result<()> {
    let env_path = sondera_env_path()?;
    if env_path.exists() {
        dotenvy::from_path(&env_path)?;
    } else {
        tracing::warn!("Environment file not found at {:?}", env_path);
    }
    Ok(())
}

/// Get the path to ~/.sondera/env.
pub fn sondera_env_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".sondera").join("env"))
}

/// Create an agent ID from provider name and current username.
pub fn agent_id(provider: &str) -> String {
    format!("{}-{}", provider, whoami::username())
}

/// Connect to the harness server using default socket path.
pub async fn connect_harness() -> Result<HarnessClient> {
    HarnessClient::connect_default().await
}
