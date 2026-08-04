//! Common I/O plumbing every hook binary needs.
//!
//! Moved here from the former `sondera-common` crate:
//! - JSON stdin/stdout for communicating with the host IDE
//! - Tracing initialization (logs to stderr to keep stdout clean for JSON)
//! - Environment loading from `~/.sondera/env`
//! - Agent identity construction
//! - Harness client connection via the gRPC endpoint

use crate::error::{HookError, Result};
use serde::{Deserialize, Serialize};
use sondera_harness_client::HarnessGrpcClient;
use std::io::{self, Read, Write};
use std::path::PathBuf;

/// Read JSON data from stdin and deserialize into the specified type.
pub fn read_stdin<T>() -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    let value = serde_json::from_str(&buffer)?;
    Ok(value)
}

/// Return the first string-valued field found under `keys`.
pub fn json_string_field<'a>(value: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
}

/// Output a response as JSON to stdout, ensuring proper flushing.
///
/// The write goes through a locked handle with `writeln!` rather than
/// `println!` so a closed stdout (EPIPE — the host went away) is returned as a
/// [`HookError::Io`] the caller can handle, instead of panicking mid-write.
/// On an enforcement hook a panic here would abort before the deny is emitted,
/// which the host would treat as "no opinion" and fail *open*.
pub fn output_response<T: Serialize>(response: T) -> Result<()> {
    let _ = io::stderr().flush();
    let json = serde_json::to_string(&response)?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{json}")?;
    stdout.flush()?;
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

/// Load environment from `~/.sondera/env` if it exists.
///
/// A missing file is not an error — the token may come from the ambient
/// environment. An unparseable one is [`HookError::Config`], which steers the
/// user at the file's format rather than at connectivity.
pub fn load_sondera_env() -> Result<()> {
    let env_path = sondera_env_path()?;
    if env_path.exists() {
        dotenvy::from_path(&env_path)
            .map_err(|e| HookError::Config(format!("failed to load {env_path:?}: {e}")))?;
    } else {
        tracing::warn!("Environment file not found at {:?}", env_path);
    }
    Ok(())
}

/// Get the path to `~/.sondera/env`.
pub fn sondera_env_path() -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| HookError::message("could not determine home directory"))?;
    Ok(home.join(".sondera").join("env"))
}

/// Create an agent ID from a provider name and the current username.
pub fn agent_id(provider: &str) -> String {
    format!("{}-{}", provider, whoami::username())
}

/// Connect to the harness gRPC server using the default endpoint
/// (`SONDERA_HARNESS_ENDPOINT`, falling back to `http://127.0.0.1:50051`).
/// A connect failure propagates as the typed client error — flattening it to a
/// string here is what used to force the caller to parse it back out.
pub async fn connect_harness() -> Result<HarnessGrpcClient> {
    Ok(HarnessGrpcClient::default().await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_field_returns_the_first_matching_string() {
        let value = serde_json::json!({"path": "/fallback", "file_path": "/preferred"});

        assert_eq!(
            json_string_field(&value, &["file_path", "path"]),
            Some("/preferred")
        );
    }

    #[test]
    fn json_string_field_skips_non_string_values() {
        let value = serde_json::json!({"file_path": 42, "path": "/fallback"});

        assert_eq!(
            json_string_field(&value, &["file_path", "path"]),
            Some("/fallback")
        );
    }
}
