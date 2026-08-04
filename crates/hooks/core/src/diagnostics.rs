//! Per-session deduplication for hook diagnostics, and the debug-output switch.
//!
//! A hook runs once per tool call, so an outage that warned on every invocation
//! would bury the terminal. Every category ([`crate::error::HookError::category`])
//! warns once per hook runtime session, identified by the parent PID.
//!
//! The messages themselves — and the classification that picks them — belong to
//! [`crate::error::HookError`]. Nothing here inspects an error.

use std::path::PathBuf;

/// Environment variable that enables verbose hook diagnostics.
pub const HOOK_DEBUG_ENV_VAR: &str = "SONDERA_HOOK_DEBUG";

/// Whether verbose hook diagnostics are enabled via [`HOOK_DEBUG_ENV_VAR`].
///
/// Truthy values are `1`, `true`, `yes`, `on` (case-insensitive); everything
/// else — including unset — is false.
#[must_use]
pub fn hook_debug_enabled() -> bool {
    std::env::var(HOOK_DEBUG_ENV_VAR)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Marker file path for a given category in the current hook runtime session.
/// Uses the parent PID on Unix so markers reset with the hook runtime process.
fn marker_path(category: &str) -> PathBuf {
    #[cfg(unix)]
    let session_id = std::os::unix::process::parent_id();
    #[cfg(not(unix))]
    let session_id = std::process::id();

    std::env::temp_dir().join(format!("sondera-warned-{session_id}-{category}"))
}

/// How long a dedup marker suppresses repeat warnings.
///
/// Markers are keyed by PID and never deleted, so without an expiry a recycled
/// PID inherits a previous session's markers and silently swallows that
/// session's first warning. The window only needs to outlast a working session.
const MARKER_TTL: std::time::Duration = std::time::Duration::from_secs(12 * 60 * 60);

/// Returns `true` if this is the first warning for `category` in the current
/// hook runtime session. Subsequent calls for the same category return `false`,
/// suppressing duplicate warnings.
pub fn should_warn(category: &str) -> bool {
    let path = marker_path(category);
    if is_fresh_marker(&path) {
        return false;
    }
    // Best-effort: if the write fails we warn anyway (better than silent).
    let _ = std::fs::write(&path, "");
    true
}

/// Whether `path` is an existing marker still inside [`MARKER_TTL`].
///
/// A marker whose age cannot be determined is treated as fresh: the fallback is
/// suppressing a duplicate warning, not hiding a first one.
fn is_fresh_marker(path: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata
        .modified()
        .map(|modified| modified.elapsed().map_or(true, |age| age < MARKER_TTL))
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HookError;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn hook_debug_enabled_parses_true_like_values() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: this test holds ENV_LOCK for the whole env mutation window.
        unsafe {
            std::env::set_var(HOOK_DEBUG_ENV_VAR, "yes");
        }

        let enabled = hook_debug_enabled();

        // SAFETY: this test holds ENV_LOCK for the whole env mutation window.
        unsafe {
            std::env::remove_var(HOOK_DEBUG_ENV_VAR);
        }

        assert!(enabled);
    }

    #[test]
    fn hook_debug_enabled_ignores_false_like_values() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: this test holds ENV_LOCK for the whole env mutation window.
        unsafe {
            std::env::set_var(HOOK_DEBUG_ENV_VAR, "0");
        }

        let enabled = hook_debug_enabled();

        // SAFETY: this test holds ENV_LOCK for the whole env mutation window.
        unsafe {
            std::env::remove_var(HOOK_DEBUG_ENV_VAR);
        }

        assert!(!enabled);
    }

    #[test]
    fn should_warn_dedup_marker_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let category = format!("test-{unique}");

        let path = marker_path(&category);
        let _ = std::fs::remove_file(&path);

        assert!(should_warn(&category), "first call should return true");
        assert!(path.exists(), "marker file should be created");

        assert!(
            !should_warn(&category),
            "second call should return false (dedup)"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn should_warn_dedup_for_server_category() {
        // The "server" category routes through the same per-session dedup as
        // every other category, so an org-wide schema outage warns once.
        let category = HookError::ServerRejected("schema".into()).category();
        assert_eq!(category, "server");

        let path = marker_path(category);
        let _ = std::fs::remove_file(&path);

        assert!(
            should_warn(category),
            "first server-category warning should fire"
        );
        assert!(
            !should_warn(category),
            "second server-category warning should be deduped"
        );

        let _ = std::fs::remove_file(&path);
    }
}
