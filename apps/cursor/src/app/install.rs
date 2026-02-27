//! Install command for setting up Cursor hooks.
//!
//! This module provides functionality to install the Sondera hooks configuration
//! into Cursor hooks files. Hooks can be installed at different scopes:
//! - User scope: `~/.cursor/hooks.json` (applies to all projects)
//! - Project scope: `<project>/.cursor/hooks.json` (committed to git)

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Scope for hooks installation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// User-level settings (~/.cursor/hooks.json)
    User,
    /// Project-level settings (.cursor/hooks.json) - committed to git
    Project,
}

impl std::fmt::Display for InstallScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallScope::User => write!(f, "user (~/.cursor/hooks.json)"),
            InstallScope::Project => write!(f, "project (.cursor/hooks.json)"),
        }
    }
}

/// Find the binary path using PATH lookup
fn find_binary_path() -> Result<PathBuf> {
    // First, try to find 'sondera-cursor' in PATH using which
    if let Ok(path) = which::which("sondera-cursor") {
        return Ok(path);
    }

    // Fall back to common installation locations
    let home = dirs::home_dir().context("Could not determine home directory")?;

    // Check ~/.cargo/bin/sondera-cursor
    let cargo_bin = home.join(".cargo/bin/sondera-cursor");
    if cargo_bin.exists() {
        return Ok(cargo_bin);
    }

    // Check /usr/local/bin/sondera-cursor
    let usr_local_bin = PathBuf::from("/usr/local/bin/sondera-cursor");
    if usr_local_bin.exists() {
        return Ok(usr_local_bin);
    }

    // Check /usr/bin/sondera-cursor
    let usr_bin = PathBuf::from("/usr/bin/sondera-cursor");
    if usr_bin.exists() {
        return Ok(usr_bin);
    }

    // If running from cargo, get the current executable
    if let Ok(exe) = env::current_exe()
        && exe.file_name().and_then(|n| n.to_str()) == Some("sondera-cursor")
    {
        return Ok(exe);
    }

    Err(anyhow::anyhow!(
        "Could not find sondera-cursor binary. Please ensure it is installed and in your PATH.\n\
        You can install it using: cargo install --path apps/cursor"
    ))
}

/// Generate the hooks configuration JSON for all Cursor hook events
fn generate_hooks_config(binary_path: &Path) -> Value {
    let binary_str = binary_path.to_string_lossy();

    // Helper to create a hook entry for a given event
    let make_hook = |event: &str| -> Value {
        json!([{
            "command": format!("{} --verbose {}", binary_str, event)
        }])
    };

    // Helper for hooks with matchers
    let make_hook_with_matcher = |event: &str, matcher: &str| -> Value {
        json!([{
            "command": format!("{} --verbose {}", binary_str, event),
            "matcher": matcher
        }])
    };

    json!({
        // Session lifecycle hooks
        "sessionStart": make_hook("session-start"),
        "sessionEnd": make_hook("session-end"),

        // Generic tool hooks (fires for all tools)
        "preToolUse": make_hook_with_matcher("pre-tool-use", "*"),
        "postToolUse": make_hook_with_matcher("post-tool-use", "*"),
        "postToolUseFailure": make_hook_with_matcher("post-tool-use-failure", "*"),

        // Subagent hooks
        "subagentStart": make_hook("subagent-start"),
        "subagentStop": make_hook("subagent-stop"),

        // Shell execution hooks
        "beforeShellExecution": make_hook("before-shell-execution"),
        "afterShellExecution": make_hook("after-shell-execution"),

        // MCP execution hooks
        "beforeMCPExecution": make_hook("before-mcp-execution"),
        "afterMCPExecution": make_hook("after-mcp-execution"),

        // File access hooks
        "beforeReadFile": make_hook("before-read-file"),
        "afterFileEdit": make_hook("after-file-edit"),

        // Prompt submission hook
        "beforeSubmitPrompt": make_hook("before-submit-prompt"),

        // Agent response hooks
        "afterAgentResponse": make_hook("after-agent-response"),
        "afterAgentThought": make_hook("after-agent-thought"),

        // Compaction hook
        "preCompact": make_hook("pre-compact"),

        // Stop hook
        "stop": make_hook("stop"),

        // Tab-specific hooks
        "beforeTabFileRead": make_hook("before-tab-file-read"),
        "afterTabFileEdit": make_hook("after-tab-file-edit")
    })
}

/// Get the hooks file path for the given scope
fn get_hooks_path(scope: InstallScope) -> Result<PathBuf> {
    match scope {
        InstallScope::User => {
            let home = dirs::home_dir().context("Could not determine home directory")?;
            Ok(home.join(".cursor").join("hooks.json"))
        }
        InstallScope::Project => {
            let cwd = env::current_dir().context("Could not determine current directory")?;
            Ok(cwd.join(".cursor").join("hooks.json"))
        }
    }
}

/// Create a backup of the existing hooks file
fn backup_hooks(path: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let backup_path = path.with_extension(format!("backup.{}.json", timestamp));

    fs::copy(path, &backup_path).context("Failed to create backup")?;

    Ok(Some(backup_path))
}

/// Read existing hooks or create empty object
fn read_hooks(path: &Path) -> Result<Map<String, Value>> {
    if path.exists() {
        let content = fs::read_to_string(path).context("Failed to read hooks file")?;
        let value: Value = serde_json::from_str(&content).context("Failed to parse hooks JSON")?;
        match value {
            Value::Object(map) => Ok(map),
            _ => Err(anyhow::anyhow!("Hooks file is not a JSON object")),
        }
    } else {
        Ok(Map::new())
    }
}

/// Write hooks to file
fn write_hooks(path: &Path, hooks: &Map<String, Value>) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create hooks directory")?;
    }

    let content = serde_json::to_string_pretty(&Value::Object(hooks.clone()))
        .context("Failed to serialize hooks")?;

    fs::write(path, content).context("Failed to write hooks file")?;

    Ok(())
}

/// Install hooks into the specified scope
pub fn install_hooks(scope: InstallScope, _verbose: bool) -> Result<()> {
    eprintln!("\x1b[32mSondera Cursor Hooks Installer\x1b[0m");
    eprintln!("==============================\n");

    // Find binary path
    let binary_path = find_binary_path()?;
    eprintln!("Binary found: {}", binary_path.display());

    // Get hooks file path
    let hooks_path = get_hooks_path(scope)?;
    eprintln!("Installing to {} scope", scope);
    eprintln!("Hooks file: {}\n", hooks_path.display());

    // Backup existing hooks
    if let Some(backup_path) = backup_hooks(&hooks_path)? {
        eprintln!(
            "\x1b[33mBacked up existing hooks to: {}\x1b[0m",
            backup_path.display()
        );
    }

    // Read existing hooks
    let mut hooks = read_hooks(&hooks_path)?;

    // Generate hooks configuration
    let hooks_config = generate_hooks_config(&binary_path);

    // Set version and merge hooks
    hooks.insert("version".to_string(), json!(1));
    hooks.insert("hooks".to_string(), hooks_config);

    // Write hooks
    write_hooks(&hooks_path, &hooks)?;

    eprintln!(
        "\x1b[32m✓ Successfully installed hooks to {}\x1b[0m\n",
        hooks_path.display()
    );

    // Print configuration details
    eprintln!("Configuration details:");
    eprintln!("  - Hook executable: {}", binary_path.display());
    eprintln!("  - Debug logging: enabled (--verbose flag)");
    eprintln!();

    eprintln!("\x1b[33mNext steps:\x1b[0m");
    eprintln!("  1. Restart Cursor to activate the hooks");
    eprintln!("  2. Check hook logs in stderr output");
    eprintln!();

    eprintln!("\x1b[32mInstallation complete!\x1b[0m");

    Ok(())
}

/// Uninstall hooks from the specified scope
pub fn uninstall_hooks(scope: InstallScope) -> Result<()> {
    eprintln!("\x1b[32mSondera Cursor Hooks Uninstaller\x1b[0m");
    eprintln!("================================\n");

    // Get hooks file path
    let hooks_path = get_hooks_path(scope)?;
    eprintln!("Uninstalling from {} scope", scope);
    eprintln!("Hooks file: {}\n", hooks_path.display());

    if !hooks_path.exists() {
        eprintln!("Hooks file does not exist. Nothing to uninstall.");
        return Ok(());
    }

    // Backup existing hooks
    if let Some(backup_path) = backup_hooks(&hooks_path)? {
        eprintln!(
            "\x1b[33mBacked up existing hooks to: {}\x1b[0m",
            backup_path.display()
        );
    }

    // Read existing hooks
    let mut hooks = read_hooks(&hooks_path)?;

    // Remove hooks
    if hooks.remove("hooks").is_some() {
        // Write hooks
        write_hooks(&hooks_path, &hooks)?;
        eprintln!(
            "\x1b[32m✓ Successfully removed hooks from {}\x1b[0m",
            hooks_path.display()
        );
    } else {
        eprintln!("No hooks found in hooks file.");
    }

    eprintln!();
    eprintln!("\x1b[33mNote:\x1b[0m Restart Cursor for changes to take effect.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hooks_config() {
        let path = PathBuf::from("/usr/local/bin/sondera-cursor");
        let config = generate_hooks_config(&path);

        assert!(config.get("sessionStart").is_some());
        assert!(config.get("sessionEnd").is_some());
        assert!(config.get("preToolUse").is_some());
        assert!(config.get("postToolUse").is_some());
        assert!(config.get("beforeShellExecution").is_some());
        assert!(config.get("afterShellExecution").is_some());
        assert!(config.get("stop").is_some());

        // Verify command format
        let session_start = &config["sessionStart"][0]["command"];
        assert_eq!(
            session_start,
            "/usr/local/bin/sondera-cursor --verbose session-start"
        );
    }

    #[test]
    fn test_generate_hooks_config_has_matchers() {
        let path = PathBuf::from("/usr/local/bin/sondera-cursor");
        let config = generate_hooks_config(&path);

        // preToolUse and postToolUse should have matchers
        let pre_tool_use = &config["preToolUse"][0];
        assert!(pre_tool_use.get("matcher").is_some());
        assert_eq!(pre_tool_use["matcher"], "*");
    }
}
