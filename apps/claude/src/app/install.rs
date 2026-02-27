//! Install command for setting up Claude Code hooks.
//!
//! This module provides functionality to install the Sondera hooks configuration
//! into Claude Code settings files. Hooks can be installed at different scopes:
//! - User scope: `~/.claude/settings.json` (applies to all projects)
//! - Local project scope: `.claude/settings.local.json` (default, not committed to git)
//!
//! Note: The hooks connect to the harness server via Unix socket IPC. The harness
//! server must be running for the hooks to function.

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Scope for hooks installation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// User-level settings (~/.claude/settings.json)
    User,
    /// Project-level settings (.claude/settings.json) - committed to git
    Project,
    /// Local project settings (.claude/settings.local.json) - not committed to git
    Local,
}

impl std::fmt::Display for InstallScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallScope::User => write!(f, "user (~/.claude/settings.json)"),
            InstallScope::Project => write!(f, "project (.claude/settings.json)"),
            InstallScope::Local => write!(f, "local project (.claude/settings.local.json)"),
        }
    }
}

/// Find the binary path using PATH lookup
fn find_binary_path() -> Result<PathBuf> {
    // First, try to find 'sondera-claude' in PATH using which
    if let Ok(path) = which::which("sondera-claude") {
        return Ok(path);
    }

    // Fall back to common installation locations
    let home = dirs::home_dir().context("Could not determine home directory")?;

    // Check ~/.cargo/bin/sondera-claude
    let cargo_bin = home.join(".cargo/bin/sondera-claude");
    if cargo_bin.exists() {
        return Ok(cargo_bin);
    }

    // Check /usr/local/bin/sondera-claude
    let usr_local_bin = PathBuf::from("/usr/local/bin/sondera-claude");
    if usr_local_bin.exists() {
        return Ok(usr_local_bin);
    }

    // Check /usr/bin/sondera-claude
    let usr_bin = PathBuf::from("/usr/bin/sondera-claude");
    if usr_bin.exists() {
        return Ok(usr_bin);
    }

    // If running from cargo, get the current executable
    if let Ok(exe) = env::current_exe()
        && exe.file_name().and_then(|n| n.to_str()) == Some("sondera-claude")
    {
        return Ok(exe);
    }

    Err(anyhow::anyhow!(
        "Could not find sondera-claude binary. Please ensure it is installed and in your PATH.\n\
        You can install it using: cargo install --path apps/claude"
    ))
}

/// Generate the hooks configuration JSON for all Claude Code hook events
fn generate_hooks_config(binary_path: &Path) -> Value {
    let binary_str = binary_path.to_string_lossy();

    // Helper to create a hook entry for a given event
    let make_hook = |event: &str| -> Value {
        json!([{
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "command": format!("{} --verbose {}", binary_str, event)
            }]
        }])
    };

    json!({
        "PreToolUse": make_hook("pre-tool-use"),
        "PermissionRequest": make_hook("permission-request"),
        "PostToolUse": make_hook("post-tool-use"),
        "PostToolUseFailure": make_hook("post-tool-use-failure"),
        "UserPromptSubmit": make_hook("user-prompt-submit"),
        "Notification": make_hook("notification"),
        "Stop": make_hook("stop"),
        "SubagentStart": make_hook("subagent-start"),
        "SubagentStop": make_hook("subagent-stop"),
        "TeammateIdle": make_hook("teammate-idle"),
        "TaskCompleted": make_hook("task-completed"),
        "PreCompact": make_hook("pre-compact"),
        "SessionStart": make_hook("session-start"),
        "SessionEnd": make_hook("session-end")
    })
}

/// Get the settings file path for the given scope
fn get_settings_path(scope: InstallScope) -> Result<PathBuf> {
    match scope {
        InstallScope::User => {
            let home = dirs::home_dir().context("Could not determine home directory")?;
            Ok(home.join(".claude").join("settings.json"))
        }
        InstallScope::Project => {
            let cwd = env::current_dir().context("Could not determine current directory")?;
            Ok(cwd.join(".claude").join("settings.json"))
        }
        InstallScope::Local => {
            let cwd = env::current_dir().context("Could not determine current directory")?;
            Ok(cwd.join(".claude").join("settings.local.json"))
        }
    }
}

/// Create a backup of the existing settings file
fn backup_settings(path: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let backup_path = path.with_extension(format!("backup.{}.json", timestamp));

    fs::copy(path, &backup_path).context("Failed to create backup")?;

    Ok(Some(backup_path))
}

/// Read existing settings or create empty object
fn read_settings(path: &Path) -> Result<Map<String, Value>> {
    if path.exists() {
        let content = fs::read_to_string(path).context("Failed to read settings file")?;
        let value: Value =
            serde_json::from_str(&content).context("Failed to parse settings JSON")?;
        match value {
            Value::Object(map) => Ok(map),
            _ => Err(anyhow::anyhow!("Settings file is not a JSON object")),
        }
    } else {
        Ok(Map::new())
    }
}

/// Write settings to file
fn write_settings(path: &Path, settings: &Map<String, Value>) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create settings directory")?;
    }

    let content = serde_json::to_string_pretty(&Value::Object(settings.clone()))
        .context("Failed to serialize settings")?;

    fs::write(path, content).context("Failed to write settings file")?;

    Ok(())
}

/// Install hooks into the specified scope
pub fn install_hooks(scope: InstallScope, _verbose: bool) -> Result<()> {
    eprintln!("\x1b[32mSondera Claude Code Hooks Installer\x1b[0m");
    eprintln!("====================================\n");

    // Find binary path
    let binary_path = find_binary_path()?;
    eprintln!("Binary found: {}", binary_path.display());

    // Get settings file path
    let settings_path = get_settings_path(scope)?;
    eprintln!("Installing to {} scope", scope);
    eprintln!("Settings file: {}\n", settings_path.display());

    // Backup existing settings
    if let Some(backup_path) = backup_settings(&settings_path)? {
        eprintln!(
            "\x1b[33mBacked up existing settings to: {}\x1b[0m",
            backup_path.display()
        );
    }

    // Read existing settings
    let mut settings = read_settings(&settings_path)?;

    // Generate hooks configuration
    let hooks_config = generate_hooks_config(&binary_path);

    // Merge hooks into settings
    settings.insert("hooks".to_string(), hooks_config);

    // Write settings
    write_settings(&settings_path, &settings)?;

    eprintln!(
        "\x1b[32m✓ Successfully installed hooks to {}\x1b[0m\n",
        settings_path.display()
    );

    // Print configuration details
    eprintln!("Configuration details:");
    eprintln!("  - Hook executable: {}", binary_path.display());
    eprintln!("  - Debug logging: enabled (--verbose flag)");
    eprintln!();

    eprintln!("\x1b[33mNext steps:\x1b[0m");
    eprintln!("  1. Start the harness server: sondera-harness-server");
    eprintln!("  2. Restart Claude Code to activate the hooks");
    eprintln!("  3. Check hook logs in stderr output");
    eprintln!();

    eprintln!("\x1b[32mInstallation complete!\x1b[0m");

    Ok(())
}

/// Uninstall hooks from the specified scope
pub fn uninstall_hooks(scope: InstallScope) -> Result<()> {
    eprintln!("\x1b[32mSondera Claude Code Hooks Uninstaller\x1b[0m");
    eprintln!("======================================\n");

    // Get settings file path
    let settings_path = get_settings_path(scope)?;
    eprintln!("Uninstalling from {} scope", scope);
    eprintln!("Settings file: {}\n", settings_path.display());

    if !settings_path.exists() {
        eprintln!("Settings file does not exist. Nothing to uninstall.");
        return Ok(());
    }

    // Backup existing settings
    if let Some(backup_path) = backup_settings(&settings_path)? {
        eprintln!(
            "\x1b[33mBacked up existing settings to: {}\x1b[0m",
            backup_path.display()
        );
    }

    // Read existing settings
    let mut settings = read_settings(&settings_path)?;

    // Remove hooks
    if settings.remove("hooks").is_some() {
        // Write settings
        write_settings(&settings_path, &settings)?;
        eprintln!(
            "\x1b[32m✓ Successfully removed hooks from {}\x1b[0m",
            settings_path.display()
        );
    } else {
        eprintln!("No hooks found in settings file.");
    }

    eprintln!();
    eprintln!("\x1b[33mNote:\x1b[0m Restart Claude Code for changes to take effect.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hooks_config() {
        let path = PathBuf::from("/usr/local/bin/sondera-claude");
        let config = generate_hooks_config(&path);

        assert!(config.get("PreToolUse").is_some());
        assert!(config.get("PostToolUse").is_some());
        assert!(config.get("SessionStart").is_some());
        assert!(config.get("SessionEnd").is_some());

        let pre_tool_use = &config["PreToolUse"][0]["hooks"][0]["command"];
        assert_eq!(
            pre_tool_use,
            "/usr/local/bin/sondera-claude --verbose pre-tool-use"
        );
    }

    #[test]
    fn test_generate_hooks_config_all_events() {
        let path = PathBuf::from("/usr/local/bin/sondera-claude");
        let config = generate_hooks_config(&path);

        // Verify all hook events are present
        let events = [
            "PreToolUse",
            "PermissionRequest",
            "PostToolUse",
            "PostToolUseFailure",
            "UserPromptSubmit",
            "Notification",
            "Stop",
            "SubagentStart",
            "SubagentStop",
            "TeammateIdle",
            "TaskCompleted",
            "PreCompact",
            "SessionStart",
            "SessionEnd",
        ];

        for event in events {
            assert!(config.get(event).is_some(), "Missing event: {}", event);
        }
    }
}
