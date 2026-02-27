//! Install command for setting up Gemini CLI hooks.
//!
//! This module provides functionality to install the Sondera hooks configuration
//! into Gemini CLI settings files. Hooks can be installed at different scopes:
//! - User scope: `~/.gemini/settings.json` (applies to all projects)
//! - Project scope: `.gemini/settings.json` (committed to git)
//! - Local project scope: `.gemini/settings.local.json` (not committed to git)
//!
//! Reference: https://geminicli.com/docs/hooks/

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Scope for hooks installation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// User-level settings (~/.gemini/settings.json)
    User,
    /// Project-level settings (.gemini/settings.json) - committed to git
    Project,
    /// Local project settings (.gemini/settings.local.json) - not committed to git
    Local,
}

impl std::fmt::Display for InstallScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallScope::User => write!(f, "user (~/.gemini/settings.json)"),
            InstallScope::Project => write!(f, "project (.gemini/settings.json)"),
            InstallScope::Local => write!(f, "local project (.gemini/settings.local.json)"),
        }
    }
}

/// Find the binary path using PATH lookup
fn find_binary_path() -> Result<PathBuf> {
    // First, try to find 'sondera-gemini' in PATH using which
    if let Ok(path) = which::which("sondera-gemini") {
        return Ok(path);
    }

    // Fall back to common installation locations
    let home = dirs::home_dir().context("Could not determine home directory")?;

    // Check ~/.cargo/bin/sondera-gemini
    let cargo_bin = home.join(".cargo/bin/sondera-gemini");
    if cargo_bin.exists() {
        return Ok(cargo_bin);
    }

    // Check /usr/local/bin/sondera-gemini
    let usr_local_bin = PathBuf::from("/usr/local/bin/sondera-gemini");
    if usr_local_bin.exists() {
        return Ok(usr_local_bin);
    }

    // Check /usr/bin/sondera-gemini
    let usr_bin = PathBuf::from("/usr/bin/sondera-gemini");
    if usr_bin.exists() {
        return Ok(usr_bin);
    }

    // If running from cargo, get the current executable
    if let Ok(exe) = env::current_exe()
        && exe.file_name().and_then(|n| n.to_str()) == Some("sondera-gemini")
    {
        return Ok(exe);
    }

    Err(anyhow::anyhow!(
        "Could not find sondera-gemini binary. Please ensure it is installed and in your PATH.\n\
        You can install it using: cargo install --path apps/gemini"
    ))
}

/// Generate the hooks configuration JSON for all Gemini CLI hook events
///
/// Gemini CLI uses a different structure than Claude:
/// - Each hook type contains an array of hook definitions
/// - Each definition can have a `matcher` and array of `hooks`
/// - The `hooks` array contains objects with `type`, `command`, `name`, `timeout`, `description`
fn generate_hooks_config(binary_path: &Path) -> Value {
    let binary_str = binary_path.to_string_lossy();

    // Helper to create a hook entry for a given event
    // Using the Gemini CLI hooks configuration schema
    let make_hook = |event: &str, description: &str| -> Value {
        json!([{
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "name": format!("sondera-{}", event.to_lowercase().replace("_", "-")),
                "description": description,
                "command": format!("{} --verbose {}", binary_str, event),
                "timeout": 60000
            }]
        }])
    };

    json!({
        "SessionStart": make_hook("session-start", "Initialize Sondera trajectory tracking"),
        "SessionEnd": make_hook("session-end", "Finalize Sondera session and cleanup"),
        "BeforeAgent": make_hook("before-agent", "Validate prompts before agent processing"),
        "AfterAgent": make_hook("after-agent", "Audit agent responses and handle retries"),
        "BeforeModel": make_hook("before-model", "Control LLM requests before submission"),
        "AfterModel": make_hook("after-model", "Filter and redact LLM responses"),
        "BeforeToolSelection": make_hook("before-tool-selection", "Filter available tools based on policy"),
        "BeforeTool": make_hook("before-tool", "Validate tool invocations and enforce security"),
        "AfterTool": make_hook("after-tool", "Audit tool results and inject context"),
        "PreCompress": make_hook("pre-compress", "Handle context compression notifications"),
        "Notification": make_hook("notification", "Handle system notifications")
    })
}

/// Get the settings file path for the given scope
fn get_settings_path(scope: InstallScope) -> Result<PathBuf> {
    match scope {
        InstallScope::User => {
            let home = dirs::home_dir().context("Could not determine home directory")?;
            Ok(home.join(".gemini").join("settings.json"))
        }
        InstallScope::Project => {
            let cwd = env::current_dir().context("Could not determine current directory")?;
            Ok(cwd.join(".gemini").join("settings.json"))
        }
        InstallScope::Local => {
            let cwd = env::current_dir().context("Could not determine current directory")?;
            Ok(cwd.join(".gemini").join("settings.local.json"))
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
    eprintln!("\x1b[32mSondera Gemini CLI Hooks Installer\x1b[0m");
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
    eprintln!("  1. Restart Gemini CLI to activate the hooks");
    eprintln!("  2. Check hook logs in stderr output");
    eprintln!();

    eprintln!("Managing hooks:");
    eprintln!("  - View hooks: /hooks panel");
    eprintln!("  - Enable/disable all: /hooks enable-all or /hooks disable-all");
    eprintln!("  - Toggle individual: /hooks enable <name> or /hooks disable <name>");
    eprintln!();

    eprintln!("\x1b[32mInstallation complete!\x1b[0m");

    Ok(())
}

/// Uninstall hooks from the specified scope
pub fn uninstall_hooks(scope: InstallScope) -> Result<()> {
    eprintln!("\x1b[32mSondera Gemini CLI Hooks Uninstaller\x1b[0m");
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
    eprintln!("\x1b[33mNote:\x1b[0m Restart Gemini CLI for changes to take effect.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hooks_config() {
        let path = PathBuf::from("/usr/local/bin/sondera-gemini");
        let config = generate_hooks_config(&path);

        // Check all expected hook types are present
        assert!(config.get("SessionStart").is_some());
        assert!(config.get("SessionEnd").is_some());
        assert!(config.get("BeforeAgent").is_some());
        assert!(config.get("AfterAgent").is_some());
        assert!(config.get("BeforeModel").is_some());
        assert!(config.get("AfterModel").is_some());
        assert!(config.get("BeforeToolSelection").is_some());
        assert!(config.get("BeforeTool").is_some());
        assert!(config.get("AfterTool").is_some());
        assert!(config.get("PreCompress").is_some());
        assert!(config.get("Notification").is_some());

        // Verbose is always enabled
        let before_tool = &config["BeforeTool"][0]["hooks"][0]["command"];
        assert_eq!(
            before_tool,
            "/usr/local/bin/sondera-gemini --verbose before-tool"
        );
    }

    #[test]
    fn test_hook_config_structure() {
        let path = PathBuf::from("/usr/local/bin/sondera-gemini");
        let config = generate_hooks_config(&path);

        // Verify Gemini CLI hook structure
        let session_start = &config["SessionStart"][0];
        assert_eq!(session_start["matcher"], "*");
        assert!(session_start["hooks"].is_array());

        let hook = &session_start["hooks"][0];
        assert_eq!(hook["type"], "command");
        assert!(hook["name"].as_str().unwrap().starts_with("sondera-"));
        assert!(hook["description"].is_string());
        assert_eq!(hook["timeout"], 60000);
    }
}
