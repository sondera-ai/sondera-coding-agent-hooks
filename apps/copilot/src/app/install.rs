//! Install command for setting up GitHub Copilot hooks.
//!
//! This module provides functionality to install the Sondera hooks configuration
//! into the .github/hooks/hooks.json file for GitHub Copilot CLI.
//!
//! Reference: https://docs.github.com/en/copilot/reference/hooks-configuration

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Find the binary path using PATH lookup
fn find_binary_path() -> Result<PathBuf> {
    // First, try to find 'sondera-copilot' in PATH using which
    if let Ok(path) = which::which("sondera-copilot") {
        return Ok(path);
    }

    // Fall back to common installation locations
    let home = dirs::home_dir().context("Could not determine home directory")?;

    // Check ~/.cargo/bin/sondera-copilot
    let cargo_bin = home.join(".cargo/bin/sondera-copilot");
    if cargo_bin.exists() {
        return Ok(cargo_bin);
    }

    // Check /usr/local/bin/sondera-copilot
    let usr_local_bin = PathBuf::from("/usr/local/bin/sondera-copilot");
    if usr_local_bin.exists() {
        return Ok(usr_local_bin);
    }

    // Check /usr/bin/sondera-copilot
    let usr_bin = PathBuf::from("/usr/bin/sondera-copilot");
    if usr_bin.exists() {
        return Ok(usr_bin);
    }

    // If running from cargo, get the current executable
    if let Ok(exe) = env::current_exe()
        && exe.file_name().and_then(|n| n.to_str()) == Some("sondera-copilot")
    {
        return Ok(exe);
    }

    Err(anyhow::anyhow!(
        "Could not find sondera-copilot binary. Please ensure it is installed and in your PATH.\n\
        You can install it using: cargo install --path apps/copilot"
    ))
}

/// Generate the hooks.json configuration for GitHub Copilot CLI
fn generate_hooks_config(binary_path: &Path) -> Value {
    let binary_str = binary_path.to_string_lossy();

    // Helper to create a hook entry for a given event
    let make_hook = |event: &str| -> Value {
        json!([{
            "type": "command",
            "bash": format!("{} --verbose {}", binary_str, event),
            "powershell": format!("{}.exe --verbose {}", binary_str, event),
            "cwd": ".",
            "timeoutSec": 30
        }])
    };

    json!({
        "version": 1,
        "hooks": {
            "sessionStart": make_hook("session-start"),
            "sessionEnd": make_hook("session-end"),
            "userPromptSubmitted": make_hook("user-prompt-submitted"),
            "preToolUse": make_hook("pre-tool-use"),
            "postToolUse": make_hook("post-tool-use"),
            "errorOccurred": make_hook("error-occurred")
        }
    })
}

/// Get the hooks.json file path
fn get_hooks_path() -> Result<PathBuf> {
    let cwd = env::current_dir().context("Could not determine current directory")?;
    Ok(cwd.join(".github").join("hooks").join("hooks.json"))
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

/// Read existing hooks config or create empty object
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

/// Write hooks config to file
fn write_hooks(path: &Path, hooks: &Value) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create hooks directory")?;
    }

    let content =
        serde_json::to_string_pretty(hooks).context("Failed to serialize hooks config")?;

    fs::write(path, content).context("Failed to write hooks file")?;

    Ok(())
}

/// Install hooks into the current repository
pub fn install_hooks(_verbose: bool) -> Result<()> {
    eprintln!("\x1b[32mSondera GitHub Copilot Hooks Installer\x1b[0m");
    eprintln!("=======================================\n");

    // Find binary path
    let binary_path = find_binary_path()?;
    eprintln!("Binary found: {}", binary_path.display());

    // Get hooks file path
    let hooks_path = get_hooks_path()?;
    eprintln!("Installing to: {}\n", hooks_path.display());

    // Backup existing hooks
    if let Some(backup_path) = backup_hooks(&hooks_path)? {
        eprintln!(
            "\x1b[33mBacked up existing hooks to: {}\x1b[0m",
            backup_path.display()
        );
    }

    // Generate hooks configuration
    let hooks_config = generate_hooks_config(&binary_path);

    // Write hooks config
    write_hooks(&hooks_path, &hooks_config)?;

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
    eprintln!("  1. Commit the .github/hooks/hooks.json file to your repository");
    eprintln!("  2. The hooks will be active for GitHub Copilot CLI sessions");
    eprintln!("  3. Check hook logs in stderr output");
    eprintln!();

    eprintln!("\x1b[32mInstallation complete!\x1b[0m");

    Ok(())
}

/// Uninstall hooks from the current repository
pub fn uninstall_hooks() -> Result<()> {
    eprintln!("\x1b[32mSondera GitHub Copilot Hooks Uninstaller\x1b[0m");
    eprintln!("=========================================\n");

    // Get hooks file path
    let hooks_path = get_hooks_path()?;
    eprintln!("Uninstalling from: {}\n", hooks_path.display());

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

    // Check if our hooks are present and remove them
    let mut removed = false;
    if let Some(hooks_obj) = hooks.get_mut("hooks")
        && let Some(hooks_map) = hooks_obj.as_object_mut()
    {
        // Remove all hooks that reference sondera-copilot
        let keys_to_remove: Vec<String> = hooks_map
            .iter()
            .filter(|(_, v)| v.to_string().contains("sondera-copilot"))
            .map(|(k, _)| k.clone())
            .collect();

        for key in keys_to_remove {
            hooks_map.remove(&key);
            removed = true;
        }
    }

    if removed {
        // If hooks object is now empty, remove the file
        if hooks
            .get("hooks")
            .map(|h| h.as_object().map(|m| m.is_empty()).unwrap_or(false))
            .unwrap_or(false)
        {
            fs::remove_file(&hooks_path).context("Failed to remove hooks file")?;
            eprintln!(
                "\x1b[32m✓ Removed hooks file: {}\x1b[0m",
                hooks_path.display()
            );
        } else {
            // Write updated hooks config
            write_hooks(&hooks_path, &Value::Object(hooks))?;
            eprintln!(
                "\x1b[32m✓ Successfully removed Sondera hooks from {}\x1b[0m",
                hooks_path.display()
            );
        }
    } else {
        eprintln!("No Sondera hooks found in the configuration.");
    }

    eprintln!();
    eprintln!(
        "\x1b[33mNote:\x1b[0m Don't forget to commit the changes if the file was tracked in git."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hooks_config() {
        let path = PathBuf::from("/usr/local/bin/sondera-copilot");
        let config = generate_hooks_config(&path);

        assert_eq!(config.get("version"), Some(&json!(1)));

        let hooks = config.get("hooks").unwrap();
        assert!(hooks.get("sessionStart").is_some());
        assert!(hooks.get("sessionEnd").is_some());
        assert!(hooks.get("userPromptSubmitted").is_some());
        assert!(hooks.get("preToolUse").is_some());
        assert!(hooks.get("postToolUse").is_some());
        assert!(hooks.get("errorOccurred").is_some());

        // Verbose is always enabled regardless of the flag
        let pre_tool_use = &hooks["preToolUse"][0]["bash"];
        assert!(pre_tool_use.as_str().unwrap().contains("--verbose"));
        assert!(pre_tool_use.as_str().unwrap().contains("pre-tool-use"));
    }
}
