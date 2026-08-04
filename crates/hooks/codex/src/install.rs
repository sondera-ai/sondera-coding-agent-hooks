//! Install/uninstall commands for OpenAI Codex CLI hooks.
//!
//! This module provides functionality to install the Sondera hooks configuration
//! into `~/.codex/hooks.json` (user-level) or `.codex/hooks.json` (project-level).
//!
//! Install is merge-based: existing third-party hook entries are preserved while
//! Sondera entries are replaced idempotently. Uninstall selectively removes only
//! Sondera entries, leaving other hooks intact.
//!
//! The installer also manages:
//! - The `hooks = true` feature flag in `config.toml`
//! - Marketplace entry in `~/.agents/plugins/`
//!
//! Reference: <https://developers.openai.com/codex/hooks>

use serde_json::{Map, Value, json};
use sondera_hooks::error::{HookResultExt as _, Result};
use sondera_hooks::install::{HookConfigInstaller, command};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// The provider this adapter's hook commands dispatch to.
const PROVIDER: &str = "codex";

/// Human-facing agent name used in installer output.
const AGENT: &str = "Codex";

const HOOK_TIMEOUT_SECS: u64 = 30;

/// All hook event names that this adapter handles.
const HOOK_EVENTS: &[&str] = &[
    "SessionStart",
    "SessionEnd",
    "SubagentStart",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PreCompact",
    "PostCompact",
    "UserPromptSubmit",
    "SubagentStop",
    "Stop",
];

// ============================================================================
// Binary resolution
// ============================================================================

// ============================================================================
// Hook configuration generation
// ============================================================================

/// Generate the hooks configuration for every current Codex CLI event.
fn generate_hooks_config(binary_path: &sondera_hooks::install::binary::ResolvedBinary) -> Value {
    let bin = binary_path.render(sondera_hooks::install::binary::CommandShell::Posix);
    let handler = |subcommand: &str, status_message: Option<&str>| {
        let mut hook = json!({
            "type": "command",
            "command": format!("{bin} hook codex --verbose {subcommand}"),
            "timeout": HOOK_TIMEOUT_SECS
        });
        if let Some(message) = status_message {
            hook["statusMessage"] = json!(message);
        }
        hook
    };
    let group = |matcher: Option<&str>, hook: Value| {
        let mut group = json!({"hooks": [hook]});
        if let Some(matcher) = matcher {
            group["matcher"] = json!(matcher);
        }
        Value::Array(vec![group])
    };

    json!({
        "hooks": {
            "SessionStart": group(Some("startup|resume|clear|compact"), handler("session-start", Some("Initializing governance session..."))),
            "SessionEnd": group(None, handler("session-end", None)),
            "SubagentStart": group(None, handler("subagent-start", None)),
            "PreToolUse": group(Some("*"), handler("pre-tool-use", Some("Evaluating policy..."))),
            "PermissionRequest": group(Some("*"), handler("permission-request", Some("Evaluating permission policy..."))),
            "PostToolUse": group(Some("*"), handler("post-tool-use", None)),
            "PreCompact": group(Some("manual|auto"), handler("pre-compact", None)),
            "PostCompact": group(Some("manual|auto"), handler("post-compact", None)),
            "UserPromptSubmit": group(None, handler("user-prompt-submit", None)),
            "SubagentStop": group(None, handler("subagent-stop", None)),
            "Stop": group(None, handler("stop", None))
        }
    })
}

// ============================================================================
// Path helpers
// ============================================================================

/// Get the user-level hooks.json path: ~/.codex/hooks.json
fn user_hooks_path_for_home(home: &Path) -> PathBuf {
    home.join(".codex").join("hooks.json")
}

fn user_hooks_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(user_hooks_path_for_home(&home))
}

/// Get the project-level hooks.json path: .codex/hooks.json
fn project_hooks_path() -> Result<PathBuf> {
    let cwd = env::current_dir().context("Could not determine current directory")?;
    Ok(cwd.join(".codex").join("hooks.json"))
}

/// Get the hooks.json path based on scope.
fn get_hooks_path(project: bool) -> Result<PathBuf> {
    if project {
        project_hooks_path()
    } else {
        user_hooks_path()
    }
}

/// Get the user-level config.toml path: ~/.codex/config.toml
fn user_config_path_for_home(home: &Path) -> PathBuf {
    home.join(".codex").join("config.toml")
}

fn user_config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(user_config_path_for_home(&home))
}

// ============================================================================
// Backup
// ============================================================================

// ============================================================================
// Hook file I/O
// ============================================================================

// ============================================================================
// Sondera entry detection
// ============================================================================

/// Whether any hook entry in a rule array is one this adapter manages.
fn rules_contain_sondera(rules: &Value) -> bool {
    command::value_targets_provider(rules, PROVIDER)
}

/// Remove all managed Sondera Codex entries from a hooks map, preserving third-party
/// entries. Returns true if anything was removed.
fn remove_sondera_entries(hooks_map: &mut Map<String, Value>) -> bool {
    let mut changed = false;

    let event_keys: Vec<String> = hooks_map.keys().cloned().collect();
    for key in event_keys {
        let Some(rules_value) = hooks_map.get(&key) else {
            continue;
        };
        let Some(rules) = rules_value.as_array() else {
            continue;
        };

        let mut kept = Vec::new();
        let mut event_changed = false;
        for rule in rules {
            let Some(rule_obj) = rule.as_object() else {
                if rules_contain_sondera(rule) {
                    event_changed = true;
                } else {
                    kept.push(rule.clone());
                }
                continue;
            };

            let Some(entries) = rule_obj.get("hooks").and_then(Value::as_array) else {
                if rules_contain_sondera(rule) {
                    event_changed = true;
                } else {
                    kept.push(rule.clone());
                }
                continue;
            };

            let kept_entries = entries
                .iter()
                .filter(|entry| !rules_contain_sondera(entry))
                .cloned()
                .collect::<Vec<_>>();

            if kept_entries.len() != entries.len() {
                event_changed = true;
            }
            if kept_entries.is_empty() {
                continue;
            }

            let mut updated_rule = rule_obj.clone();
            updated_rule.insert("hooks".to_string(), Value::Array(kept_entries));
            kept.push(Value::Object(updated_rule));
        }

        if !event_changed {
            continue;
        }
        changed = true;
        if kept.is_empty() {
            hooks_map.remove(&key);
        } else {
            hooks_map.insert(key, Value::Array(kept));
        }
    }

    changed
}

/// Merge sondera hooks into an existing hooks map. Existing sondera entries
/// are removed first, then the new ones are appended to each event's rule
/// array so that third-party hooks are preserved.
fn merge_hooks(existing: &mut Map<String, Value>, new_hooks: &Map<String, Value>) {
    // First pass: remove stale sondera entries
    remove_sondera_entries(existing);

    // Second pass: merge new entries
    for (event_name, new_rules) in new_hooks {
        let Some(new_arr) = new_rules.as_array() else {
            continue;
        };

        if let Some(existing_val) = existing.get_mut(event_name)
            && let Some(existing_arr) = existing_val.as_array_mut()
        {
            existing_arr.extend(new_arr.iter().cloned());
        } else {
            existing.insert(event_name.clone(), new_rules.clone());
        }
    }
}

// ============================================================================
// Feature flag management
// ============================================================================

/// Check if Codex hooks are enabled in the given config file path.
///
/// `hooks = true` is the current Codex feature flag. `codex_hooks = true` is
/// accepted for compatibility with earlier installs, but new installs write the
/// canonical flag.
fn check_feature_flag_at(path: &Path) -> bool {
    if let Ok(content) = fs::read_to_string(path)
        && let Ok(value) = content.parse::<toml::Value>()
        && let Some(features) = value.get("features")
        && let Some(features) = features.as_table()
    {
        for key in ["hooks", "codex_hooks"] {
            if features.get(key).and_then(toml::Value::as_bool) == Some(true) {
                return true;
            }
        }
    }
    false
}

/// Check if Codex hooks are enabled in any config.toml.
///
/// Checks both ~/.codex/config.toml and .codex/config.toml.
fn check_feature_flag() -> bool {
    let paths = [
        dirs::home_dir().map(|h| h.join(".codex").join("config.toml")),
        env::current_dir()
            .ok()
            .map(|c| c.join(".codex").join("config.toml")),
    ];

    for path in paths.into_iter().flatten() {
        if check_feature_flag_at(&path) {
            return true;
        }
    }

    false
}

/// Enable the `hooks = true` feature flag in the user-level config.toml.
///
/// Preserves existing config content. Creates the file and parent directory
/// if they do not exist.
fn enable_feature_flag(config_path: &Path) -> Result<()> {
    if check_feature_flag_at(config_path) {
        return Ok(()); // already enabled
    }

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).context("Failed to create config directory")?;
    }

    if config_path.exists() {
        let content = fs::read_to_string(config_path).context("Failed to read config.toml")?;
        let mut doc: toml::Value = content.parse().context("Failed to parse config.toml")?;

        // Navigate or create `features.hooks`.
        let table = doc
            .as_table_mut()
            .context("config.toml root is not a table")?;
        let features = table
            .entry("features")
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
        if let Some(features_table) = features.as_table_mut() {
            features_table.insert("hooks".to_string(), toml::Value::Boolean(true));
        }

        let serialized = toml::to_string_pretty(&doc).context("Failed to serialize config.toml")?;
        fs::write(config_path, serialized).context("Failed to write config.toml")?;
    } else {
        // Create a minimal config.toml
        let content = "[features]\nhooks = true\n";
        fs::write(config_path, content).context("Failed to write config.toml")?;
    }

    Ok(())
}

// ============================================================================
// Marketplace entry
// ============================================================================

/// Generate a marketplace entry JSON for personal marketplace discovery.
fn generate_marketplace_entry() -> Value {
    json!({
        "name": "sondera-tools",
        "interface": {
            "displayName": "Sondera Governance Tools"
        },
        "plugins": [
            {
                "name": "sondera-codex",
                "source": {
                    "source": "local",
                    "path": "./sondera"
                },
                "policy": {
                    "installation": "AVAILABLE"
                },
                "category": "Security"
            }
        ]
    })
}

/// Write marketplace entry to ~/.agents/plugins/marketplace.json.
///
/// If the file already exists and already contains a `sondera-codex` plugin
/// entry, it is updated in place to point at the umbrella binary. If it exists
/// with other plugins but not ours, we merge our entry into the existing
/// plugins array.
fn marketplace_path_for_home(home: &Path) -> PathBuf {
    home.join(".agents")
        .join("plugins")
        .join("marketplace.json")
}

fn write_marketplace_entry_at(marketplace_path: &Path) -> Result<()> {
    let marketplace_dir = marketplace_path
        .parent()
        .context("marketplace path must have a parent directory")?;

    fs::create_dir_all(marketplace_dir).context("Failed to create plugins directory")?;

    let sondera_plugin = json!({
        "name": "sondera-codex",
        "source": {
            "source": "local",
            "path": "./sondera"
        },
        "policy": {
            "installation": "AVAILABLE"
        },
        "category": "Security"
    });

    if marketplace_path.exists() {
        let content =
            fs::read_to_string(marketplace_path).context("Failed to read marketplace.json")?;
        let mut doc: Value =
            serde_json::from_str(&content).context("Failed to parse marketplace.json")?;

        if let Some(plugins) = doc.get_mut("plugins").and_then(|p| p.as_array_mut()) {
            if let Some(existing) = plugins
                .iter_mut()
                .find(|p| p.get("name").and_then(Value::as_str) == Some("sondera-codex"))
            {
                *existing = sondera_plugin;
            } else {
                plugins.push(sondera_plugin);
            }
        } else {
            doc["plugins"] = json!([sondera_plugin]);
        }

        let serialized =
            serde_json::to_string_pretty(&doc).context("Failed to serialize marketplace.json")?;
        fs::write(marketplace_path, serialized).context("Failed to write marketplace.json")?;
    } else {
        let entry = generate_marketplace_entry();
        let content = serde_json::to_string_pretty(&entry)
            .context("Failed to serialize marketplace entry")?;
        fs::write(marketplace_path, content).context("Failed to write marketplace.json")?;
    }

    Ok(())
}

fn write_marketplace_entry() -> Result<()> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    write_marketplace_entry_at(&marketplace_path_for_home(&home))
}

/// Remove the sondera-codex entry from ~/.agents/plugins/marketplace.json.
///
/// If sondera-codex is the only plugin, removes the file entirely.
/// If other plugins exist, rewrites the file without the sondera-codex entry.
fn remove_marketplace_entry() -> Result<()> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    let marketplace_path = home
        .join(".agents")
        .join("plugins")
        .join("marketplace.json");

    if !marketplace_path.exists() {
        return Ok(());
    }

    let content =
        fs::read_to_string(&marketplace_path).context("Failed to read marketplace.json")?;
    let mut doc: Value =
        serde_json::from_str(&content).context("Failed to parse marketplace.json")?;

    if let Some(plugins) = doc.get_mut("plugins").and_then(|p| p.as_array_mut()) {
        let original_len = plugins.len();
        plugins.retain(|p| p.get("name").and_then(Value::as_str) != Some("sondera-codex"));

        if plugins.len() == original_len {
            return Ok(()); // sondera-codex wasn't present
        }

        if plugins.is_empty() {
            fs::remove_file(&marketplace_path).context("Failed to remove marketplace.json")?;
        } else {
            let serialized = serde_json::to_string_pretty(&doc)
                .context("Failed to serialize marketplace.json")?;
            fs::write(&marketplace_path, serialized).context("Failed to write marketplace.json")?;
        }
    }

    Ok(())
}

// ============================================================================
// Public install/uninstall API
// ============================================================================

/// Splice our hooks into `existing`, replacing any we installed previously.
///
/// Idempotent: running twice produces the same hooks.json content, and
/// third-party hook entries are preserved.
fn apply_hooks(
    existing: &mut Map<String, Value>,
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
) {
    let new_config = generate_hooks_config(binary_path);
    let new_hooks = new_config
        .get("hooks")
        .and_then(|h| h.as_object())
        .cloned()
        .unwrap_or_default();

    let existing_hooks = existing
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(hooks_map) = existing_hooks.as_object_mut() {
        merge_hooks(hooks_map, &new_hooks);
    } else {
        // Existing "hooks" key is not an object; replace it
        *existing_hooks = Value::Object(new_hooks.clone());
    }
}

/// Remove our hooks from `top_level`, returning whether anything changed.
fn revoke_hooks(top_level: &mut Map<String, Value>) -> bool {
    let removed = top_level
        .get_mut("hooks")
        .and_then(Value::as_object_mut)
        .is_some_and(remove_sondera_entries);

    if removed
        && top_level
            .get("hooks")
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
    {
        top_level.remove("hooks");
    }
    removed
}

fn installer(project: bool) -> Result<HookConfigInstaller> {
    let (scope, next_steps) = if project {
        (
            "project (.codex/hooks.json)",
            vec![
                "Commit the .codex/hooks.json file to your repository",
                "Ensure the project is marked as trusted in Codex",
            ],
        )
    } else {
        (
            "user (~/.codex/hooks.json)",
            vec!["The hooks are now active for all Codex CLI sessions"],
        )
    };
    Ok(
        HookConfigInstaller::new(AGENT, get_hooks_path(project)?, scope)
            .with_next_steps(next_steps)
            // `hooks.json` exists only to hold hooks.
            .remove_when(Map::is_empty),
    )
}

pub fn install_hooks(project: bool) -> Result<()> {
    installer(project)?.install(apply_hooks)?;

    // Codex needs two things beyond the hooks file itself: the feature flag
    // that turns hooks on at all, and a marketplace entry for plugin
    // discovery. Both are best-effort — a failure here leaves working hooks.
    if !check_feature_flag() {
        if let Ok(config_path) = user_config_path() {
            match enable_feature_flag(&config_path) {
                Ok(()) => {
                    eprintln!(
                        "Feature flag: hooks = true (enabled in {})",
                        config_path.display()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "\x1b[33mWARNING: Failed to auto-enable feature flag: {}\x1b[0m",
                        e
                    );
                    eprintln!("Add the following to ~/.codex/config.toml:\n");
                    eprintln!("  [features]");
                    eprintln!("  hooks = true\n");
                }
            }
        }
    } else {
        eprintln!("Feature flag: hooks = true (already enabled)\n");
    }

    // Write marketplace entry (best-effort, non-fatal)
    match write_marketplace_entry() {
        Ok(()) => eprintln!("Marketplace entry: registered"),
        Err(e) => eprintln!(
            "\x1b[33mWARNING: Failed to write marketplace entry: {}\x1b[0m",
            e
        ),
    }
    eprintln!("Events: {}", HOOK_EVENTS.join(", "));

    Ok(())
}

/// Uninstall hooks from the specified scope.
///
/// Only removes Sondera hook entries; third-party hooks are preserved. The
/// hooks file is deleted only when it becomes empty after removal.
pub fn uninstall_hooks(project: bool) -> Result<()> {
    installer(project)?.uninstall(revoke_hooks)?;

    // Clean up marketplace entry (best-effort)
    if let Err(e) = remove_marketplace_entry() {
        eprintln!(
            "\x1b[33mWARNING: Failed to clean marketplace entry: {}\x1b[0m",
            e
        );
    }

    eprintln!();
    eprintln!(
        "\x1b[33mNote:\x1b[0m Codex hooks feature flag is left enabled (other hooks may depend on it)."
    );
    if project {
        eprintln!("If this was a project-scoped config, remember to commit the change.");
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_hooks::install::config;

    fn binary() -> sondera_hooks::install::binary::ResolvedBinary {
        sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ))
    }
    use tempfile::TempDir;

    // ================================================================
    // generate_hooks_config
    // ================================================================

    #[test]
    fn test_generate_hooks_config() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path);

        let hooks = config.get("hooks").unwrap();
        assert!(hooks.get("SessionStart").is_some());
        assert!(hooks.get("PreToolUse").is_some());
        assert!(hooks.get("PostToolUse").is_some());
        assert!(hooks.get("UserPromptSubmit").is_some());
        assert!(hooks.get("Stop").is_some());

        // Verify binary path is embedded
        let pre_tool = &hooks["PreToolUse"][0]["hooks"][0]["command"];
        let cmd = pre_tool.as_str().unwrap();
        assert!(cmd.contains("/usr/local/bin/sondera hook codex"));
        assert!(cmd.contains("--verbose"));
        assert!(cmd.contains("pre-tool-use"));
    }

    #[test]
    fn test_generate_hooks_config_has_matchers() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path);

        let hooks = config.get("hooks").unwrap();

        let session_start_matcher = &hooks["SessionStart"][0]["matcher"];
        assert_eq!(
            session_start_matcher.as_str().unwrap(),
            "startup|resume|clear|compact"
        );

        let pre_tool_matcher = &hooks["PreToolUse"][0]["matcher"];
        assert_eq!(pre_tool_matcher.as_str().unwrap(), "*");
    }

    #[test]
    fn test_generate_hooks_config_has_thirty_second_timeouts() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path);
        let hooks = config.get("hooks").unwrap();

        for event in HOOK_EVENTS {
            assert_eq!(
                hooks[*event][0]["hooks"][0]["timeout"], 30,
                "{event} timeout"
            );
        }
    }

    #[test]
    fn test_user_hooks_path() {
        let path = user_hooks_path().unwrap();
        assert!(path.to_string_lossy().contains(".codex"));
        assert!(path.to_string_lossy().ends_with("hooks.json"));
    }

    #[test]
    fn user_scope_install_writes_hooks_feature_flag_and_marketplace_entry() {
        let home = TempDir::new().unwrap();
        let hooks_path = user_hooks_path_for_home(home.path());
        let config_path = user_config_path_for_home(home.path());
        let marketplace_path = marketplace_path_for_home(home.path());

        fs::create_dir_all(hooks_path.parent().unwrap()).unwrap();
        fs::write(
            &hooks_path,
            json!({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": ".*",
                        "hooks": [{
                            "type": "command",
                            "command": "/usr/local/bin/customer-codex-hook"
                        }]
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();

        let backup = HookConfigInstaller::new(AGENT, &hooks_path, "user (test)")
            .apply(&binary(), apply_hooks)
            .unwrap()
            .expect("existing Codex hooks file should be backed up");
        enable_feature_flag(&config_path).unwrap();
        write_marketplace_entry_at(&marketplace_path).unwrap();

        assert!(
            backup.exists(),
            "backup should exist at {}",
            backup.display()
        );
        let hooks: Value = serde_json::from_str(&fs::read_to_string(&hooks_path).unwrap()).unwrap();
        let pre_tool_use = hooks["hooks"]["PreToolUse"].as_array().unwrap();
        assert!(
            pre_tool_use.iter().any(|rule| rule
                .to_string()
                .contains("/usr/local/bin/customer-codex-hook")),
            "customer Codex hook should be preserved"
        );
        assert!(
            pre_tool_use.iter().any(|rule| rule
                .to_string()
                .contains("/usr/local/bin/sondera hook codex --verbose pre-tool-use")),
            "Sondera Codex PreToolUse hook should be installed"
        );
        assert_eq!(
            hooks["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"],
            "/usr/local/bin/sondera hook codex --verbose user-prompt-submit"
        );

        assert!(
            check_feature_flag_at(&config_path),
            "Codex user config should enable hooks"
        );
        let marketplace: Value =
            serde_json::from_str(&fs::read_to_string(&marketplace_path).unwrap()).unwrap();
        assert!(
            marketplace["plugins"]
                .as_array()
                .unwrap()
                .iter()
                .any(|plugin| plugin["name"] == "sondera-codex"
                    && plugin["source"]["path"] == "./sondera"),
            "Codex marketplace entry should register the local Sondera plugin"
        );
    }

    // ================================================================
    // remove_sondera_entries
    // ================================================================

    #[test]
    fn test_remove_sondera_entries_removes_only_sondera() {
        let mut hooks_map: Map<String, Value> = serde_json::from_value(json!({
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "/usr/local/bin/sondera hook codex --verbose pre-tool-use"
                        }
                    ]
                },
                {
                    "matcher": ".*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "my-custom-hook pre-tool-use"
                        }
                    ]
                }
            ],
            "SessionStart": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "sondera hook codex --verbose session-start"
                        }
                    ]
                }
            ]
        }))
        .unwrap();

        let changed = remove_sondera_entries(&mut hooks_map);
        assert!(changed);

        // Custom hook should be preserved
        assert!(hooks_map.contains_key("PreToolUse"));
        let pre_tool = hooks_map["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool.len(), 1);
        assert!(pre_tool[0].to_string().contains("my-custom-hook"));

        // SessionStart had only sondera entries, should be removed entirely
        assert!(!hooks_map.contains_key("SessionStart"));
    }

    #[test]
    fn test_remove_sondera_entries_preserves_third_party_entries_in_same_rule() {
        let mut hooks_map: Map<String, Value> = serde_json::from_value(json!({
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "/usr/local/bin/sondera hook codex --verbose pre-tool-use"
                        },
                        {
                            "type": "command",
                            "command": "/usr/local/bin/customer-codex-hook"
                        }
                    ]
                }
            ]
        }))
        .unwrap();

        assert!(remove_sondera_entries(&mut hooks_map));

        let pre_tool = hooks_map["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool.len(), 1);
        let entries = pre_tool[0]["hooks"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["command"], "/usr/local/bin/customer-codex-hook");
    }

    #[test]
    fn test_remove_sondera_entries_removes_windows_sondera_commands() {
        let mut hooks_map: Map<String, Value> = serde_json::from_value(json!({
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": r"C:\Program Files\Sondera\sondera.exe hook codex --verbose pre-tool-use"
                        }
                    ]
                },
                {
                    "matcher": ".*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "my-custom-hook pre-tool-use"
                        }
                    ]
                }
            ]
        }))
        .unwrap();

        let changed = remove_sondera_entries(&mut hooks_map);
        assert!(changed);

        let pre_tool = hooks_map["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool.len(), 1);
        assert!(pre_tool[0].to_string().contains("my-custom-hook"));
    }

    #[test]
    fn test_remove_sondera_entries_returns_false_when_none_found() {
        let mut hooks_map: Map<String, Value> = serde_json::from_value(json!({
            "EmptyEvent": [],
            "PreToolUse": [
                {
                    "matcher": ".*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "other-tool pre-tool-use"
                        }
                    ]
                }
            ]
        }))
        .unwrap();
        let original = hooks_map.clone();

        let changed = remove_sondera_entries(&mut hooks_map);
        assert!(!changed);
        assert_eq!(hooks_map, original);
    }

    // ================================================================
    // merge_hooks
    // ================================================================

    #[test]
    fn test_merge_hooks_preserves_third_party() {
        let mut existing: Map<String, Value> = serde_json::from_value(json!({
            "PreToolUse": [
                {
                    "matcher": ".*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "my-linter pre-tool-use"
                        }
                    ]
                }
            ]
        }))
        .unwrap();

        let new_hooks: Map<String, Value> = serde_json::from_value(json!({
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "sondera hook codex --verbose pre-tool-use"
                        }
                    ]
                }
            ],
            "SessionStart": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "sondera hook codex --verbose session-start"
                        }
                    ]
                }
            ]
        }))
        .unwrap();

        merge_hooks(&mut existing, &new_hooks);

        // PreToolUse should have both the custom hook and sondera hook
        let pre_tool = existing["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool.len(), 2);
        assert!(pre_tool[0].to_string().contains("my-linter"));
        assert!(pre_tool[1].to_string().contains("sondera hook codex"));

        // SessionStart should be added
        assert!(existing.contains_key("SessionStart"));
    }

    #[test]
    fn test_merge_hooks_idempotent() {
        let bin = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&bin);
        let new_hooks = config
            .get("hooks")
            .and_then(|h| h.as_object())
            .unwrap()
            .clone();

        // Start with empty
        let mut existing: Map<String, Value> = Map::new();

        // First merge
        merge_hooks(&mut existing, &new_hooks);
        let after_first = serde_json::to_string(&existing).unwrap();

        // Second merge (should be idempotent)
        merge_hooks(&mut existing, &new_hooks);
        let after_second = serde_json::to_string(&existing).unwrap();

        assert_eq!(after_first, after_second, "merge_hooks must be idempotent");
    }

    #[test]
    fn test_merge_hooks_replaces_stale_sondera_entries() {
        // Start with an "old" sondera entry
        let mut existing: Map<String, Value> = serde_json::from_value(json!({
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "/old/path/sondera hook codex --verbose pre-tool-use"
                        }
                    ]
                }
            ]
        }))
        .unwrap();

        // Merge with new path
        let new_hooks: Map<String, Value> = serde_json::from_value(json!({
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "/new/path/sondera hook codex --verbose pre-tool-use"
                        }
                    ]
                }
            ]
        }))
        .unwrap();

        merge_hooks(&mut existing, &new_hooks);

        let pre_tool = existing["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_tool.len(), 1);
        assert!(
            pre_tool[0]
                .to_string()
                .contains("/new/path/sondera hook codex")
        );
        assert!(!pre_tool[0].to_string().contains("/old/path/"));
    }

    // ================================================================
    // Feature flag management
    // ================================================================

    #[test]
    fn test_check_feature_flag_at_missing_file() {
        assert!(!check_feature_flag_at(Path::new(
            "/nonexistent/config.toml"
        )));
    }

    #[test]
    fn test_check_feature_flag_at_enabled() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, "[features]\nhooks = true\n").unwrap();

        assert!(check_feature_flag_at(&config_path));
    }

    #[test]
    fn test_check_feature_flag_at_legacy_codex_hooks_enabled() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, "[features]\ncodex_hooks = true\n").unwrap();

        assert!(check_feature_flag_at(&config_path));
    }

    #[test]
    fn test_check_feature_flag_at_disabled() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, "[features]\ncodex_hooks = false\n").unwrap();

        assert!(!check_feature_flag_at(&config_path));
    }

    #[test]
    fn test_check_feature_flag_at_missing_section() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, "[other_section]\nsome_key = true\n").unwrap();

        assert!(!check_feature_flag_at(&config_path));
    }

    #[test]
    fn test_enable_feature_flag_creates_file() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".codex").join("config.toml");

        enable_feature_flag(&config_path).unwrap();

        assert!(config_path.exists());
        assert!(check_feature_flag_at(&config_path));
    }

    #[test]
    fn test_enable_feature_flag_preserves_existing() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, "[settings]\nmodel = \"o3-mini\"\n").unwrap();

        enable_feature_flag(&config_path).unwrap();

        let content = fs::read_to_string(&config_path).unwrap();
        // Feature flag should be enabled
        assert!(check_feature_flag_at(&config_path));
        assert!(
            content.contains("hooks = true"),
            "new installs should write canonical Codex hook flag: {content}"
        );
        assert!(
            !content.contains("codex_hooks = true"),
            "new installs should not write deprecated Codex hook flag: {content}"
        );
        // Original content should be preserved
        assert!(content.contains("model"));
        assert!(content.contains("o3-mini"));
    }

    #[test]
    fn test_enable_feature_flag_idempotent() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");

        enable_feature_flag(&config_path).unwrap();
        let first = fs::read_to_string(&config_path).unwrap();

        enable_feature_flag(&config_path).unwrap();
        let second = fs::read_to_string(&config_path).unwrap();

        assert_eq!(first, second);
    }

    // ================================================================
    // Hooks file read/write round-trip
    // ================================================================

    #[test]
    fn test_read_write_hooks_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");

        let original = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "echo hello"
                            }
                        ]
                    }
                ]
            }
        });

        config::write_value(&path, &original).unwrap();
        let read_back = config::read_object(&path).unwrap();

        assert_eq!(Value::Object(read_back), original);
    }

    #[test]
    fn test_read_hooks_nonexistent_returns_empty() {
        let map = config::read_object(Path::new("/nonexistent/hooks.json")).unwrap();
        assert!(map.is_empty());
    }

    // ================================================================
    // Full install/uninstall integration (filesystem-based)
    // ================================================================

    #[test]
    fn test_install_creates_correct_hooks_structure() {
        let dir = TempDir::new().unwrap();
        let hooks_path = dir.path().join("hooks.json");
        let bin = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));

        // Simulate what install_hooks does (without binary resolution)
        let config = generate_hooks_config(&bin);
        config::write_value(&hooks_path, &config).unwrap();

        let content = fs::read_to_string(&hooks_path).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        let hooks = parsed.get("hooks").unwrap();

        // All 5 events present
        for event in HOOK_EVENTS {
            assert!(hooks.get(*event).is_some(), "Missing hook event: {}", event);
        }
    }

    #[test]
    fn test_install_idempotent_no_duplicates() {
        let bin = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&bin);
        let new_hooks = config
            .get("hooks")
            .and_then(|h| h.as_object())
            .unwrap()
            .clone();

        // First install
        let mut existing = Map::new();
        merge_hooks(&mut existing, &new_hooks);
        let first_result = existing.clone();

        // Second install (idempotent)
        merge_hooks(&mut existing, &new_hooks);

        // Compare: should be identical
        assert_eq!(
            serde_json::to_string(&first_result).unwrap(),
            serde_json::to_string(&existing).unwrap(),
        );

        // Verify no duplicate entries
        for event in HOOK_EVENTS {
            if let Some(rules) = existing.get(*event).and_then(|v| v.as_array()) {
                let sondera_count = rules
                    .iter()
                    .filter(|r| r.to_string().contains("sondera hook codex"))
                    .count();
                assert_eq!(
                    sondera_count, 1,
                    "Event {} has {} sondera entries (expected 1)",
                    event, sondera_count
                );
            }
        }
    }

    #[test]
    fn test_uninstall_removes_only_sondera_preserves_others() {
        let dir = TempDir::new().unwrap();
        let hooks_path = dir.path().join("hooks.json");

        // Create a hooks file with both sondera and third-party hooks
        let mixed = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "sondera hook codex --verbose pre-tool-use"
                            }
                        ]
                    },
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "custom-linter check"
                            }
                        ]
                    }
                ],
                "SessionStart": [
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": "sondera hook codex --verbose session-start"
                            }
                        ]
                    }
                ]
            }
        });

        config::write_value(&hooks_path, &mixed).unwrap();

        // Simulate uninstall
        let mut top_level = config::read_object(&hooks_path).unwrap();
        if let Some(hooks_obj) = top_level.get_mut("hooks")
            && let Some(hooks_map) = hooks_obj.as_object_mut()
        {
            remove_sondera_entries(hooks_map);
        }

        config::write_value(&hooks_path, &Value::Object(top_level.clone())).unwrap();

        // Verify custom hook preserved
        let hooks = top_level.get("hooks").unwrap().as_object().unwrap();
        assert!(
            hooks.contains_key("PreToolUse"),
            "PreToolUse should remain (has custom hook)"
        );
        let rules = hooks["PreToolUse"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].to_string().contains("custom-linter"));

        // Verify sondera-only event removed
        assert!(!hooks.contains_key("SessionStart"));
    }

    #[test]
    fn test_uninstall_deletes_file_when_empty() {
        let dir = TempDir::new().unwrap();
        let hooks_path = dir.path().join("hooks.json");

        // Create a hooks file with only sondera hooks
        let sondera_only = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "sondera hook codex --verbose pre-tool-use"
                            }
                        ]
                    }
                ]
            }
        });

        config::write_value(&hooks_path, &sondera_only).unwrap();
        assert!(hooks_path.exists());

        // Simulate uninstall
        let mut top_level = config::read_object(&hooks_path).unwrap();
        if let Some(hooks_obj) = top_level.get_mut("hooks")
            && let Some(hooks_map) = hooks_obj.as_object_mut()
        {
            remove_sondera_entries(hooks_map);
            if hooks_map.is_empty() {
                top_level.remove("hooks");
            }
        }

        if top_level.is_empty() {
            fs::remove_file(&hooks_path).unwrap();
        }

        assert!(!hooks_path.exists(), "Empty hooks file should be deleted");
    }

    // ================================================================
    // Marketplace entry
    // ================================================================

    #[test]
    fn test_generate_marketplace_entry() {
        let entry = generate_marketplace_entry();
        assert_eq!(entry["name"], "sondera-tools");
        assert_eq!(
            entry["interface"]["displayName"],
            "Sondera Governance Tools"
        );
        let plugins = entry["plugins"].as_array().unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0]["name"], "sondera-codex");
        assert_eq!(plugins[0]["source"]["source"], "local");
        assert_eq!(plugins[0]["source"]["path"], "./sondera");
        assert_eq!(plugins[0]["policy"]["installation"], "AVAILABLE");
        assert_eq!(plugins[0]["category"], "Security");
    }

    // ================================================================
    // Backup
    // ================================================================

    #[test]
    fn test_backup_creates_timestamped_copy() {
        let dir = TempDir::new().unwrap();
        let hooks_path = dir.path().join("hooks.json");
        fs::write(&hooks_path, r#"{"hooks":{}}"#).unwrap();

        let backup = config::backup(&hooks_path).unwrap();
        assert!(backup.is_some());

        let backup_path = backup.unwrap();
        assert!(backup_path.exists());
        assert!(backup_path.to_string_lossy().contains("hooks.backup."));
    }

    #[test]
    fn test_backup_nonexistent_returns_none() {
        let result = config::backup(Path::new("/nonexistent/hooks.json")).unwrap();
        assert!(result.is_none());
    }

    // ================================================================
    // Edge cases and error handling
    // ================================================================

    #[test]
    fn test_read_hooks_malformed_json_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(&path, "{ not valid json }").unwrap();

        let result = config::read_object(&path);
        assert!(result.is_err(), "Malformed JSON should return an error");
    }

    #[test]
    fn test_read_hooks_non_object_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(&path, "[1, 2, 3]").unwrap();

        let result = config::read_object(&path);
        assert!(result.is_err(), "Non-object JSON should return an error");
    }

    #[test]
    fn test_merge_hooks_empty_existing_empty_new() {
        let mut existing: Map<String, Value> = Map::new();
        let new_hooks: Map<String, Value> = Map::new();

        merge_hooks(&mut existing, &new_hooks);
        assert!(existing.is_empty());
    }

    #[test]
    fn test_project_hooks_path_resolves_to_cwd() {
        let path = project_hooks_path().unwrap();
        let cwd = env::current_dir().unwrap();
        assert_eq!(path, cwd.join(".codex").join("hooks.json"));
    }

    #[test]
    fn test_get_hooks_path_user_scope() {
        let path = get_hooks_path(false).unwrap();
        assert!(
            path.to_string_lossy().contains(".codex"),
            "User scope path should be in home ~/.codex"
        );
    }

    #[test]
    fn test_get_hooks_path_project_scope() {
        let path = get_hooks_path(true).unwrap();
        let cwd = env::current_dir().unwrap();
        assert_eq!(
            path,
            cwd.join(".codex").join("hooks.json"),
            "Project scope path should be in cwd/.codex"
        );
    }

    #[test]
    fn test_enable_feature_flag_handles_malformed_toml() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, "this is not valid toml {{{").unwrap();

        let result = enable_feature_flag(&config_path);
        assert!(result.is_err(), "Malformed TOML should produce an error");
    }
}
