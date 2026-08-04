//! Install/uninstall commands for Hermes Agent shell hooks.
//!
//! Hermes reads shell hooks from `~/.hermes/config.yaml` under a top-level
//! `hooks:` block. Install is merge-based: existing third-party hook entries
//! are preserved while Sondera entries are replaced idempotently. Uninstall
//! removes only entries whose command invokes a managed Sondera Hermes adapter.

use serde_json::{Map, Value, json};
use sondera_hooks::error::{HookResultExt as _, Result};
use sondera_hooks::install::{HookConfigInstaller, command, config};
use std::fs;
use std::path::{Path, PathBuf};

/// The provider this adapter's hook commands dispatch to.
const PROVIDER: &str = "hermes";

/// Human-facing agent name used in installer output.
const AGENT: &str = "Hermes";
const AUTO_ACCEPT_MANAGED_KEY: &str = "sondera_hooks_auto_accept_managed";
const HOOK_TIMEOUT_SECS: u64 = 30;

/// Hermes shell-hook events installed by Sondera.
pub const HOOK_EVENTS: &[&str] = &[
    "pre_tool_call",
    "post_tool_call",
    "pre_llm_call",
    "post_llm_call",
    "pre_verify",
    "on_session_start",
    "on_session_end",
    "on_session_finalize",
    "on_session_reset",
    "subagent_start",
    "subagent_stop",
    "pre_gateway_dispatch",
    "pre_approval_request",
    "post_approval_response",
    "transform_tool_result",
    "transform_terminal_output",
    "transform_llm_output",
];

fn user_config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".hermes").join("config.yaml"))
}

/// Hermes keeps its config in YAML, so the shared installer flow reads and
/// writes this document instead of the default JSON one.
struct Yaml;

impl config::ConfigDocument for Yaml {
    fn read(&self, path: &Path) -> Result<Map<String, Value>> {
        let Some(content) = config::read_to_object_source(path)? else {
            return Ok(Map::new());
        };
        match serde_norway::from_str::<Value>(&content)
            .context("Failed to parse Hermes YAML config")?
        {
            Value::Object(map) => Ok(map),
            _ => Err(config::not_an_object(path)),
        }
    }

    fn write(&self, path: &Path, config: &Map<String, Value>) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("Failed to create ~/.hermes directory")?;
        }
        let content =
            serde_norway::to_string(config).context("Failed to serialize Hermes YAML config")?;
        fs::write(path, content).context("Failed to write Hermes config")
    }
}

fn hook_command(
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    subcommand: &str,
    verbose: bool,
) -> String {
    let verbose_flag = if verbose { " --verbose" } else { "" };
    // POSIX rendering quotes the path only when it carries shell-significant
    // characters, matching Hermes' `sh`-style command contract.
    format!(
        "{} hook hermes{verbose_flag} {subcommand}",
        binary_path.render(sondera_hooks::install::binary::CommandShell::Posix)
    )
}

fn hook_entry(
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    event: &str,
    verbose: bool,
) -> Value {
    let mut entry = json!({
        "command": hook_command(binary_path, event, verbose),
        "timeout": HOOK_TIMEOUT_SECS,
    });
    if matches!(event, "pre_tool_call" | "post_tool_call") {
        entry["matcher"] = json!(".*");
    }
    entry
}

fn generate_hooks_config(
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    verbose: bool,
) -> Map<String, Value> {
    let mut hooks = Map::new();
    for event in HOOK_EVENTS {
        hooks.insert(
            (*event).to_string(),
            Value::Array(vec![hook_entry(binary_path, event, verbose)]),
        );
    }
    hooks
}

fn entry_contains_sondera(entry: &Value) -> bool {
    command::value_targets_provider(entry, PROVIDER)
}

fn remove_sondera_entries(hooks_map: &mut Map<String, Value>) -> bool {
    let mut changed = false;
    let event_keys: Vec<String> = hooks_map.keys().cloned().collect();
    for key in event_keys {
        let Some(entries) = hooks_map.get(&key).and_then(Value::as_array) else {
            continue;
        };
        let kept: Vec<Value> = entries
            .iter()
            .filter(|entry| !entry_contains_sondera(entry))
            .cloned()
            .collect();
        if kept.len() != entries.len() {
            changed = true;
            if kept.is_empty() {
                hooks_map.remove(&key);
            } else {
                hooks_map.insert(key, Value::Array(kept));
            }
        }
    }
    changed
}

fn merge_hooks(existing: &mut Map<String, Value>, new_hooks: &Map<String, Value>) {
    remove_sondera_entries(existing);
    for (event, new_entries) in new_hooks {
        let Some(new_arr) = new_entries.as_array() else {
            continue;
        };
        if let Some(existing_arr) = existing.get_mut(event).and_then(Value::as_array_mut) {
            let mut merged = new_arr.clone();
            merged.extend(existing_arr.iter().cloned());
            *existing_arr = merged;
        } else {
            existing.insert(event.clone(), Value::Array(new_arr.clone()));
        }
    }
}

/// Install Hermes shell hooks in `~/.hermes/config.yaml`.
pub fn install_hooks(auto_accept: bool, verbose: bool) -> Result<()> {
    installer(&user_config_path()?).install(|config, binary| {
        apply_hooks(config, binary, auto_accept, verbose);
    })?;
    announce_consent(auto_accept);
    Ok(())
}

/// Uninstall managed Hermes shell hooks from `~/.hermes/config.yaml`.
pub fn uninstall_hooks() -> Result<()> {
    installer(&user_config_path()?).uninstall(revoke_hooks)
}

/// Hermes will not run a shell hook the user has not consented to, so say which
/// way consent was left.
fn announce_consent(auto_accept: bool) {
    if auto_accept {
        eprintln!("Shell-hook consent: hooks_auto_accept=true was written at user request");
        eprintln!(
            "Security note: hooks_auto_accept applies to all Hermes shell hooks in this config, not only Sondera-managed entries"
        );
    } else {
        eprintln!(
            "Shell-hook consent: approve prompts on first Hermes run, or rerun with --auto-accept-all-hooks for non-TTY gateway sessions"
        );
    }
}

/// The installer for `config_path`, which is `~/.hermes/config.yaml` outside
/// tests.
fn installer(config_path: &Path) -> HookConfigInstaller {
    HookConfigInstaller::new(AGENT, config_path, "user (~/.hermes/config.yaml)")
        .with_document(Yaml)
        // The config is Hermes' own, shared with its other settings, so it is
        // deleted only if our hooks were the only thing in it.
        .remove_when(Map::is_empty)
        .with_next_steps([format!("Events: {}", HOOK_EVENTS.join(", "))])
}

/// Splice our hooks into `config`, plus the shell-hook consent flag when the
/// user asked for it.
fn apply_hooks(
    config: &mut Map<String, Value>,
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    auto_accept: bool,
    verbose: bool,
) {
    let new_hooks = generate_hooks_config(binary_path, verbose);
    let hooks_value = config
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(hooks_map) = hooks_value.as_object_mut() {
        merge_hooks(hooks_map, &new_hooks);
    } else {
        *hooks_value = Value::Object(new_hooks);
    }

    if auto_accept {
        let previously_auto_accepted = config
            .get("hooks_auto_accept")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        config.insert("hooks_auto_accept".to_string(), Value::Bool(true));
        // Remembered so uninstall only revokes consent it granted itself.
        if !previously_auto_accepted {
            config.insert(AUTO_ACCEPT_MANAGED_KEY.to_string(), Value::Bool(true));
        }
    }
}

/// Remove our hooks and any consent we granted, returning whether anything
/// changed.
fn revoke_hooks(config: &mut Map<String, Value>) -> bool {
    let removed = config
        .get_mut("hooks")
        .and_then(Value::as_object_mut)
        .is_some_and(remove_sondera_entries);
    if !removed {
        return false;
    }

    let auto_accept_managed = config
        .remove(AUTO_ACCEPT_MANAGED_KEY)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if auto_accept_managed {
        config.remove("hooks_auto_accept");
    }
    if config
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
    {
        config.remove("hooks");
    }
    true
}

#[cfg(test)]
fn install_hooks_at(
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    config_path: &Path,
    auto_accept: bool,
    verbose: bool,
) -> Result<Option<PathBuf>> {
    installer(config_path).apply(binary_path, |config, binary| {
        apply_hooks(config, binary, auto_accept, verbose);
    })
}

#[cfg(test)]
fn uninstall_hooks_at(config_path: &Path) -> Result<Option<PathBuf>> {
    Ok(installer(config_path)
        .revoke(revoke_hooks)?
        .and_then(|revoked| revoked.backup))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn read_value(path: &Path) -> Value {
        serde_norway::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn generate_config_has_all_hermes_events() {
        let hooks = generate_hooks_config(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/usr/local/bin/sondera",
            )),
            true,
        );
        for event in HOOK_EVENTS {
            assert!(hooks.contains_key(*event), "missing {event}");
            assert_eq!(hooks[*event][0]["timeout"], 30, "{event} timeout");
        }
        assert_eq!(hooks["pre_tool_call"][0]["matcher"], ".*");
        assert!(
            hooks["pre_tool_call"]
                .to_string()
                .contains("hermes --verbose pre_tool_call")
        );
    }

    #[test]
    fn generate_config_omits_verbose_unless_requested() {
        let hooks = generate_hooks_config(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/usr/local/bin/sondera",
            )),
            false,
        );
        assert!(
            hooks["pre_tool_call"][0]["command"]
                .as_str()
                .unwrap()
                .contains("sondera hook hermes pre_tool_call")
        );
        assert!(
            !hooks["pre_tool_call"][0]["command"]
                .as_str()
                .unwrap()
                .contains("--verbose")
        );
    }

    #[test]
    fn generate_config_shell_quotes_binary_paths_with_spaces() {
        let command = hook_command(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/Applications/Sondera CLI/sondera",
            )),
            "pre_tool_call",
            false,
        );
        assert_eq!(
            command,
            "'/Applications/Sondera CLI/sondera' hook hermes pre_tool_call"
        );
    }

    #[test]
    fn install_is_idempotent_and_preserves_third_party_hooks() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.yaml");
        fs::write(
            &config_path,
            "hooks:\n  pre_tool_call:\n    - matcher: terminal\n      command: third-party pre\n      timeout: 3\nmodel: hermes\n",
        )
        .unwrap();

        let backup = install_hooks_at(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/usr/local/bin/sondera",
            )),
            &config_path,
            false,
            false,
        )
        .unwrap();
        assert!(backup.unwrap().exists());
        let once = read_value(&config_path);
        install_hooks_at(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/usr/local/bin/sondera",
            )),
            &config_path,
            false,
            false,
        )
        .unwrap();
        let twice = read_value(&config_path);
        assert_eq!(once, twice);
        assert!(twice.to_string().contains("third-party pre"));
        assert!(
            twice["hooks"]["pre_tool_call"][0]["command"]
                .as_str()
                .unwrap()
                .contains("sondera hook hermes pre_tool_call")
        );
        assert_eq!(twice["model"], "hermes");
    }

    #[test]
    fn uninstall_removes_only_sondera_entries() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.yaml");
        install_hooks_at(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/usr/local/bin/sondera",
            )),
            &config_path,
            false,
            false,
        )
        .unwrap();
        let mut value = read_value(&config_path);
        value["hooks"]["post_tool_call"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "matcher":".*",
                "command":"third-party post",
                "timeout":3
            }));
        fs::write(&config_path, serde_norway::to_string(&value).unwrap()).unwrap();

        let backup = uninstall_hooks_at(&config_path).unwrap();
        assert!(backup.unwrap().exists());
        let remaining = read_value(&config_path);
        assert!(remaining.to_string().contains("third-party post"));
        assert!(!remaining.to_string().contains("sondera hermes"));
    }

    #[test]
    fn no_op_uninstall_does_not_create_backup() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.yaml");
        fs::write(
            &config_path,
            "hooks:\n  pre_tool_call:\n    - command: third-party pre\n      timeout: 3\n",
        )
        .unwrap();

        let backup = uninstall_hooks_at(&config_path).unwrap();

        assert!(backup.is_none());
        assert!(fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".backup.")
        }));
    }

    #[test]
    fn uninstall_removes_managed_auto_accept_flag() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.yaml");
        install_hooks_at(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/usr/local/bin/sondera",
            )),
            &config_path,
            true,
            false,
        )
        .unwrap();
        uninstall_hooks_at(&config_path).unwrap();

        assert!(!config_path.exists());
    }

    #[test]
    fn uninstall_preserves_preexisting_auto_accept_flag() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.yaml");
        fs::write(&config_path, "hooks_auto_accept: true\n").unwrap();
        install_hooks_at(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/usr/local/bin/sondera",
            )),
            &config_path,
            false,
            false,
        )
        .unwrap();
        uninstall_hooks_at(&config_path).unwrap();

        let value = read_value(&config_path);
        assert_eq!(value["hooks_auto_accept"], true);
        assert!(value.get(AUTO_ACCEPT_MANAGED_KEY).is_none());
    }

    #[test]
    fn install_can_set_auto_accept_when_requested() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.yaml");
        install_hooks_at(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/usr/local/bin/sondera",
            )),
            &config_path,
            true,
            false,
        )
        .unwrap();
        let value = read_value(&config_path);
        assert_eq!(value["hooks_auto_accept"], true);
    }

    #[test]
    fn reinstall_without_auto_accept_preserves_managed_auto_accept_until_uninstall() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.yaml");
        install_hooks_at(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/usr/local/bin/sondera",
            )),
            &config_path,
            true,
            false,
        )
        .unwrap();
        install_hooks_at(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/usr/local/bin/sondera",
            )),
            &config_path,
            false,
            false,
        )
        .unwrap();

        let value = read_value(&config_path);
        assert_eq!(value["hooks_auto_accept"], true);
        assert_eq!(value[AUTO_ACCEPT_MANAGED_KEY], true);

        uninstall_hooks_at(&config_path).unwrap();
        assert!(!config_path.exists());
    }
}
