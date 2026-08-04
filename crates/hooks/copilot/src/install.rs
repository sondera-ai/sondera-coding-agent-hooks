//! Install command for setting up GitHub Copilot hooks.
//!
//! This module provides functionality to install the Sondera hooks configuration
//! into GitHub Copilot CLI's user or repository hooks directory.
//!
//! Reference: <https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks>

use serde_json::{Map, Value, json};
use sondera_hooks::error::{HookError, HookResultExt as _, Result};
use sondera_hooks::install::{HookConfigInstaller, command};
use std::env;
use std::path::{Path, PathBuf};

/// The provider this adapter's hook commands dispatch to.
const PROVIDER: &str = "copilot";

/// Human-facing agent name used in installer output.
const AGENT: &str = "GitHub Copilot";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// User-level hooks directory (`$COPILOT_HOME/hooks/` or `~/.copilot/hooks/`).
    User,
    /// Repository-level hooks directory (`.github/hooks/`).
    Project,
}

impl std::fmt::Display for InstallScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallScope::User => write!(f, "user ($COPILOT_HOME/hooks or ~/.copilot/hooks)"),
            InstallScope::Project => write!(f, "project (.github/hooks)"),
        }
    }
}

fn is_managed_sondera_hook(value: &Value) -> bool {
    command::value_targets_provider(value, PROVIDER)
}

fn remove_managed_sondera_hooks(hooks_map: &mut Map<String, Value>) -> bool {
    let mut changed = false;
    let keys = hooks_map.keys().cloned().collect::<Vec<_>>();

    for key in keys {
        let Some(value) = hooks_map.get(&key) else {
            continue;
        };

        let Some(entries) = value.as_array() else {
            if is_managed_sondera_hook(value) {
                hooks_map.remove(&key);
                changed = true;
            }
            continue;
        };

        let kept = entries
            .iter()
            .filter(|entry| !is_managed_sondera_hook(entry))
            .cloned()
            .collect::<Vec<_>>();
        if kept.len() == entries.len() {
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

/// Generate the hooks.json configuration for GitHub Copilot CLI
#[cfg(test)]
fn generate_hooks_config(binary_path: &sondera_hooks::install::binary::ResolvedBinary) -> Value {
    generate_hooks_config_with_disable(binary_path, false)
}

fn generate_hooks_config_with_disable(
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    disable_all_hooks: bool,
) -> Value {
    use sondera_hooks::install::binary::CommandShell;

    // The `bash` field is a POSIX shell script (portable, extension-less
    // `sondera`, quoted only when the path has spaces). The `powershell` field
    // is a PowerShell *script*, so the executable is launched with the `&` call
    // operator, retains `.exe`, and is single-quoted for `C:\Program Files\...`
    // paths — without which the command splits at the space and never runs
    // sondera.
    let bash_bin = binary_path.render(CommandShell::Posix);
    let powershell_bin = binary_path.render(CommandShell::PowerShell);

    // Helper to create a hook entry for a given event
    let make_hook = |event: &str| -> Value {
        json!([{
            "type": "command",
            "bash": format!("{} hook copilot --verbose {}", bash_bin, event),
            "powershell": format!("{} hook copilot --verbose {}", powershell_bin, event),
            "cwd": ".",
            "timeoutSec": 30
        }])
    };

    let hooks: Map<String, Value> = crate::event::HOOK_EVENTS
        .iter()
        .map(|event| (event.event.to_string(), make_hook(event.subcommand)))
        .collect();

    json!({
        "version": 1,
        "disableAllHooks": disable_all_hooks,
        "hooks": hooks
    })
}

/// Get the project-scope hooks.json file path.
fn hooks_path_for_root(root: &Path) -> PathBuf {
    root.join(".github").join("hooks").join("hooks.json")
}

fn user_hooks_path_for_home(home: &Path) -> PathBuf {
    home.join(".copilot").join("hooks").join("hooks.json")
}

fn user_hooks_path() -> Result<PathBuf> {
    if let Some(copilot_home) = env::var_os("COPILOT_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(copilot_home).join("hooks").join("hooks.json"));
    }

    let home = dirs::home_dir().ok_or_else(|| {
        HookError::message("Could not determine home directory for Copilot hooks")
    })?;
    Ok(user_hooks_path_for_home(&home))
}

fn get_hooks_path(scope: InstallScope) -> Result<PathBuf> {
    match scope {
        InstallScope::User => user_hooks_path(),
        InstallScope::Project => {
            let cwd = env::current_dir().context("Could not determine current directory")?;
            Ok(hooks_path_for_root(&cwd))
        }
    }
}

/// Splice our hooks into `top_level`, replacing any we installed previously and
/// preserving both third-party hooks and the user's `disableAllHooks` choice.
fn apply_hooks(
    top_level: &mut Map<String, Value>,
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
) {
    let disable_all_hooks = top_level
        .get("disableAllHooks")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let generated = generate_hooks_config_with_disable(binary_path, disable_all_hooks);
    let generated_hooks = generated
        .get("hooks")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let mut hooks = top_level
        .remove("hooks")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    remove_managed_sondera_hooks(&mut hooks);

    for (event_name, generated_entries) in generated_hooks {
        if let Some(existing_entries) = hooks.get_mut(&event_name).and_then(Value::as_array_mut)
            && let Some(generated_entries) = generated_entries.as_array()
        {
            let mut merged = generated_entries.clone();
            merged.append(existing_entries);
            hooks.insert(event_name, Value::Array(merged));
        } else {
            hooks.insert(event_name, generated_entries);
        }
    }

    top_level.insert("version".to_string(), json!(1));
    top_level.insert("disableAllHooks".to_string(), json!(disable_all_hooks));
    top_level.insert("hooks".to_string(), Value::Object(hooks));
}

/// Remove our hooks from `top_level`, returning whether anything changed.
fn revoke_hooks(top_level: &mut Map<String, Value>) -> bool {
    let Some(hooks) = top_level.get_mut("hooks").and_then(Value::as_object_mut) else {
        return false;
    };
    if !remove_managed_sondera_hooks(hooks) {
        return false;
    }
    if hooks.is_empty() {
        top_level.remove("hooks");
    }
    true
}

/// Whether what uninstall left behind is a husk: the scaffolding Copilot needs
/// in a hooks file, with no hooks left in it.
fn is_husk(top_level: &Map<String, Value>) -> bool {
    top_level.is_empty()
        || (top_level.len() == 2
            && top_level.get("version") == Some(&json!(1))
            && top_level.get("disableAllHooks") == Some(&json!(false)))
}

fn installer(scope: InstallScope) -> Result<HookConfigInstaller> {
    let next_steps = match scope {
        InstallScope::User => vec!["The hooks are active for GitHub Copilot CLI sessions"],
        InstallScope::Project => vec![
            "Commit the .github/hooks/hooks.json file to your repository",
            "The hooks are active for GitHub Copilot CLI sessions",
        ],
    };
    Ok(
        HookConfigInstaller::new(AGENT, get_hooks_path(scope)?, scope.to_string())
            .with_next_steps(next_steps)
            .remove_when(is_husk),
    )
}

pub fn install_hooks(scope: InstallScope, _verbose: bool) -> Result<()> {
    installer(scope)?.install(apply_hooks)
}

/// Uninstall hooks from the selected Copilot hooks scope.
pub fn uninstall_hooks(scope: InstallScope) -> Result<()> {
    installer(scope)?.uninstall(revoke_hooks)?;

    if matches!(scope, InstallScope::Project) {
        eprintln!(
            "\x1b[33mNote:\x1b[0m Don't forget to commit the changes if the file was tracked in git."
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_hooks::install::config;
    use std::fs;
    use tempfile::TempDir;

    fn binary() -> sondera_hooks::install::binary::ResolvedBinary {
        sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ))
    }

    #[test]
    fn test_generate_hooks_config() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path);

        assert_eq!(config.get("version"), Some(&json!(1)));
        assert_eq!(config.get("disableAllHooks"), Some(&json!(false)));

        let hooks = config.get("hooks").unwrap();
        assert!(hooks.get("sessionStart").is_some());
        assert!(hooks.get("sessionEnd").is_some());
        assert!(hooks.get("userPromptSubmitted").is_some());
        assert!(hooks.get("preToolUse").is_some());
        assert!(hooks.get("postToolUse").is_some());
        assert!(hooks.get("errorOccurred").is_some());
        assert!(hooks.get("permissionRequest").is_some());
        assert!(hooks.get("postToolUseFailure").is_some());
        assert!(hooks.get("agentStop").is_some());
        assert_eq!(
            hooks.as_object().unwrap().len(),
            crate::event::HOOK_EVENTS.len()
        );

        // Verbose is always enabled regardless of the flag
        let pre_tool_use = &hooks["preToolUse"][0]["bash"];
        assert!(pre_tool_use.as_str().unwrap().contains("--verbose"));
        assert!(
            pre_tool_use
                .as_str()
                .unwrap()
                .contains("sondera hook copilot")
        );
        assert!(pre_tool_use.as_str().unwrap().contains("pre-tool-use"));
    }

    #[test]
    fn powershell_field_uses_call_operator_and_quotes_program_files() {
        // `find_sondera_binary` canonicalizes a real MSI install to a
        // `\\?\C:\Program Files\...` verbatim path. The PowerShell script field
        // must strip the prefix, retain `.exe`, single-quote the spaced path, and
        // launch it with `&` — otherwise PowerShell treats the quoted path as a
        // string literal and never runs sondera.
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            r"\\?\C:\Program Files\Sondera\sondera.exe",
        ));
        let config = generate_hooks_config(&path);
        let hooks = config["hooks"].as_object().unwrap();
        assert_eq!(
            hooks["preToolUse"][0]["powershell"],
            r"& 'C:\Program Files\Sondera\sondera.exe' hook copilot --verbose pre-tool-use"
        );
        // The bash field stays the portable, extension-less POSIX form (quoted
        // for the space).
        assert_eq!(
            hooks["preToolUse"][0]["bash"],
            r"'C:\Program Files\Sondera\sondera' hook copilot --verbose pre-tool-use"
        );
    }

    #[test]
    fn test_generate_hooks_config_preserves_disable_all_hooks() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config_with_disable(&path, true);

        assert_eq!(config.get("disableAllHooks"), Some(&json!(true)));
    }

    #[test]
    fn test_user_hooks_path_for_home() {
        let home = PathBuf::from("/home/alice");
        assert_eq!(
            user_hooks_path_for_home(&home),
            PathBuf::from("/home/alice/.copilot/hooks/hooks.json")
        );
    }

    #[test]
    fn user_scope_install_writes_copilot_hooks_and_preserves_disable_all_hooks() {
        let home = TempDir::new().unwrap();
        let hooks_path = user_hooks_path_for_home(home.path());
        config::write_value(
            &hooks_path,
            &json!({
                "version": 1,
                "disableAllHooks": true,
                "customerSetting": "preserve-me",
                "hooks": {
                    "preToolUse": [{
                        "type": "command",
                        "bash": "customer-copilot-hook",
                        "powershell": "customer-copilot-hook"
                    }]
                }
            }),
        )
        .unwrap();

        let backup = HookConfigInstaller::new(AGENT, &hooks_path, "user (test)")
            .apply(
                &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                    "/usr/local/bin/sondera",
                )),
                apply_hooks,
            )
            .unwrap()
            .expect("existing Copilot hooks file should be backed up");
        assert!(
            backup.exists(),
            "backup should exist at {}",
            backup.display()
        );

        let hooks: Value = serde_json::from_str(&fs::read_to_string(&hooks_path).unwrap()).unwrap();
        assert_eq!(hooks["version"], 1);
        assert_eq!(hooks["disableAllHooks"], true);
        assert_eq!(hooks["customerSetting"], "preserve-me");
        assert_eq!(
            hooks["hooks"].as_object().unwrap().len(),
            crate::event::HOOK_EVENTS.len()
        );
        assert_eq!(
            hooks["hooks"]["preToolUse"][0]["bash"],
            "/usr/local/bin/sondera hook copilot --verbose pre-tool-use"
        );
        assert_eq!(
            hooks["hooks"]["preToolUse"][0]["powershell"],
            "& /usr/local/bin/sondera.exe hook copilot --verbose pre-tool-use"
        );
        assert_eq!(hooks["hooks"]["preToolUse"][0]["cwd"], ".");
        assert_eq!(hooks["hooks"]["preToolUse"][0]["timeoutSec"], 30);
        assert_eq!(
            hooks["hooks"]["preToolUse"][1]["bash"],
            "customer-copilot-hook"
        );
    }

    #[test]
    fn a_disabled_hooks_file_stays_disabled_across_a_reinstall() {
        // `disableAllHooks` is the user's kill switch; installing must not
        // quietly re-enable every hook in the file.
        let mut config: Map<String, Value> =
            serde_json::from_value(json!({"version": 1, "disableAllHooks": true, "hooks": {}}))
                .unwrap();

        apply_hooks(&mut config, &binary());

        assert_eq!(config["disableAllHooks"], json!(true));
    }

    #[test]
    fn test_hooks_path_for_root() {
        let root = PathBuf::from("/repo/project");
        assert_eq!(
            hooks_path_for_root(&root),
            PathBuf::from("/repo/project/.github/hooks/hooks.json")
        );
    }

    #[test]
    fn test_is_managed_sondera_hook_matches_windows_commands() {
        let rule = json!([{
            "type": "command",
            "powershell": r"C:\Program Files\Sondera\sondera.exe hook copilot --verbose pre-tool-use"
        }]);

        assert!(is_managed_sondera_hook(&rule));
    }

    #[test]
    fn test_uninstall_removes_windows_sondera_hooks() {
        let mut top_level: Map<String, Value> = serde_json::from_value(json!({
            "version": 1,
            "hooks": {
                "preToolUse": [{
                    "type": "command",
                    "bash": "custom-linter check",
                    "powershell": "custom-linter check"
                }],
                "postToolUse": [
                    {
                        "type": "command",
                        "bash": r"C:/Program Files/Sondera/sondera.exe hook copilot --verbose post-tool-use",
                        "powershell": r"C:\Program Files\Sondera\sondera.exe hook copilot --verbose post-tool-use"
                    },
                    {
                        "type": "command",
                        "bash": "customer-post-hook",
                        "powershell": "customer-post-hook"
                    }
                ]
            }
        }))
        .unwrap();

        assert!(revoke_hooks(&mut top_level));

        let hooks_map = top_level["hooks"].as_object().unwrap();
        assert!(hooks_map.contains_key("preToolUse"));
        assert!(hooks_map.contains_key("postToolUse"));
        assert_eq!(hooks_map["postToolUse"][0]["bash"], "customer-post-hook");
    }

    #[test]
    fn uninstall_deletes_a_file_that_holds_nothing_but_our_scaffolding() {
        let mut config = Map::new();
        apply_hooks(&mut config, &binary());

        assert!(revoke_hooks(&mut config));
        assert!(
            is_husk(&config),
            "a file left with only version + disableAllHooks should be deleted: {config:?}"
        );
    }

    #[test]
    fn uninstall_keeps_a_file_that_still_holds_a_third_party_hook() {
        let mut config: Map<String, Value> = serde_json::from_value(json!({
            "hooks": {"preToolUse": [{"type": "command", "bash": "custom-linter check"}]}
        }))
        .unwrap();
        apply_hooks(&mut config, &binary());

        assert!(revoke_hooks(&mut config));
        assert!(!is_husk(&config), "a third-party hook survives: {config:?}");
    }
}
