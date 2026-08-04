//! Install command for setting up VS Code Copilot Chat hooks.
//!
//! Hook files are written to:
//! - **Local scope**: `.github/hooks/sondera.json` in the current working directory
//! - **User scope**: `~/.sondera/vscode/hooks/sondera.json` + the `chat.hookFilesLocations`
//!   entry is added to VS Code user settings so VS Code automatically loads the file
//!
//! The generated JSON uses PascalCase event names as required by the VS Code hooks spec:
//! <https://code.visualstudio.com/docs/agent-customization/hooks#_hook-configuration-format>

use crate::event::HOOK_EVENTS;
use serde_json::{Map, Value, json};
use sondera_hooks::error::{HookError, HookResultExt as _, Result};
use sondera_hooks::install::{HookConfigInstaller, config};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

// ============================================================================
// Scope
// ============================================================================

/// Human-facing agent name used in installer output.
const AGENT: &str = "VS Code Copilot";

/// Scope for hooks installation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// User-level hooks — written to `~/.sondera/vscode/hooks/sondera.json`
    /// and registered in VS Code user settings via `chat.hookFilesLocations`.
    User,
    /// Local project hooks — written to `.github/hooks/sondera.json`
    /// (loaded by default per VS Code's `chat.hookFilesLocations` default value).
    Local,
}

impl std::fmt::Display for InstallScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallScope::User => write!(f, "user (~/.sondera/vscode/hooks/)"),
            InstallScope::Local => write!(f, "local project (.github/hooks/)"),
        }
    }
}

// ============================================================================
// Hook config generation
// ============================================================================

/// Generate the `{ "hooks": { ... } }` JSON object for a VS Code hooks file.
///
/// Event names are PascalCase and the array format matches the VS Code hooks spec:
/// ```json
/// {"hooks": {"PreToolUse": [{"type": "command", "command": "...", "timeout": 30}]}}
/// ```
pub fn generate_hooks_config(
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    verbose: bool,
) -> Value {
    // The hooks file is consumed only on the host it is installed on, so render
    // the `command` for that host's shell. On Windows the VS Code `command` is a
    // command line whose first token is the program, so a `C:\Program Files\...`
    // path must retain `.exe` and be double-quoted.
    let shell = if cfg!(target_os = "windows") {
        sondera_hooks::install::binary::CommandShell::WindowsCmd
    } else {
        sondera_hooks::install::binary::CommandShell::Posix
    };
    generate_hooks_config_for_shell(binary_path, verbose, shell)
}

fn generate_hooks_config_for_shell(
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    verbose: bool,
    shell: sondera_hooks::install::binary::CommandShell,
) -> Value {
    let binary_str = binary_path.render(shell);
    let verbose_flag = if verbose { " --verbose" } else { "" };

    let make_hook = |subcommand: &str| -> Value {
        json!([{
            "type": "command",
            "command": format!("{} hook vscode{} {}", binary_str, verbose_flag, subcommand),
            "timeout": 30
        }])
    };

    let mut hooks = serde_json::Map::new();
    for (event_name, subcommand) in HOOK_EVENTS {
        hooks.insert((*event_name).to_string(), make_hook(subcommand));
    }

    json!({ "hooks": Value::Object(hooks) })
}

// ============================================================================
// Path helpers
// ============================================================================

/// Path to the local project hook file: `.github/hooks/sondera.json`
fn local_hooks_path(cwd: &Path) -> PathBuf {
    cwd.join(".github").join("hooks").join("sondera.json")
}

/// Path to the user-level hook file: `~/.sondera/vscode/hooks/sondera.json`
fn user_hooks_path_for_home(home: &Path) -> PathBuf {
    home.join(".sondera")
        .join("vscode")
        .join("hooks")
        .join("sondera.json")
}

fn user_hooks_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(user_hooks_path_for_home(&home))
}

/// VS Code user settings file path for user-scope hook installation.
///
/// Production only calls this helper on macOS; the non-macOS branches are kept
/// for unit tests that exercise platform path handling under test cfg.
#[cfg(any(test, target_os = "macos"))]
fn vscode_user_settings_path_for_home(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support/Code/User/settings.json")
    }

    #[cfg(target_os = "linux")]
    {
        home.join(".config/Code/User/settings.json")
    }

    #[cfg(target_os = "windows")]
    {
        home.join("AppData/Roaming/Code/User/settings.json")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        home.join(".config").join("Code/User/settings.json")
    }
}

fn vscode_user_settings_path() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        Ok(vscode_user_settings_path_for_home(&home))
    }

    #[cfg(target_os = "linux")]
    {
        let config_dir = dirs::config_dir().context("Could not determine config directory")?;
        Ok(config_dir.join("Code/User/settings.json"))
    }

    #[cfg(target_os = "windows")]
    {
        let appdata = dirs::config_dir().context("Could not determine AppData directory")?;
        Ok(appdata.join("Code/User/settings.json"))
    }

    // Fallback for other targets (e.g. tests on unsupported platforms)
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        Ok(home.join(".config").join("Code/User/settings.json"))
    }
}

// ============================================================================
// File I/O helpers
// ============================================================================

fn read_json_object(path: &Path) -> Result<Map<String, Value>> {
    if path.exists() {
        let content = fs::read_to_string(path).context("Failed to read JSON file")?;
        let value: Value = parse_json_or_jsonc(&content).context("Failed to parse JSON/JSONC")?;
        match value {
            Value::Object(map) => Ok(map),
            _ => Err(HookError::message("JSON file is not an object")),
        }
    } else {
        Ok(Map::new())
    }
}

fn write_json_object(path: &Path, obj: &Map<String, Value>) -> Result<()> {
    config::write_object(path, obj)
}

fn parse_json_or_jsonc(content: &str) -> serde_json::Result<Value> {
    if let Ok(parsed) = serde_json::from_str(content) {
        return Ok(parsed);
    }
    let without_comments = strip_jsonc_comments(content);
    let without_trailing_commas = strip_trailing_json_commas(&without_comments);
    serde_json::from_str(&without_trailing_commas)
}

fn strip_jsonc_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if in_string {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            in_string = true;
            output.push(ch);
            continue;
        }

        if ch == '/' {
            match chars.peek().copied() {
                Some('/') => {
                    chars.next();
                    for comment_ch in chars.by_ref() {
                        if comment_ch == '\n' {
                            output.push('\n');
                            break;
                        }
                    }
                    continue;
                }
                Some('*') => {
                    chars.next();
                    let mut previous = '\0';
                    for comment_ch in chars.by_ref() {
                        if comment_ch == '\n' {
                            output.push('\n');
                        }
                        if previous == '*' && comment_ch == '/' {
                            break;
                        }
                        previous = comment_ch;
                    }
                    continue;
                }
                _ => {}
            }
        }

        output.push(ch);
    }

    output
}

fn strip_trailing_json_commas(text: &str) -> String {
    let chars = text.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    let mut index = 0;

    while index < chars.len() {
        let ch = chars[index];
        if in_string {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if ch == '"' {
            in_string = true;
            output.push(ch);
            index += 1;
            continue;
        }

        if ch == ',' {
            let mut next = index + 1;
            while next < chars.len() && chars[next].is_whitespace() {
                next += 1;
            }
            if next < chars.len() && matches!(chars[next], '}' | ']') {
                index += 1;
                continue;
            }
        }

        output.push(ch);
        index += 1;
    }

    output
}

// ============================================================================
// Install / uninstall
// ============================================================================

/// The path of the hook file for `scope`.
fn hooks_path(scope: InstallScope) -> Result<PathBuf> {
    match scope {
        InstallScope::Local => {
            let cwd = env::current_dir().context("Could not determine current directory")?;
            Ok(local_hooks_path(&cwd))
        }
        InstallScope::User => user_hooks_path(),
    }
}

/// The installer for the hook file itself.
///
/// Unlike the other providers', this file is wholly ours — VS Code discovers
/// hooks by directory, so `sondera.json` holds nothing but our hooks and
/// uninstall deletes it outright. The user-scope *registration* of that
/// directory is a separate document, handled in [`register_hooks_directory`].
fn hooks_installer(scope: InstallScope) -> Result<HookConfigInstaller> {
    Ok(
        HookConfigInstaller::new(AGENT, hooks_path(scope)?, scope.to_string())
            .with_next_steps(["Authenticate if needed with: sondera auth login"])
            .remove_when(Map::is_empty),
    )
}

/// Install hooks into the specified scope.
pub fn install_hooks(scope: InstallScope, verbose: bool) -> Result<()> {
    hooks_installer(scope)?.install(|hooks_file, binary| {
        // The whole file is ours, so it is replaced rather than spliced.
        *hooks_file = generate_hooks_config(binary, verbose)
            .as_object()
            .cloned()
            .unwrap_or_default();
    })?;

    if matches!(scope, InstallScope::User) {
        register_hooks_directory(&vscode_user_settings_path()?)?;
    }
    Ok(())
}

/// The `chat.hookFilesLocations` key for user-level hooks directory.
const USER_HOOKS_DIR_TILDE: &str = "~/.sondera/vscode/hooks";

/// Register `~/.sondera/vscode/hooks` in VS Code user settings under
/// `chat.hookFilesLocations`, so VS Code looks in it at all.
///
/// A second document, and the host's own: it holds every VS Code setting the
/// user has, so it is spliced rather than replaced, and never deleted.
fn register_hooks_directory(settings_path: &Path) -> Result<()> {
    if let Some(backup) = config::backup(settings_path)? {
        eprintln!(
            "\x1b[33mBacked up VS Code settings to: {}\x1b[0m",
            backup.display()
        );
    }

    let mut settings = read_json_object(settings_path)?;
    let locations = settings
        .entry("chat.hookFilesLocations")
        .or_insert_with(|| json!({}));
    if let Some(obj) = locations.as_object_mut() {
        obj.insert(USER_HOOKS_DIR_TILDE.to_string(), json!(true));
    }

    write_json_object(settings_path, &settings)?;
    eprintln!(
        "\x1b[32m✓ Registered {} in VS Code user settings (chat.hookFilesLocations)\x1b[0m",
        USER_HOOKS_DIR_TILDE
    );
    Ok(())
}

/// Undo [`register_hooks_directory`], leaving every other setting alone.
fn deregister_hooks_directory(settings_path: &Path) -> Result<()> {
    if !settings_path.exists() {
        return Ok(());
    }

    let mut settings = read_json_object(settings_path)?;
    let removed = match settings.get_mut("chat.hookFilesLocations") {
        Some(Value::Object(locations)) => locations.remove(USER_HOOKS_DIR_TILDE).is_some(),
        _ => false,
    };
    if removed {
        write_json_object(settings_path, &settings)?;
        eprintln!(
            "\x1b[32m✓ Removed {} from chat.hookFilesLocations\x1b[0m",
            USER_HOOKS_DIR_TILDE
        );
    }
    Ok(())
}

/// Uninstall hooks from the specified scope.
pub fn uninstall_hooks(scope: InstallScope) -> Result<()> {
    // Every key in the file is ours, so revoking is emptying it; the installer
    // then deletes the file rather than leaving a `{}` for VS Code to load.
    hooks_installer(scope)?.uninstall(|hooks_file| {
        let had_hooks = !hooks_file.is_empty();
        hooks_file.clear();
        had_hooks
    })?;

    if matches!(scope, InstallScope::User) {
        deregister_hooks_directory(&vscode_user_settings_path()?)?;
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn binary() -> sondera_hooks::install::binary::ResolvedBinary {
        sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ))
    }

    #[test]
    fn test_generate_hooks_config_all_events() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path, false);
        let hooks = config.get("hooks").expect("must have 'hooks' key");

        // All eight VS Code hook events must be present
        for (event_name, _) in HOOK_EVENTS {
            assert!(
                hooks.get(*event_name).is_some(),
                "Missing hook event: {}",
                event_name
            );
        }
    }

    #[test]
    fn test_generate_hooks_config_pascal_case_keys() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path, false);
        let hooks = config.get("hooks").unwrap();

        // Verify PascalCase event names (VS Code native format)
        assert!(hooks.get("SessionStart").is_some());
        assert!(hooks.get("UserPromptSubmit").is_some());
        assert!(hooks.get("PreToolUse").is_some());
        assert!(hooks.get("PostToolUse").is_some());
        assert!(hooks.get("PreCompact").is_some());
        assert!(hooks.get("SubagentStart").is_some());
        assert!(hooks.get("SubagentStop").is_some());
        assert!(hooks.get("Stop").is_some());
    }

    #[test]
    fn test_generate_hooks_config_command_format() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path, false);
        let hooks = config["hooks"].as_object().unwrap();

        let pre_tool_use_cmd = &hooks["PreToolUse"][0]["command"];
        assert_eq!(
            pre_tool_use_cmd,
            "/usr/local/bin/sondera hook vscode pre-tool-use"
        );

        let timeout = &hooks["PreToolUse"][0]["timeout"];
        assert_eq!(timeout, 30);

        let hook_type = &hooks["PreToolUse"][0]["type"];
        assert_eq!(hook_type, "command");
    }

    #[test]
    fn windows_command_quotes_program_files_path_and_retains_exe() {
        // A real MSI install lives at `C:\Program Files\Sondera\sondera.exe`
        // (`find_sondera_binary` canonicalizes to a `\\?\` verbatim path). The
        // Windows `command` must strip the verbatim prefix, retain `.exe`, and
        // double-quote the path so VS Code invokes the whole path, not `C:\Program`.
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            r"\\?\C:\Program Files\Sondera\sondera.exe",
        ));
        let config = generate_hooks_config_for_shell(
            &path,
            false,
            sondera_hooks::install::binary::CommandShell::WindowsCmd,
        );
        let hooks = config["hooks"].as_object().unwrap();
        assert_eq!(
            hooks["PreToolUse"][0]["command"],
            r#""C:\Program Files\Sondera\sondera.exe" hook vscode pre-tool-use"#
        );
    }

    #[test]
    fn test_generate_hooks_config_verbose_flag() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path, true);
        let hooks = config["hooks"].as_object().unwrap();

        let pre_tool_use_cmd = &hooks["PreToolUse"][0]["command"];
        assert_eq!(
            pre_tool_use_cmd,
            "/usr/local/bin/sondera hook vscode --verbose pre-tool-use"
        );
    }

    #[test]
    fn test_hook_events_count() {
        // VS Code documents exactly 8 hook events
        assert_eq!(HOOK_EVENTS.len(), 8);
    }

    #[test]
    fn test_local_hooks_path() {
        let root = PathBuf::from("/workspace/my-project");
        let path = local_hooks_path(&root);
        assert_eq!(
            path,
            PathBuf::from("/workspace/my-project/.github/hooks/sondera.json")
        );
    }

    #[test]
    fn user_scope_paths_target_vscode_user_config() {
        let home = PathBuf::from("/Users/alice");
        assert_eq!(
            user_hooks_path_for_home(&home),
            PathBuf::from("/Users/alice/.sondera/vscode/hooks/sondera.json")
        );
        assert!(
            vscode_user_settings_path_for_home(&home)
                .to_string_lossy()
                .contains("Code"),
            "settings path should target the VS Code user settings directory"
        );
    }

    #[test]
    fn user_scope_install_writes_hook_file_and_registers_settings_location() {
        let home = tempfile::tempdir().unwrap();
        let hooks_path = user_hooks_path_for_home(home.path());
        let settings_path = vscode_user_settings_path_for_home(home.path());
        fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
        fs::write(
            &settings_path,
            r#"{
              "editor.formatOnSave": true,
              "chat.hookFilesLocations": {
                "/customer/hooks": true,
              },
            }"#,
        )
        .unwrap();

        HookConfigInstaller::new(AGENT, &hooks_path, "user (test)")
            .apply(&binary(), |hooks_file, binary| {
                *hooks_file = generate_hooks_config(binary, true)
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
            })
            .unwrap();
        register_hooks_directory(&settings_path).unwrap();

        let hooks: Value = serde_json::from_str(&fs::read_to_string(&hooks_path).unwrap()).unwrap();
        assert_eq!(
            hooks["hooks"]["PreToolUse"][0]["command"],
            "/usr/local/bin/sondera hook vscode --verbose pre-tool-use"
        );
        assert_eq!(hooks["hooks"]["PreToolUse"][0]["type"], "command");
        assert_eq!(hooks["hooks"]["PreToolUse"][0]["timeout"], 30);

        let settings = read_json_object(&settings_path).unwrap();
        assert_eq!(settings["editor.formatOnSave"], true);
        let locations = settings["chat.hookFilesLocations"].as_object().unwrap();
        assert_eq!(locations.get("/customer/hooks"), Some(&json!(true)));
        assert_eq!(locations.get(USER_HOOKS_DIR_TILDE), Some(&json!(true)));
    }

    #[test]
    fn user_scope_uninstall_removes_only_sondera_hook_file_and_settings_location() {
        let home = tempfile::tempdir().unwrap();
        let hooks_path = user_hooks_path_for_home(home.path());
        let settings_path = vscode_user_settings_path_for_home(home.path());
        fs::create_dir_all(hooks_path.parent().unwrap()).unwrap();
        config::write_value(&hooks_path, &generate_hooks_config(&binary(), false)).unwrap();
        fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
        write_json_object(
            &settings_path,
            &serde_json::from_value(json!({
                "editor.formatOnSave": true,
                "chat.hookFilesLocations": {
                    USER_HOOKS_DIR_TILDE: true,
                    "/customer/hooks": true
                }
            }))
            .unwrap(),
        )
        .unwrap();

        HookConfigInstaller::new(AGENT, &hooks_path, "user (test)")
            .remove_when(Map::is_empty)
            .revoke(|hooks_file| {
                let had_hooks = !hooks_file.is_empty();
                hooks_file.clear();
                had_hooks
            })
            .unwrap();
        deregister_hooks_directory(&settings_path).unwrap();

        assert!(!hooks_path.exists(), "Sondera VS Code hook file removed");
        let settings = read_json_object(&settings_path).unwrap();
        assert_eq!(settings["editor.formatOnSave"], true);
        let locations = settings["chat.hookFilesLocations"].as_object().unwrap();
        assert!(!locations.contains_key(USER_HOOKS_DIR_TILDE));
        assert_eq!(locations.get("/customer/hooks"), Some(&json!(true)));
    }

    #[test]
    fn test_hooks_config_has_hooks_wrapper() {
        // The generated config must have a top-level "hooks" key per VS Code spec
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/bin/sondera",
        ));
        let config = generate_hooks_config(&path, false);
        assert!(
            config.as_object().unwrap().contains_key("hooks"),
            "hooks config must have top-level 'hooks' key"
        );
    }

    #[test]
    fn test_read_json_object_accepts_jsonc_settings() {
        let path = std::env::temp_dir().join(format!(
            "vscode-jsonc-settings-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::write(
            &path,
            r#"{
                // VS Code settings are JSONC.
                "chat.hookFilesLocations": {
                    "~/.sondera/vscode/hooks": true,
                },
                "terminal.integrated.env.osx": {
                    "URL": "https://example.test/path",
                },
            }"#,
        )
        .unwrap();

        let parsed = read_json_object(&path).unwrap();
        assert!(
            parsed
                .get("chat.hookFilesLocations")
                .and_then(Value::as_object)
                .and_then(|locations| locations.get(USER_HOOKS_DIR_TILDE))
                .and_then(Value::as_bool)
                .unwrap()
        );
        assert_eq!(
            parsed["terminal.integrated.env.osx"]["URL"],
            "https://example.test/path"
        );

        let _ = fs::remove_file(path);
    }
}
