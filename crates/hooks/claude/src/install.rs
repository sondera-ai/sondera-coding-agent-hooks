//! Install command for setting up Claude Code hooks.
//!
//! This module provides functionality to install the Sondera hooks configuration
//! into Claude Code settings files. Hooks can be installed at different scopes:
//! - User scope: `~/.claude/settings.json` (applies to all projects)
//! - Local project scope: `.claude/settings.local.json` (default, not committed to git)
//!
//! This build performs no authentication — the harness requires none — so there
//! is no post-install auth check or prompt.

use crate::event::HOOK_EVENTS;
use serde_json::{Map, Value, json};
use sondera_hooks::error::{HookError, HookResultExt as _, Result};
use sondera_hooks::install::{command, config};
use std::env;
#[cfg(unix)]
use std::ffi::{CStr, CString, OsString};
use std::fs;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The provider this adapter's hook commands dispatch to.
const PROVIDER: &str = "claude";

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

const CLAUDE_PLUGIN_DIR_ENV_VAR: &str = "CLAUDE_PLUGIN_DIR";
const FORCE_MANAGED_HOOKS_ENV_VAR: &str = "SONDERA_FORCE_MANAGED_HOOKS";
pub const HOOK_TIMEOUT_SECS: u64 = 30;
const RETIRED_MANAGED_HOOK_SUBCOMMANDS: &[&str] = &["worktree-create"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetiredHookCleanup {
    pub settings_path: PathBuf,
    pub backup_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedHookCleanup {
    pub settings_path: PathBuf,
    pub backup_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaudeSettingsLocation {
    label: String,
    path: PathBuf,
    read_only: bool,
}

fn required_hook_subcommands() -> Vec<&'static str> {
    HOOK_EVENTS
        .iter()
        .map(|(_, subcommand)| *subcommand)
        .collect()
}

fn find_binary_path() -> Result<sondera_hooks::install::binary::ResolvedBinary> {
    sondera_hooks::install::binary::find_sondera_binary()
}

/// Build the hooks-config entry for a single hook event:
/// `[{ "matcher": "*", "hooks": [{ "type": "command", "command": "<binary> hook claude [--verbose] <subcommand>", "timeout": HOOK_TIMEOUT_SECS }] }]`.
///
/// Used by the Claude Code installer ([`generate_hooks_config`]) so the hook
/// command shape and timeout are defined once.
///
/// The command is always rendered with [`CommandShell::Posix`], on every host
/// including Windows: Claude Code executes a hook
/// `command` string through a POSIX shell, so a single unquoted `command` field
/// is the portable contract — there is no separate Windows `command` variant to
/// render (unlike VS Code, whose Windows `command` is a native command line and
/// so branches on the host in `sondera-vscode`, or Copilot, whose distinct
/// `powershell` field is rendered with [`CommandShell::PowerShell`]). If a
/// future Claude Code release runs Windows hook commands through `cmd.exe`
/// instead of a POSIX shell, this would need a host branch like `vscode.rs`.
///
/// [`CommandShell::Posix`]: sondera_hooks::install::binary::CommandShell::Posix
/// [`CommandShell::PowerShell`]: sondera_hooks::install::binary::CommandShell::PowerShell
pub fn hook_command_entry(
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    subcommand: &str,
    verbose: bool,
) -> Value {
    let binary_str = binary_path.render(sondera_hooks::install::binary::CommandShell::Posix);
    let verbose_flag = if verbose { " --verbose" } else { "" };
    let command = format!("{binary_str} hook claude{verbose_flag} {subcommand}");
    json!([{
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": command,
            "timeout": HOOK_TIMEOUT_SECS
        }]
    }])
}

/// Generate the hooks configuration JSON for all Claude Code hook events.
///
/// Hook commands use the umbrella binary format: `sondera hook claude <subcommand>`.
pub fn generate_hooks_config(
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    verbose: bool,
) -> Value {
    let mut hooks = Map::new();
    for (event_name, subcommand) in HOOK_EVENTS {
        hooks.insert(
            (*event_name).to_string(),
            hook_command_entry(binary_path, subcommand, verbose),
        );
    }
    Value::Object(hooks)
}

fn parse_true_like(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn plugin_manifest_has_sondera_hooks(plugin_root: &Path) -> bool {
    let manifest_path = plugin_root.join(".claude-plugin").join("plugin.json");
    let content = match fs::read_to_string(&manifest_path) {
        Ok(content) => content,
        Err(_) => return false,
    };
    let plugin_json: Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(_) => return false,
    };

    plugin_json
        .get("hooks")
        .and_then(Value::as_object)
        .map(|hooks| {
            hooks.values().any(|rules| {
                rules.as_array().is_some_and(|rule_list| {
                    rule_list.iter().any(|rule| {
                        rule.get("hooks")
                            .and_then(Value::as_array)
                            .is_some_and(|hook_list| {
                                hook_list.iter().any(|hook| {
                                    hook.get("command")
                                        .and_then(Value::as_str)
                                        .is_some_and(|command| command.contains("sondera-hook.sh"))
                                })
                            })
                    })
                })
            })
        })
        .unwrap_or(false)
}

fn resolve_plugin_root(cwd: &Path) -> Option<PathBuf> {
    if env::var(FORCE_MANAGED_HOOKS_ENV_VAR)
        .map(|v| parse_true_like(&v))
        .unwrap_or(false)
    {
        return None;
    }

    let plugin_dir_raw = env::var(CLAUDE_PLUGIN_DIR_ENV_VAR).ok()?;
    let plugin_dir = PathBuf::from(plugin_dir_raw);
    let resolved = if plugin_dir.is_relative() {
        cwd.join(plugin_dir)
    } else {
        plugin_dir
    };

    plugin_manifest_has_sondera_hooks(&resolved).then_some(resolved)
}

fn should_dedupe_with_plugin(scope: InstallScope) -> bool {
    !matches!(scope, InstallScope::User)
}

/// Whether `command` is one of our Claude hooks for exactly `subcommand`.
///
/// Claude classifies by event rather than by provider alone: `remove_retired…`
/// must remove the hooks for events we no longer install while leaving the
/// current ones in place, so the subcommand is part of the question.
fn command_matches_sondera_hook_subcommand(command: &str, subcommand: &str) -> bool {
    command::HookCommand::parse(command).is_some_and(|parsed| {
        parsed.provider == PROVIDER && parsed.subcommand.as_deref() == Some(subcommand)
    })
}

fn is_managed_sondera_hook_command_by_binary(command: &str) -> bool {
    HOOK_EVENTS
        .iter()
        .map(|(_, subcommand)| *subcommand)
        .chain(RETIRED_MANAGED_HOOK_SUBCOMMANDS.iter().copied())
        .any(|subcommand| command_matches_sondera_hook_subcommand(command, subcommand))
}

fn is_managed_sondera_hook_command(command: &str) -> bool {
    command.contains("sondera-hook.sh") || is_managed_sondera_hook_command_by_binary(command)
}

fn is_retired_managed_sondera_hook_command(command: &str) -> bool {
    RETIRED_MANAGED_HOOK_SUBCOMMANDS
        .iter()
        .copied()
        .any(|subcommand| command_matches_sondera_hook_subcommand(command, subcommand))
}

fn warn_malformed_hooks(message: impl AsRef<str>) {
    eprintln!("\x1b[33mWARNING: {}\x1b[0m", message.as_ref());
}

/// Remove managed Sondera Claude hook command entries from an already parsed
/// Claude settings object, preserving unrelated settings and third-party hooks.
pub fn remove_managed_sondera_hooks(settings: &mut Map<String, Value>) -> bool {
    remove_matching_hook_commands(settings, is_managed_sondera_hook_command)
}

fn remove_retired_managed_sondera_hooks(settings: &mut Map<String, Value>) -> bool {
    remove_matching_hook_commands(settings, is_retired_managed_sondera_hook_command)
}

fn remove_matching_hook_commands(
    settings: &mut Map<String, Value>,
    should_remove: impl Fn(&str) -> bool,
) -> bool {
    let Some(existing_hooks) = settings.get("hooks").cloned() else {
        return false;
    };
    let Some(existing_hook_map) = existing_hooks.as_object() else {
        return false;
    };

    let mut changed = false;
    let mut cleaned_hooks = Map::new();

    for (event_name, rules_value) in existing_hook_map {
        let Some(rules) = rules_value.as_array() else {
            cleaned_hooks.insert(event_name.clone(), rules_value.clone());
            continue;
        };

        let mut kept_rules = Vec::new();
        for rule in rules {
            let Some(rule_obj) = rule.as_object() else {
                kept_rules.push(rule.clone());
                continue;
            };

            let Some(hook_entries) = rule_obj.get("hooks").and_then(Value::as_array) else {
                kept_rules.push(rule.clone());
                continue;
            };

            let mut kept_entries = Vec::new();
            for entry in hook_entries {
                let remove_entry = entry
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(&should_remove);
                if remove_entry {
                    changed = true;
                    continue;
                }
                kept_entries.push(entry.clone());
            }

            if kept_entries.is_empty() {
                changed = true;
                continue;
            }

            let mut updated_rule = rule_obj.clone();
            updated_rule.insert("hooks".to_string(), Value::Array(kept_entries));
            kept_rules.push(Value::Object(updated_rule));
        }

        if kept_rules.is_empty() {
            changed = true;
            continue;
        }

        cleaned_hooks.insert(event_name.clone(), Value::Array(kept_rules));
    }

    if !changed {
        return false;
    }

    if cleaned_hooks.is_empty() {
        settings.remove("hooks");
    } else {
        settings.insert("hooks".to_string(), Value::Object(cleaned_hooks));
    }

    true
}

fn settings_have_matching_hook_command(
    settings: &Map<String, Value>,
    matches_command: impl Fn(&str) -> bool,
) -> bool {
    settings
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(|hooks| {
            hooks.values().any(|rules_value| {
                rules_value.as_array().is_some_and(|rules| {
                    rules.iter().any(|rule| {
                        rule.get("hooks")
                            .and_then(Value::as_array)
                            .is_some_and(|entries| {
                                entries.iter().any(|entry| {
                                    entry
                                        .get("command")
                                        .and_then(Value::as_str)
                                        .is_some_and(&matches_command)
                                })
                            })
                    })
                })
            })
        })
}

pub fn settings_path(scope: InstallScope) -> Result<PathBuf> {
    get_settings_path(scope)
}

#[cfg(unix)]
fn is_elevated_process() -> bool {
    // SAFETY: `geteuid` has no preconditions and does not retain pointers.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_elevated_process() -> bool {
    false
}

#[cfg(unix)]
fn lookup_user_home(username: &str) -> Result<PathBuf> {
    let username = CString::new(username.as_bytes())
        .map_err(|_| HookError::message("SUDO_USER contains an invalid NUL byte"))?;
    // POSIX permits `_SC_GETPW_R_SIZE_MAX` to return -1 when no fixed upper
    // bound is known. Start at 16 KiB and grow on ERANGE in that case.
    // SAFETY: `sysconf` has no pointer arguments and does not retain state.
    let configured_size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer_size = if configured_size > 0 {
        configured_size as usize
    } else {
        16 * 1024
    };

    loop {
        let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; buffer_size];
        // SAFETY: every pointer refers to live writable storage for the duration
        // of the call, and the copied home path is materialized before `buffer`
        // and `passwd` leave this scope.
        let status = unsafe {
            libc::getpwnam_r(
                username.as_ptr(),
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };

        if status == libc::ERANGE {
            buffer_size = buffer_size
                .checked_mul(2)
                .ok_or_else(|| HookError::message("passwd lookup buffer size overflowed"))?;
            continue;
        }
        if status != 0 {
            return Err(HookError::message(format!(
                "Could not resolve sudo user '{username:?}': {}",
                std::io::Error::from_raw_os_error(status)
            )));
        }
        if result.is_null() {
            return Err(HookError::message(format!(
                "Could not resolve home directory for sudo user '{username:?}'"
            )));
        }

        // SAFETY: a successful `getpwnam_r` result points into `passwd` and its
        // caller-owned buffer until this scope ends.
        let passwd = unsafe { passwd.assume_init() };
        if passwd.pw_dir.is_null() {
            return Err(HookError::message(format!(
                "Sudo user '{username:?}' does not have a home directory"
            )));
        }
        // SAFETY: `pw_dir` is a NUL-terminated C string on successful lookup.
        let home = unsafe { CStr::from_ptr(passwd.pw_dir) };
        return Ok(PathBuf::from(OsString::from_vec(home.to_bytes().to_vec())));
    }
}

#[cfg(unix)]
fn sudo_invoking_user_home() -> Result<Option<PathBuf>> {
    if !is_elevated_process() {
        return Ok(None);
    }
    let Some(username) = env::var_os("SUDO_USER") else {
        return Ok(None);
    };
    if username.is_empty() || username == "root" {
        return Ok(None);
    }
    let username = username.to_str().ok_or_else(|| {
        HookError::message("SUDO_USER is not valid UTF-8 and cannot be resolved safely")
    })?;
    lookup_user_home(username).map(Some)
}

#[cfg(not(unix))]
fn sudo_invoking_user_home() -> Result<Option<PathBuf>> {
    Ok(None)
}

fn settings_home_dir() -> Result<PathBuf> {
    if let Some(home) = sudo_invoking_user_home()? {
        return Ok(home);
    }
    dirs::home_dir().context("Could not determine home directory")
}

#[cfg(unix)]
fn sudo_invoking_user_ids() -> Option<(u32, u32)> {
    if !is_elevated_process() {
        return None;
    }
    let uid = env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid = env::var("SUDO_GID").ok()?.parse().ok()?;
    Some((uid, gid))
}

#[cfg(not(unix))]
fn sudo_invoking_user_ids() -> Option<(u32, u32)> {
    None
}

#[cfg(unix)]
fn chown_to(path: &Path, uid: u32, gid: u32) -> Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
        .with_context(|| format!("Failed to preserve ownership for {}", path.display()))
}

#[cfg(not(unix))]
fn chown_to(_path: &Path, _uid: u32, _gid: u32) -> Result<()> {
    Ok(())
}

fn preserve_backup_owner(source: &Path, backup: &Path) -> Result<()> {
    if !is_elevated_process() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let metadata = fs::metadata(source)
            .with_context(|| format!("Failed to read ownership for {}", source.display()))?;
        chown_to(backup, metadata.uid(), metadata.gid())?;
    }
    #[cfg(not(unix))]
    let _ = (source, backup);
    Ok(())
}

fn preserve_new_user_settings_owner(path: &Path, parent_existed: bool) -> Result<()> {
    let Some((uid, gid)) = sudo_invoking_user_ids() else {
        return Ok(());
    };
    chown_to(path, uid, gid)?;
    if !parent_existed && let Some(parent) = path.parent() {
        chown_to(parent, uid, gid)?;
    }
    Ok(())
}

fn push_settings_location(
    locations: &mut Vec<ClaudeSettingsLocation>,
    label: impl Into<String>,
    path: PathBuf,
    read_only: bool,
) {
    if locations.iter().any(|location| location.path == path) {
        return;
    }
    locations.push(ClaudeSettingsLocation {
        label: label.into(),
        path,
        read_only,
    });
}

fn managed_settings_paths_for_base(base: &Path) -> Vec<PathBuf> {
    // Keep this in sync with `crates/common/authflow/src/status.rs` so
    // install/uninstall diagnostics and `sondera auth status` agree.
    let drop_in_dir = base.join("managed-settings.d");
    // The historical Sondera-owned drop-in is always a candidate, even when a
    // non-admin process cannot enumerate the root-owned directory.
    let mut paths = vec![
        base.join("managed-settings.json"),
        drop_in_dir.join("sondera-hooks.json"),
    ];
    if let Ok(entries) = fs::read_dir(&drop_in_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("json")
                && !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'))
            {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

pub fn managed_settings_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    #[cfg(target_os = "macos")]
    paths.extend(managed_settings_paths_for_base(Path::new(
        "/Library/Application Support/ClaudeCode",
    )));

    #[cfg(target_os = "linux")]
    paths.extend(managed_settings_paths_for_base(Path::new(
        "/etc/claude-code",
    )));

    #[cfg(target_os = "windows")]
    paths.extend(managed_settings_paths_for_base(Path::new(
        r"C:\Program Files\ClaudeCode",
    )));

    paths.sort();
    paths.dedup();
    paths
}

fn project_roots_from(cwd: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut dir = cwd.to_path_buf();
    loop {
        if dir.join(".git").exists() || dir.join(".claude").exists() {
            roots.push(dir.clone());
        }
        if !dir.pop() {
            break;
        }
    }
    roots
}

fn diagnostic_settings_locations(
    home: Option<&Path>,
    cwd: Option<&Path>,
    managed_paths: &[PathBuf],
) -> Vec<ClaudeSettingsLocation> {
    let mut locations = Vec::new();

    if let Some(cwd) = cwd {
        push_settings_location(
            &mut locations,
            "current local project settings",
            settings_path_for_scope(InstallScope::Local, cwd, cwd),
            false,
        );
        push_settings_location(
            &mut locations,
            "current project settings",
            settings_path_for_scope(InstallScope::Project, cwd, cwd),
            false,
        );

        for root in project_roots_from(cwd) {
            push_settings_location(
                &mut locations,
                "ancestor local project settings",
                settings_path_for_scope(InstallScope::Local, &root, &root),
                false,
            );
            push_settings_location(
                &mut locations,
                "ancestor project settings",
                settings_path_for_scope(InstallScope::Project, &root, &root),
                false,
            );
        }
    }

    if let Some(home) = home {
        push_settings_location(
            &mut locations,
            "user settings",
            settings_path_for_scope(InstallScope::User, home, home),
            false,
        );
    }

    for path in managed_paths {
        push_settings_location(
            &mut locations,
            "enterprise managed settings",
            path.clone(),
            true,
        );
    }

    locations
}

fn settings_file_contains_managed_sondera_hooks(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(HookError::message(format!(
                "Failed to inspect settings file {}: {err}",
                path.display()
            )));
        }
    }
    let settings = read_settings(path)?;
    Ok(settings_have_matching_hook_command(
        &settings,
        is_managed_sondera_hook_command,
    ))
}

fn managed_sondera_hook_locations(
    locations: &[ClaudeSettingsLocation],
) -> Vec<ClaudeSettingsLocation> {
    locations
        .iter()
        .filter_map(
            |location| match settings_file_contains_managed_sondera_hooks(&location.path) {
                Ok(true) => Some(location.clone()),
                Ok(false) => None,
                Err(err) => {
                    warn_malformed_hooks(format!(
                        "Could not inspect Claude settings at {}: {err:#}",
                        location.path.display()
                    ));
                    None
                }
            },
        )
        .collect()
}

#[cfg(unix)]
fn scope_flag(scope: InstallScope) -> &'static str {
    match scope {
        InstallScope::User => " --user",
        InstallScope::Project => " --project",
        InstallScope::Local => "",
    }
}

fn print_remaining_hook_locations(
    locations: &[ClaudeSettingsLocation],
    elevated: bool,
    action: &str,
    scope: InstallScope,
) -> bool {
    #[cfg(not(unix))]
    let _ = (action, scope);
    let found_locations = managed_sondera_hook_locations(locations);
    if found_locations.is_empty() {
        return false;
    }

    eprintln!();
    eprintln!("Sondera hooks remain active in known Claude settings locations:");
    let mut managed_hooks_remain = false;
    for location in found_locations {
        if location.read_only {
            managed_hooks_remain = true;
            let note = if elevated {
                "enterprise managed settings; cleanup failed, was unsafe, or was redeployed"
            } else {
                "enterprise managed settings; administrator cleanup required"
            };
            eprintln!(
                "  - {}: {} ({note})",
                location.label,
                location.path.display()
            );
        } else {
            eprintln!("  - {}: {}", location.label, location.path.display());
        }
    }

    if managed_hooks_remain && !elevated {
        eprintln!();
        eprintln!(
            "Re-run with administrator privileges to remove only recognized Sondera hook entries:"
        );
        #[cfg(unix)]
        eprintln!("  sudo sondera hook claude {action}{}", scope_flag(scope));
        #[cfg(windows)]
        eprintln!(
            "  Reconcile the Sondera hook payload through the customer package or IT/MDM; elevated CLI cleanup is not available on Windows."
        );
        #[cfg(not(any(unix, windows)))]
        eprintln!("  Reconcile the Sondera hook payload through IT/MDM.");
        eprintln!(
            "If device management restores the file, remove or redeploy the Sondera hook payload through IT/MDM."
        );
    }
    true
}

fn reconcile_managed_settings_paths(
    paths: &[PathBuf],
    elevated: bool,
    action: &str,
    scope: InstallScope,
) {
    let locations = paths
        .iter()
        .cloned()
        .map(|path| ClaudeSettingsLocation {
            label: "enterprise managed settings".to_string(),
            path,
            read_only: true,
        })
        .collect::<Vec<_>>();

    if elevated {
        for location in &locations {
            match cleanup_managed_sondera_hooks_at(&location.path) {
                Ok(Some(cleanup)) => {
                    eprintln!(
                        "\x1b[32m✓ Removed recognized Sondera hooks from managed settings {}\x1b[0m",
                        cleanup.settings_path.display()
                    );
                    eprintln!("  Backup: {}", cleanup.backup_path.display());
                }
                Ok(None) => {}
                Err(err) => warn_malformed_hooks(format!(
                    "Could not safely reconcile managed Claude settings at {}: {err:#}",
                    location.path.display()
                )),
            }
        }
    }

    print_remaining_hook_locations(&locations, elevated, action, scope);
}

pub fn contains_retired_managed_hooks_at(settings_path: &Path) -> Result<bool> {
    if !settings_path.exists() {
        return Ok(false);
    }
    let settings = read_settings(settings_path)?;
    Ok(settings_have_matching_hook_command(
        &settings,
        is_retired_managed_sondera_hook_command,
    ))
}

pub fn cleanup_retired_managed_hooks_at(
    settings_path: &Path,
) -> Result<Option<RetiredHookCleanup>> {
    if !settings_path.exists() {
        return Ok(None);
    }

    let mut settings = read_settings(settings_path)?;
    if !remove_retired_managed_sondera_hooks(&mut settings) {
        return Ok(None);
    }

    let backup_path = backup_settings(settings_path)?;
    write_settings(settings_path, &settings)?;
    Ok(Some(RetiredHookCleanup {
        settings_path: settings_path.to_path_buf(),
        backup_path,
    }))
}

/// Remove only recognized Sondera Claude hook command entries from one
/// existing settings file. The file is backed up before mutation; unrelated
/// Anthropic policy, third-party hooks, and non-hook fields are preserved.
///
/// Symlinks and non-regular files are rejected so an elevated reconciliation
/// cannot be redirected outside the known settings path.
pub fn cleanup_managed_sondera_hooks_at(
    settings_path: &Path,
) -> Result<Option<ManagedHookCleanup>> {
    cleanup_sondera_hooks_at(settings_path, SymlinkHandling::Reject)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymlinkHandling {
    Reject,
    FollowRegularTarget,
}

fn cleanup_sondera_hooks_at(
    settings_path: &Path,
    symlink_handling: SymlinkHandling,
) -> Result<Option<ManagedHookCleanup>> {
    let metadata = match fs::symlink_metadata(settings_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(HookError::message(format!(
                "Failed to inspect settings file {}: {err}",
                settings_path.display()
            )));
        }
    };
    let is_regular_file = if metadata.file_type().is_file() {
        true
    } else if metadata.file_type().is_symlink()
        && symlink_handling == SymlinkHandling::FollowRegularTarget
    {
        fs::metadata(settings_path)
            .with_context(|| {
                format!(
                    "Failed to inspect symlink target for {}",
                    settings_path.display()
                )
            })?
            .file_type()
            .is_file()
    } else {
        false
    };
    if !is_regular_file {
        return Err(HookError::message(format!(
            "Refusing to modify non-regular Claude settings path {}",
            settings_path.display()
        )));
    }

    let mut settings = read_settings(settings_path)?;
    if settings
        .get("hooks")
        .is_some_and(|hooks| !hooks.is_object())
    {
        warn_malformed_hooks(format!(
            "Existing Claude 'hooks' setting at {} is not an object; leaving it unchanged.",
            settings_path.display()
        ));
        return Ok(None);
    }
    if !remove_managed_sondera_hooks(&mut settings) {
        return Ok(None);
    }

    let backup_path = backup_settings_for_cleanup(settings_path)?.ok_or_else(|| {
        HookError::message(format!(
            "Settings file disappeared before backup: {}",
            settings_path.display()
        ))
    })?;
    write_settings(settings_path, &settings)?;
    Ok(Some(ManagedHookCleanup {
        settings_path: settings_path.to_path_buf(),
        backup_path,
    }))
}

fn warn_existing_malformed_hooks(
    existing_hooks: &Map<String, Value>,
    new_hooks: &Map<String, Value>,
) {
    for (event_name, rules_value) in existing_hooks {
        if rules_value.is_array() {
            continue;
        }

        if new_hooks.contains_key(event_name) {
            warn_malformed_hooks(format!(
                "Existing Claude hook event '{event_name}' is not an array; replacing that \
                 event with managed Sondera hooks. The original value remains in the backup."
            ));
        } else {
            warn_malformed_hooks(format!(
                "Existing Claude hook event '{event_name}' is not an array; preserving it \
                 unchanged because Sondera does not manage that event."
            ));
        }
    }
}

fn prepend_hooks(existing_hooks: &mut Map<String, Value>, new_hooks: &Map<String, Value>) {
    for (event_name, new_rules) in new_hooks {
        let Some(new_rules_array) = new_rules.as_array() else {
            warn_malformed_hooks(format!(
                "Generated Sondera Claude hook event '{event_name}' is not an array; skipping it."
            ));
            continue;
        };

        if let Some(existing_rules) = existing_hooks.get_mut(event_name) {
            if let Some(existing_rules_array) = existing_rules.as_array_mut() {
                let mut merged_rules = new_rules_array.clone();
                merged_rules.append(existing_rules_array);
                *existing_rules = Value::Array(merged_rules);
            } else {
                *existing_rules = new_rules.clone();
            }
        } else {
            existing_hooks.insert(event_name.clone(), new_rules.clone());
        }
    }
}

fn merge_managed_sondera_hooks(settings: &mut Map<String, Value>, hooks_config: Value) {
    let Some(new_hooks) = hooks_config.as_object() else {
        warn_malformed_hooks(
            "Generated Sondera Claude hook config is not an object; skipping merge.",
        );
        return;
    };

    remove_managed_sondera_hooks(settings);

    let Some(existing_hooks_value) = settings.remove("hooks") else {
        settings.insert("hooks".to_string(), Value::Object(new_hooks.clone()));
        return;
    };

    let Value::Object(mut existing_hooks) = existing_hooks_value else {
        warn_malformed_hooks(
            "Existing Claude 'hooks' setting is not an object; replacing it with managed \
             Sondera hooks. The original value remains in the backup.",
        );
        settings.insert("hooks".to_string(), Value::Object(new_hooks.clone()));
        return;
    };

    warn_existing_malformed_hooks(&existing_hooks, new_hooks);
    prepend_hooks(&mut existing_hooks, new_hooks);
    settings.insert("hooks".to_string(), Value::Object(existing_hooks));
}

fn settings_path_for_scope(scope: InstallScope, home: &Path, cwd: &Path) -> PathBuf {
    match scope {
        InstallScope::User => home.join(".claude").join("settings.json"),
        InstallScope::Project => cwd.join(".claude").join("settings.json"),
        InstallScope::Local => cwd.join(".claude").join("settings.local.json"),
    }
}

/// Get the settings file path for the given scope
fn get_settings_path(scope: InstallScope) -> Result<PathBuf> {
    match scope {
        InstallScope::User => {
            let home = settings_home_dir()?;
            Ok(settings_path_for_scope(scope, &home, &home))
        }
        InstallScope::Project | InstallScope::Local => {
            let cwd = env::current_dir().context("Could not determine current directory")?;
            Ok(settings_path_for_scope(scope, &cwd, &cwd))
        }
    }
}

fn output_to_text(output: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn help_contains_subcommand(help_text: &str, subcommand: &str) -> bool {
    help_text.split_whitespace().any(|token| {
        token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-') == subcommand
    })
}

fn missing_subcommands(help_text: &str, required_subcommands: &[&str]) -> Vec<String> {
    required_subcommands
        .iter()
        .filter(|subcommand| !help_contains_subcommand(help_text, subcommand))
        .map(|subcommand| (*subcommand).to_string())
        .collect()
}

fn ensure_binary_supports_hooks(
    binary_path: &sondera_hooks::install::binary::ResolvedBinary,
    required_subcommands: &[&str],
) -> Result<()> {
    let output = Command::new(binary_path.as_execution_path())
        .args(["hook", "claude", "--help"])
        .output()
        .with_context(|| {
            format!(
                "Failed to run '{} hook claude --help'",
                binary_path.display_path()
            )
        })?;
    let help_text = output_to_text(&output);
    if !output.status.success() {
        return Err(HookError::message(format!(
            "[sondera] Binary '{}' failed compatibility check \
             (`hook claude --help` exited with {}).\n\
             Run 'make install-claude' to install a compatible version.",
            binary_path.display_path(),
            output.status,
        )));
    }

    let missing = missing_subcommands(&help_text, required_subcommands);
    if !missing.is_empty() {
        return Err(HookError::message(format!(
            "[sondera] Binary '{}' is missing required hook subcommands: {}.\n\
             This usually means an older binary is on PATH.\n\
             Run 'make install-claude' to install a compatible version.",
            binary_path.display_path(),
            missing.join(", ")
        )));
    }

    Ok(())
}

/// Create a timestamped `*.backup.<ts>.json` copy of an existing settings file
/// before it is modified. Returns the backup path, or `None` if the file does
/// not exist.
///
/// [`config::backup`] with one addition: a root-owned settings file must not
/// leave a user-owned backup behind.
fn backup_settings(path: &Path) -> Result<Option<PathBuf>> {
    let Some(backup_path) = config::backup(path)? else {
        return Ok(None);
    };
    preserve_backup_owner(path, &backup_path)?;
    Ok(Some(backup_path))
}

fn backup_settings_for_cleanup(path: &Path) -> Result<Option<PathBuf>> {
    let is_managed_drop_in = path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "managed-settings.d");
    if !is_managed_drop_in {
        return backup_settings(path);
    }
    if !path.exists() {
        return Ok(None);
    }

    // Claude loads JSON files from `managed-settings.d`, so a conventional
    // `*.backup.<timestamp>.json` copy would remain active. Keep the backup in
    // place for recovery, but give it a non-JSON suffix that Claude ignores.
    let timestamp = config::backup_timestamp();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("managed-settings.json");
    let mut backup_path = path.with_file_name(format!("{file_name}.backup.{timestamp}"));
    let mut counter = 1_u32;
    while backup_path.exists() {
        backup_path = path.with_file_name(format!("{file_name}.backup.{timestamp}.{counter}"));
        counter += 1;
    }

    fs::copy(path, &backup_path).context("Failed to create backup")?;
    preserve_backup_owner(path, &backup_path)?;
    Ok(Some(backup_path))
}

/// Read existing settings or create empty object
fn read_settings(path: &Path) -> Result<Map<String, Value>> {
    config::read_object(path)
}

/// Write settings to file
fn write_settings(path: &Path, settings: &Map<String, Value>) -> Result<()> {
    config::write_object(path, settings)
}

/// Install hooks into the specified scope
pub fn install_hooks(scope: InstallScope, verbose: bool) -> Result<InstallResult> {
    eprintln!("\x1b[32mSondera Claude Code Hooks Installer\x1b[0m");
    eprintln!("====================================\n");

    // Find binary path
    let binary_path = find_binary_path()?;
    eprintln!("Binary found: {}", binary_path.display_path());
    let required_subcommands = required_hook_subcommands();
    ensure_binary_supports_hooks(&binary_path, &required_subcommands)?;
    eprintln!(
        "Binary compatibility check passed ({} hook subcommands).",
        required_subcommands.len()
    );

    // Get settings file path
    let settings_path = get_settings_path(scope)?;
    let settings_existed = settings_path.exists();
    let settings_parent_existed = settings_path.parent().is_none_or(Path::exists);
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

    // If plugin-managed hooks are present, avoid installing managed hooks in settings.
    if should_dedupe_with_plugin(scope) {
        let cwd = env::current_dir().context("Could not determine current directory")?;
        if let Some(plugin_root) = resolve_plugin_root(&cwd) {
            if remove_managed_sondera_hooks(&mut settings) {
                write_settings(&settings_path, &settings)?;
                if !settings_existed {
                    preserve_new_user_settings_owner(&settings_path, settings_parent_existed)?;
                }
                eprintln!(
                    "\x1b[33mRemoved managed sondera hooks from {}\x1b[0m",
                    settings_path.display()
                );
            }

            eprintln!(
                "\x1b[33mDetected plugin hook config at {}.\x1b[0m",
                plugin_root.display()
            );
            eprintln!("Skipping managed hook installation to avoid duplicate events.");
            eprintln!(
                "Set {}=1 to force managed hook installation.",
                FORCE_MANAGED_HOOKS_ENV_VAR
            );
            eprintln!();
            reconcile_managed_settings_paths(
                &managed_settings_paths(),
                is_elevated_process(),
                "install",
                scope,
            );
            eprintln!("\x1b[32mInstallation complete!\x1b[0m");
            return Ok(InstallResult { settings_path });
        }
    }

    // Generate hooks configuration
    let hooks_config = generate_hooks_config(&binary_path, verbose);

    // Merge hooks into settings
    merge_managed_sondera_hooks(&mut settings, hooks_config);

    // Write settings
    write_settings(&settings_path, &settings)?;
    if !settings_existed {
        preserve_new_user_settings_owner(&settings_path, settings_parent_existed)?;
    }

    reconcile_managed_settings_paths(
        &managed_settings_paths(),
        is_elevated_process(),
        "install",
        scope,
    );

    eprintln!(
        "\x1b[32m✓ Successfully installed hooks to {}\x1b[0m\n",
        settings_path.display()
    );

    // Print configuration details
    eprintln!("Configuration details:");
    eprintln!("  - Hook executable: {}", binary_path.display_path());
    if verbose {
        eprintln!("  - Debug logging: enabled (--verbose flag)");
    }
    eprintln!();

    Ok(InstallResult { settings_path })
}

/// Result from a successful `install_hooks` call.
pub struct InstallResult {
    /// Path to the settings file that was written.
    pub settings_path: PathBuf,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct UninstallCleanupResult {
    removed_count: usize,
    had_failures: bool,
}

fn cleanup_uninstall_locations(
    selected_path: &Path,
    scope: InstallScope,
    locations: &[ClaudeSettingsLocation],
    elevated: bool,
) -> Result<UninstallCleanupResult> {
    let cleanup_locations = if elevated {
        locations.to_vec()
    } else {
        vec![ClaudeSettingsLocation {
            label: format!("selected {scope} settings"),
            path: selected_path.to_path_buf(),
            read_only: false,
        }]
    };

    let mut outcome = UninstallCleanupResult::default();
    for location in cleanup_locations {
        let result = if elevated {
            cleanup_managed_sondera_hooks_at(&location.path)
        } else {
            cleanup_sondera_hooks_at(&location.path, SymlinkHandling::FollowRegularTarget)
        };
        match result {
            Ok(Some(cleanup)) => {
                outcome.removed_count += 1;
                eprintln!(
                    "\x1b[32m✓ Removed recognized Sondera hooks from {}\x1b[0m",
                    cleanup.settings_path.display()
                );
                eprintln!("  Backup: {}", cleanup.backup_path.display());
            }
            Ok(None) => {}
            Err(err) if elevated || location.path != selected_path => {
                outcome.had_failures = true;
                warn_malformed_hooks(format!(
                    "Could not safely reconcile Claude settings at {}: {err:#}",
                    location.path.display()
                ));
            }
            Err(err) => return Err(err),
        }
    }

    Ok(outcome)
}

/// Uninstall hooks from the specified scope
pub fn uninstall_hooks(scope: InstallScope) -> Result<()> {
    eprintln!("\x1b[32mSondera Claude Code Hooks Uninstaller\x1b[0m");
    eprintln!("======================================\n");

    let settings_path = get_settings_path(scope)?;
    let selected_exists = settings_path.exists();
    let elevated = is_elevated_process();
    eprintln!("Uninstalling from {} scope", scope);
    eprintln!("Settings file: {}\n", settings_path.display());

    if !selected_exists {
        eprintln!(
            "Selected settings file does not exist; continuing scan of known Claude settings locations."
        );
    }

    let home = settings_home_dir()?;
    let cwd = env::current_dir().context("Could not determine current directory")?;
    let locations =
        diagnostic_settings_locations(Some(&home), Some(&cwd), &managed_settings_paths());
    let cleanup = cleanup_uninstall_locations(&settings_path, scope, &locations, elevated)?;

    if selected_exists && cleanup.removed_count == 0 && !cleanup.had_failures {
        eprintln!(
            "No managed Sondera hooks found in selected {} settings file.",
            scope
        );
    }

    let hooks_remain = print_remaining_hook_locations(&locations, elevated, "uninstall", scope);
    if !hooks_remain {
        if cleanup.had_failures {
            eprintln!(
                "\x1b[33mWARNING: Some Claude settings locations could not be verified; review the warnings above before assuming cleanup is complete.\x1b[0m"
            );
        } else if cleanup.removed_count == 0 {
            eprintln!("No Sondera hooks were found in known Claude settings locations.");
        } else {
            eprintln!("\x1b[32m✓ All detected Sondera Claude Code hooks were removed.\x1b[0m");
        }
    } else {
        eprintln!();
        eprintln!(
            "Tip: `sondera hook claude uninstall` defaults to the local project settings for the current working directory."
        );
        eprintln!(
            "Use `--project` or `--user`, or run the command from the project directory that owns the settings file."
        );
    }

    eprintln!();
    eprintln!("\x1b[33mNote:\x1b[0m Restart Claude Code for changes to take effect.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    #[cfg(windows)]
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_generate_hooks_config() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path, false);

        assert!(config.get("PreToolUse").is_some());
        assert!(config.get("PostToolUse").is_some());
        assert!(config.get("SessionStart").is_some());
        assert!(config.get("SessionEnd").is_some());

        let pre_tool_use = &config["PreToolUse"][0]["hooks"][0]["command"];
        assert_eq!(
            pre_tool_use,
            "/usr/local/bin/sondera hook claude pre-tool-use"
        );
        assert_eq!(config["PreToolUse"][0]["hooks"][0]["timeout"], 30);
    }

    #[test]
    fn test_generate_hooks_config_verbose() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path, true);

        let pre_tool_use = &config["PreToolUse"][0]["hooks"][0]["command"];
        assert_eq!(
            pre_tool_use,
            "/usr/local/bin/sondera hook claude --verbose pre-tool-use"
        );
        assert_eq!(config["PreToolUse"][0]["hooks"][0]["timeout"], 30);
    }

    #[test]
    fn test_generate_hooks_config_all_events() {
        let path = sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        ));
        let config = generate_hooks_config(&path, false);

        // Verify all hook events from the canonical HOOK_EVENTS list are present.
        for (event_name, _) in HOOK_EVENTS {
            assert!(
                config.get(*event_name).is_some(),
                "Missing event: {}",
                event_name
            );
        }
        assert!(
            config.get("WorktreeCreate").is_none(),
            "WorktreeCreate must not be installed because it delegates worktree creation"
        );
    }

    #[test]
    fn test_settings_path_for_scope() {
        let home = PathBuf::from("/home/tester");
        let cwd = PathBuf::from("/repo/project");

        assert_eq!(
            settings_path_for_scope(InstallScope::User, &home, &cwd),
            PathBuf::from("/home/tester/.claude/settings.json")
        );
        assert_eq!(
            settings_path_for_scope(InstallScope::Project, &home, &cwd),
            PathBuf::from("/repo/project/.claude/settings.json")
        );
        assert_eq!(
            settings_path_for_scope(InstallScope::Local, &home, &cwd),
            PathBuf::from("/repo/project/.claude/settings.local.json")
        );
    }

    #[test]
    fn test_managed_settings_paths_for_base_includes_sorted_drop_ins() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("ClaudeCode");
        let drop_in_dir = base.join("managed-settings.d");
        fs::create_dir_all(&drop_in_dir).unwrap();
        fs::write(drop_in_dir.join("b.json"), "{}").unwrap();
        fs::write(drop_in_dir.join("a.json"), "{}").unwrap();
        fs::write(drop_in_dir.join(".hidden.json"), "{}").unwrap();
        fs::write(drop_in_dir.join("not-json.txt"), "{}").unwrap();

        let paths = managed_settings_paths_for_base(&base);

        assert_eq!(
            paths,
            vec![
                base.join("managed-settings.d/a.json"),
                base.join("managed-settings.d/b.json"),
                base.join("managed-settings.d/sondera-hooks.json"),
                base.join("managed-settings.json"),
            ]
        );
    }

    #[test]
    fn test_diagnostic_locations_find_ancestor_and_managed_hooks() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        let nested = project.join("packages/core");
        fs::create_dir_all(project.join(".git")).unwrap();
        fs::create_dir_all(&nested).unwrap();

        let project_settings_path = project.join(".claude/settings.local.json");
        fs::create_dir_all(project_settings_path.parent().unwrap()).unwrap();
        fs::write(
            &project_settings_path,
            json!({
                "hooks": {
                    "SessionStart": [{
                        "hooks": [{
                            "type": "command",
                            "command": "/usr/local/bin/sondera hook claude session-start"
                        }]
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();

        let managed_base = temp.path().join("managed");
        let managed_path = managed_base.join("managed-settings.d/sondera-hooks.json");
        fs::create_dir_all(managed_path.parent().unwrap()).unwrap();
        fs::write(
            &managed_path,
            json!({
                "hooks": {
                    "PreToolUse": [{
                        "hooks": [{
                            "type": "command",
                            "command": "${CLAUDE_PLUGIN_ROOT}/scripts/sondera-hook.sh pre-tool-use"
                        }]
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();

        let managed_paths = managed_settings_paths_for_base(&managed_base);
        let locations = diagnostic_settings_locations(Some(&home), Some(&nested), &managed_paths);
        let found = managed_sondera_hook_locations(&locations);

        assert!(found.iter().any(|location| {
            location.label == "ancestor local project settings"
                && location.path == project_settings_path
                && !location.read_only
        }));
        assert!(found.iter().any(|location| {
            location.label == "enterprise managed settings"
                && location.path == managed_path
                && location.read_only
        }));
        assert!(
            !found
                .iter()
                .any(|location| { location.path == nested.join(".claude/settings.local.json") })
        );
    }

    #[test]
    fn test_cleanup_managed_hooks_preserves_anthropic_policy_and_customer_hooks() {
        let temp = tempfile::tempdir().unwrap();
        let settings_path = temp.path().join("managed-settings.json");
        fs::write(
            &settings_path,
            json!({
                "$schema": "https://json.schemastore.org/claude-code-settings.json",
                "allowManagedHooksOnly": true,
                "strictKnownMarketplaces": true,
                "permissions": {"defaultMode": "plan"},
                "hooks": {
                    "SessionStart": [{
                        "hooks": [
                            {
                                "type": "command",
                                "command": "/usr/local/bin/sondera hook claude session-start"
                            },
                            {
                                "type": "command",
                                "command": "/usr/local/bin/customer-session-start"
                            }
                        ]
                    }],
                    "CustomEvent": [{
                        "hooks": [{
                            "type": "command",
                            "command": "/usr/local/bin/customer-custom-event"
                        }]
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();

        let cleanup = cleanup_managed_sondera_hooks_at(&settings_path)
            .unwrap()
            .expect("Sondera hooks should be removed");
        assert_eq!(cleanup.settings_path, settings_path);
        assert!(cleanup.backup_path.exists());

        let cleaned: Value =
            serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
        assert_eq!(cleaned["allowManagedHooksOnly"], true);
        assert_eq!(cleaned["strictKnownMarketplaces"], true);
        assert_eq!(cleaned["permissions"]["defaultMode"], "plan");
        assert!(cleaned.to_string().contains("customer-session-start"));
        assert!(cleaned.to_string().contains("customer-custom-event"));
        assert!(!cleaned.to_string().contains("sondera hook claude"));

        assert!(
            cleanup_managed_sondera_hooks_at(&settings_path)
                .unwrap()
                .is_none(),
            "a second cleanup should be a no-op with no additional backup"
        );
        let backup_count = fs::read_dir(temp.path())
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("managed-settings.backup.")
            })
            .count();
        assert_eq!(backup_count, 1);
    }

    #[cfg(unix)]
    #[test]
    fn test_cleanup_managed_hooks_rejects_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("customer-settings.json");
        let link = temp.path().join("managed-settings.json");
        let original = json!({
            "hooks": {
                "SessionStart": [{
                    "hooks": [{
                        "type": "command",
                        "command": "/usr/local/bin/sondera hook claude session-start"
                    }]
                }]
            }
        })
        .to_string();
        fs::write(&target, &original).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = cleanup_managed_sondera_hooks_at(&link).unwrap_err();
        assert!(err.to_string().contains("non-regular Claude settings path"));
        assert_eq!(fs::read_to_string(&target).unwrap(), original);
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_non_elevated_uninstall_follows_selected_settings_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("dotfiles/claude-settings.json");
        let selected = temp.path().join("home/.claude/settings.json");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::create_dir_all(selected.parent().unwrap()).unwrap();
        fs::write(
            &target,
            json!({
                "permissions": {"defaultMode": "plan"},
                "hooks": {
                    "SessionStart": [{
                        "hooks": [
                            {
                                "type": "command",
                                "command": "/usr/local/bin/sondera hook claude session-start"
                            },
                            {
                                "type": "command",
                                "command": "/usr/local/bin/customer-session-start"
                            }
                        ]
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, &selected).unwrap();

        let cleanup =
            cleanup_uninstall_locations(&selected, InstallScope::User, &[], false).unwrap();

        assert_eq!(
            cleanup,
            UninstallCleanupResult {
                removed_count: 1,
                had_failures: false,
            }
        );
        assert!(
            fs::symlink_metadata(&selected)
                .unwrap()
                .file_type()
                .is_symlink(),
            "non-elevated uninstall should preserve the selected settings symlink"
        );
        let cleaned: Value = serde_json::from_str(&fs::read_to_string(&target).unwrap()).unwrap();
        assert_eq!(cleaned["permissions"]["defaultMode"], "plan");
        assert!(cleaned.to_string().contains("customer-session-start"));
        assert!(!cleaned.to_string().contains("sondera hook claude"));
        let backup_count = fs::read_dir(selected.parent().unwrap())
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("settings.backup.")
            })
            .count();
        assert_eq!(backup_count, 1);
    }

    #[test]
    fn test_uninstall_cleanup_respects_privilege_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let selected = temp.path().join("user/settings.json");
        let project = temp.path().join("project/settings.local.json");
        let managed = temp.path().join("managed/managed-settings.json");
        let fixture = json!({
            "allowManagedHooksOnly": true,
            "permissions": {"defaultMode": "plan"},
            "hooks": {
                "SessionStart": [{
                    "hooks": [
                        {
                            "type": "command",
                            "command": "/usr/local/bin/sondera hook claude session-start"
                        },
                        {
                            "type": "command",
                            "command": "/usr/local/bin/customer-session-start"
                        }
                    ]
                }]
            }
        });
        for path in [&selected, &project, &managed] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, fixture.to_string()).unwrap();
        }
        let locations = vec![
            ClaudeSettingsLocation {
                label: "user settings".to_string(),
                path: selected.clone(),
                read_only: false,
            },
            ClaudeSettingsLocation {
                label: "project settings".to_string(),
                path: project.clone(),
                read_only: false,
            },
            ClaudeSettingsLocation {
                label: "enterprise managed settings".to_string(),
                path: managed.clone(),
                read_only: true,
            },
        ];

        assert_eq!(
            cleanup_uninstall_locations(&selected, InstallScope::User, &locations, false).unwrap(),
            UninstallCleanupResult {
                removed_count: 1,
                had_failures: false,
            }
        );
        assert!(!settings_file_contains_managed_sondera_hooks(&selected).unwrap());
        assert!(settings_file_contains_managed_sondera_hooks(&project).unwrap());
        assert!(settings_file_contains_managed_sondera_hooks(&managed).unwrap());

        assert_eq!(
            cleanup_uninstall_locations(&selected, InstallScope::User, &locations, true).unwrap(),
            UninstallCleanupResult {
                removed_count: 2,
                had_failures: false,
            }
        );
        for path in [&selected, &project, &managed] {
            assert!(!settings_file_contains_managed_sondera_hooks(path).unwrap());
            let cleaned: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
            assert_eq!(cleaned["allowManagedHooksOnly"], true);
            assert_eq!(cleaned["permissions"]["defaultMode"], "plan");
            assert!(cleaned.to_string().contains("customer-session-start"));
        }
    }

    #[test]
    fn test_missing_subcommands_from_help() {
        let help = "Commands:\n  pre-tool-use\n  subagent-start\n  post-tool-use-failure";
        let required = vec![
            "pre-tool-use",
            "subagent-start",
            "post-tool-use-failure",
            "session-end",
        ];

        let missing = missing_subcommands(help, &required);
        assert_eq!(missing, vec!["session-end".to_string()]);
    }

    #[test]
    fn test_required_subcommands_include_runtime_critical_hooks() {
        let required = required_hook_subcommands();
        assert!(required.contains(&"post-tool-use-failure"));
        assert!(required.contains(&"subagent-start"));
        assert!(
            !required.contains(&"worktree-create"),
            "retired hooks should be cleaned up but not required from the binary"
        );
    }

    #[test]
    fn test_merge_managed_sondera_hooks_prepends_and_preserves_third_party() {
        let mut settings = serde_json::from_value::<Map<String, Value>>(json!({
            "env": {"EXISTING": "kept"},
            "hooks": {
                "PostToolUse": [{
                    "matcher": "*",
                    "hooks": [{
                        "type": "command",
                        "command": "/usr/local/bin/custom-post-tool"
                    }]
                }],
                "CustomEvent": [{
                    "hooks": [{
                        "type": "command",
                        "command": "/usr/local/bin/custom-event"
                    }]
                }]
            }
        }))
        .unwrap();

        merge_managed_sondera_hooks(
            &mut settings,
            generate_hooks_config(
                &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                    "/opt/bin/sondera",
                )),
                false,
            ),
        );

        assert_eq!(settings["env"]["EXISTING"], "kept");
        let hooks = settings.get("hooks").and_then(Value::as_object).unwrap();
        assert!(hooks.contains_key("CustomEvent"));

        let post_tool_use = hooks.get("PostToolUse").and_then(Value::as_array).unwrap();
        assert_eq!(post_tool_use.len(), 2);
        assert!(
            post_tool_use[0]
                .to_string()
                .contains("/opt/bin/sondera hook claude post-tool-use")
        );
        assert!(
            post_tool_use[1]
                .to_string()
                .contains("/usr/local/bin/custom-post-tool")
        );
    }

    #[test]
    fn test_merge_managed_sondera_hooks_is_idempotent() {
        let hooks_config = generate_hooks_config(
            &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                "/opt/bin/sondera",
            )),
            false,
        );
        let mut settings = Map::new();

        merge_managed_sondera_hooks(&mut settings, hooks_config.clone());
        let after_first = serde_json::to_string(&settings).unwrap();

        merge_managed_sondera_hooks(&mut settings, hooks_config);
        let after_second = serde_json::to_string(&settings).unwrap();

        assert_eq!(after_first, after_second);

        let hooks = settings.get("hooks").and_then(Value::as_object).unwrap();
        for (event_name, _) in HOOK_EVENTS {
            let rules = hooks
                .get(*event_name)
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("missing event {event_name}"));
            let sondera_count = rules
                .iter()
                .filter(|rule| rule.to_string().contains("/opt/bin/sondera hook claude"))
                .count();
            assert_eq!(
                sondera_count, 1,
                "event {event_name} should have one managed Sondera rule"
            );
        }
    }

    #[test]
    fn test_merge_managed_sondera_hooks_replaces_stale_sondera_entries() {
        let mut settings = serde_json::from_value::<Map<String, Value>>(json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [{
                            "type": "command",
                            "command": "/old/bin/sondera hook claude pre-tool-use"
                        }]
                    },
                    {
                        "matcher": "*",
                        "hooks": [{
                            "type": "command",
                            "command": "/usr/local/bin/custom-pre-tool"
                        }]
                    }
                ]
            }
        }))
        .unwrap();

        merge_managed_sondera_hooks(
            &mut settings,
            generate_hooks_config(
                &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                    "/new/bin/sondera",
                )),
                false,
            ),
        );

        let hooks = settings.get("hooks").and_then(Value::as_object).unwrap();
        let pre_tool_use = hooks.get("PreToolUse").and_then(Value::as_array).unwrap();

        assert_eq!(pre_tool_use.len(), 2);
        let merged_text = Value::Array(pre_tool_use.clone()).to_string();
        assert!(merged_text.contains("/new/bin/sondera hook claude pre-tool-use"));
        assert!(merged_text.contains("/usr/local/bin/custom-pre-tool"));
        assert!(!merged_text.contains("/old/bin/sondera"));
    }

    #[test]
    fn test_merge_managed_sondera_hooks_removes_retired_worktree_create() {
        let mut settings = serde_json::from_value::<Map<String, Value>>(json!({
            "hooks": {
                "WorktreeCreate": [{
                    "hooks": [{
                        "type": "command",
                        "command": "/old/bin/sondera hook claude --verbose worktree-create"
                    }]
                }],
                "WorktreeRemove": [{
                    "hooks": [{
                        "type": "command",
                        "command": "/old/bin/sondera hook claude --verbose worktree-remove"
                    }]
                }]
            }
        }))
        .unwrap();

        merge_managed_sondera_hooks(
            &mut settings,
            generate_hooks_config(
                &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                    "/new/bin/sondera",
                )),
                false,
            ),
        );

        let hooks = settings.get("hooks").and_then(Value::as_object).unwrap();
        assert!(
            !hooks.contains_key("WorktreeCreate"),
            "retired WorktreeCreate hook must be removed during upgrade"
        );
        assert!(
            hooks["WorktreeRemove"]
                .to_string()
                .contains("/new/bin/sondera hook claude worktree-remove"),
            "active WorktreeRemove hook should still be managed"
        );
        assert!(
            !hooks["WorktreeRemove"]
                .to_string()
                .contains("/old/bin/sondera")
        );
    }

    #[test]
    fn test_cleanup_retired_managed_hooks_at_removes_only_retired_hooks() {
        let temp = tempfile::tempdir().unwrap();
        let settings_path = temp.path().join("settings.json");
        fs::write(
            &settings_path,
            json!({
                "hooks": {
                    "WorktreeCreate": [{
                        "hooks": [{
                            "type": "command",
                            "command": "/old/bin/sondera hook claude --verbose worktree-create"
                        }]
                    }],
                    "WorktreeRemove": [{
                        "hooks": [{
                            "type": "command",
                            "command": "/old/bin/sondera hook claude --verbose worktree-remove"
                        }]
                    }],
                    "CustomEvent": [{
                        "hooks": [{
                            "type": "command",
                            "command": "some-tool --config=\"sondera hook claude worktree-create mode\""
                        }]
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();

        let cleanup = cleanup_retired_managed_hooks_at(&settings_path)
            .unwrap()
            .expect("retired hook should be removed");
        assert_eq!(cleanup.settings_path, settings_path);
        assert!(cleanup.backup_path.unwrap().exists());

        let settings: Value =
            serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
        let hooks = settings.get("hooks").and_then(Value::as_object).unwrap();
        assert!(!hooks.contains_key("WorktreeCreate"));
        assert!(
            hooks["WorktreeRemove"]
                .to_string()
                .contains("worktree-remove"),
            "active WorktreeRemove hook should be preserved"
        );
        assert!(
            hooks["CustomEvent"]
                .to_string()
                .contains("worktree-create mode"),
            "third-party commands that mention retired hooks as data should be preserved"
        );
    }

    #[test]
    fn test_contains_retired_managed_hooks_at_detects_stale_worktree_create() {
        let temp = tempfile::tempdir().unwrap();
        let settings_path = temp.path().join("managed-settings.json");
        fs::write(
            &settings_path,
            json!({
                "hooks": {
                    "WorktreeCreate": [{
                        "hooks": [{
                            "type": "command",
                            "command": "/usr/local/bin/sondera hook claude --verbose worktree-create"
                        }]
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();

        assert!(contains_retired_managed_hooks_at(&settings_path).unwrap());
    }

    #[test]
    fn test_merge_managed_sondera_hooks_handles_malformed_existing_events() {
        let mut settings = serde_json::from_value::<Map<String, Value>>(json!({
            "hooks": {
                "PreToolUse": {"malformed": true},
                "NotManagedBySondera": {"malformed": true}
            }
        }))
        .unwrap();

        merge_managed_sondera_hooks(
            &mut settings,
            generate_hooks_config(
                &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                    "/opt/bin/sondera",
                )),
                false,
            ),
        );

        let hooks = settings.get("hooks").and_then(Value::as_object).unwrap();
        assert!(
            hooks.get("PreToolUse").and_then(Value::as_array).is_some(),
            "managed malformed event should be replaced with a valid hook array"
        );
        assert_eq!(
            hooks.get("NotManagedBySondera"),
            Some(&json!({"malformed": true})),
            "unmanaged malformed event should be preserved"
        );
    }

    #[test]
    fn test_merge_managed_sondera_hooks_replaces_malformed_hooks_root() {
        let mut settings = serde_json::from_value::<Map<String, Value>>(json!({
            "hooks": "malformed",
            "permissions": {"allow": ["Bash(git status:*)"]}
        }))
        .unwrap();

        merge_managed_sondera_hooks(
            &mut settings,
            generate_hooks_config(
                &sondera_hooks::install::binary::ResolvedBinary::from_exe_path(PathBuf::from(
                    "/opt/bin/sondera",
                )),
                false,
            ),
        );

        assert_eq!(settings["permissions"]["allow"][0], "Bash(git status:*)");
        assert!(
            settings.get("hooks").and_then(Value::as_object).is_some(),
            "malformed hooks root should be replaced with managed Sondera hooks"
        );
    }

    #[test]
    fn test_remove_managed_sondera_hooks_preserves_non_sondera_entries() {
        let mut settings = serde_json::from_value::<Map<String, Value>>(json!({
            "hooks": {
                "SessionStart": [{
                    "hooks": [
                        {"type": "command", "command": "/opt/bin/sondera hook claude session-start"},
                        {"type": "command", "command": "/usr/local/bin/custom-hook"}
                    ]
                }],
                "Notification": [{
                    "hooks": [
                        {"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/scripts/sondera-hook.sh notification"}
                    ]
                }],
                "PreToolUse": [{
                    "hooks": [
                        {"type": "command", "command": "/opt/bin/sondera hook claude pre-tool-use"}
                    ]
                }]
            }
        }))
            .unwrap();

        assert!(remove_managed_sondera_hooks(&mut settings));

        let hooks = settings.get("hooks").and_then(Value::as_object).unwrap();
        let session_start = hooks
            .get("SessionStart")
            .and_then(Value::as_array)
            .unwrap()
            .first()
            .and_then(Value::as_object)
            .unwrap()
            .get("hooks")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(session_start.len(), 1);
        assert_eq!(
            session_start[0].get("command").and_then(Value::as_str),
            Some("/usr/local/bin/custom-hook")
        );
        // Both plugin-format and legacy binary-format hooks removed
        assert!(!hooks.contains_key("Notification"));
        assert!(!hooks.contains_key("PreToolUse"));
    }

    #[test]
    fn test_remove_managed_sondera_hooks_preserves_malformed_hooks_root() {
        let mut settings = serde_json::from_value::<Map<String, Value>>(json!({
            "hooks": "malformed",
            "permissions": {"allow": ["Bash(git status:*)"]}
        }))
        .unwrap();

        assert!(!remove_managed_sondera_hooks(&mut settings));
        assert_eq!(settings.get("hooks"), Some(&json!("malformed")));
        assert_eq!(settings["permissions"]["allow"][0], "Bash(git status:*)");
    }

    #[test]
    fn test_plugin_manifest_detection() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("sondera-plugin-test-{}", unique));
        let plugin_root = base.join("test-plugin-root");
        let manifest_path = plugin_root.join(".claude-plugin").join("plugin.json");
        fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        fs::write(
            &manifest_path,
            json!({
                "hooks": {
                    "SessionStart": [{
                        "hooks": [{
                            "type": "command",
                            "command": "${CLAUDE_PLUGIN_ROOT}/scripts/sondera-hook.sh session-start"
                        }]
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();

        assert!(plugin_manifest_has_sondera_hooks(&plugin_root));
        // SAFETY: test-only env mutation in a single-threaded test.
        unsafe {
            std::env::set_var(CLAUDE_PLUGIN_DIR_ENV_VAR, &plugin_root);
        }
        assert_eq!(resolve_plugin_root(&base), Some(plugin_root.clone()));
        // SAFETY: test-only env mutation in a single-threaded test.
        unsafe {
            std::env::remove_var(CLAUDE_PLUGIN_DIR_ENV_VAR);
        }
        assert_eq!(resolve_plugin_root(&base), None);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn test_should_dedupe_with_plugin_scope() {
        assert!(should_dedupe_with_plugin(InstallScope::Project));
        assert!(should_dedupe_with_plugin(InstallScope::Local));
        assert!(!should_dedupe_with_plugin(InstallScope::User));
    }

    #[test]
    fn shell_escapes_and_windows_paths_do_not_change_what_is_recognized() {
        // The tokenizer itself is tested in `sondera_hooks::install::command`;
        // what matters here is that its quoting rules leave our own hooks
        // recognizable and a third party's unrecognized.
        assert!(is_managed_sondera_hook_command(
            "/opt/Sondera\\ Bin/sondera hook claude session-end"
        ));
        assert!(is_managed_sondera_hook_command(
            "C:\\bin\\sondera.exe hook claude session-end"
        ));
        // A tool that merely quotes our command line is not our hook.
        assert!(!is_managed_sondera_hook_command(
            "some-tool --config=\\\"sondera hook claude session-end\\\""
        ));
    }

    #[test]
    fn test_managed_hook_command_matching_is_specific() {
        // Current umbrella format: `sondera hook claude <subcommand>`
        assert!(is_managed_sondera_hook_command(
            "/opt/bin/sondera hook claude session-end"
        ));
        // Windows current format
        assert!(is_managed_sondera_hook_command(
            "C:\\bin\\sondera.exe hook claude session-end"
        ));
        // Verbose current format
        assert!(is_managed_sondera_hook_command(
            "/opt/bin/sondera hook claude --verbose session-end"
        ));
        // Plugin shell script format
        assert!(is_managed_sondera_hook_command(
            "${CLAUDE_PLUGIN_ROOT}/scripts/sondera-hook.sh session-end"
        ));
        // Retired managed hooks must still be recognized so upgrades remove
        // stale config for events we no longer install.
        assert!(is_managed_sondera_hook_command(
            "/opt/bin/sondera hook claude --verbose worktree-create"
        ));
        assert!(is_managed_sondera_hook_command(
            "SONDERA_HOOK_DEBUG=1 /opt/bin/sondera hook claude --verbose worktree-create"
        ));
        assert!(is_managed_sondera_hook_command(
            "/opt/Sondera\\ Bin/sondera hook claude --verbose worktree-create"
        ));
        assert!(is_managed_sondera_hook_command(
            "\"/opt/Sondera Bin/sondera\" hook claude --verbose worktree-create"
        ));
        assert!(!is_managed_sondera_hook_command(
            "some-tool --config=\"sondera hook claude worktree-create mode\""
        ));
        assert!(!is_managed_sondera_hook_command(
            "/opt/bin/sondera hook claude --verbose worktree-create-extra"
        ));
        assert!(!is_managed_sondera_hook_command(
            "/opt/bin/sondera\\ hook claude --verbose worktree-create"
        ));
        assert!(!is_managed_sondera_hook_command(
            "/opt/bin/not-sondera hook claude --verbose worktree-create"
        ));
        // Another provider's hook in the same file is not ours.
        assert!(!is_managed_sondera_hook_command(
            "/opt/bin/sondera hook codex session-end"
        ));
        // Unknown subcommands should not match
        assert!(!is_managed_sondera_hook_command(
            "/opt/bin/sondera hook claude custom-event"
        ));
    }

    // -- Post-install auth logic --
}
