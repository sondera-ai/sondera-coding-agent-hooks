//! Install command for setting up Antigravity CLI (`agy`) hooks.
//!
//! Verified against the live `agy` 1.0.6 binary and the official hooks docs.
//! Antigravity's `hooks.json` is **not** the Gemini-CLI format — it maps a
//! *named hook* to its per-event configuration:
//!
//! ```jsonc
//! {
//!   "sondera": {
//!     "PreToolUse":  [ { "matcher": "*", "hooks": [ { "type": "command", "command": "…", "timeout": 30 } ] } ],
//!     "PostToolUse": [ { "matcher": "*", "hooks": [ { … } ] } ],
//!     "PreInvocation":  [ { "type": "command", "command": "…", "timeout": 30 } ],
//!     "PostInvocation": [ { … } ],
//!     "Stop":           [ { … } ]
//!   }
//! }
//! ```
//!
//! Note the asymmetry from the docs: `PreToolUse`/`PostToolUse` take an array of
//! `{matcher, hooks:[…]}` groups (the matcher targets a tool name), while
//! `PreInvocation`/`PostInvocation`/`Stop` take a flat array of handlers
//! directly (the matcher is ignored). `timeout` is in **seconds** (default 30).
//!
//! Discovery (per the docs): `hooks.json` lives in a customization directory —
//! `~/.gemini/config/` (global/user) or `.agents/` in the workspace root
//! (workspace-scoped, takes precedence).
//!
//! Reference: <https://antigravity.google/docs/hooks>

use std::env;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sondera_hooks::error::{HookResultExt as _, Result};
use sondera_hooks::install::HookConfigInstaller;
use sondera_hooks::install::binary::{CommandShell, ResolvedBinary};

/// Human-facing agent name used in installer output.
const AGENT: &str = "Antigravity CLI";

/// Top-level named-hook key this installer owns. Install overwrites it;
/// uninstall removes it. Unrelated named hooks in the file are preserved.
const HOOK_NAME: &str = "sondera";

/// Per-event hook timeout in seconds (Antigravity unit; doc default is 30).
const HOOK_TIMEOUT_SECS: u64 = 30;

/// Events taking `[{matcher, hooks:[handler]}]` groups.
const TOOL_EVENTS: &[(&str, &str)] = &[
    ("PreToolUse", "pre-tool-use"),
    ("PostToolUse", "post-tool-use"),
];

/// Events taking a flat `[handler]` array.
const FLAT_EVENTS: &[(&str, &str)] = &[
    ("PreInvocation", "pre-invocation"),
    ("PostInvocation", "post-invocation"),
    ("Stop", "stop"),
];

/// Scope for Antigravity hooks installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// Global user-level hooks (`~/.gemini/config/hooks.json`).
    User,
    /// Workspace hooks for the active project (`<cwd>/.agents/hooks.json`),
    /// which take precedence over the global file.
    Workspace,
}

impl std::fmt::Display for InstallScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallScope::User => write!(f, "user (~/.gemini/config/hooks.json)"),
            InstallScope::Workspace => write!(f, "workspace (.agents/hooks.json)"),
        }
    }
}

/// The user-scope `hooks.json` path under `home`.
fn user_hooks_path_for_home(home: &Path) -> PathBuf {
    home.join(".gemini").join("config").join("hooks.json")
}

/// The `hooks.json` path for `scope`.
fn hooks_path(scope: InstallScope) -> Result<PathBuf> {
    match scope {
        InstallScope::User => {
            let home = dirs::home_dir().context("Could not determine home directory")?;
            Ok(user_hooks_path_for_home(&home))
        }
        InstallScope::Workspace => Ok(env::current_dir()
            .context("Could not determine current directory")?
            .join(".agents")
            .join("hooks.json")),
    }
}

/// Build a single command handler object: `{type, command, timeout}`.
fn handler(binary_str: &str, subcommand: &str) -> Value {
    json!({
        "type": "command",
        "command": format!("{binary_str} hook antigravity --verbose {subcommand}"),
        "timeout": HOOK_TIMEOUT_SECS
    })
}

/// Build the `"sondera"` named-hook configuration covering every event.
fn generate_sondera_hook(binary: &ResolvedBinary) -> Value {
    let binary_str = binary.render(CommandShell::Posix);
    let mut events = serde_json::Map::new();

    for (event, subcommand) in TOOL_EVENTS {
        events.insert(
            (*event).to_string(),
            json!([{ "matcher": "*", "hooks": [handler(&binary_str, subcommand)] }]),
        );
    }
    for (event, subcommand) in FLAT_EVENTS {
        events.insert(
            (*event).to_string(),
            json!([handler(&binary_str, subcommand)]),
        );
    }

    Value::Object(events)
}

fn installer(scope: InstallScope) -> Result<HookConfigInstaller> {
    Ok(
        HookConfigInstaller::new(AGENT, hooks_path(scope)?, scope.to_string())
            // The file exists only to hold named hooks, so once ours is the
            // last one left there is nothing to keep.
            .remove_when(Map::is_empty),
    )
}

/// Install Sondera Antigravity hooks for the given scope.
///
/// Overwrites our own `"sondera"` named hook; any other named hooks already in
/// the file are preserved.
pub fn install_hooks(scope: InstallScope, _verbose: bool) -> Result<()> {
    installer(scope)?.install(|config, binary| {
        config.insert(HOOK_NAME.to_string(), generate_sondera_hook(binary));
    })
}

/// Uninstall Sondera Antigravity hooks from the given scope.
///
/// Removes only the `"sondera"` named hook; deletes the file if nothing else
/// remains, otherwise writes the other named hooks back.
pub fn uninstall_hooks(scope: InstallScope) -> Result<()> {
    installer(scope)?.uninstall(|config| config.remove(HOOK_NAME).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook() -> Value {
        generate_sondera_hook(&ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        )))
    }

    #[test]
    fn user_scope_path_targets_antigravity_user_config() {
        assert_eq!(
            user_hooks_path_for_home(&PathBuf::from("/Users/alice")),
            PathBuf::from("/Users/alice/.gemini/config/hooks.json")
        );
    }

    #[test]
    fn tool_events_use_the_matcher_group_shape() {
        let hook = hook();
        for (event, _) in TOOL_EVENTS {
            let group = &hook[event][0];
            assert_eq!(group["matcher"], "*", "{event} matcher");
            assert_eq!(group["hooks"][0]["type"], "command", "{event} type");
            assert!(group["hooks"][0]["command"].is_string(), "{event} command");
            assert_eq!(group["hooks"][0]["timeout"], HOOK_TIMEOUT_SECS);
        }
    }

    #[test]
    fn lifecycle_events_use_the_flat_handler_shape() {
        let hook = hook();
        for (event, _) in FLAT_EVENTS {
            let handler = &hook[event][0];
            assert_eq!(handler["type"], "command", "{event} type");
            assert!(handler.get("matcher").is_none(), "{event} should be flat");
            assert!(handler["command"].is_string(), "{event} command");
        }
    }

    #[test]
    fn commands_route_through_the_antigravity_subcommand() {
        let hook = hook();
        assert_eq!(
            hook["PreToolUse"][0]["hooks"][0]["command"],
            "/usr/local/bin/sondera hook antigravity --verbose pre-tool-use"
        );
        assert_eq!(
            hook["Stop"][0]["command"],
            "/usr/local/bin/sondera hook antigravity --verbose stop"
        );
    }
}
