//! Install command for setting up Cursor hooks.
//!
//! Installs the Sondera hooks configuration into Cursor's hooks file at one of
//! two scopes:
//! - User scope: `~/.cursor/hooks.json` (applies to all projects)
//! - Project scope: `<project>/.cursor/hooks.json` (committed to git)

use std::env;
use std::path::PathBuf;

use serde_json::{Map, Value, json};
use sondera_hooks::error::{HookResultExt as _, Result};
use sondera_hooks::install::HookConfigInstaller;
use sondera_hooks::install::binary::{CommandShell, ResolvedBinary};

/// Human-facing agent name used in installer output.
const AGENT: &str = "Cursor";

/// Top-level key in `hooks.json` holding the event map this installer owns.
const HOOKS_KEY: &str = "hooks";

/// Cursor hook events, as `(hooks.json key, `sondera hook cursor` subcommand)`.
const HOOK_EVENTS: &[(&str, &str)] = &[
    // Session lifecycle
    ("sessionStart", "session-start"),
    ("sessionEnd", "session-end"),
    // Generic tool hooks (fire for all tools)
    ("preToolUse", "pre-tool-use"),
    ("postToolUse", "post-tool-use"),
    ("postToolUseFailure", "post-tool-use-failure"),
    // Subagents
    ("subagentStart", "subagent-start"),
    ("subagentStop", "subagent-stop"),
    // Shell execution
    ("beforeShellExecution", "before-shell-execution"),
    ("afterShellExecution", "after-shell-execution"),
    // MCP execution
    ("beforeMCPExecution", "before-mcp-execution"),
    ("afterMCPExecution", "after-mcp-execution"),
    // File access
    ("beforeReadFile", "before-read-file"),
    ("afterFileEdit", "after-file-edit"),
    // Prompt submission
    ("beforeSubmitPrompt", "before-submit-prompt"),
    // Agent responses
    ("afterAgentResponse", "after-agent-response"),
    ("afterAgentThought", "after-agent-thought"),
    // Compaction and stop
    ("preCompact", "pre-compact"),
    ("stop", "stop"),
    // Tab-specific
    ("beforeTabFileRead", "before-tab-file-read"),
    ("afterTabFileEdit", "after-tab-file-edit"),
    // App lifecycle
    ("workspaceOpen", "workspace-open"),
];

/// Scope for hooks installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// User-level hooks (`~/.cursor/hooks.json`).
    User,
    /// Project-level hooks (`.cursor/hooks.json`) — committed to git.
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

/// The `hooks.json` path for `scope`.
fn hooks_path(scope: InstallScope) -> Result<PathBuf> {
    let root = match scope {
        InstallScope::User => dirs::home_dir().context("Could not determine home directory")?,
        InstallScope::Project => {
            env::current_dir().context("Could not determine current directory")?
        }
    };
    Ok(root.join(".cursor").join("hooks.json"))
}

fn fail_closed_event(event: &str) -> bool {
    matches!(
        event,
        "preToolUse"
            | "subagentStart"
            | "beforeShellExecution"
            | "beforeMCPExecution"
            | "beforeReadFile"
            | "beforeSubmitPrompt"
            | "beforeTabFileRead"
    )
}

/// Generate the hooks configuration for every Cursor hook event.
fn generate_hooks_config(binary: &ResolvedBinary) -> Value {
    let binary_str = binary.render(CommandShell::Posix);
    let hooks: Map<String, Value> = HOOK_EVENTS
        .iter()
        .map(|(event, subcommand)| {
            let mut hook = json!({
                "command": format!("{binary_str} hook cursor --verbose {subcommand}")
            });
            if fail_closed_event(event) {
                hook["failClosed"] = json!(true);
            }
            ((*event).to_string(), Value::Array(vec![hook]))
        })
        .collect();
    Value::Object(hooks)
}

fn installer(scope: InstallScope) -> Result<HookConfigInstaller> {
    Ok(HookConfigInstaller::new(
        AGENT,
        hooks_path(scope)?,
        scope.to_string(),
    ))
}

/// Install hooks into the specified scope.
pub fn install_hooks(scope: InstallScope, _verbose: bool) -> Result<()> {
    installer(scope)?.install(|config, binary| {
        config.insert("version".to_string(), json!(1));
        config.insert(HOOKS_KEY.to_string(), generate_hooks_config(binary));
    })
}

/// Uninstall hooks from the specified scope.
pub fn uninstall_hooks(scope: InstallScope) -> Result<()> {
    installer(scope)?.uninstall(|config| config.remove(HOOKS_KEY).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Value {
        generate_hooks_config(&ResolvedBinary::from_exe_path(PathBuf::from(
            "/usr/local/bin/sondera",
        )))
    }

    #[test]
    fn covers_every_cursor_hook_event() {
        let config = config();
        for (event, _) in HOOK_EVENTS {
            assert!(config.get(event).is_some(), "missing {event}");
        }
        assert_eq!(config.as_object().unwrap().len(), HOOK_EVENTS.len());
    }

    #[test]
    fn renders_the_hook_command_for_each_event() {
        assert_eq!(
            config()["sessionStart"][0]["command"],
            "/usr/local/bin/sondera hook cursor --verbose session-start"
        );
        assert_eq!(
            config()["workspaceOpen"][0]["command"],
            "/usr/local/bin/sondera hook cursor --verbose workspace-open"
        );
    }

    #[test]
    fn does_not_filter_generic_tool_hooks_with_a_matcher() {
        assert!(config()["preToolUse"][0].get("matcher").is_none());
    }

    #[test]
    fn preventive_hooks_enable_host_level_fail_closed_behavior() {
        let config = config();
        for event in [
            "preToolUse",
            "subagentStart",
            "beforeShellExecution",
            "beforeMCPExecution",
            "beforeReadFile",
            "beforeSubmitPrompt",
            "beforeTabFileRead",
        ] {
            assert_eq!(config[event][0]["failClosed"], true, "{event}");
        }
        assert!(config["postToolUse"][0].get("failClosed").is_none());
    }

    #[test]
    fn scopes_resolve_to_the_cursor_hooks_file() {
        assert!(
            hooks_path(InstallScope::Project)
                .unwrap()
                .ends_with(".cursor/hooks.json")
        );
        assert!(
            hooks_path(InstallScope::User)
                .unwrap()
                .ends_with(".cursor/hooks.json")
        );
    }
}
