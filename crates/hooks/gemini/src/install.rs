//! Install command for setting up Gemini CLI hooks.
//!
//! Installs the Sondera hooks configuration into Gemini CLI settings files at
//! one of three scopes:
//! - User scope: `~/.gemini/settings.json` (applies to all projects)
//! - Project scope: `.gemini/settings.json` (committed to git)
//! - Local project scope: `.gemini/settings.local.json` (not committed to git)
//!
//! Reference: <https://geminicli.com/docs/hooks/>

use std::env;
use std::path::PathBuf;

use serde_json::{Map, Value, json};
use sondera_hooks::error::{HookResultExt as _, Result};
use sondera_hooks::install::HookConfigInstaller;
use sondera_hooks::install::binary::{CommandShell, ResolvedBinary};

/// Human-facing agent name used in installer output.
const AGENT: &str = "Gemini CLI";

/// Key in `settings.json` holding the hook map this installer owns.
const HOOKS_KEY: &str = "hooks";

/// Per-hook timeout in milliseconds (Gemini CLI unit).
const HOOK_TIMEOUT_MS: u64 = 30_000;

/// Gemini CLI hook events: `(settings key, subcommand, description)`.
const HOOK_EVENTS: &[(&str, &str, &str)] = &[
    (
        "SessionStart",
        "session-start",
        "Initialize Sondera trajectory tracking",
    ),
    (
        "SessionEnd",
        "session-end",
        "Finalize Sondera session and cleanup",
    ),
    (
        "BeforeAgent",
        "before-agent",
        "Validate prompts before agent processing",
    ),
    (
        "AfterAgent",
        "after-agent",
        "Audit agent responses and handle retries",
    ),
    (
        "BeforeModel",
        "before-model",
        "Control LLM requests before submission",
    ),
    (
        "AfterModel",
        "after-model",
        "Filter and redact LLM responses",
    ),
    (
        "BeforeToolSelection",
        "before-tool-selection",
        "Filter available tools based on policy",
    ),
    (
        "BeforeTool",
        "before-tool",
        "Validate tool invocations and enforce security",
    ),
    (
        "AfterTool",
        "after-tool",
        "Audit tool results and inject context",
    ),
    (
        "PreCompress",
        "pre-compress",
        "Handle context compression notifications",
    ),
    (
        "Notification",
        "notification",
        "Handle system notifications",
    ),
];

/// Scope for hooks installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// User-level settings (`~/.gemini/settings.json`).
    User,
    /// Project-level settings (`.gemini/settings.json`) — committed to git.
    Project,
    /// Local project settings (`.gemini/settings.local.json`) — not committed.
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

/// The settings file path for `scope`.
fn settings_path(scope: InstallScope) -> Result<PathBuf> {
    let (root, file) = match scope {
        InstallScope::User => (
            dirs::home_dir().context("Could not determine home directory")?,
            "settings.json",
        ),
        InstallScope::Project => (
            env::current_dir().context("Could not determine current directory")?,
            "settings.json",
        ),
        InstallScope::Local => (
            env::current_dir().context("Could not determine current directory")?,
            "settings.local.json",
        ),
    };
    Ok(root.join(".gemini").join(file))
}

/// Generate the hooks configuration for every Gemini CLI hook event.
///
/// Gemini CLI nests each event under a `matcher` group whose `hooks` array
/// holds `{type, name, description, command, timeout}` entries.
fn generate_hooks_config(binary: &ResolvedBinary) -> Value {
    let binary_str = binary.render(CommandShell::Posix);
    let hooks: Map<String, Value> = HOOK_EVENTS
        .iter()
        .map(|(event, subcommand, description)| {
            (
                (*event).to_string(),
                json!([{
                    "matcher": "*",
                    "hooks": [{
                        "type": "command",
                        "name": format!("sondera-{subcommand}"),
                        "description": description,
                        "command": format!("{binary_str} hook gemini --verbose {subcommand}"),
                        "timeout": HOOK_TIMEOUT_MS
                    }]
                }]),
            )
        })
        .collect();
    Value::Object(hooks)
}

fn installer(scope: InstallScope) -> Result<HookConfigInstaller> {
    Ok(
        HookConfigInstaller::new(AGENT, settings_path(scope)?, scope.to_string()).with_next_steps(
            [
                "View hooks with the /hooks panel",
                "Enable/disable all: /hooks enable-all or /hooks disable-all",
                "Toggle individually: /hooks enable <name> or /hooks disable <name>",
            ],
        ),
    )
}

/// Install hooks into the specified scope.
pub fn install_hooks(scope: InstallScope, _verbose: bool) -> Result<()> {
    installer(scope)?.install(|config, binary| {
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
    fn covers_every_gemini_hook_event() {
        let config = config();
        for (event, _, _) in HOOK_EVENTS {
            assert!(config.get(event).is_some(), "missing {event}");
        }
        assert_eq!(config.as_object().unwrap().len(), HOOK_EVENTS.len());
    }

    #[test]
    fn renders_the_hook_command_with_verbose_logging() {
        assert_eq!(
            config()["BeforeTool"][0]["hooks"][0]["command"],
            "/usr/local/bin/sondera hook gemini --verbose before-tool"
        );
    }

    #[test]
    fn matches_the_gemini_cli_hook_structure() {
        let config = config();
        let session_start = &config["SessionStart"][0];
        assert_eq!(session_start["matcher"], "*");
        assert!(session_start["hooks"].is_array());

        let hook = &session_start["hooks"][0];
        assert_eq!(hook["type"], "command");
        assert!(hook["name"].as_str().unwrap().starts_with("sondera-"));
        assert!(hook["description"].is_string());
        assert_eq!(hook["timeout"], 30_000);
    }

    #[test]
    fn local_scope_targets_the_uncommitted_settings_file() {
        assert!(
            settings_path(InstallScope::Local)
                .unwrap()
                .ends_with(".gemini/settings.local.json")
        );
        assert!(
            settings_path(InstallScope::Project)
                .unwrap()
                .ends_with(".gemini/settings.json")
        );
    }
}
