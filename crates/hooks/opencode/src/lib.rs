//! Sondera hook adapter for OpenCode.
//!
//! OpenCode is reached two ways, and they use different response shapes:
//!
//! - **Direct CLI hooks** — one subcommand per event, reading the event JSON on
//!   stdin and writing the minimal allow/deny/context
//!   [`DecisionEnvelope`](sondera_hooks::response::DecisionEnvelope), the same
//!   envelope the OpenHands adapter emits.
//! - **Local plugin** — `install` / `uninstall` manage a project plugin that
//!   invokes this adapter for typed hooks and event-bus observations.
//!
//! Adjudication runs through [`sondera_hooks::runner::resolve_hook`], so every
//! failure — unreachable harness, malformed event, panic, budget overrun —
//! resolves to a degraded response rather than a bare non-zero exit. Preventive
//! events fail closed.
//!
//! Reference: <https://opencode.ai/docs/plugins/>

pub mod sidecar;

use clap::{Args, Subcommand};
use serde_json::Value;
use sondera_harness_client::connect_harness_for_hook_agent_id;
use sondera_hooks::adjudication::fail_closed_reason;
// OpenCode's direct CLI hook mode consumes the same minimal allow/deny/context
// JSON envelope as the existing OpenHands hook path. The sidecar plugin path
// uses `SidecarResponse` instead.
use sidecar::SidecarDecision;
use sondera_hooks::error::{HookError, HookResultExt as _, Result};
use sondera_hooks::install::binary::{CommandShell, ResolvedBinary, find_sondera_binary};
use sondera_hooks::response::DecisionEnvelope as HookResponse;
use sondera_hooks::runner::resolve_hook;
use sondera_hooks::{flush_output, output_response};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

pub const OPENCODE_PROVIDER: &str = "opencode";
pub const OPENCODE_PLATFORM: &str = "opencode-bun";
const LEGACY_PLUGIN_PACKAGE: &str = "@sondera/opencode-plugin";
const PLUGIN_RELATIVE_PATH: &str = ".opencode/plugins/sondera.js";

#[derive(Args, Debug)]
pub struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Install,
    Uninstall,
    SessionCreated,
    SessionUpdated,
    SessionDeleted,
    SessionIdle,
    SessionError,
    ChatMessage,
    PermissionAsk,
    ToolExecuteBefore,
    ToolExecuteAfter,
    Event,
}

impl Commands {
    fn event_kind(&self) -> Option<&'static str> {
        match self {
            Self::Install | Self::Uninstall => None,
            Self::SessionCreated => Some("session.created"),
            Self::SessionUpdated => Some("session.updated"),
            Self::SessionDeleted => Some("session.deleted"),
            Self::SessionIdle => Some("session.idle"),
            Self::SessionError => Some("session.error"),
            Self::ChatMessage => Some("chat.message"),
            Self::PermissionAsk => Some("permission.ask"),
            Self::ToolExecuteBefore => Some("tool.execute.before"),
            Self::ToolExecuteAfter => Some("tool.execute.after"),
            Self::Event => None,
        }
    }

    fn is_adjudication(&self) -> bool {
        matches!(self, Self::ToolExecuteBefore | Self::PermissionAsk)
    }
}

/// Fail closed for adjudication events (`tool.execute.before`, `permission.ask`)
/// when the harness is unavailable, the sidecar RPC errors, or the hook times
/// out; observation events degrade to a passthrough.
fn degraded_response(command: &Commands, error: &HookError) -> HookResponse {
    let reason = fail_closed_reason(error);
    if command.is_adjudication() {
        HookResponse::deny(reason)
    } else {
        HookResponse::ok()
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Install => return install_plugin(&std::env::current_dir()?),
        Commands::Uninstall => return uninstall_plugin(&std::env::current_dir()?),
        _ => {}
    }

    let command = cli.command;
    let response = resolve_hook(
        command,
        degraded_response,
        || async {
            let agent_id = sondera_hooks::agent_id(OPENCODE_PROVIDER);
            let harness = connect_harness_for_hook_agent_id(&agent_id, OPENCODE_PROVIDER).await?;
            Ok::<_, HookError>(harness)
        },
        |harness, command, raw| async move {
            let (kind, payload) = if let Some(kind) = command.event_kind() {
                (kind.to_string(), raw)
            } else {
                let kind = raw
                    .get("kind")
                    .and_then(Value::as_str)
                    .filter(|kind| !kind.trim().is_empty())
                    .ok_or_else(|| HookError::message("OpenCode event kind is required"))?
                    .to_string();
                let payload = raw.get("payload").cloned().unwrap_or(Value::Null);
                (kind, payload)
            };
            let request = sidecar::request_from_opencode_event(&kind, payload);
            // Direct CLI hook mode is one event per process, so there is
            // intentionally no cross-invocation session cache here. The sidecar
            // process owns that.
            let mut state = sidecar::OpenCodeSidecarState::default();
            // A sidecar RPC/decode error raised after a successful connect
            // propagates here and is mapped to `degraded` (fail closed for
            // adjudication events) by `resolve_hook`.
            let sidecar = sidecar::handle_sidecar_request(&harness, &mut state, request).await?;
            let response = match sidecar.decision {
                SidecarDecision::Allow => match sidecar.additional_context {
                    Some(context) => HookResponse::additional_context(context),
                    None => HookResponse::ok(),
                },
                SidecarDecision::Deny | SidecarDecision::Escalate => HookResponse::deny(
                    sidecar
                        .reason
                        .unwrap_or_else(|| "Tool use blocked by Sondera policy".to_string()),
                ),
            };
            Ok::<_, HookError>(response)
        },
    )
    .await;

    // OpenCode enforces a block via exit code 2 with the decision JSON on stdout.
    let denied = response.is_deny();
    output_response(response)?;
    flush_output();
    if denied {
        std::process::exit(2);
    }
    Ok(())
}

pub fn install_plugin(project_root: &Path) -> Result<()> {
    let binary = find_sondera_binary()?;
    install_plugin_with_binary(project_root, &binary)
}

fn install_plugin_with_binary(project_root: &Path, binary: &ResolvedBinary) -> Result<()> {
    let config_path = project_root.join("opencode.json");
    let mut config = read_json_object(&config_path)?;
    let plugin_path = project_root.join(PLUGIN_RELATIVE_PATH);
    if let Some(parent) = plugin_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if plugin_path.is_symlink() {
        return Err(HookError::message(format!(
            "refusing to overwrite symlink at {}",
            plugin_path.display()
        )));
    }
    fs::write(&plugin_path, generated_plugin(binary)?)
        .with_context(|| format!("failed to write {}", plugin_path.display()))?;

    remove_plugin(&mut config, LEGACY_PLUGIN_PACKAGE);
    persist_optional_config(&config_path, &config)
}

pub fn uninstall_plugin(project_root: &Path) -> Result<()> {
    let plugin_path = project_root.join(PLUGIN_RELATIVE_PATH);
    match fs::remove_file(&plugin_path) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("failed to remove {}", plugin_path.display()));
        }
    }

    let config_path = project_root.join("opencode.json");
    let mut config = read_json_object(&config_path)?;
    remove_plugin(&mut config, LEGACY_PLUGIN_PACKAGE);
    persist_optional_config(&config_path, &config)
}

fn persist_optional_config(path: &Path, config: &serde_json::Map<String, Value>) -> Result<()> {
    if !config.is_empty() {
        return write_json_object(path, config).context("failed to write OpenCode plugin config");
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove empty {}", path.display())),
    }
}

fn generated_plugin(binary: &ResolvedBinary) -> Result<String> {
    let command = |subcommand: &str| {
        serde_json::to_string(&format!(
            "{} hook opencode {subcommand}",
            binary.render(CommandShell::Posix)
        ))
    };
    let mut plugin = OPENCODE_PLUGIN_TEMPLATE.to_string();
    for (placeholder, subcommand) in [
        ("__CHAT_MESSAGE__", "chat-message"),
        ("__PERMISSION_ASK__", "permission-ask"),
        ("__TOOL_BEFORE__", "tool-execute-before"),
        ("__TOOL_AFTER__", "tool-execute-after"),
        ("__EVENT__", "event"),
    ] {
        plugin = plugin.replace(placeholder, &command(subcommand)?);
    }
    Ok(plugin)
}

const OPENCODE_PLUGIN_TEMPLATE: &str = r#"import { $ } from "bun"

const CHAT_MESSAGE = __CHAT_MESSAGE__
const PERMISSION_ASK = __PERMISSION_ASK__
const TOOL_BEFORE = __TOOL_BEFORE__
const TOOL_AFTER = __TOOL_AFTER__
const EVENT = __EVENT__
const DIRECT_EVENT_TYPES = new Set(["tool.execute.before", "tool.execute.after"])

async function invoke(command, payload) {
  const result = await $`${{ raw: command }}`
    .stdin(JSON.stringify(payload))
    .quiet()
    .nothrow()
  let response = {}
  try {
    response = JSON.parse(result.stdout.toString() || "{}")
  } catch {
    response = {}
  }
  if (result.exitCode !== 0 && response.decision !== "deny") {
    response = {
      decision: "deny",
      reason: result.stderr.toString().trim() || "Sondera hook failed closed",
    }
  }
  return response
}

export const Sondera = async () => ({
  "chat.message": async (input, output) => {
    const content = output.parts
      .filter((part) => part.type === "text")
      .map((part) => part.text)
      .join("")
    await invoke(CHAT_MESSAGE, { ...input, ...output, content })
  },
  "permission.ask": async (input, output) => {
    const response = await invoke(PERMISSION_ASK, { ...input, ...output })
    if (response.decision === "deny") output.status = "deny"
  },
  "tool.execute.before": async (input, output) => {
    const response = await invoke(TOOL_BEFORE, { ...input, ...output, args: output.args })
    if (response.decision === "deny") {
      throw new Error(response.reason || "Tool execution blocked by Sondera policy")
    }
  },
  "tool.execute.after": async (input, output) => {
    await invoke(TOOL_AFTER, { ...input, ...output })
  },
  event: async ({ event }) => {
    if (DIRECT_EVENT_TYPES.has(event.type)) return
    await invoke(EVENT, { kind: event.type, payload: event.properties ?? event })
  },
})
"#;

fn read_json_object(path: &Path) -> Result<serde_json::Map<String, Value>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(serde_json::Map::new()),
        Err(err) => return Err(err).with_context(|| format!("failed to read {}", path.display())),
    };
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    value
        .as_object()
        .cloned()
        .with_context(|| format!("{} must contain a JSON object", path.display()))
}

fn write_json_object(path: &Path, config: &serde_json::Map<String, Value>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.is_symlink() {
        return Err(HookError::message(format!(
            "refusing to overwrite symlink at {}",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temp file for {}", path.display()))?;
    serde_json::to_writer_pretty(&mut temp, config)?;
    temp.persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("failed to persist {}", path.display()))?;
    Ok(())
}

fn remove_plugin(config: &mut serde_json::Map<String, Value>, package: &str) {
    let remove_plugin_key = match config.get_mut("plugin") {
        Some(Value::Array(items)) => {
            items.retain(|item| item.as_str() != Some(package));
            items.is_empty()
        }
        Some(Value::String(existing)) if existing == package => true,
        _ => false,
    };
    if remove_plugin_key {
        config.remove("plugin");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_hooks::runner::assert_fail_closed_matrix;

    fn test_binary() -> ResolvedBinary {
        ResolvedBinary::from_exe_path(std::path::PathBuf::from("/opt/sondera"))
    }

    fn all_hook_commands() -> Vec<Commands> {
        vec![
            Commands::SessionCreated,
            Commands::SessionUpdated,
            Commands::SessionDeleted,
            Commands::SessionIdle,
            Commands::SessionError,
            Commands::ChatMessage,
            Commands::PermissionAsk,
            Commands::ToolExecuteBefore,
            Commands::ToolExecuteAfter,
            Commands::Event,
        ]
    }

    #[test]
    fn generated_plugin_quotes_binary_paths_with_spaces() {
        let binary =
            ResolvedBinary::from_exe_path(std::path::PathBuf::from("/opt/Sondera Tools/sondera"));

        let plugin = generated_plugin(&binary).unwrap();

        assert!(plugin.contains("'/opt/Sondera Tools/sondera' hook opencode tool-execute-before"));
    }

    #[test]
    fn every_adjudication_command_degrades_to_a_deny() {
        assert_fail_closed_matrix(
            all_hook_commands(),
            Commands::is_adjudication,
            degraded_response,
            HookResponse::is_deny,
        );
    }

    #[test]
    fn cli_and_sidecar_agree_on_which_events_are_enforcement_gates() {
        // The direct CLI path keys off `Commands::is_adjudication`; the sidecar
        // path keys off `criticality_for_event`. If they drift, one transport
        // silently stops failing closed for a gate the other enforces.
        for command in all_hook_commands() {
            let Some(kind) = command.event_kind() else {
                continue;
            };
            let sidecar_critical = matches!(
                sidecar::criticality_for_event(kind),
                sidecar::HookCriticality::AdjudicationCritical
            );
            assert_eq!(
                command.is_adjudication(),
                sidecar_critical,
                "CLI and sidecar disagree on whether {kind:?} is an enforcement gate"
            );
        }
    }

    #[test]
    fn install_preserves_existing_plugin_entries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("opencode.json"),
            r#"{"plugin":["./local-plugin.ts"]}"#,
        )
        .unwrap();

        install_plugin_with_binary(temp.path(), &test_binary()).unwrap();

        let raw = fs::read_to_string(temp.path().join("opencode.json")).unwrap();
        assert!(raw.contains("./local-plugin.ts"));
        assert!(!raw.contains(LEGACY_PLUGIN_PACKAGE));
        let plugin = fs::read_to_string(temp.path().join(PLUGIN_RELATIVE_PATH)).unwrap();
        assert!(plugin.contains("tool.execute.before"));
        assert!(plugin.contains("hook opencode event"));
    }

    #[test]
    fn install_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        install_plugin_with_binary(temp.path(), &test_binary()).unwrap();
        let first = fs::read_to_string(temp.path().join(PLUGIN_RELATIVE_PATH)).unwrap();
        install_plugin_with_binary(temp.path(), &test_binary()).unwrap();
        let second = fs::read_to_string(temp.path().join(PLUGIN_RELATIVE_PATH)).unwrap();
        assert_eq!(first, second);
        assert!(!temp.path().join("opencode.json").exists());
    }

    #[test]
    fn uninstall_missing_config_does_not_create_empty_config() {
        let temp = tempfile::tempdir().unwrap();

        uninstall_plugin(temp.path()).unwrap();

        assert!(!temp.path().join("opencode.json").exists());
    }

    #[test]
    fn uninstall_removes_empty_plugin_config() {
        let temp = tempfile::tempdir().unwrap();
        install_plugin_with_binary(temp.path(), &test_binary()).unwrap();

        uninstall_plugin(temp.path()).unwrap();

        assert!(!temp.path().join("opencode.json").exists());
    }

    #[test]
    fn uninstall_preserves_other_config_keys() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("opencode.json"),
            r#"{"plugin":["@sondera/opencode-plugin"],"theme":"dark"}"#,
        )
        .unwrap();

        uninstall_plugin(temp.path()).unwrap();

        let value: Value =
            serde_json::from_slice(&fs::read(temp.path().join("opencode.json")).unwrap()).unwrap();
        assert_eq!(value.get("theme").and_then(Value::as_str), Some("dark"));
        assert!(value.get("plugin").is_none());
    }

    #[test]
    fn uninstall_removes_string_plugin_config() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("opencode.json"),
            r#"{"plugin":"@sondera/opencode-plugin","theme":"dark"}"#,
        )
        .unwrap();

        uninstall_plugin(temp.path()).unwrap();

        let value: Value =
            serde_json::from_slice(&fs::read(temp.path().join("opencode.json")).unwrap()).unwrap();
        assert_eq!(value.get("theme").and_then(Value::as_str), Some("dark"));
        assert!(value.get("plugin").is_none());
    }

    #[test]
    fn install_rejects_non_object_config() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("opencode.json"), r#"["not-an-object"]"#).unwrap();

        let error = install_plugin_with_binary(temp.path(), &test_binary())
            .unwrap_err()
            .to_string();

        assert!(error.contains("must contain a JSON object"));
    }
}
