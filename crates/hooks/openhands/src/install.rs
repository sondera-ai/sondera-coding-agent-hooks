//! Install/uninstall commands for OpenHands hooks.
//!
//! MVP writes project-level `.openhands/hooks.json`. OpenHands SDK also searches
//! a user-level path, but this adapter intentionally omits a `--user` flag until
//! product policy confirms user-scope governance semantics.

use std::env;
use std::path::PathBuf;

use serde_json::{Map, Value, json};
use sondera_hooks::error::{HookResultExt as _, Result};
use sondera_hooks::install::binary::{CommandShell, ResolvedBinary};
use sondera_hooks::install::{HookConfigInstaller, command};

/// Human-facing agent name used in installer output.
const AGENT: &str = "OpenHands";

/// Key in `hooks.json` holding the event map.
const HOOKS_KEY: &str = "hooks";

/// The provider this adapter's hook commands dispatch to.
const PROVIDER: &str = "openhands";

const HOOK_TIMEOUT_SECS: u64 = 30;

/// OpenHands hook events: `(event name, subcommand, matcher)`.
const HOOK_EVENTS: &[(&str, &str, &str)] = &[
    ("SessionStart", "session-start", "*"),
    ("PreToolUse", "pre-tool-use", "*"),
    ("PostToolUse", "post-tool-use", "*"),
    ("UserPromptSubmit", "user-prompt-submit", "*"),
    ("Stop", "stop", "*"),
    ("SessionEnd", "session-end", "*"),
];

/// The project-scope `.openhands/hooks.json` path.
fn project_hooks_path() -> Result<PathBuf> {
    Ok(env::current_dir()
        .context("Could not determine current directory")?
        .join(".openhands")
        .join("hooks.json"))
}

/// Generate the event map for every OpenHands hook event.
fn generate_hooks_config(binary: &ResolvedBinary) -> Map<String, Value> {
    let binary_str = binary.render(CommandShell::Posix);
    HOOK_EVENTS
        .iter()
        .map(|(event, subcommand, matcher)| {
            (
                (*event).to_string(),
                json!([{
                    "matcher": matcher,
                    "hooks": [{
                        "type": "command",
                        "command": format!("{binary_str} hook openhands --verbose {subcommand}"),
                        "timeout": HOOK_TIMEOUT_SECS
                    }]
                }]),
            )
        })
        .collect()
}

/// Whether `rules` contains a hook command this adapter manages.
fn is_managed(rules: &Value) -> bool {
    command::value_targets_provider(rules, PROVIDER)
}

/// Drop every Sondera-managed rule from the event map, returning whether
/// anything changed. Third-party rules under the same events are preserved.
fn remove_managed_entries(events: &mut Map<String, Value>) -> bool {
    let mut changed = false;
    for key in events.keys().cloned().collect::<Vec<_>>() {
        let Some(rules) = events.get(&key).and_then(Value::as_array) else {
            continue;
        };
        let kept: Vec<Value> = rules
            .iter()
            .filter(|rule| !is_managed(rule))
            .cloned()
            .collect();
        if kept.len() != rules.len() {
            changed = true;
            if kept.is_empty() {
                events.remove(&key);
            } else {
                events.insert(key, Value::Array(kept));
            }
        }
    }
    changed
}

/// Splice our hooks into `config`, replacing any we installed previously.
///
/// Idempotent: the managed entries are removed before the fresh ones are
/// appended, so reinstalling does not accumulate duplicates.
fn apply_hooks(config: &mut Map<String, Value>, binary: &ResolvedBinary) {
    let events = config
        .entry(HOOKS_KEY.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(events) = events.as_object_mut() else {
        *events = Value::Object(generate_hooks_config(binary));
        return;
    };

    remove_managed_entries(events);
    for (event, rules) in generate_hooks_config(binary) {
        let Some(new_rules) = rules.as_array() else {
            continue;
        };
        match events.get_mut(&event).and_then(Value::as_array_mut) {
            Some(existing) => existing.extend(new_rules.iter().cloned()),
            None => {
                events.insert(event, rules);
            }
        }
    }
}

/// Remove our hooks from `config`, returning whether anything changed.
fn revoke_hooks(config: &mut Map<String, Value>) -> bool {
    let removed = config
        .get_mut(HOOKS_KEY)
        .and_then(Value::as_object_mut)
        .is_some_and(remove_managed_entries);

    if removed
        && config
            .get(HOOKS_KEY)
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
    {
        config.remove(HOOKS_KEY);
    }
    removed
}

fn installer() -> Result<HookConfigInstaller> {
    Ok(HookConfigInstaller::new(
        AGENT,
        project_hooks_path()?,
        "project (.openhands/hooks.json)",
    )
    // `.openhands/hooks.json` exists only to hold hooks.
    .remove_when(Map::is_empty))
}

/// Install hooks into the project-scope config.
pub fn install_hooks() -> Result<()> {
    installer()?.install(apply_hooks)
}

/// Uninstall hooks from the project-scope config.
pub fn uninstall_hooks() -> Result<()> {
    installer()?.uninstall(revoke_hooks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary() -> ResolvedBinary {
        ResolvedBinary::from_exe_path(PathBuf::from("/usr/local/bin/sondera"))
    }

    #[test]
    fn generates_the_openhands_hook_shape() {
        let events = generate_hooks_config(&binary());
        for (event, _, _) in HOOK_EVENTS {
            assert!(events.contains_key(*event), "missing {event}");
            assert_eq!(
                events[*event][0]["hooks"][0]["timeout"], 30,
                "{event} timeout"
            );
        }
        assert_eq!(events["PreToolUse"][0]["matcher"], "*");
        assert_eq!(events["PostToolUse"][0]["matcher"], "*");
        assert_eq!(
            events["PreToolUse"][0]["hooks"][0]["command"],
            "/usr/local/bin/sondera hook openhands --verbose pre-tool-use"
        );
    }

    #[test]
    fn recognizes_only_our_own_hooks_in_a_shared_event_map() {
        /// One rule in the shape OpenHands stores it, around `command`.
        fn rule(command: &str) -> Value {
            json!({"matcher": "*", "hooks": [{"type": "command", "command": command}]})
        }

        assert!(is_managed(&rule(
            "/bin/sondera hook openhands --verbose stop"
        )));
        assert!(!is_managed(&rule("third-party stop")));
        // Another provider's hook in this file is not ours to remove.
        assert!(!is_managed(&rule("/bin/sondera hook claude stop")));
    }

    #[test]
    fn install_is_idempotent_and_preserves_third_party_hooks() {
        let mut config: Map<String, Value> = serde_json::from_value(json!({
            "hooks": {
                "PreToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"third-party pre"}]}]
            },
            "other": true
        }))
        .unwrap();

        apply_hooks(&mut config, &binary());
        let once = config.clone();
        apply_hooks(&mut config, &binary());

        assert_eq!(once, config, "reinstall must not accumulate duplicates");
        assert!(
            Value::Object(config.clone())
                .to_string()
                .contains("third-party pre")
        );
        assert_eq!(config["other"], json!(true));
    }

    #[test]
    fn uninstall_removes_only_sondera_entries() {
        let mut config = Map::new();
        apply_hooks(&mut config, &binary());
        config["hooks"]["Stop"].as_array_mut().unwrap().push(json!({
            "matcher": "*",
            "hooks": [{"type":"command","command":"third-party stop"}]
        }));

        assert!(revoke_hooks(&mut config));

        let remaining = Value::Object(config).to_string();
        assert!(remaining.contains("third-party stop"));
        assert!(!remaining.contains("hook openhands"));
    }

    #[test]
    fn uninstall_drops_the_hooks_key_once_it_is_empty() {
        let mut config = Map::new();
        apply_hooks(&mut config, &binary());

        assert!(revoke_hooks(&mut config));
        assert!(
            config.is_empty(),
            "an emptied config lets the driver delete the file"
        );
    }

    #[test]
    fn uninstall_reports_no_change_when_nothing_is_installed() {
        let mut config: Map<String, Value> =
            serde_json::from_value(json!({"hooks": {"Stop": []}})).unwrap();
        assert!(!revoke_hooks(&mut config));
    }
}
