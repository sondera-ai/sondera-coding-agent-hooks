//! Recognizing our own hook commands inside a provider's config.
//!
//! Provider installers render a hook command as a single string (`"<binary>
//! hook claude pre-tool-use"`). To reinstall or uninstall idempotently, an
//! installer has to read that string back and decide whether the command is one
//! *it* owns — not merely one of ours, since a host config can hold hooks for
//! several providers at once.
//!
//! [`HookCommand::parse`] answers that by recovering the three parts that
//! matter — binary, provider, subcommand — from `<binary> hook <provider>
//! [--verbose] <subcommand>` however the host rendered it: the quoting the
//! target shell required, a PowerShell `&` call operator or `env VAR=…` prefix,
//! an unquoted path that split on its own space. That one shape is the whole
//! grammar; a command in any other shape is not ours. Installers ask
//! [`command_targets_provider`]; [`shell_tokens`] is the tokenizer underneath.

use serde_json::Value;

/// Split `command` into at most `max_tokens` shell-like tokens.
///
/// This intentionally handles only the quoting forms our installers emit for
/// binary paths — single quotes, double quotes, and POSIX backslash escapes —
/// rather than implementing a full shell grammar.
pub fn shell_tokens(command: &str, max_tokens: usize) -> Vec<String> {
    let mut chars = command.trim_start().chars().peekable();
    let mut tokens = Vec::new();

    while tokens.len() < max_tokens {
        let mut token = String::new();
        let mut saw_token = false;
        let mut in_single = false;
        let mut in_double = false;

        while let Some(ch) = chars.next() {
            if !in_single && !in_double && ch.is_whitespace() {
                if saw_token {
                    break;
                }
                continue;
            }

            saw_token = true;
            match ch {
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single => in_double = !in_double,
                '\\' if !in_single => {
                    // Treat backslash as a POSIX escape only when it precedes a
                    // shell-meaningful character (whitespace or a quote). A
                    // backslash before an ordinary character is a literal path
                    // separator on Windows (e.g. `C:\Users\...\sondera.exe`);
                    // consuming it there would mangle the binary path and blind
                    // missing-binary detection on Windows.
                    match chars.peek() {
                        Some(&next)
                            if next.is_whitespace()
                                || next == '\''
                                || next == '"'
                                || next == '\\' =>
                        {
                            token.push(next);
                            chars.next();
                        }
                        _ => token.push('\\'),
                    }
                }
                _ => token.push(ch),
            }
        }

        if !saw_token {
            break;
        }
        tokens.push(token);
    }

    tokens
}

/// Whether `name` is the sondera binary.
fn is_sondera_binary_name(name: &str) -> bool {
    matches!(name, "sondera" | "sondera.exe")
}

/// The final path segment of a command token, split on *both* `/` and `\`.
///
/// `Path::file_name` only honors the host separator, so on a non-Windows host it
/// would treat `C:\Program Files\Sondera\sondera.exe` as one segment and miss
/// the `sondera.exe` basename. Classifying an installed Windows command must not
/// depend on which OS is doing the classifying, so split on both separators.
fn token_basename(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token)
}

/// Whether a single command token resolves (by basename) to a sondera binary.
fn is_sondera_token(token: &str) -> bool {
    is_sondera_binary_name(token_basename(token))
}

/// Whether `command` invokes a sondera-managed binary, whichever provider it
/// then dispatches to.
///
/// Weaker than [`command_targets_provider`] and rarely what an installer wants:
/// a host config can hold hooks for more than one provider, and an installer
/// must only rewrite its own. Use it when the question really is "did we write
/// this", such as reporting a stale binary.
#[must_use]
pub fn command_targets_sondera(command: &str) -> bool {
    shell_tokens(command, usize::MAX)
        .iter()
        .any(|token| is_sondera_token(token))
}

/// Whether `command` is a sondera hook command dispatching to `provider`.
///
/// The predicate every installer uses to recognize its own entries.
#[must_use]
pub fn command_targets_provider(command: &str, provider: &str) -> bool {
    HookCommand::parse(command).is_some_and(|parsed| parsed.provider == provider)
}

/// Config keys whose string value is a shell command.
///
/// `bash`/`powershell` are Copilot's per-shell pair; every other provider
/// spells it `command`.
const COMMAND_KEYS: [&str; 3] = ["command", "bash", "powershell"];

/// Whether any command anywhere in `value` dispatches to `provider`.
///
/// Installers classify whole config fragments, not bare strings — an event maps
/// to an array of rules, a rule nests an array of hook entries, and only the
/// leaves carry a command. Walking to those leaves and parsing each one is what
/// every installer needs; the alternative each of them reached for first,
/// substring-matching `value.to_string()`, silently stops matching as soon as
/// the rendered command needs quoting.
/// Only a command-bearing key's *string* value counts as a command, so a
/// `description` that quotes one is not mistaken for the real thing.
#[must_use]
pub fn value_targets_provider(value: &Value, provider: &str) -> bool {
    match value {
        Value::Array(items) => items
            .iter()
            .any(|item| value_targets_provider(item, provider)),
        Value::Object(map) => map.iter().any(|(key, child)| {
            (COMMAND_KEYS.contains(&key.as_str())
                && child
                    .as_str()
                    .is_some_and(|command| command_targets_provider(command, provider)))
                || value_targets_provider(child, provider)
        }),
        _ => false,
    }
}

/// A sondera hook command recovered from a host agent's config.
///
/// Built by [`HookCommand::parse`]; see the module docs for the shapes it
/// accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookCommand {
    /// The binary token with its quoting removed, as it would be exec'd.
    pub binary: String,
    /// The provider the command dispatches to, e.g. `"claude"`.
    pub provider: String,
    /// The hook event subcommand, absent when the command names none.
    pub subcommand: Option<String>,
}

/// Tokens that may precede the binary without changing what is invoked.
///
/// Two kinds. The first is a genuine prefix: the PowerShell call operator,
/// `env`, and `VAR=value` assignments. The second is the head of a path that
/// whitespace split — an unquoted `C:\Program Files\Sondera\sondera.exe` leaves
/// the binary in the *second* token — which is why a path-shaped token counts
/// too. A token that is neither (`sh`, `-c`, `docker`, `run`) means some other
/// program is being invoked and our binary is merely one of its arguments.
fn is_transparent_prefix_token(token: &str) -> bool {
    if token == "&" || token == "env" {
        return true;
    }
    // A path fragment: something with a separator in it that is not a flag.
    if !token.starts_with('-') && token.contains(['/', '\\']) {
        return true;
    }
    // `VAR=value`, but not a flag (`--opt=x`) and not a path that happens to
    // carry an `=` (`/opt/a=b/tool`).
    token
        .find('=')
        .is_some_and(|split| split > 0 && !token.starts_with('-') && !token[..split].contains('/'))
}

impl HookCommand {
    /// Parse `command`, or `None` if it does not invoke a sondera hook.
    ///
    /// # Examples
    ///
    /// ```
    /// use sondera_hooks::install::command::HookCommand;
    ///
    /// let parsed = HookCommand::parse("/usr/local/bin/sondera hook claude --verbose pre-tool-use")
    ///     .expect("a sondera hook command");
    /// assert_eq!(parsed.provider, "claude");
    /// assert_eq!(parsed.subcommand.as_deref(), Some("pre-tool-use"));
    ///
    /// assert!(HookCommand::parse("npx some-linter --fix").is_none());
    /// ```
    #[must_use]
    pub fn parse(command: &str) -> Option<Self> {
        let tokens = shell_tokens(command, usize::MAX);
        // The binary is not always the first token: a PowerShell `&` or an
        // `env VAR=…` prefix can precede it. Anything else in front of it means
        // some other program is being run, so this is not our hook.
        let index = (0..tokens.len()).find(|&index| {
            is_sondera_token(&tokens[index])
                && tokens[..index]
                    .iter()
                    .all(|token| is_transparent_prefix_token(token))
        })?;

        let binary = tokens[index].clone();
        // Installers differ in where they render `--verbose`, so drop it before
        // matching on structure.
        let mut tail = tokens[index + 1..]
            .iter()
            .filter(|token| *token != "--verbose")
            .map(String::as_str);

        if tail.next()? != "hook" {
            return None;
        }
        let provider = tail.next()?.to_string();

        Some(Self {
            binary,
            provider,
            subcommand: tail.next().map(str::to_string),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_unquoted_whitespace() {
        assert_eq!(
            shell_tokens("/bin/sondera hook claude pre-tool-use", usize::MAX),
            ["/bin/sondera", "hook", "claude", "pre-tool-use"]
        );
    }

    #[test]
    fn honors_the_token_limit() {
        assert_eq!(
            shell_tokens("/bin/sondera hook claude", 1),
            ["/bin/sondera"]
        );
    }

    #[test]
    fn keeps_quoted_paths_with_spaces_intact() {
        assert_eq!(
            shell_tokens("\"C:\\Program Files\\Sondera\\sondera.exe\" hook claude", 1),
            ["C:\\Program Files\\Sondera\\sondera.exe"]
        );
        assert_eq!(
            shell_tokens("'/opt/my apps/sondera' hook claude", 1),
            ["/opt/my apps/sondera"]
        );
    }

    #[test]
    fn preserves_windows_backslash_path_separators() {
        // A backslash before an ordinary character is a path separator, not an
        // escape — consuming it would mangle the binary path.
        assert_eq!(
            shell_tokens("C:\\Users\\dev\\sondera.exe hook claude", 1),
            ["C:\\Users\\dev\\sondera.exe"]
        );
    }

    #[test]
    fn unescapes_posix_escaped_spaces_and_quotes() {
        assert_eq!(
            shell_tokens("/opt/my\\ apps/sondera hook claude", 1),
            ["/opt/my apps/sondera"]
        );
        // The `'…'\''…'` form a POSIX shell uses to put a quote inside a
        // single-quoted path.
        assert_eq!(
            shell_tokens(r"'O'\''Brien'/sondera arg", 1),
            ["O'Brien/sondera"]
        );
    }

    #[test]
    fn empty_command_yields_no_tokens() {
        assert!(shell_tokens("   ", usize::MAX).is_empty());
    }

    #[test]
    fn recognizes_a_sondera_command_across_quoting_forms() {
        assert!(command_targets_sondera(
            r"& 'C:\Program Files\Sondera\sondera.exe' hook copilot --verbose pre-tool-use"
        ));
        assert!(command_targets_sondera(
            r"C:\Users\dev\sondera.exe hook claude pre-tool-use"
        ));
    }

    #[test]
    fn ignores_third_party_commands() {
        assert!(!command_targets_sondera("/usr/bin/other-tool do-something"));
        assert!(!command_targets_sondera("npx some-linter --fix"));
        // A path that merely contains "sondera" is not our binary.
        assert!(!command_targets_sondera("/opt/sondera/other-binary run"));
    }

    /// `(command, provider, subcommand)` for the rendering of the one command
    /// shape on each platform an installer targets.
    const PARSEABLE: &[(&str, &str, Option<&str>)] = &[
        // `--verbose` after the provider.
        (
            "/usr/local/bin/sondera hook claude --verbose pre-tool-use",
            "claude",
            Some("pre-tool-use"),
        ),
        // `--verbose` before it, as the claude installer renders it.
        (
            "/usr/local/bin/sondera hook --verbose codex session-start",
            "codex",
            Some("session-start"),
        ),
        // Windows: PowerShell call operator plus a quoted path with spaces.
        (
            r"& 'C:\Program Files\Sondera\sondera.exe' hook copilot pre-tool-use",
            "copilot",
            Some("pre-tool-use"),
        ),
        // An `env` prefix does not change what is invoked.
        (
            "env SONDERA_HOOK_DEBUG=1 /bin/sondera hook gemini before-tool",
            "gemini",
            Some("before-tool"),
        ),
        (
            "SONDERA_HOOK_DEBUG=1 /bin/sondera hook vscode pre-tool-use",
            "vscode",
            Some("pre-tool-use"),
        ),
        // A provider with no event names one anyway.
        ("/bin/sondera hook hermes", "hermes", None),
        // Windows, unquoted: the path splits on its own space, leaving the
        // binary in the second token rather than the first.
        (
            r"C:\Program Files\Sondera\sondera.exe hook codex --verbose pre-tool-use",
            "codex",
            Some("pre-tool-use"),
        ),
    ];

    #[test]
    fn parses_every_installed_command_shape() {
        for (command, provider, subcommand) in PARSEABLE {
            let parsed = HookCommand::parse(command)
                .unwrap_or_else(|| panic!("{command} should parse as a sondera hook"));
            assert_eq!(&parsed.provider, provider, "{command}");
            assert_eq!(parsed.subcommand.as_deref(), *subcommand, "{command}");
        }
    }

    #[test]
    fn parse_recovers_the_binary_as_it_would_be_exec_d() {
        let parsed = HookCommand::parse("'/opt/my apps/sondera' hook claude stop").unwrap();
        assert_eq!(parsed.binary, "/opt/my apps/sondera");
    }

    #[test]
    fn a_command_belongs_to_exactly_one_provider() {
        // The reason an installer must parse rather than substring-match: a
        // host config can hold hooks for several providers, and each installer
        // may only rewrite its own.
        let command = "/bin/sondera hook copilot --verbose pre-tool-use";
        assert!(command_targets_provider(command, "copilot"));
        assert!(!command_targets_provider(command, "claude"));
        assert!(!command_targets_provider(command, "codex"));
    }

    #[test]
    fn rejects_commands_that_do_not_invoke_a_sondera_hook() {
        for command in [
            "npx some-linter --fix",
            "/opt/sondera/other-binary hook claude stop",
            // Our binary, but no provider to dispatch to.
            "/bin/sondera",
            "/bin/sondera hook",
            // Our binary is an *argument* here, not what runs.
            "sh -c /bin/sondera hook claude stop",
            "docker run /bin/sondera hook claude stop",
            // Shapes shipped by earlier releases. They are not recognized: the
            // `hook` group is the only grammar, so an upgrade replaces what an
            // older binary wrote rather than editing it in place.
            "/bin/sondera claude pre-tool-use",
            "/usr/local/bin/sondera-hermes stop",
        ] {
            assert!(
                HookCommand::parse(command).is_none(),
                "{command} should not parse as a sondera hook"
            );
        }
    }

    #[test]
    fn classifies_a_whole_config_fragment_by_its_nested_commands() {
        // The shape providers actually store: an event maps to rules, a rule
        // nests hook entries, and only the leaves carry a command.
        let rule = serde_json::json!({
            "matcher": "*",
            "hooks": [{
                "type": "command",
                "command": "/bin/sondera hook codex --verbose pre-tool-use",
                "timeout": 30
            }]
        });
        assert!(value_targets_provider(&rule, "codex"));
        assert!(!value_targets_provider(&rule, "claude"));

        // Copilot's per-shell pair.
        let copilot = serde_json::json!([{
            "bash": "/bin/sondera hook copilot pre-tool-use",
            "powershell": "& 'C:\\bin\\sondera.exe' hook copilot pre-tool-use"
        }]);
        assert!(value_targets_provider(&copilot, "copilot"));

        // A third-party hook under the same event is not ours.
        let foreign = serde_json::json!({"hooks": [{"command": "/usr/bin/my-linter check"}]});
        assert!(!value_targets_provider(&foreign, "codex"));
    }

    #[test]
    fn a_quoted_command_in_a_description_is_not_a_command() {
        let rule = serde_json::json!({
            "description": "runs /bin/sondera hook codex pre-tool-use",
            "hooks": [{"command": "/usr/bin/my-linter check"}]
        });
        assert!(!value_targets_provider(&rule, "codex"));
    }

    #[test]
    fn a_substring_match_would_miss_what_parsing_catches() {
        // The regression this type exists to prevent: quoted and `&`-prefixed
        // Windows commands contain no bare `sondera copilot` substring, so the
        // installers' old `command.contains(marker)` check stopped recognizing
        // their own hooks.
        let command = r"& 'C:\Program Files\Sondera\sondera.exe' hook copilot pre-tool-use";
        assert!(!command.contains("sondera hook copilot"));
        assert!(command_targets_provider(command, "copilot"));
    }
}
