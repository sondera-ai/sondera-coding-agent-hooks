//! VS Code Copilot Chat hook event metadata.

/// Canonical list of VS Code Copilot Chat hook events: `(PascalCase event name, kebab-case subcommand)`.
///
/// Single source of truth used by agent card introspection and installation.
/// <https://code.visualstudio.com/docs/agent-customization/hooks>
pub const HOOK_EVENTS: &[(&str, &str)] = &[
    ("SessionStart", "session-start"),
    ("UserPromptSubmit", "user-prompt-submit"),
    ("PreToolUse", "pre-tool-use"),
    ("PostToolUse", "post-tool-use"),
    ("PreCompact", "pre-compact"),
    ("SubagentStart", "subagent-start"),
    ("SubagentStop", "subagent-stop"),
    ("Stop", "stop"),
];
