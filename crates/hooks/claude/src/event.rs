//! Claude Code hook event metadata.

/// Whether Sondera currently installs and dispatches a Claude Code hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookSupport {
    /// The hook is delivered by `sondera hook claude install` and accepted by the
    /// Claude hook dispatcher.
    Delivered,
    /// The hook exists in Claude Code but is intentionally not installed or
    /// dispatched by Sondera yet.
    Unsupported,
}

/// Sondera's enforcement posture for one Claude Code hook event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEnforcement {
    /// Claude can honor a blocking response and Sondera must block on
    /// governance failures. Runtime adapters may still distinguish an outer
    /// hook-budget timeout from a policy denial when a lifecycle hook is
    /// retrospective.
    FailClosed,
    /// Claude can continue safely with degraded behavior for this event.
    DegradeOpen,
    /// Claude ignores block/exit-code semantics for this event; use only for
    /// telemetry or local state maintenance.
    ObservationOnly,
    /// Sondera does not deliver this event.
    Unsupported,
}

/// Which Claude surface a hook serves. Selects how fired events are
/// attributed. Only Claude Code is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPlatform {
    ClaudeCode,
}

impl HookPlatform {
    /// Platform identifier used as the agent's provider/platform name (the
    /// agent id is `<as_str>-<username>`).
    pub const fn as_str(self) -> &'static str {
        match self {
            HookPlatform::ClaudeCode => "claude-code",
        }
    }

    /// `provider` label for logs. Claude Code collapses to `"claude"`.
    pub const fn metric_provider(self) -> &'static str {
        match self {
            HookPlatform::ClaudeCode => "claude",
        }
    }
}

/// Canonical Claude Code hook metadata, including current-document events
/// that Sondera intentionally does not deliver yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookSpec {
    /// PascalCase event name from the Claude Code hook payload.
    pub event_name: &'static str,
    /// Kebab-case `sondera hook claude` subcommand when this hook is delivered.
    pub subcommand: Option<&'static str>,
    /// Current Sondera delivery status.
    pub support: HookSupport,
    /// Current Sondera enforcement posture.
    pub enforcement: HookEnforcement,
    /// Short operational rationale for delivery/enforcement decisions.
    pub rationale: &'static str,
}

impl HookSpec {
    const fn delivered(
        event_name: &'static str,
        subcommand: &'static str,
        enforcement: HookEnforcement,
        rationale: &'static str,
    ) -> Self {
        Self {
            event_name,
            subcommand: Some(subcommand),
            support: HookSupport::Delivered,
            enforcement,
            rationale,
        }
    }

    const fn unsupported(event_name: &'static str, rationale: &'static str) -> Self {
        Self {
            event_name,
            subcommand: None,
            support: HookSupport::Unsupported,
            enforcement: HookEnforcement::Unsupported,
            rationale,
        }
    }
}

/// Complete Claude Code hook matrix as of the current public reference.
///
/// Keep unsupported events visible here so runtime, installer, and packaging
/// reviews can distinguish deliberate gaps from accidental drift.
/// <https://code.claude.com/docs/en/hooks>
pub const HOOK_MATRIX: &[HookSpec] = &[
    HookSpec::delivered(
        "ConfigChange",
        "config-change",
        HookEnforcement::FailClosed,
        "Blockable except for policy_settings, which Claude always applies.",
    ),
    HookSpec::unsupported(
        "CwdChanged",
        "Observation-only environment event; delivery deferred until cwd semantics are modeled.",
    ),
    HookSpec::unsupported(
        "DirectoryAdded",
        "Observation-only repository event; delivery deferred until added-root trust semantics are modeled.",
    ),
    HookSpec::unsupported(
        "Elicitation",
        "Specialized action/content response schema needs explicit product semantics.",
    ),
    HookSpec::unsupported(
        "ElicitationResult",
        "Specialized action/content response schema needs explicit product semantics.",
    ),
    HookSpec::unsupported(
        "FileChanged",
        "Observation-only filesystem event; delivery deferred until volume and privacy semantics are modeled.",
    ),
    HookSpec::delivered(
        "InstructionsLoaded",
        "instructions-loaded",
        HookEnforcement::ObservationOnly,
        "Updates local instruction provenance; Claude does not support blocking this event.",
    ),
    HookSpec::unsupported(
        "MessageDisplay",
        "Display-rewrite hook is not an enforcement point and needs UX policy before delivery.",
    ),
    HookSpec::delivered(
        "Notification",
        "notification",
        HookEnforcement::ObservationOnly,
        "Notification hooks are advisory; Claude ignores blocking decisions.",
    ),
    HookSpec::unsupported(
        "PermissionDenied",
        "Retry behavior requires an explicit policy model; exit/stderr are ignored.",
    ),
    HookSpec::delivered(
        "PermissionRequest",
        "permission-request",
        HookEnforcement::FailClosed,
        "Permission requests are blockable and must deny on governance failures.",
    ),
    HookSpec::unsupported(
        "PostCompact",
        "Observation-only compaction event; delivery deferred until summary provenance is modeled.",
    ),
    HookSpec::unsupported(
        "PostToolBatch",
        "Batch boundary can stop the agentic loop; output and loop semantics need first-class modeling.",
    ),
    HookSpec::delivered(
        "PostToolUse",
        "post-tool-use",
        HookEnforcement::FailClosed,
        "Tool output can be replaced with redacted output when policy blocks.",
    ),
    HookSpec::delivered(
        "PostToolUseFailure",
        "post-tool-use-failure",
        HookEnforcement::ObservationOnly,
        "The tool already failed; Claude ignores blocking decisions.",
    ),
    HookSpec::delivered(
        "PreCompact",
        "pre-compact",
        HookEnforcement::FailClosed,
        "Compaction is blockable before Claude rewrites context.",
    ),
    HookSpec::delivered(
        "PreToolUse",
        "pre-tool-use",
        HookEnforcement::FailClosed,
        "Tool calls are blockable before execution.",
    ),
    HookSpec::delivered(
        "SessionEnd",
        "session-end",
        HookEnforcement::DegradeOpen,
        "Session end is lifecycle accounting; it should not strand users when telemetry is unavailable.",
    ),
    HookSpec::delivered(
        "SessionStart",
        "session-start",
        HookEnforcement::DegradeOpen,
        "Session start can inject fallback context when governance is unavailable.",
    ),
    HookSpec::unsupported(
        "Setup",
        "Setup lifecycle and persisted environment behavior need explicit sessionless semantics.",
    ),
    HookSpec::delivered(
        "Stop",
        "stop",
        HookEnforcement::ObservationOnly,
        "Stop adjudicates the transcript tail for visibility, but cannot fail closed because Claude treats Stop blocks as continue-conversation signals.",
    ),
    HookSpec::unsupported(
        "StopFailure",
        "Claude ignores output and exit code for failed-stop telemetry.",
    ),
    HookSpec::delivered(
        "SubagentStart",
        "subagent-start",
        HookEnforcement::ObservationOnly,
        "Subagent start can observe and add context, but cannot block creation.",
    ),
    HookSpec::delivered(
        "SubagentStop",
        "subagent-stop",
        HookEnforcement::FailClosed,
        "Subagent stop is blockable and can require continued work.",
    ),
    HookSpec::unsupported(
        "TaskCreated",
        "Task creation rollback semantics need first-class task policy modeling.",
    ),
    HookSpec::delivered(
        "TaskCompleted",
        "task-completed",
        HookEnforcement::FailClosed,
        "Task completion is blockable when policy requires more work.",
    ),
    HookSpec::delivered(
        "TeammateIdle",
        "teammate-idle",
        HookEnforcement::FailClosed,
        "Teammate idle is blockable and can require a teammate to continue.",
    ),
    HookSpec::unsupported(
        "UserPromptExpansion",
        "Prompt expansion response semantics need explicit command/skill policy modeling.",
    ),
    HookSpec::delivered(
        "UserPromptSubmit",
        "user-prompt-submit",
        HookEnforcement::FailClosed,
        "User prompts are blockable before submission to the model.",
    ),
    HookSpec::unsupported(
        "WorktreeCreate",
        "Claude delegates worktree creation to this hook and requires an absolute path on stdout.",
    ),
    HookSpec::delivered(
        "WorktreeRemove",
        "worktree-remove",
        HookEnforcement::ObservationOnly,
        "Worktree removal is cleanup telemetry; Claude does not block on this event.",
    ),
];

/// Canonical list of Claude Code hook events: `(PascalCase event name, kebab-case subcommand)`.
///
/// Single source of truth used by agent card introspection and installation.
/// <https://code.claude.com/docs/en/hooks>
pub const HOOK_EVENTS: &[(&str, &str)] = &[
    ("ConfigChange", "config-change"),
    ("InstructionsLoaded", "instructions-loaded"),
    ("Notification", "notification"),
    ("PermissionRequest", "permission-request"),
    ("PostToolUse", "post-tool-use"),
    ("PostToolUseFailure", "post-tool-use-failure"),
    ("PreCompact", "pre-compact"),
    ("PreToolUse", "pre-tool-use"),
    ("SessionEnd", "session-end"),
    ("SessionStart", "session-start"),
    ("Stop", "stop"),
    ("SubagentStart", "subagent-start"),
    ("SubagentStop", "subagent-stop"),
    ("TaskCompleted", "task-completed"),
    ("TeammateIdle", "teammate-idle"),
    ("UserPromptSubmit", "user-prompt-submit"),
    // Do not install WorktreeCreate unless Sondera owns delegated worktree
    // creation. Claude Code treats that hook as a replacement for default
    // git worktree creation and requires the command to print an absolute
    // path on stdout.
    ("WorktreeRemove", "worktree-remove"),
];

/// Return the canonical metadata for a Claude hook event.
pub fn hook_spec(event_name: &str) -> Option<&'static HookSpec> {
    HOOK_MATRIX
        .iter()
        .find(|spec| spec.event_name == event_name)
}

/// Returns true when this delivered Claude hook must block on governance
/// failures instead of degrading open.
pub fn is_fail_closed_hook(event_name: &str) -> bool {
    hook_spec(event_name).is_some_and(|spec| spec.enforcement == HookEnforcement::FailClosed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivered_hook_events_are_projection_of_matrix() {
        let delivered: Vec<(&str, &str)> = HOOK_MATRIX
            .iter()
            .filter(|spec| spec.support == HookSupport::Delivered)
            .map(|spec| {
                (
                    spec.event_name,
                    spec.subcommand.expect("delivered hooks have commands"),
                )
            })
            .collect();

        assert_eq!(delivered, HOOK_EVENTS);
        assert_eq!(HOOK_EVENTS.len(), 17);
        assert!(hook_spec("WorktreeCreate").is_some());
        assert!(
            !HOOK_EVENTS
                .iter()
                .any(|(event_name, _)| *event_name == "WorktreeCreate")
        );
    }

    #[test]
    fn current_public_hook_matrix_has_explicit_support_posture() {
        assert_eq!(HOOK_MATRIX.len(), 31);

        for event in [
            "Setup",
            "UserPromptExpansion",
            "MessageDisplay",
            "PostToolBatch",
            "PermissionDenied",
            "TaskCreated",
            "StopFailure",
            "CwdChanged",
            "DirectoryAdded",
            "FileChanged",
            "PostCompact",
            "Elicitation",
            "ElicitationResult",
            "WorktreeCreate",
        ] {
            let spec = hook_spec(event).expect("public hook should be in matrix");
            assert_eq!(spec.support, HookSupport::Unsupported, "{event}");
            assert_eq!(spec.enforcement, HookEnforcement::Unsupported, "{event}");
            assert!(!spec.rationale.is_empty(), "{event}");
        }
    }

    #[test]
    fn fail_closed_hooks_match_blockable_delivered_policy() {
        let fail_closed: Vec<&str> = HOOK_MATRIX
            .iter()
            .filter(|spec| spec.enforcement == HookEnforcement::FailClosed)
            .map(|spec| spec.event_name)
            .collect();

        assert_eq!(
            fail_closed,
            vec![
                "ConfigChange",
                "PermissionRequest",
                "PostToolUse",
                "PreCompact",
                "PreToolUse",
                "SubagentStop",
                "TaskCompleted",
                "TeammateIdle",
                "UserPromptSubmit",
            ]
        );
        assert!(is_fail_closed_hook("PreToolUse"));
        assert!(!is_fail_closed_hook("Stop"));
        assert!(!is_fail_closed_hook("SessionStart"));
        assert!(!is_fail_closed_hook("WorktreeCreate"));
    }
}
