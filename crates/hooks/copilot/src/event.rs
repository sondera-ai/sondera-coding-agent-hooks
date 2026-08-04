//! GitHub Copilot CLI hook event metadata.

/// Provider-specific behavior class for a Copilot hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookBehavior {
    /// The hook can allow, deny, or rewrite a requested action.
    Adjudication,
    /// The hook records context but must not be treated as an enforcement point.
    Observation,
    /// The hook may inject context or ask Copilot to continue.
    Continuation,
}

/// Canonical metadata for one Copilot hook event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookEventSpec {
    /// Copilot event name as it appears in hooks JSON.
    pub event: &'static str,
    /// Kebab-case `sondera hook copilot ...` subcommand.
    pub subcommand: &'static str,
    /// Provider-specific behavior class.
    pub behavior: HookBehavior,
}

impl HookEventSpec {
    pub const fn new(
        event: &'static str,
        subcommand: &'static str,
        behavior: HookBehavior,
    ) -> Self {
        Self {
            event,
            subcommand,
            behavior,
        }
    }
}

/// Current Copilot CLI hook matrix from the GitHub hooks reference.
///
/// This is the source of truth used by installation and runtime card output.
/// Keep the older six-event how-to compatible by retaining those event names
/// inside this complete reference matrix.
pub const HOOK_EVENTS: &[HookEventSpec] = &[
    HookEventSpec::new("agentStop", "agent-stop", HookBehavior::Continuation),
    HookEventSpec::new("errorOccurred", "error-occurred", HookBehavior::Observation),
    HookEventSpec::new("notification", "notification", HookBehavior::Observation),
    HookEventSpec::new(
        "permissionRequest",
        "permission-request",
        HookBehavior::Adjudication,
    ),
    HookEventSpec::new("postToolUse", "post-tool-use", HookBehavior::Observation),
    HookEventSpec::new(
        "postToolUseFailure",
        "post-tool-use-failure",
        HookBehavior::Continuation,
    ),
    HookEventSpec::new("preCompact", "pre-compact", HookBehavior::Observation),
    HookEventSpec::new("preToolUse", "pre-tool-use", HookBehavior::Adjudication),
    HookEventSpec::new("sessionEnd", "session-end", HookBehavior::Observation),
    HookEventSpec::new("sessionStart", "session-start", HookBehavior::Observation),
    HookEventSpec::new("subagentStart", "subagent-start", HookBehavior::Observation),
    HookEventSpec::new("subagentStop", "subagent-stop", HookBehavior::Continuation),
    HookEventSpec::new(
        "userPromptSubmitted",
        "user-prompt-submitted",
        HookBehavior::Observation,
    ),
    HookEventSpec::new(
        "userPromptTransformed",
        "user-prompt-transformed",
        HookBehavior::Adjudication,
    ),
];
