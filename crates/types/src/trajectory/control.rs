//! Control events: lifecycle and policy-evaluation flow.
//!
//! Control events manage trajectory flow rather than describing agent
//! perception or action: lifecycle transitions (started, completed, failed,
//! terminated, suspended, resumed), the [`Adjudicated`] policy-evaluation
//! result, and the [`Scanned`] trajectory-scanner result. They are one of the
//! four [`TrajectoryEvent`] categories.
//!
//! [`TrajectoryEvent`]: super::TrajectoryEvent

use super::scan::Scanned;
use crate::Agent;
use crate::policy::{Decision, GuardrailResults, Mode, PolicyMetadata};
use serde::{Deserialize, Serialize};

/// Flow management and policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum Control {
    Started(Started),
    Completed(Completed),
    Failed(Failed),
    Terminated(Terminated),
    Suspended(Suspended),
    Resumed(Resumed),
    Adjudicated(Adjudicated),
    Scanned(Scanned),
}

impl Control {
    /// Check if this is a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Control::Completed(_) | Control::Failed(_) | Control::Terminated(_)
        )
    }

    /// Check if this is an initial lifecycle state.
    pub fn is_initial(&self) -> bool {
        matches!(self, Control::Started(_))
    }
}

/// Agent started.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Started {
    pub agent: Agent,
    pub task: Option<String>,
}

impl Started {
    pub fn new(agent: Agent) -> Self {
        Self { agent, task: None }
    }

    pub fn with_task(mut self, task: impl Into<String>) -> Self {
        self.task = Some(task.into());
        self
    }
}

/// Agent completed successfully.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Completed {
    pub summary: Option<String>,
}

impl Completed {
    pub fn new() -> Self {
        Self { summary: None }
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }
}

impl Default for Completed {
    fn default() -> Self {
        Self::new()
    }
}

/// Agent failed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Failed {
    pub reason: String,
}

impl Failed {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Agent terminated externally.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Terminated {
    pub reason: String,
    pub terminated_by: String,
}

impl Terminated {
    pub fn new(reason: impl Into<String>, terminated_by: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            terminated_by: terminated_by.into(),
        }
    }
}

/// Agent suspended.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Suspended {
    pub reason: String,
}

impl Suspended {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Agent resumed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resumed {
    pub resumed_by: String,
}

impl Resumed {
    pub fn new(resumed_by: impl Into<String>) -> Self {
        Self {
            resumed_by: resumed_by.into(),
        }
    }
}

/// LLM-generated remediation instructions for policy violations in Steer mode.
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Steering {
    /// Step-by-step instructions for the agent to work around the violation.
    pub instructions: Vec<String>,
    /// Explanation of why the policies were violated and what triggered them.
    pub explanation: String,
}

/// Decode fallback for [`Adjudicated::mode`].
///
/// `Mode::default()` is `Monitor` — the *permissive* mode — so a record written
/// before `mode` existed, or one whose field was dropped in transit, would read
/// back as "policy was only observed", silently under-reporting an enforced
/// decision in the audit trail. An audit record must never claim less
/// enforcement than actually happened, so the fallback is the enforcing mode.
fn enforcing_mode() -> Mode {
    Mode::Govern
}

/// Policy evaluation result.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use sondera_types::Adjudicated;
///
/// Adjudicated::deny();
/// ```
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Adjudicated {
    /// The final decision
    pub decision: Decision,
    /// The engine mode at evaluation time.
    #[serde(default = "enforcing_mode")]
    pub mode: Mode,
    /// Optional reason for the decision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Metadata from matching policies (extracted from Cedar @annotations)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub metadata: Vec<PolicyMetadata>,
    /// Structured guardrail results captured during adjudication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardrails: Option<GuardrailResults>,
    /// LLM-generated steering instructions (populated only in Steer mode on deny).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steering: Option<Steering>,
}

impl Adjudicated {
    pub fn new(decision: Decision) -> Self {
        Self {
            decision,
            mode: Mode::default(),
            reason: None,
            metadata: Vec::new(),
            guardrails: None,
            steering: None,
        }
    }

    pub fn allow() -> Self {
        Self::new(Decision::Allow)
    }

    pub fn deny() -> Self {
        Self::new(Decision::Deny)
    }

    pub fn escalate() -> Self {
        Self::new(Decision::Escalate)
    }

    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn with_metadata(mut self, metadata: PolicyMetadata) -> Self {
        self.metadata.push(metadata);
        self
    }

    pub fn with_guardrails(mut self, guardrails: GuardrailResults) -> Self {
        self.guardrails = Some(guardrails);
        self
    }

    pub fn with_steering(mut self, steering: Steering) -> Self {
        self.steering = Some(steering);
        self
    }

    /// Format policy metadata into a structured context string.
    ///
    /// Returns `None` if there are no metadata entries with useful content.
    ///
    /// Example output:
    /// ```text
    /// [Policy: SEC-001] Sensitive file access denied
    ///   severity: high
    ///   category: data-protection
    /// ```
    pub fn format_policy_context(&self) -> Option<String> {
        if self.metadata.is_empty() {
            return None;
        }

        let parts: Vec<String> = self
            .metadata
            .iter()
            .map(|a| {
                let mut lines = Vec::new();

                match (&a.policy_id, &a.description) {
                    (Some(id), Some(desc)) => lines.push(format!("[Policy: {id}] {desc}")),
                    (Some(id), None) => lines.push(format!("[Policy: {id}]")),
                    (None, Some(desc)) => lines.push(desc.clone()),
                    (None, None) => {}
                }

                let mut keys: Vec<&String> = a.metadata.keys().collect();
                keys.sort();
                for key in keys {
                    if let Some(value) = a.metadata.get(key) {
                        lines.push(format!("  {key}: {value}"));
                    }
                }

                lines.join("\n")
            })
            .filter(|s| !s.is_empty())
            .collect();

        if parts.is_empty() {
            None
        } else {
            Some(parts.join("\n"))
        }
    }

    /// Build a deny message that appends policy context to the reason.
    ///
    /// Uses `self.reason` if present, otherwise falls back to `default_reason`.
    /// Appends formatted metadata if any are present.
    pub fn deny_message(&self, default_reason: &str) -> String {
        let reason = self.reason.as_deref().unwrap_or(default_reason);

        match self.format_policy_context() {
            Some(context) => format!("{reason}\n\n{context}"),
            None => reason.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_terminal_states() {
        assert!(Control::Completed(Completed::new()).is_terminal());
        assert!(Control::Failed(Failed::new("oops")).is_terminal());
        assert!(Control::Terminated(Terminated::new("timeout", "system")).is_terminal());

        assert!(
            !Control::Started(Started::new(Agent {
                id: "agent-1".to_string(),
                provider: "test".to_string(),
                platform: String::new(),
            }))
            .is_terminal()
        );
        assert!(!Control::Suspended(Suspended::new("waiting")).is_terminal());
        assert!(!Control::Resumed(Resumed::new("user")).is_terminal());
    }

    #[test]
    fn adjudicated_deny_message_variants() {
        // With reason + metadata
        let adj = Adjudicated::deny()
            .with_reason("Command blocked")
            .with_metadata(
                PolicyMetadata::new()
                    .with_id("SEC-001".into())
                    .with_description("Block dangerous commands".into())
                    .with("severity".into(), "high".into()),
            );

        let msg = adj.deny_message("fallback");
        assert!(msg.starts_with("Command blocked"));
        assert!(msg.contains("[Policy: SEC-001] Block dangerous commands"));
        assert!(msg.contains("severity: high"));

        // No reason — uses default
        let adj = Adjudicated::deny();
        assert_eq!(adj.deny_message("default reason"), "default reason");
        assert!(adj.format_policy_context().is_none());

        // With reason, no metadata — no appended context
        let adj = Adjudicated::deny().with_reason("Just denied");
        assert_eq!(adj.deny_message("fallback"), "Just denied");
    }
}
