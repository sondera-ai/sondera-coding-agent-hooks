//! Trajectory event types for the agent perception-action loop.
//!
//! Events are organized into four categories:
//!
//! - **Action**: Agent-initiated operations (tool calls, shell commands, file ops, web fetches)
//! - **Observation**: Environment responses (tool output, command output, prompts, reasoning)
//! - **Control**: Lifecycle events (started, completed, failed, adjudicated)
//! - **State**: Context snapshots (working directory, git branch, open files)
//!
//! The [`Event`] envelope wraps any [`TrajectoryEvent`] with metadata:
//! agent identity, timestamps, causality chain, and optional raw payload.
//! Cedar policies are evaluated against these events to produce [`Adjudicated`]
//! decisions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum_macros::Display;

// ============================================================================
// Adjudication
// ============================================================================
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Decision {
    /// Allow the operation
    Allow,
    /// Deny the operation
    Deny,
    /// Escalate for human review
    Escalate,
}

/// Cedar policy annotations extracted from matching policies
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Annotation {
    /// Policy ID from @id annotation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// Description from @description annotation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Custom annotations (key-value pairs) including finra_rule, business_impact, etc.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub annotations: HashMap<String, String>,
}

impl Annotation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_id(mut self, id: String) -> Self {
        self.policy_id = Some(id);
        self
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn with(mut self, key: String, value: String) -> Self {
        self.annotations.insert(key, value);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Adjudication {
    /// The final decision
    pub decision: Decision,
    /// Optional reason for the decision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Annotations from matching policies (extracted from Cedar @annotations)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub annotations: Vec<Annotation>,
}

// ============================================================================
// Agent
// ============================================================================

/// Agent represents a unique AI agent in the environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    /// Unique identifier for the agent.
    pub id: String,
    /// Identifier for the provider of the agent.
    pub provider_id: String,
}

// ============================================================================
// Event Envelope & Attribution
// ============================================================================

/// Event envelope wrapping all trajectory events with metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    /// Unique event identifier.
    pub event_id: String,
    /// Trajectory this event belongs to.
    pub trajectory_id: String,
    /// The agent that generated this event.
    pub agent: Agent,
    /// When this event occurred.
    pub timestamp: DateTime<Utc>,
    /// The actual event payload.
    pub event: TrajectoryEvent,
    /// Who triggered this event.
    pub actor: Actor,
    /// Event causation chain.
    pub causality: Causality,
    /// Raw event data from the source system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

impl Event {
    pub fn new(agent: Agent, trajectory_id: impl Into<String>, event: TrajectoryEvent) -> Self {
        let agent_id = agent.id.clone();
        Self {
            event_id: format!("evt-{}", uuid::Uuid::new_v4()),
            trajectory_id: trajectory_id.into(),
            agent,
            timestamp: Utc::now(),
            event,
            actor: Actor::agent(agent_id),
            causality: Causality::default(),
            raw: None,
        }
    }

    pub fn with_raw(mut self, raw: serde_json::Value) -> Self {
        self.raw = Some(raw);
        self
    }

    pub fn with_actor(mut self, actor: Actor) -> Self {
        self.actor = actor;
        self
    }

    pub fn with_causality(mut self, causality: Causality) -> Self {
        self.causality = causality;
        self
    }
}

/// Who triggered the event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Actor {
    pub id: String,
    pub actor_type: ActorType,
}

impl Actor {
    pub fn human(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            actor_type: ActorType::Human,
        }
    }

    pub fn agent(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            actor_type: ActorType::Agent,
        }
    }

    pub fn system(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            actor_type: ActorType::System,
        }
    }

    pub fn policy(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            actor_type: ActorType::Policy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorType {
    Human,
    Agent,
    System,
    Policy,
}

/// Event causation chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Causality {
    /// Correlation ID linking related operations.
    pub correlation_id: String,
    /// What caused this event.
    pub causation_id: Option<String>,
    /// Parent event in hierarchical chains.
    pub parent_id: Option<String>,
}

impl Default for Causality {
    fn default() -> Self {
        Self {
            correlation_id: format!("corr-{}", uuid::Uuid::new_v4()),
            causation_id: None,
            parent_id: None,
        }
    }
}

impl Causality {
    pub fn caused_by(mut self, event_id: impl Into<String>) -> Self {
        self.causation_id = Some(event_id.into());
        self
    }

    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }
}

// ============================================================================
// Root Event Type
// ============================================================================

/// Root trajectory event enum with four core categories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "category", content = "payload")]
pub enum TrajectoryEvent {
    Action(Action),
    Observation(Observation),
    Control(Control),
    State(State),
}

// ============================================================================
// Action Events
// ============================================================================

/// Agent-initiated operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum Action {
    ToolCall(ToolCall),
    ShellCommand(ShellCommand),
    WebFetch(WebFetch),
    FileOperation(FileOperation),
}

/// Generic tool/function invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCall {
    pub call_id: String,
    pub tool: String,
    pub arguments: serde_json::Value,
}

impl ToolCall {
    pub fn new(tool_name: impl Into<String>, arguments: serde_json::Value) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            tool: tool_name.into(),
            arguments,
        }
    }
}

/// Shell command execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellCommand {
    pub call_id: String,
    pub command: String,
    pub working_dir: Option<String>,
}

impl ShellCommand {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            command: command.into(),
            working_dir: None,
        }
    }

    pub fn with_cwd(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }
}

/// Web fetch operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebFetch {
    pub call_id: String,
    pub url: String,
    pub prompt: String,
}

impl WebFetch {
    pub fn new(url: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            url: url.into(),
            prompt: prompt.into(),
        }
    }
}

/// File system operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileOperation {
    pub call_id: String,
    pub operation: FileOpType,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// For edit operations, the content being replaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_content: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
pub enum FileOpType {
    Read,
    Write,
    Edit,
    Delete,
}

impl FileOperation {
    pub fn read(path: impl Into<String>) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            operation: FileOpType::Read,
            path: path.into(),
            content: None,
            old_content: None,
        }
    }

    pub fn write(path: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            operation: FileOpType::Write,
            path: path.into(),
            content: Some(content.into()),
            old_content: None,
        }
    }

    pub fn edit(
        path: impl Into<String>,
        old_content: impl Into<String>,
        new_content: impl Into<String>,
    ) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            operation: FileOpType::Edit,
            path: path.into(),
            content: Some(new_content.into()),
            old_content: Some(old_content.into()),
        }
    }

    pub fn delete(path: impl Into<String>) -> Self {
        Self {
            call_id: format!("call-{}", uuid::Uuid::new_v4()),
            operation: FileOpType::Delete,
            path: path.into(),
            content: None,
            old_content: None,
        }
    }
}

// ============================================================================
// Observation Events
// ============================================================================

/// Environment responses and agent observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum Observation {
    Prompt(Prompt),
    Think(Think),
    ToolOutput(ToolOutput),
    ShellCommandOutput(ShellCommandOutput),
    WebFetchOutput(WebFetchOutput),
    FileOperationResult(FileOperationResult),
}

/// User or system prompt input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Prompt {
    pub content: String,
    pub role: PromptRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
pub enum PromptRole {
    User,
    System,
}

impl Prompt {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            role: PromptRole::User,
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            role: PromptRole::System,
        }
    }
}

/// Internal reasoning (no side effects).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Think {
    pub thought: String,
}

impl Think {
    pub fn new(thought: impl Into<String>) -> Self {
        Self {
            thought: thought.into(),
        }
    }
}

/// Generic tool output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolOutput {
    pub call_id: String,
    pub success: bool,
    pub output: serde_json::Value,
    pub error: Option<String>,
}

impl ToolOutput {
    pub fn success(call_id: impl Into<String>, output: impl Into<serde_json::Value>) -> Self {
        Self {
            call_id: call_id.into(),
            success: true,
            output: output.into(),
            error: None,
        }
    }

    pub fn error(call_id: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            success: false,
            output: serde_json::Value::Null,
            error: Some(error.into()),
        }
    }
}

/// Shell command output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellCommandOutput {
    pub call_id: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ShellCommandOutput {
    pub fn new(
        call_id: impl Into<String>,
        exit_code: i32,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            exit_code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }
}

/// Web fetch output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebFetchOutput {
    pub call_id: String,
    pub url: String,
    pub code: i32,
    pub result: String,
}

impl WebFetchOutput {
    pub fn new(
        call_id: impl Into<String>,
        url: impl Into<String>,
        code: i32,
        result: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            url: url.into(),
            code,
            result: result.into(),
        }
    }
}

/// File operation result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileOperationResult {
    pub call_id: String,
    pub success: bool,
    pub content: Option<String>,
    pub error: Option<String>,
}

impl FileOperationResult {
    pub fn success(call_id: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            success: true,
            content: None,
            error: None,
        }
    }

    pub fn with_content(mut self, content: impl Into<String>) -> Self {
        self.content = Some(content.into());
        self
    }

    pub fn error(call_id: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            success: false,
            content: None,
            error: Some(error.into()),
        }
    }
}

// ============================================================================
// Control Events
// ============================================================================

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
}

impl Control {
    /// Check if this is a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Control::Completed(_) | Control::Failed(_) | Control::Terminated(_)
        )
    }
}

/// Agent started.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Started {
    pub agent_id: String,
    pub task: Option<String>,
}

impl Started {
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            task: None,
        }
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

/// Policy evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Adjudicated {
    /// The final decision
    pub decision: Decision,
    /// Optional reason for the decision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Annotations from matching policies (extracted from Cedar @annotations)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub annotations: Vec<Annotation>,
}

impl Adjudicated {
    pub fn new(decision: Decision) -> Self {
        Self {
            decision,
            reason: None,
            annotations: Vec::new(),
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

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn with_annotation(mut self, annotation: Annotation) -> Self {
        self.annotations.push(annotation);
        self
    }

    /// Format policy annotations into a structured context string.
    ///
    /// Returns `None` if there are no annotations with useful content.
    ///
    /// Example output:
    /// ```text
    /// [Policy: SEC-001] Sensitive file access denied
    ///   severity: high
    ///   category: data-protection
    /// ```
    pub fn format_policy_context(&self) -> Option<String> {
        if self.annotations.is_empty() {
            return None;
        }

        let parts: Vec<String> = self
            .annotations
            .iter()
            .map(|a| {
                let mut lines = Vec::new();

                match (&a.policy_id, &a.description) {
                    (Some(id), Some(desc)) => lines.push(format!("[Policy: {id}] {desc}")),
                    (Some(id), None) => lines.push(format!("[Policy: {id}]")),
                    (None, Some(desc)) => lines.push(desc.clone()),
                    (None, None) => {}
                }

                let mut keys: Vec<&String> = a.annotations.keys().collect();
                keys.sort();
                for key in keys {
                    if let Some(value) = a.annotations.get(key) {
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
    /// Appends formatted annotations if any are present.
    pub fn deny_message(&self, default_reason: &str) -> String {
        let reason = self.reason.as_deref().unwrap_or(default_reason);

        match self.format_policy_context() {
            Some(context) => format!("{reason}\n\n{context}"),
            None => reason.to_string(),
        }
    }
}

// ============================================================================
// State Events
// ============================================================================

/// Context snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum State {
    Snapshot(Snapshot),
}

/// Full environment snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Snapshot {
    pub snapshot_id: String,
    pub working_dir: Option<String>,
    pub open_files: Vec<String>,
    pub git_branch: Option<String>,
    pub variables: HashMap<String, serde_json::Value>,
}

impl Snapshot {
    pub fn new() -> Self {
        Self {
            snapshot_id: format!("snap-{}", uuid::Uuid::new_v4()),
            working_dir: None,
            open_files: Vec::new(),
            git_branch: None,
            variables: HashMap::new(),
        }
    }

    pub fn with_cwd(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    pub fn with_git_branch(mut self, branch: impl Into<String>) -> Self {
        self.git_branch = Some(branch.into());
        self
    }
}

impl Default for Snapshot {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_envelope_creation() {
        let agent = Agent {
            id: "agent-1".to_string(),
            provider_id: "test".to_string(),
        };
        let event = TrajectoryEvent::Observation(Observation::Think(Think::new("test")));
        let envelope = Event::new(agent.clone(), "traj-123", event);

        assert_eq!(envelope.trajectory_id, "traj-123");
        assert_eq!(envelope.agent.id, "agent-1");
        assert_eq!(envelope.actor.id, "agent-1");
    }

    #[test]
    fn control_terminal_states() {
        assert!(Control::Completed(Completed::new()).is_terminal());
        assert!(Control::Failed(Failed::new("oops")).is_terminal());
        assert!(Control::Terminated(Terminated::new("timeout", "system")).is_terminal());

        assert!(!Control::Started(Started::new("agent-1")).is_terminal());
        assert!(!Control::Suspended(Suspended::new("waiting")).is_terminal());
        assert!(!Control::Resumed(Resumed::new("user")).is_terminal());
    }

    #[test]
    fn adjudicated_deny_message_variants() {
        // With reason + annotations
        let adj = Adjudicated::deny()
            .with_reason("Command blocked")
            .with_annotation(
                Annotation::new()
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

        // With reason, no annotations — no appended context
        let adj = Adjudicated::deny().with_reason("Just denied");
        assert_eq!(adj.deny_message("fallback"), "Just denied");
    }

    #[test]
    fn snapshot_builder() {
        let snap = Snapshot::new()
            .with_cwd("/workspace")
            .with_git_branch("main");

        assert_eq!(snap.working_dir.as_deref(), Some("/workspace"));
        assert_eq!(snap.git_branch.as_deref(), Some("main"));
    }

    #[test]
    fn trajectory_event_json_roundtrip() {
        let event = TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
            "test",
            serde_json::json!({"arg": "value"}),
        )));

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: TrajectoryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn error_observations() {
        let tool_err = ToolOutput::error("call-1", "connection refused");
        assert!(!tool_err.success);
        assert_eq!(tool_err.error.as_deref(), Some("connection refused"));

        let file_err = FileOperationResult::error("call-2", "permission denied");
        assert!(!file_err.success);
        assert_eq!(file_err.error.as_deref(), Some("permission denied"));
    }
}
