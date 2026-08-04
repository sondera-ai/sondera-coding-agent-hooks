//! The [`Event`] envelope, attribution ([`Actor`], [`Causality`]), and the root
//! [`TrajectoryEvent`] enum.
//!
//! The [`Event`] envelope wraps any [`TrajectoryEvent`] with metadata: agent
//! identity, timestamps, and causality chain. Cedar policies are evaluated
//! against these events to produce [`Adjudicated`](super::Adjudicated) decisions.
//!
//! The four category payloads live in their own sibling modules:
//! [`action`](super::action), [`observation`](super::observation),
//! [`control`](super::control), and [`state`](super::state).

use super::action::Action;
use super::control::{Adjudicated, Control};
use super::observation::Observation;
use super::state::State;
use crate::Agent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

// Proto-encoder source type. The proto `From`/`TryFrom` conversions between
// `Event`/`Adjudicated` and the wire `Event` live in `sondera-schema`; what
// remains here is the proto-free `AdjudicatedEvent` encoder source struct.

/// Source metadata needed to encode an adjudication result as a response event.
///
/// The `From<AdjudicatedEvent> for pb::Event` encoder lives in `sondera-schema`.
#[derive(Debug, Clone, Copy)]
pub struct AdjudicatedEvent<'a> {
    pub adjudicated: &'a Adjudicated,
    pub source_event_id: &'a str,
    pub source_trajectory_id: &'a str,
    pub source_agent_id: &'a str,
}

// ============================================================================
// Event Envelope & Attribution
// ============================================================================

/// Event envelope wrapping all trajectory events with metadata.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
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
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Event")
            .field("event_id", &self.event_id)
            .field("trajectory_id", &self.trajectory_id)
            .field("agent", &self.agent)
            .field("timestamp", &self.timestamp)
            .field("event", &self.event.to_string())
            .field("actor", &self.actor)
            .field("causality", &self.causality)
            .finish()
    }
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
        }
    }

    pub fn with_actor(mut self, actor: Actor) -> Self {
        self.actor = actor;
        self
    }

    pub fn with_causality(mut self, causality: Causality) -> Self {
        self.causality = causality;
        self
    }

    pub fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
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

impl std::fmt::Display for TrajectoryEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Action(Action::ToolCall(_)) => write!(f, "Action::ToolCall"),
            Self::Action(Action::ShellCommand(_)) => write!(f, "Action::ShellCommand"),
            Self::Action(Action::WebFetch(_)) => write!(f, "Action::WebFetch"),
            Self::Action(Action::FileOperation(_)) => write!(f, "Action::FileOperation"),
            Self::Observation(Observation::Prompt(_)) => write!(f, "Observation::Prompt"),
            Self::Observation(Observation::ShellCommandOutput(_)) => {
                write!(f, "Observation::ShellCommandOutput")
            }
            Self::Observation(Observation::WebFetchOutput(_)) => {
                write!(f, "Observation::WebFetchOutput")
            }
            Self::Observation(Observation::FileOperationResult(_)) => {
                write!(f, "Observation::FileOperationResult")
            }
            Self::Observation(Observation::ToolOutput(_)) => write!(f, "Observation::ToolOutput"),
            Self::Observation(Observation::Thought(_)) => write!(f, "Observation::Thought"),
            Self::Control(Control::Started(_)) => write!(f, "Control::Started"),
            Self::Control(Control::Completed(_)) => write!(f, "Control::Completed"),
            Self::Control(Control::Failed(_)) => write!(f, "Control::Failed"),
            Self::Control(Control::Terminated(_)) => write!(f, "Control::Terminated"),
            Self::Control(Control::Suspended(_)) => write!(f, "Control::Suspended"),
            Self::Control(Control::Resumed(_)) => write!(f, "Control::Resumed"),
            Self::Control(Control::Adjudicated(_)) => write!(f, "Control::Adjudicated"),
            Self::Control(Control::Scanned(_)) => write!(f, "Control::Scanned"),
            Self::State(State::Snapshot(_)) => write!(f, "State::Snapshot"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileOperationResult, ShellCommand, Thought, ToolCall, ToolOutput};

    #[test]
    fn event_envelope_creation() {
        let agent = Agent {
            id: "agent-1".to_string(),
            provider: "test".to_string(),
            platform: String::new(),
        };
        let event = TrajectoryEvent::Observation(Observation::Thought(Thought::new("test")));
        let envelope = Event::new(agent.clone(), "traj-123", event);

        assert_eq!(envelope.trajectory_id, "traj-123");
        assert_eq!(envelope.agent.id, "agent-1");
        assert_eq!(envelope.actor.id, "agent-1");
    }

    #[test]
    fn event_debug_redacts_payload_values() {
        let agent = Agent {
            id: "agent-1".to_string(),
            provider: "test".to_string(),
            platform: String::new(),
        };
        let envelope = Event::new(
            agent,
            "traj-123",
            TrajectoryEvent::Action(Action::ShellCommand(
                ShellCommand::new("export TOKEN=super-secret-token").with_cwd("/workspace"),
            )),
        );

        let debug_output = format!("{envelope:?}");
        assert!(debug_output.contains("Action::ShellCommand"));
        assert!(!debug_output.contains("super-secret-token"));
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
