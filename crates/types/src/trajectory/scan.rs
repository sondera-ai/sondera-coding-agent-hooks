//! Event scan result types for trajectory log analysis.
//!
//! These types are the structured output of the trajectory scanner's per-event
//! and per-transcript analysis, plus the [`Scanned`] control-event payload that
//! carries them through the trajectory log. They live in `sondera_types` so the
//! scanner and the policy engine can share them without circular dependencies.
//!
//! [`ScanReaderWriter`] is the store surface these are persisted through. A scan
//! is recorded twice, on purpose: as a [`Scanned`] control event (the trajectory
//! log is the complete record of what happened to a run) and as a row in a
//! dedicated table keyed by the event or run it describes (a reader wants the
//! latest digest for a run without replaying its control events). The table is
//! authoritative for reads — it survives a failed control-event write, and it
//! answers "what is this run's digest" in one indexed lookup rather than a scan.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;

use crate::error::StoreError;

// ============================================================================
// Signal taxonomy
// ============================================================================

/// Whether a signal relates to the environment, the AI agent, or governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum SignalFocus {
    Environment,
    Agent,
    Governance,
}

/// Signal category taxonomy from AISI Tables 2-3.
///
/// Variant descriptions are intentionally omitted from doc comments to prevent
/// `schemars` from emitting them as JSON schema `description` fields, which
/// can cause LLMs to use the description text as the enum value instead of
/// the snake_case variant name. The rubric prompt defines each category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum SignalCategory {
    InputIssues,
    InfrastructureFailure,
    TaskDesign,
    StaticKnowledge,
    LowLevelIncoherence,
    HighLevelIncoherence,
    SelfCorrection,
    RefusalBehaviour,
    ToolMisuse,
    EvaluationAwareness,
    PolicyViolation,
    PrivilegeEscalation,
    DataExfiltration,
    DestructiveOperation,
    CredentialExposure,
}

/// Severity of a detected signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum SignalSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A concrete signal detected in a trajectory event or transcript.
#[must_use]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Signal {
    /// Whether this signal relates to the environment or the agent.
    pub focus: SignalFocus,
    /// The signal category from the AISI taxonomy.
    pub category: SignalCategory,
    /// Severity of this signal instance.
    pub severity: SignalSeverity,
    /// What was detected and why it was flagged.
    pub description: String,
    /// Event indices (0-based) in the transcript that evidence this signal.
    #[serde(default)]
    pub evidence_indices: Vec<u32>,
}

// ============================================================================
// Message-level scan types
// ============================================================================

/// The structural type of a trajectory message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum MessageType {
    ToolCall,
    ToolResult,
    UserInput,
    Reasoning,
    Lifecycle,
    Adjudication,
    StateCapture,
}

/// The inferred intent or purpose of an event within the trajectory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum AgentIntent {
    Investigate,
    Plan,
    Implement,
    Verify,
    Debug,
    Communicate,
    Lifecycle,
    Govern,
}

/// Structured result of scanning a single trajectory event.
#[must_use]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EventScanResult {
    /// Step-by-step reasoning about this event BEFORE assigning the grade.
    pub explanation: String,
    /// The structural message type.
    pub message_type: MessageType,
    /// The inferred intent.
    pub intent: AgentIntent,
    /// A concise one-sentence description of what happened.
    pub description: String,
    /// Key entities referenced: file paths, tool names, URLs, commands.
    #[serde(default)]
    pub key_entities: Vec<String>,
    /// Whether this event produces side effects.
    pub is_side_effecting: bool,
    /// Signals detected in this event.
    #[serde(default)]
    pub signals: Vec<Signal>,
    /// Scanner confidence in this classification (0.0 to 1.0).
    pub confidence: f64,
    /// Embedding vector of the `description` field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schemars(skip)]
    pub embedding: Option<Vec<f64>>,
}

// ============================================================================
// Transcript-level scan types
// ============================================================================

/// Hierarchical summary of an entire trajectory transcript.
///
/// Groups events into logical phases and extracts key statistics.
/// This is the transcript-level summarization layer — it answers
/// "what did the agent do?" without making judgments about risk.
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct TranscriptDigest {
    /// The trajectory ID being summarized.
    pub trajectory_id: String,
    /// A short title (under 80 chars) capturing the primary task.
    pub title: String,
    /// A 1-3 sentence narrative of what the agent did from start to finish.
    pub summary: String,
    /// True when this digest summarizes an active trajectory before a terminal
    /// control event. Final terminal digests leave this false.
    #[serde(default)]
    pub interim: bool,
    /// Logical phases of work detected in the transcript.
    #[serde(default)]
    pub phases: Vec<TranscriptPhase>,
    /// Distinct file paths that were modified (written, edited, or deleted).
    #[serde(default)]
    pub files_modified: Vec<String>,
    /// Distinct tool names used during the trajectory.
    #[serde(default)]
    pub tools_used: Vec<String>,
    /// Total number of events in the transcript.
    pub total_events: u32,
    /// Count of events that produced side effects.
    pub side_effecting_count: u32,
}

/// A logical work phase within a trajectory transcript.
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct TranscriptPhase {
    /// Short name: "Investigation", "Implementation", "Verification", etc.
    pub name: String,
    /// One-sentence description of what happened in this phase.
    pub description: String,
    /// Event indices (0-based) belonging to this phase.
    #[serde(default)]
    pub event_indices: Vec<u32>,
}

/// Outcome assessment of the trajectory transcript.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum TranscriptOutcome {
    /// Agent completed the task successfully.
    Success,
    /// Agent completed but with partial results or workarounds.
    Partial,
    /// Agent failed to complete the task.
    Failure,
    /// Agent was terminated or suspended before completion.
    Interrupted,
    /// Trajectory is still in progress (no terminal control event).
    InProgress,
}

/// A transcript-level behavioral scan paired with the event that triggered it.
///
/// [`TranscriptScanResult`] is the scanner's output; this adds the provenance a
/// reader needs to point back at the event the scan was run from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TranscriptScan {
    /// Id of the trajectory event the scan was triggered by.
    pub source_event_id: String,
    /// The transcript-level behavioral scan result.
    pub result: TranscriptScanResult,
}

/// Full behavioral scan of a trajectory transcript.
///
/// This is the transcript-level scanner — it answers "how did the agent
/// behave?" and "what signals should we flag?" Uses the AISI signal
/// taxonomy to detect patterns across the full event sequence.
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct TranscriptScanResult {
    /// Step-by-step reasoning about the trajectory BEFORE assigning grades.
    pub explanation: String,
    /// Overall outcome of the trajectory.
    pub outcome: TranscriptOutcome,
    /// One-sentence description of the trajectory outcome.
    pub outcome_description: String,
    /// Aggregate severity across all detected signals.
    pub aggregate_severity: SignalSeverity,
    /// Signals detected across the full transcript.
    #[serde(default)]
    pub signals: Vec<Signal>,
    /// Summary of policy adjudication events in the trajectory.
    pub adjudication_summary: String,
    /// Notable behavioral observations about the agent's approach.
    #[serde(default)]
    pub behavioral_notes: Vec<String>,
    /// Scanner confidence in the overall assessment (0.0 to 1.0).
    pub confidence: f64,
}

// ============================================================================
// Scanned control-event payload
// ============================================================================

/// Result of LLM-based scanning at message or transcript level.
///
/// Emitted as the [`Control::Scanned`](super::Control::Scanned) event when the
/// trajectory scanner finishes analysing an event or transcript.  The payload is
/// stored both in the control event (for the trajectory log) and in the
/// dedicated results table (for querying).
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "scan_type", content = "data")]
pub enum Scanned {
    /// Message-level event scan result.
    Message {
        /// The event_id that was scanned (causality source).
        source_event_id: String,
        /// Structured scan result from the trajectory scanner.
        result: EventScanResult,
    },
    /// Transcript-level hierarchical digest.
    TranscriptDigest {
        /// The event_id that triggered this scan (causality source).
        source_event_id: String,
        /// Structured digest of the trajectory transcript.
        result: TranscriptDigest,
    },
    /// Transcript-level behavioral scan.
    TranscriptScan {
        /// The event_id that triggered this scan (causality source).
        source_event_id: String,
        /// Full behavioral scan result.
        result: TranscriptScanResult,
    },
}

impl Scanned {
    /// Create a Message scan result (backward compatible with old `Scanned::new`).
    pub fn new(source_event_id: impl Into<String>, result: EventScanResult) -> Self {
        Self::message(source_event_id, result)
    }

    /// Create a Message-level scan result.
    pub fn message(source_event_id: impl Into<String>, result: EventScanResult) -> Self {
        Self::Message {
            source_event_id: source_event_id.into(),
            result,
        }
    }

    /// Create a TranscriptDigest scan result.
    pub fn transcript_digest(source_event_id: impl Into<String>, result: TranscriptDigest) -> Self {
        Self::TranscriptDigest {
            source_event_id: source_event_id.into(),
            result,
        }
    }

    /// Create a TranscriptScan scan result.
    pub fn transcript_scan(
        source_event_id: impl Into<String>,
        result: TranscriptScanResult,
    ) -> Self {
        Self::TranscriptScan {
            source_event_id: source_event_id.into(),
            result,
        }
    }

    /// The message-level scan result, when this is a `Message` scan.
    pub fn event_scan_result(&self) -> Option<&EventScanResult> {
        match self {
            Self::Message { result, .. } => Some(result),
            _ => None,
        }
    }

    /// The hierarchical digest, when this is a `TranscriptDigest` scan.
    pub fn transcript_digest_result(&self) -> Option<&TranscriptDigest> {
        match self {
            Self::TranscriptDigest { result, .. } => Some(result),
            _ => None,
        }
    }

    /// The behavioral scan result, when this is a `TranscriptScan`.
    pub fn transcript_scan_result(&self) -> Option<&TranscriptScanResult> {
        match self {
            Self::TranscriptScan { result, .. } => Some(result),
            _ => None,
        }
    }

    /// Get the source event ID regardless of variant.
    pub fn source_event_id(&self) -> &str {
        match self {
            Self::Message {
                source_event_id, ..
            } => source_event_id,
            Self::TranscriptDigest {
                source_event_id, ..
            } => source_event_id,
            Self::TranscriptScan {
                source_event_id, ..
            } => source_event_id,
        }
    }
}

// ============================================================================
// Scan store surface
// ============================================================================

/// Where a scan came from: the event that triggered it, plus the run and agent
/// it belongs to.
///
/// A struct rather than three positional `&str` arguments because two of them
/// are ids of the same shape — an `(event_id, trajectory_id)` pair swapped at a
/// call site would key a scan to the wrong row and fail silently, since both
/// are valid strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanSource<'a> {
    /// Id of the trajectory event the scan was triggered by. For a
    /// message-level scan this is the event that was scanned; for a
    /// transcript-level scan it is the event that triggered the scan.
    pub event_id: &'a str,
    /// Bare id of the run the scan describes.
    pub trajectory_id: &'a str,
    /// Bare id of the agent that produced the run.
    pub agent_id: &'a str,
}

impl<'a> ScanSource<'a> {
    /// The provenance of a scan triggered by `event`.
    #[must_use]
    pub fn of(event: &'a super::Event) -> Self {
        Self {
            event_id: &event.event_id,
            trajectory_id: &event.trajectory_id,
            agent_id: &event.agent.id,
        }
    }
}

/// The transcript-level scan results recorded for one run.
///
/// Both are `None` until the scanner has produced them, which is the normal
/// state for a run in flight and the permanent state for every run when no
/// scanner is configured.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TrajectoryScans {
    /// Latest hierarchical digest. A run accumulates several over its lifetime
    /// — interim digests plus a terminal one — and the most recent wins.
    pub digest: Option<TranscriptDigest>,
    /// Latest transcript-level behavioral scan, with the event that triggered
    /// it.
    pub scan: Option<TranscriptScan>,
}

impl TrajectoryScans {
    /// Whether the scanner has produced anything at all for this run.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.digest.is_none() && self.scan.is_none()
    }
}

/// The scan store surface: the harness's background scanner writes, the console
/// read path joins.
///
/// Separate from
/// [`TrajectoryReaderWriter`](super::TrajectoryReaderWriter) because the two
/// have different writers and different failure semantics. Trajectory events
/// are written on the adjudication path and losing one loses audit evidence;
/// scans are written by a background task and losing one costs a summary. A
/// store implements both over the same database, but a caller that only needs
/// enrichment should not have to name the ledger surface to get it.
pub trait ScanReaderWriter: Send + Sync {
    // ── Writes (background scanner) ──────────────────────────────────────────

    /// Record a message-level scan for one event.
    ///
    /// Keyed by [`ScanSource::event_id`]: an event has at most one scan, and
    /// re-scanning replaces it.
    fn insert_event_scan(
        &self,
        source: ScanSource<'_>,
        result: &EventScanResult,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Record a transcript digest for one run.
    ///
    /// Keyed by [`ScanSource::event_id`], not by run: interim digests and the
    /// terminal digest are separate rows, and reads take the most recent.
    fn insert_transcript_digest(
        &self,
        source: ScanSource<'_>,
        digest: &TranscriptDigest,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Record a transcript-level behavioral scan for one run.
    fn insert_transcript_scan(
        &self,
        source: ScanSource<'_>,
        scan: &TranscriptScanResult,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    // ── Reads (console projections) ──────────────────────────────────────────

    /// Every message-level scan recorded for one run, keyed by the id of the
    /// event it describes.
    ///
    /// A map rather than a list because the only consumer folds these onto
    /// events by id.
    fn event_scans(
        &self,
        trajectory_id: &str,
    ) -> impl Future<Output = Result<HashMap<String, EventScanResult>, StoreError>> + Send;

    /// The latest digest and behavioral scan for one run.
    fn transcript_scans(
        &self,
        trajectory_id: &str,
    ) -> impl Future<Output = Result<TrajectoryScans, StoreError>> + Send;

    /// The latest digest and behavioral scan for every run that has one, keyed
    /// by run id.
    ///
    /// The batch form exists so a list read joins with a bounded number of
    /// queries instead of one per row.
    fn latest_transcript_scans(
        &self,
    ) -> impl Future<Output = Result<HashMap<String, TrajectoryScans>, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_provenance_is_read_off_the_triggering_event() {
        use crate::trajectory::{Observation, Thought, TrajectoryEvent};
        use crate::{Agent, Event};

        let event = Event::new(
            Agent::new("agent-1", "test", "test"),
            "run-1",
            TrajectoryEvent::Observation(Observation::Thought(Thought::new("hm"))),
        );

        let source = ScanSource::of(&event);
        assert_eq!(source.event_id, event.event_id);
        assert_eq!(source.trajectory_id, "run-1");
        assert_eq!(source.agent_id, "agent-1");
    }

    #[test]
    fn a_run_with_no_scans_reports_empty_rather_than_a_default_digest() {
        // "not scanned yet" and "scanned, found nothing" are different claims;
        // only the first is representable as absent.
        assert!(TrajectoryScans::default().is_empty());
        assert!(
            !TrajectoryScans {
                digest: Some(TranscriptDigest {
                    trajectory_id: "run-1".to_string(),
                    title: "Did a thing".to_string(),
                    summary: String::new(),
                    interim: false,
                    phases: Vec::new(),
                    files_modified: Vec::new(),
                    tools_used: Vec::new(),
                    total_events: 0,
                    side_effecting_count: 0,
                }),
                scan: None,
            }
            .is_empty()
        );
    }

    #[test]
    fn transcript_digest_serde_roundtrip() {
        let digest = TranscriptDigest {
            trajectory_id: "traj-1".to_string(),
            title: "Added user auth".to_string(),
            summary: "Implemented JWT auth flow.".to_string(),
            interim: false,
            phases: vec![TranscriptPhase {
                name: "Implementation".to_string(),
                description: "Wrote auth middleware".to_string(),
                event_indices: vec![0, 1, 2, 3, 4],
            }],
            files_modified: vec!["src/auth.rs".to_string()],
            tools_used: vec!["Write".to_string(), "Bash".to_string()],
            total_events: 8,
            side_effecting_count: 4,
        };

        let json = serde_json::to_string(&digest).unwrap();
        let parsed: TranscriptDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.trajectory_id, "traj-1");
        assert_eq!(parsed.phases.len(), 1);
        assert_eq!(parsed.phases[0].event_indices.len(), 5);
    }

    #[test]
    fn transcript_scan_result_serde_roundtrip() {
        let scan = TranscriptScanResult {
            explanation: "Agent completed task normally.".to_string(),
            outcome: TranscriptOutcome::Success,
            outcome_description: "Completed successfully.".to_string(),
            aggregate_severity: SignalSeverity::Low,
            signals: vec![Signal {
                focus: SignalFocus::Agent,
                category: SignalCategory::LowLevelIncoherence,
                severity: SignalSeverity::Low,
                description: "Agent retried same command 3 times".to_string(),
                evidence_indices: vec![4, 5, 6],
            }],
            adjudication_summary: "No adjudication events.".to_string(),
            behavioral_notes: vec!["Systematic approach".to_string()],
            confidence: 0.85,
        };

        let json = serde_json::to_string(&scan).unwrap();
        let parsed: TranscriptScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.outcome, TranscriptOutcome::Success);
        assert_eq!(parsed.aggregate_severity, SignalSeverity::Low);
        assert_eq!(parsed.signals.len(), 1);
        assert!(parsed.confidence > 0.8);
    }

    #[test]
    fn transcript_outcome_serde() {
        assert_eq!(
            serde_json::to_string(&TranscriptOutcome::Interrupted).unwrap(),
            r#""Interrupted""#
        );
    }

    #[test]
    fn transcript_scan_result_json_schema() {
        use schemars::schema_for;

        let schema = schema_for!(TranscriptScanResult);
        let json = serde_json::to_string_pretty(&schema).unwrap();

        assert!(json.contains("explanation"));
        assert!(json.contains("outcome"));
        assert!(json.contains("aggregate_severity"));
        assert!(json.contains("signals"));
        assert!(json.contains("confidence"));
        assert!(json.contains("adjudication_summary"));
    }
}
