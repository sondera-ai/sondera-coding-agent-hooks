//! Trajectory domain: events, storage traits, and scan results.
//!
//! A trajectory is the sequence of execution steps an agent takes. This module
//! gathers everything that describes and persists those steps:
//!
//! - **Events** (`event`): the perception-action loop. The [`Event`] envelope
//!   wraps a [`TrajectoryEvent`] in one of four categories, each in its own
//!   sibling module:
//!   - [`Action`] (`action`): agent-initiated operations (tool calls, shell
//!     commands, file ops, web fetches).
//!   - [`Observation`] (`observation`): environment responses (tool/command
//!     output, prompts, reasoning).
//!   - [`Control`] (`control`): lifecycle events (started, completed, failed,
//!     adjudicated, scanned).
//!   - [`State`] (`state`): context snapshots (working directory, git branch,
//!     open files).
//!
//!   Cedar policies are evaluated against these events to produce [`Adjudicated`]
//!   decisions.
//! - **Status** (`status`): [`TrajectoryStatus`], the lifecycle vocabulary
//!   derived from a run's control events.
//! - **Run rollups** (`summary`): [`Trajectory`], one run rolled up from its
//!   events, the [`EventDetail`] governance fold, and the
//!   [`TrajectoryReaderWriter`] store surface those projections are read
//!   through.
//! - **Scan results** (`scan`): the structured output of the trajectory
//!   scanner ([`EventScanResult`], [`TranscriptDigest`], [`TranscriptScanResult`]).
//! - **Redaction** (`redact`): [`Event::redact_file_content`], which strips the
//!   file bodies an event carried for adjudication before it is written to the
//!   ledger, leaving a [`redaction_marker`] in their place.
//!
//! Submodules are private; the curated public surface is the explicit re-export
//! list below. Callers reach these types via `sondera_types::<Type>` (the
//! crate-root glob re-export) or `sondera_types::trajectory::<Type>`.

mod action;
mod control;
mod event;
mod observation;
mod redact;
mod scan;
mod state;
mod status;
mod summary;

pub use action::{Action, FileOpType, FileOperation, ShellCommand, ToolCall, WebFetch};
pub use control::{
    Adjudicated, Completed, Control, Failed, Resumed, Started, Steering, Suspended, Terminated,
};
pub use event::{Actor, ActorType, AdjudicatedEvent, Causality, Event, TrajectoryEvent};
pub use observation::{
    FileOperationResult, Observation, Prompt, PromptRole, ShellCommandOutput, Thought, ToolOutput,
    WebFetchOutput,
};
pub use redact::redaction_marker;
pub use scan::{
    AgentIntent, EventScanResult, MessageType, ScanReaderWriter, ScanSource, Scanned, Signal,
    SignalCategory, SignalFocus, SignalSeverity, TrajectoryScans, TranscriptDigest,
    TranscriptOutcome, TranscriptPhase, TranscriptScan, TranscriptScanResult,
};
pub use state::{Snapshot, State};
pub use status::TrajectoryStatus;
pub use summary::{
    EventDetail, Trajectory, TrajectoryEventStream, TrajectoryFilter, TrajectoryOrderBy,
    TrajectoryQuery, TrajectoryReaderWriter, TrajectoryStream, adjudication_policy_hit,
    decision_severity, fold_event_details, run_decision, run_policy_hits,
};
