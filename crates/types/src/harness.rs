use crate::{Adjudicated, Event, HarnessClientError, HarnessError};
use std::future::Future;

type HarnessResult<T> = std::result::Result<T, HarnessError>;
type ClientResult<T> = std::result::Result<T, HarnessClientError>;

/// Core interface for the Sondera harness service.
///
pub trait Harness: Send + Sync {
    /// Add a step to a trajectory and return the adjudicated result.
    ///
    /// The harness evaluates the step against configured policies and guardrails,
    /// returning an `AdjudicatedStep` with the decision (Allow/Deny/Escalate).
    fn adjudicate(&self, event: Event) -> impl Future<Output = HarnessResult<Adjudicated>> + Send;
}

/// Core client interface for the Sondera harness service.
///
/// Implementations of this trait provide trajectory management and policy
/// adjudication for AI agent governance. The gRPC `Client` is the primary
/// implementation, but this trait enables alternative backends (e.g., in-memory
/// for testing).
pub trait HarnessClient: Send + Sync {
    /// Add a step to a trajectory and return the adjudicated result.
    ///
    /// The harness evaluates the step against configured policies and guardrails,
    /// returning an `AdjudicatedStep` with the decision (Allow/Deny/Escalate).
    fn adjudicate(&self, event: Event) -> impl Future<Output = ClientResult<Adjudicated>> + Send;

    /// Add multiple steps to a trajectory and return their adjudicated results.
    ///
    /// Implementations may override this to use a transport-level batch RPC.
    /// The default preserves existing in-memory test harness behavior.
    fn adjudicates(
        &self,
        events: Vec<Event>,
    ) -> impl Future<Output = ClientResult<Vec<Adjudicated>>> + Send {
        async move {
            let mut results = Vec::with_capacity(events.len());
            for event in events {
                results.push(self.adjudicate(event).await?);
            }
            Ok(results)
        }
    }
}

/// Kind of asynchronous trajectory scan task produced during adjudication.
///
/// The label is the stable identity used for metrics, structured logging, and
/// worker queue routing; keep it in sync with the worker's permit dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanTaskKind {
    /// Scan a single source event.
    EventScan,
    /// Produce an interim or terminal transcript digest.
    TranscriptDigest,
    /// Scan a full transcript.
    TranscriptScan,
}

impl ScanTaskKind {
    /// Stable lowercase label for metrics, logging, and queue routing.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::EventScan => "event_scan",
            Self::TranscriptDigest => "transcript_digest",
            Self::TranscriptScan => "transcript_scan",
        }
    }
}

/// Identifier-only request to enqueue an asynchronous scan task.
///
/// Carries durable identifiers only: a [`HarnessTaskProducer`] never ships raw
/// transcript or event payloads. The worker reloads trajectory data from storage
/// before any provider call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanTaskRequest {
    /// Durable trajectory identifier containing the event or transcript to scan.
    pub trajectory_id: String,
    /// Source event that triggered the scan.
    pub source_event_id: String,
    /// Agent associated with the trajectory.
    pub agent_id: String,
    /// Which scan the worker should run.
    pub kind: ScanTaskKind,
    /// Whether the worker should append a `Control::Scanned` event afterwards.
    pub emit_scanned_event: bool,
}

/// Port for producing asynchronous harness worker tasks.
///
/// The policy engine depends on this abstraction so the Cedar harness stays free
/// of queue transport (Pub/Sub) and wire (`HarnessTask` proto) concerns. The
/// concrete Pub/Sub adapter lives in the harness service layer and is wired in by
/// the harness binary.
pub trait HarnessTaskProducer: Send + Sync {
    /// Fire-and-forget enqueue of a scan task.
    ///
    /// Implementations must return promptly without blocking the caller (the
    /// request-serving adjudication path); transport failures are surfaced through
    /// the implementation's own telemetry rather than to the caller.
    fn produce_scan_task(&self, request: ScanTaskRequest);
}
