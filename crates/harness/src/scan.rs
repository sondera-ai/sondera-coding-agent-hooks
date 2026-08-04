//! Background trajectory scanning off the adjudication path.
//!
//! The harness serves one job: adjudicate an event and answer. Scanning is
//! enrichment layered on top — it classifies what an agent did, summarizes a
//! run, and flags behavioral signals — and it costs a model round trip, which
//! is orders of magnitude slower than a Cedar evaluation. So it never runs
//! inline. [`ScanDispatcher::dispatch`] spawns detached tokio tasks and returns
//! immediately; the RPC that triggered it has already answered by the time the
//! first scan starts.
//!
//! Three consequences follow from that, and they are the whole design:
//!
//! - **A scan can never change a decision.** It runs after the verdict is
//!   returned. Nothing here is reachable from the enforcement path, and nothing
//!   here may become reachable from it.
//! - **A scan is allowed to be lost.** A provider outage, a timeout, or a full
//!   concurrency limiter drops the scan with a log line. Losing a trajectory
//!   event loses audit evidence; losing a scan loses a summary.
//! - **Scans must not outpace the harness.** Each spawned task holds a permit
//!   from a bounded semaphore, so a burst of events cannot open unbounded
//!   concurrent model calls. When the permits are gone, the scan is skipped
//!   rather than queued: a backlog of stale scans is worth less than the
//!   memory it would hold.
//!
//! Each scan is written twice, deliberately: to its table via
//! [`ScanReaderWriter`](crate::types::ScanReaderWriter) (the read path the
//! console joins) and to the trajectory
//! ledger as a `Control::Scanned` event (the complete record of what happened
//! to a run). The table write happens first — the control event is only emitted
//! once the authoritative payload is durable, so a reader never sees a ledger
//! event pointing at a scan that was never stored.

use crate::types::Event;

/// Fire-and-forget dispatch of the scans an event warrants.
///
/// Object-safe on purpose: [`HarnessGrpcService`](crate::rpc::HarnessGrpcService)
/// holds one of these as `Arc<dyn ScanDispatch>` so the transport stays generic
/// over the harness alone and does not grow a store type parameter. It also
/// means the `scanner` feature can be off — and `sondera-trajectory` unlinked —
/// without the transport changing shape.
pub trait ScanDispatch: Send + Sync {
    /// Start whatever scans `event` warrants, returning without awaiting them.
    ///
    /// Called once per adjudicated event, after the verdict has been produced
    /// and the event persisted. Implementations must not block: everything
    /// past the decision of *what* to scan belongs in a spawned task.
    ///
    /// Takes the event by value because the spawned task outlives this call and
    /// therefore has to own it. An `Event` can carry a whole file's contents or
    /// a command's stdout, so borrowing here would only move the clone to the
    /// caller.
    fn dispatch(&self, event: Event);
}

#[cfg(feature = "scanner")]
pub use dispatcher::{DEFAULT_MAX_CONCURRENT_SCANS, ScanDispatcher};

#[cfg(feature = "scanner")]
mod dispatcher {
    use super::ScanDispatch;
    use crate::types::{
        Actor, Causality, Control, Event, EventScanResult, ScanReaderWriter, ScanSource, Scanned,
        StoreError, TrajectoryEvent, TrajectoryReaderWriter, TranscriptDigest,
        TranscriptScanResult,
    };
    use sondera_trajectory::{
        ScannerError, TrajectoryScanner, TrajectoryScannerBackend, is_scanner_output,
    };
    use std::future::Future;
    use std::sync::Arc;
    use tokio::sync::{OwnedSemaphorePermit, Semaphore};
    use tracing::{Instrument, Span, info_span, warn};

    /// Concurrent background scans allowed per harness process.
    ///
    /// Small on purpose. This is a developer machine running a local model as
    /// often as it is a server, and the scanner competes with the agent it is
    /// observing for the same GPU. Raise it with
    /// [`ScanDispatcher::max_concurrency`] when the provider is remote.
    pub const DEFAULT_MAX_CONCURRENT_SCANS: usize = 4;

    /// The actor recorded on every `Control::Scanned` event the harness emits.
    const SCANNER_ACTOR: &str = "trajectory-scanner";

    /// Runs the trajectory scanner in the background and persists what it
    /// produces.
    pub struct ScanDispatcher<S> {
        scanner: Arc<dyn TrajectoryScannerBackend>,
        store: Arc<S>,
        permits: Arc<Semaphore>,
    }

    impl<S> ScanDispatcher<S> {
        /// Dispatch scans from `scanner`, persisting through `store`.
        pub fn new(scanner: Arc<dyn TrajectoryScannerBackend>, store: Arc<S>) -> Self {
            Self {
                scanner,
                store,
                permits: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_SCANS)),
            }
        }

        /// Cap concurrent background scans. Zero is raised to one — a
        /// dispatcher configured to run nothing should not be built at all.
        #[must_use]
        pub fn max_concurrency(mut self, max: usize) -> Self {
            self.permits = Arc::new(Semaphore::new(max.max(1)));
            self
        }

        /// Take a permit, or `None` when every one is in use.
        ///
        /// Never waits. A dispatcher that blocked here would push provider
        /// latency back onto the caller — which is exactly what running off the
        /// adjudication path exists to prevent.
        fn permit(&self, kind: &'static str, event: &Event) -> Option<OwnedSemaphorePermit> {
            match Arc::clone(&self.permits).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    warn!(
                        scan.kind = kind,
                        event.id = %event.event_id,
                        trajectory.id = %event.trajectory_id,
                        "Skipping background scan: concurrency limit reached"
                    );
                    None
                }
            }
        }
    }

    impl<S> ScanDispatch for ScanDispatcher<S>
    where
        S: TrajectoryReaderWriter + ScanReaderWriter + 'static,
    {
        fn dispatch(&self, event: Event) {
            // A scan is itself written back to the ledger as a `Control::Scanned`
            // event. Scanning one would have the scanner grade its own output
            // and emit another, which is a loop with a model call in it.
            if is_scanner_output(&event) {
                return;
            }

            // The transcript paths run first so they can clone, leaving the
            // message-level scan — the one every event takes — to consume the
            // original. Only a terminal event or a turn end pays for a copy.
            if TrajectoryScanner::should_scan_transcript_for_event(&event) {
                self.dispatch_transcript_scan(event.clone());
            } else if TrajectoryScanner::should_digest_interim_transcript_for_event(&event) {
                // Only when the run is *not* terminal: the terminal path already
                // writes a final digest, and running both would spend two model
                // calls to have the second overwrite the first.
                self.dispatch_interim_digest(event.clone());
            }

            self.dispatch_event_scan(event);
        }
    }

    impl<S> ScanDispatcher<S>
    where
        S: TrajectoryReaderWriter + ScanReaderWriter + 'static,
    {
        /// Spawn one background scan, holding a permit for as long as it runs.
        ///
        /// Every scan kind goes through here so the permit, the detached spawn,
        /// and the span attachment are decided once. A kind that acquired its
        /// own permit — or forgot to — would break the concurrency bound the
        /// module contract rests on.
        fn spawn_scan<F, Fut>(&self, kind: &'static str, span: Span, event: Event, run: F)
        where
            F: FnOnce(Arc<dyn TrajectoryScannerBackend>, Arc<S>, Event) -> Fut + Send + 'static,
            Fut: Future<Output = ()> + Send,
        {
            let Some(permit) = self.permit(kind, &event) else {
                return;
            };
            let scanner = Arc::clone(&self.scanner);
            let store = Arc::clone(&self.store);

            tokio::spawn(
                async move {
                    let _permit = permit;
                    run(scanner, store, event).await;
                }
                .instrument(span),
            );
        }

        /// Classify one event, message-level.
        fn dispatch_event_scan(&self, event: Event) {
            self.spawn_scan(
                "event",
                scan_span("trajectory.event_scan", &event),
                event,
                |scanner, store, event| async move {
                    match scanner.scan_event(&event).await {
                        Ok(result) => record_event_scan(&*store, &event, result).await,
                        Err(error) => report(&*scanner, "event_scan", &event, &error),
                    }
                },
            );
        }

        /// Digest and behaviorally scan a finished run.
        ///
        /// One task rather than two: both need the same transcript, and loading
        /// a run's events twice to save a little wall clock is the wrong trade
        /// when the model call dominates either way.
        fn dispatch_transcript_scan(&self, event: Event) {
            self.spawn_scan(
                "transcript",
                scan_span("trajectory.transcript_scan", &event),
                event,
                |scanner, store, event| async move {
                    let Some(events) = transcript(&*store, &event).await else {
                        return;
                    };

                    match scanner
                        .digest_transcript(&event.trajectory_id, &events)
                        .await
                    {
                        Ok(digest) => record_digest(&*store, &event, digest).await,
                        Err(error) => report(&*scanner, "transcript_digest", &event, &error),
                    }

                    // The behavioral scan runs even if the digest failed: they
                    // answer different questions ("what happened" vs. "what
                    // should worry us"), and the second is the governance one.
                    match scanner.scan_transcript(&event.trajectory_id, &events).await {
                        Ok(scan) => record_transcript_scan(&*store, &event, scan).await,
                        Err(error) => report(&*scanner, "transcript_scan", &event, &error),
                    }
                },
            );
        }

        /// Refresh the digest of a run that is still going.
        fn dispatch_interim_digest(&self, event: Event) {
            self.spawn_scan(
                "interim_digest",
                scan_span("trajectory.interim_transcript_digest", &event),
                event,
                |scanner, store, event| async move {
                    let Some(events) = transcript(&*store, &event).await else {
                        return;
                    };

                    match scanner
                        .digest_interim_transcript(&event.trajectory_id, &events)
                        .await
                    {
                        Ok(digest) => record_digest(&*store, &event, digest).await,
                        Err(error) => {
                            report(&*scanner, "interim_transcript_digest", &event, &error);
                        }
                    }
                },
            );
        }
    }

    /// The span every background scan runs under.
    ///
    /// Built at the dispatch site rather than inside the task: `info_span!`
    /// needs a literal name, and the fields have to be read before the event
    /// moves into the closure.
    fn scan_span(name: &'static str, event: &Event) -> Span {
        info_span!(
            "scan",
            otel.name = name,
            agent.id = %event.agent.id,
            event.id = %event.event_id,
            trajectory.id = %event.trajectory_id,
        )
    }

    /// Persist a message-level scan, then append its ledger record.
    async fn record_event_scan<S>(store: &S, event: &Event, result: EventScanResult)
    where
        S: TrajectoryReaderWriter + ScanReaderWriter,
    {
        if persisted(
            store
                .insert_event_scan(ScanSource::of(event), &result)
                .await,
            event,
            "event scan",
        ) {
            emit_scanned(store, event, Scanned::message(&event.event_id, result)).await;
        }
    }

    /// Persist a transcript digest, then append its ledger record.
    async fn record_digest<S>(store: &S, event: &Event, digest: TranscriptDigest)
    where
        S: TrajectoryReaderWriter + ScanReaderWriter,
    {
        if persisted(
            store
                .insert_transcript_digest(ScanSource::of(event), &digest)
                .await,
            event,
            "transcript digest",
        ) {
            emit_scanned(
                store,
                event,
                Scanned::transcript_digest(&event.event_id, digest),
            )
            .await;
        }
    }

    /// Persist a behavioral transcript scan, then append its ledger record.
    async fn record_transcript_scan<S>(store: &S, event: &Event, scan: TranscriptScanResult)
    where
        S: TrajectoryReaderWriter + ScanReaderWriter,
    {
        if persisted(
            store
                .insert_transcript_scan(ScanSource::of(event), &scan)
                .await,
            event,
            "transcript scan",
        ) {
            emit_scanned(
                store,
                event,
                Scanned::transcript_scan(&event.event_id, scan),
            )
            .await;
        }
    }

    /// Whether a scan reached its table, logging the failure if it did not.
    ///
    /// The return value gates the ledger record: emitting `Control::Scanned`
    /// for a scan that was never stored would leave a reader following a
    /// pointer to nothing.
    fn persisted(result: Result<(), StoreError>, event: &Event, what: &'static str) -> bool {
        match result {
            Ok(()) => true,
            Err(error) => {
                warn!(
                    event.id = %event.event_id,
                    trajectory.id = %event.trajectory_id,
                    error = %error,
                    "Failed to persist {what}"
                );
                false
            }
        }
    }

    /// Load a run's events, or `None` when there are none to scan.
    async fn transcript<S: TrajectoryReaderWriter>(store: &S, event: &Event) -> Option<Vec<Event>> {
        match store.trajectory_events(&event.trajectory_id).await {
            Ok(events) if !events.is_empty() => Some(events),
            Ok(_) => {
                warn!(
                    trajectory.id = %event.trajectory_id,
                    "No events found for transcript scan"
                );
                None
            }
            Err(error) => {
                warn!(
                    trajectory.id = %event.trajectory_id,
                    error = %error,
                    "Failed to load trajectory for transcript scan"
                );
                None
            }
        }
    }

    /// Append the `Control::Scanned` record for a scan already persisted to its
    /// table.
    ///
    /// Causally linked to the event that triggered it, so the console's fold
    /// hides it and attaches it to that event instead of rendering a bare
    /// governance row.
    async fn emit_scanned<S: TrajectoryReaderWriter>(store: &S, event: &Event, scanned: Scanned) {
        let record = Event::new(
            event.agent.clone(),
            &event.trajectory_id,
            TrajectoryEvent::Control(Control::Scanned(scanned)),
        )
        .with_actor(Actor::system(SCANNER_ACTOR))
        .with_causality(Causality::default().caused_by(&event.event_id));

        if let Err(error) = store.insert_event(&record).await {
            warn!(
                event.id = %event.event_id,
                error = %error,
                "Failed to append the scanned control event"
            );
        }
    }

    /// Log a failed scan.
    ///
    /// Logs [`ScannerError::kind`] rather than the rendered error: an
    /// extraction failure quotes the model output that failed to parse, which
    /// is trajectory content and does not belong in a log field anything
    /// aggregates.
    fn report(
        scanner: &dyn TrajectoryScannerBackend,
        kind: &'static str,
        event: &Event,
        error: &ScannerError,
    ) {
        warn!(
            scan.kind = kind,
            event.id = %event.event_id,
            trajectory.id = %event.trajectory_id,
            provider = scanner.provider_name(),
            model = scanner.model(),
            error.kind = error.kind(),
            "Background trajectory scan failed"
        );
    }
}
