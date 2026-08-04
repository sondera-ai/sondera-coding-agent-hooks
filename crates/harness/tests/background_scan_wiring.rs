//! What the background scanner is wired to do once it produces a result.
//!
//! The scanner itself is exercised in `sondera-trajectory`; these tests own the
//! seam between it and the store. A stub backend returns fixed results
//! instantly, so what is under test is the dispatcher's decisions — which
//! events it scans, which table each result lands in, and what it appends to
//! the ledger — rather than a model's output.
//!
//! Every assertion polls: `dispatch` is fire-and-forget by design, so a test
//! that read the store immediately would be racing the task it spawned.

#![cfg(feature = "scanner")]

use sondera_harness::scan::{ScanDispatch, ScanDispatcher};
use sondera_harness::{
    Action, Agent, AgentIntent, Completed, Control, Event, EventScanResult, MessageType,
    Observation, ScanReaderWriter, Scanned, ShellCommand, SignalSeverity, Thought, TrajectoryEvent,
    TrajectoryReaderWriter, TranscriptDigest, TranscriptOutcome, TranscriptScanResult,
};
use sondera_storage::TrajectoryStore;
use sondera_trajectory::{ScannerError, ScannerFuture, TrajectoryScannerBackend};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A scanner that returns fixed results and counts what it was asked to do.
struct StubScanner {
    event_scans: AtomicUsize,
    digests: AtomicUsize,
    transcript_scans: AtomicUsize,
    interim_digests: AtomicUsize,
}

impl StubScanner {
    fn new() -> Self {
        Self {
            event_scans: AtomicUsize::new(0),
            digests: AtomicUsize::new(0),
            transcript_scans: AtomicUsize::new(0),
            interim_digests: AtomicUsize::new(0),
        }
    }
}

fn event_scan_result() -> EventScanResult {
    EventScanResult {
        explanation: "A destructive shell command.".to_string(),
        message_type: MessageType::ToolCall,
        intent: AgentIntent::Implement,
        description: "Ran 'rm -rf /tmp/data'".to_string(),
        key_entities: vec!["/tmp/data".to_string()],
        is_side_effecting: true,
        signals: Vec::new(),
        confidence: 0.95,
        embedding: None,
    }
}

fn digest_result(trajectory_id: &str, interim: bool) -> TranscriptDigest {
    TranscriptDigest {
        trajectory_id: trajectory_id.to_string(),
        title: if interim {
            "Working on it".to_string()
        } else {
            "Cleaned up /tmp".to_string()
        },
        summary: "Removed a scratch directory.".to_string(),
        interim,
        phases: Vec::new(),
        files_modified: Vec::new(),
        tools_used: vec!["Bash".to_string()],
        total_events: 2,
        side_effecting_count: 1,
    }
}

fn transcript_scan_result() -> TranscriptScanResult {
    TranscriptScanResult {
        explanation: "The agent removed a directory and stopped.".to_string(),
        outcome: TranscriptOutcome::Success,
        outcome_description: "Completed.".to_string(),
        aggregate_severity: SignalSeverity::Medium,
        signals: Vec::new(),
        adjudication_summary: "No adjudication events.".to_string(),
        behavioral_notes: vec!["Systematic".to_string()],
        confidence: 0.88,
    }
}

impl TrajectoryScannerBackend for StubScanner {
    fn scan_event<'a>(&'a self, _event: &'a Event) -> ScannerFuture<'a, EventScanResult> {
        self.event_scans.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(event_scan_result()) })
    }

    fn digest_transcript<'a>(
        &'a self,
        trajectory_id: &'a str,
        _events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptDigest> {
        self.digests.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(digest_result(trajectory_id, false)) })
    }

    fn scan_transcript<'a>(
        &'a self,
        _trajectory_id: &'a str,
        _events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptScanResult> {
        self.transcript_scans.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(transcript_scan_result()) })
    }

    fn digest_interim_transcript<'a>(
        &'a self,
        trajectory_id: &'a str,
        _events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptDigest> {
        self.interim_digests.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(digest_result(trajectory_id, true)) })
    }

    fn provider_name(&self) -> &'static str {
        "stub"
    }

    fn model(&self) -> &str {
        "stub-model"
    }
}

/// A scanner whose every call fails, for the degraded paths.
struct FailingScanner;

impl TrajectoryScannerBackend for FailingScanner {
    fn scan_event<'a>(&'a self, _event: &'a Event) -> ScannerFuture<'a, EventScanResult> {
        Box::pin(async { Err(ScannerError::Timeout) })
    }

    fn digest_transcript<'a>(
        &'a self,
        _trajectory_id: &'a str,
        _events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptDigest> {
        Box::pin(async { Err(ScannerError::Timeout) })
    }

    fn scan_transcript<'a>(
        &'a self,
        _trajectory_id: &'a str,
        _events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptScanResult> {
        Box::pin(async { Err(ScannerError::Timeout) })
    }

    fn digest_interim_transcript<'a>(
        &'a self,
        _trajectory_id: &'a str,
        _events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptDigest> {
        Box::pin(async { Err(ScannerError::Timeout) })
    }

    fn provider_name(&self) -> &'static str {
        "failing"
    }

    fn model(&self) -> &str {
        "failing-model"
    }
}

fn agent(platform: &str) -> Agent {
    Agent::new("test-agent", "test", platform)
}

/// A store holding `events`, plus a dispatcher over it.
async fn fixture(
    scanner: Arc<dyn TrajectoryScannerBackend>,
    events: &[Event],
) -> (Arc<TrajectoryStore>, ScanDispatcher<TrajectoryStore>) {
    let store = Arc::new(TrajectoryStore::open_in_memory().await.expect("store"));
    store.insert_events(events).await.expect("seed events");
    let dispatcher = ScanDispatcher::new(scanner, Arc::clone(&store));
    (store, dispatcher)
}

/// Poll `condition` until it holds, or fail after a bounded wait.
///
/// The dispatcher spawns detached tasks, so there is no handle to await; this
/// is the observable substitute.
async fn eventually<F, Fut>(what: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..200 {
        if condition().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn an_adjudicated_event_gets_a_message_level_scan_in_its_own_table() {
    let scanner = Arc::new(StubScanner::new());
    let event = Event::new(
        agent("claude-code"),
        "run-1",
        TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("rm -rf /tmp/data"))),
    );
    let (store, dispatcher) = fixture(scanner, std::slice::from_ref(&event)).await;

    dispatcher.dispatch(event.clone());

    eventually("the event scan to be persisted", || async {
        !store.event_scans("run-1").await.expect("read").is_empty()
    })
    .await;

    let scans = store.event_scans("run-1").await.expect("read");
    assert_eq!(scans[&event.event_id].description, "Ran 'rm -rf /tmp/data'");
}

#[tokio::test]
async fn the_scan_is_also_appended_to_the_ledger_causally_linked_to_its_source() {
    // The table is the read path; the ledger is the record of what happened.
    // The control event must name its source, or the console's fold renders it
    // as a bare governance row instead of attaching it to the action.
    let scanner = Arc::new(StubScanner::new());
    let event = Event::new(
        agent("claude-code"),
        "run-1",
        TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("ls"))),
    );
    let (store, dispatcher) = fixture(scanner, std::slice::from_ref(&event)).await;

    dispatcher.dispatch(event.clone());

    eventually("the scanned control event to be appended", || async {
        store.trajectory_events("run-1").await.expect("read").len() > 1
    })
    .await;

    let events = store.trajectory_events("run-1").await.expect("read");
    let scanned = events
        .iter()
        .find_map(|e| match &e.event {
            TrajectoryEvent::Control(Control::Scanned(scanned)) => Some((e, scanned)),
            _ => None,
        })
        .expect("a Scanned control event was appended");

    assert_eq!(
        scanned.0.causality.causation_id.as_deref(),
        Some(event.event_id.as_str()),
        "the scan must be causally linked to the event it describes"
    );
    assert_eq!(scanned.1.source_event_id(), event.event_id);
    assert!(matches!(scanned.1, Scanned::Message { .. }));

    // The visible event count is unchanged: the fold hides the scan.
    let page = store
        .list_trajectory_events("run-1", 0, usize::MAX)
        .await
        .expect("read");
    assert_eq!(page.total, 1);
    assert!(page.items[0].summary.is_some());
}

#[tokio::test]
async fn a_terminal_event_triggers_both_transcript_granularities() {
    let scanner = Arc::new(StubScanner::new());
    let action = Event::new(
        agent("claude-code"),
        "run-1",
        TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("rm -rf /tmp/data"))),
    );
    let completed = Event::new(
        agent("claude-code"),
        "run-1",
        TrajectoryEvent::Control(Control::Completed(Completed::new())),
    );
    let (store, dispatcher) = fixture(
        Arc::clone(&scanner) as Arc<dyn TrajectoryScannerBackend>,
        &[action, completed.clone()],
    )
    .await;

    dispatcher.dispatch(completed.clone());

    eventually("both transcript results to be persisted", || async {
        let scans = store.transcript_scans("run-1").await.expect("read");
        scans.digest.is_some() && scans.scan.is_some()
    })
    .await;

    let scans = store.transcript_scans("run-1").await.expect("read");
    let digest = scans.digest.expect("digest");
    assert_eq!(digest.title, "Cleaned up /tmp");
    assert!(!digest.interim, "a terminal digest is not interim");
    let scan = scans.scan.expect("scan");
    assert_eq!(scan.result.outcome, TranscriptOutcome::Success);
    assert_eq!(scan.source_event_id, completed.event_id);

    // A terminal run takes the final digest path, never the interim one.
    assert_eq!(scanner.interim_digests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_codex_turn_end_refreshes_the_digest_without_a_behavioral_scan() {
    // Codex `Stop` is turn-scoped: the run is still going, so it earns a fresh
    // digest but not the terminal behavioral audit.
    let scanner = Arc::new(StubScanner::new());
    let turn_end = Event::new(
        agent("codex"),
        "run-1",
        TrajectoryEvent::Observation(Observation::Prompt(sondera_harness::Prompt::assistant(
            "Done with this turn.",
        ))),
    );
    let (store, dispatcher) = fixture(
        Arc::clone(&scanner) as Arc<dyn TrajectoryScannerBackend>,
        std::slice::from_ref(&turn_end),
    )
    .await;

    dispatcher.dispatch(turn_end.clone());

    eventually("the interim digest to be persisted", || async {
        store
            .transcript_scans("run-1")
            .await
            .expect("read")
            .digest
            .is_some()
    })
    .await;

    let scans = store.transcript_scans("run-1").await.expect("read");
    assert!(
        scans.digest.expect("digest").interim,
        "a turn-end digest must be marked interim"
    );
    assert!(
        scans.scan.is_none(),
        "the behavioral scan is terminal-only; a live run has not finished behaving"
    );
    assert_eq!(scanner.interim_digests.load(Ordering::SeqCst), 1);
    assert_eq!(scanner.transcript_scans.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_scanners_own_output_is_never_scanned_again() {
    // A `Scanned` event fed back in would have the scanner grade its own
    // output and emit another — a loop with a model call in it.
    let scanner = Arc::new(StubScanner::new());
    let scanned = Event::new(
        agent("claude-code"),
        "run-1",
        TrajectoryEvent::Control(Control::Scanned(Scanned::message(
            "event-0",
            event_scan_result(),
        ))),
    );
    let (store, dispatcher) = fixture(
        Arc::clone(&scanner) as Arc<dyn TrajectoryScannerBackend>,
        std::slice::from_ref(&scanned),
    )
    .await;

    dispatcher.dispatch(scanned.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(scanner.event_scans.load(Ordering::SeqCst), 0);
    assert_eq!(scanner.digests.load(Ordering::SeqCst), 0);
    assert!(store.event_scans("run-1").await.expect("read").is_empty());
    // The ledger still holds only the event it was seeded with.
    assert_eq!(
        store.trajectory_events("run-1").await.expect("read").len(),
        1
    );
}

#[tokio::test]
async fn a_failed_scan_leaves_the_trajectory_intact() {
    // Scanning is enrichment. A provider outage costs a summary, not a run.
    let event = Event::new(
        agent("claude-code"),
        "run-1",
        TrajectoryEvent::Observation(Observation::Thought(Thought::new("planning"))),
    );
    let (store, dispatcher) = fixture(Arc::new(FailingScanner), std::slice::from_ref(&event)).await;

    dispatcher.dispatch(event.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(store.event_scans("run-1").await.expect("read").is_empty());
    assert!(
        store
            .transcript_scans("run-1")
            .await
            .expect("read")
            .is_empty()
    );
    // No half-written `Scanned` event: the ledger record is only appended once
    // the authoritative payload is durable.
    let events = store.trajectory_events("run-1").await.expect("read");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, event.event_id);
    // And the run still reads back normally.
    assert!(store.get_trajectory("run-1").await.expect("read").is_some());
}

#[tokio::test]
async fn dispatch_returns_without_waiting_for_the_scan() {
    // The whole reason this is a background task: the RPC that triggered it has
    // already answered.
    struct SlowScanner;

    impl TrajectoryScannerBackend for SlowScanner {
        fn scan_event<'a>(&'a self, _event: &'a Event) -> ScannerFuture<'a, EventScanResult> {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(event_scan_result())
            })
        }

        fn digest_transcript<'a>(
            &'a self,
            trajectory_id: &'a str,
            _events: &'a [Event],
        ) -> ScannerFuture<'a, TranscriptDigest> {
            Box::pin(async move { Ok(digest_result(trajectory_id, false)) })
        }

        fn scan_transcript<'a>(
            &'a self,
            _trajectory_id: &'a str,
            _events: &'a [Event],
        ) -> ScannerFuture<'a, TranscriptScanResult> {
            Box::pin(async { Ok(transcript_scan_result()) })
        }

        fn digest_interim_transcript<'a>(
            &'a self,
            trajectory_id: &'a str,
            _events: &'a [Event],
        ) -> ScannerFuture<'a, TranscriptDigest> {
            Box::pin(async move { Ok(digest_result(trajectory_id, true)) })
        }

        fn provider_name(&self) -> &'static str {
            "slow"
        }

        fn model(&self) -> &str {
            "slow-model"
        }
    }

    let event = Event::new(
        agent("claude-code"),
        "run-1",
        TrajectoryEvent::Observation(Observation::Thought(Thought::new("planning"))),
    );
    let (_store, dispatcher) = fixture(Arc::new(SlowScanner), std::slice::from_ref(&event)).await;

    let started = std::time::Instant::now();
    dispatcher.dispatch(event.clone());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "dispatch blocked on the scan it spawned"
    );
}

#[tokio::test]
async fn scans_beyond_the_concurrency_limit_are_dropped_rather_than_queued() {
    // A backlog of stale scans is worth less than the memory it would hold, so
    // the limiter sheds rather than buffers.
    struct BlockingScanner;

    impl TrajectoryScannerBackend for BlockingScanner {
        fn scan_event<'a>(&'a self, _event: &'a Event) -> ScannerFuture<'a, EventScanResult> {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(event_scan_result())
            })
        }

        fn digest_transcript<'a>(
            &'a self,
            trajectory_id: &'a str,
            _events: &'a [Event],
        ) -> ScannerFuture<'a, TranscriptDigest> {
            Box::pin(async move { Ok(digest_result(trajectory_id, false)) })
        }

        fn scan_transcript<'a>(
            &'a self,
            _trajectory_id: &'a str,
            _events: &'a [Event],
        ) -> ScannerFuture<'a, TranscriptScanResult> {
            Box::pin(async { Ok(transcript_scan_result()) })
        }

        fn digest_interim_transcript<'a>(
            &'a self,
            trajectory_id: &'a str,
            _events: &'a [Event],
        ) -> ScannerFuture<'a, TranscriptDigest> {
            Box::pin(async move { Ok(digest_result(trajectory_id, true)) })
        }

        fn provider_name(&self) -> &'static str {
            "blocking"
        }

        fn model(&self) -> &str {
            "blocking-model"
        }
    }

    let store = Arc::new(TrajectoryStore::open_in_memory().await.expect("store"));
    let dispatcher =
        ScanDispatcher::new(Arc::new(BlockingScanner), Arc::clone(&store)).max_concurrency(1);

    let events: Vec<Event> = (0..5)
        .map(|i| {
            Event::new(
                agent("claude-code"),
                "run-1",
                TrajectoryEvent::Observation(Observation::Thought(Thought::new(format!(
                    "step-{i}"
                )))),
            )
        })
        .collect();
    store.insert_events(&events).await.expect("seed");

    let started = std::time::Instant::now();
    for event in &events {
        dispatcher.dispatch(event.clone());
    }

    // Four of the five find no permit and are dropped on the spot; none of them
    // waits for the one that holds it.
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "dispatch blocked waiting for a permit"
    );
}
