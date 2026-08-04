//! End-to-end tests over the real transport and the real Turso store.
//!
//! These drive the generated client against a served `ConsoleGrpcService` so the
//! proto surface, the handler layer, the DTO conversions, and the store all have
//! to agree — a shape mismatch anywhere in that chain fails here rather than
//! only at integration time.

use crate::service::serve;
use sondera_schema::console_v1 as pb;
use sondera_schema::console_v1::console_service_client::ConsoleServiceClient;
use sondera_schema::harness_v1 as hb;
use sondera_storage::TrajectoryStore;
use sondera_types::{
    Action, Adjudicated, Agent, AgentIntent, Completed, Control, Event, EventScanResult,
    MessageType, Observation, PolicyMetadata, ScanReaderWriter, ScanSource, ShellCommand, Signal,
    SignalCategory, SignalFocus, SignalSeverity, Thought, TrajectoryEvent, TrajectoryReaderWriter,
    TranscriptDigest, TranscriptOutcome, TranscriptPhase, TranscriptScanResult,
};
use std::sync::Arc;
use tonic::Request;
use tonic::transport::Channel;

fn agent() -> Agent {
    Agent::new("claude-code", "anthropic", "claude-code")
}

fn event(trajectory_id: &str, event: TrajectoryEvent) -> Event {
    Event::new(agent(), trajectory_id, event)
}

/// A run that shell-executed something, got denied for it, and completed.
fn denied_run(trajectory_id: &str) -> Vec<Event> {
    let action = event(
        trajectory_id,
        TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("rm -rf /"))),
    );
    let mut adjudication = event(
        trajectory_id,
        TrajectoryEvent::Control(Control::Adjudicated(
            Adjudicated::deny()
                .with_metadata(PolicyMetadata::new().with_id("policies/no-shell".into())),
        )),
    );
    adjudication.causality = adjudication.causality.caused_by(action.event_id.clone());
    let completed = event(
        trajectory_id,
        TrajectoryEvent::Control(Control::Completed(Completed::new())),
    );
    vec![action, adjudication, completed]
}

/// Seed a store, serve it, and return a connected client.
///
/// The store is in-memory and the port is ephemeral, so tests are independent
/// and can run concurrently.
async fn serve_with(events: Vec<Event>) -> ConsoleServiceClient<Channel> {
    serve_seeded(events, |_| async {}).await
}

/// [`serve_with`], plus a hook to seed anything the ledger does not hold.
///
/// The scanner's output lives in its own tables rather than in
/// `trajectory_events`, so a test that wants a digest on the wire has to write
/// one the way the background scanner would.
async fn serve_seeded<F, Fut>(events: Vec<Event>, seed: F) -> ConsoleServiceClient<Channel>
where
    F: FnOnce(Arc<TrajectoryStore>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let store = Arc::new(
        TrajectoryStore::open_in_memory()
            .await
            .expect("store opens"),
    );
    store.insert_events(&events).await.expect("seed writes");
    seed(Arc::clone(&store)).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);

    tokio::spawn(async move {
        serve(store, addr).await.expect("server runs");
    });

    // Retry the connect rather than sleeping a fixed interval: the server needs
    // an unpredictable moment to start listening.
    for _ in 0..50 {
        if let Ok(client) = ConsoleServiceClient::connect(format!("http://{addr}")).await {
            return client;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("console server did not start listening");
}

#[tokio::test]
async fn agent_surface_lists_gets_and_analyzes_over_the_wire() {
    let mut client = serve_with(denied_run("run-1")).await;

    let listed = client
        .list_agents(Request::new(pb::ListAgentsRequest::default()))
        .await
        .expect("list_agents")
        .into_inner();
    assert_eq!(listed.total_size, 1);
    let summary = &listed.agents[0];
    assert_eq!(summary.name, "agents/claude-code");
    assert_eq!(summary.provider, "anthropic");
    assert_eq!(summary.platform, "claude-code");
    // One deny out of one adjudication.
    assert_eq!(summary.deny_rate, 1.0);
    assert_eq!(summary.status, pb::AgentStatus::Degraded as i32);
    assert!(summary.sparkline.is_some());

    let detail = client
        .get_agent(Request::new(pb::GetAgentRequest {
            name: "agents/claude-code".to_string(),
        }))
        .await
        .expect("get_agent")
        .into_inner();
    assert_eq!(detail.name, "agents/claude-code");
    assert_eq!(detail.summary.expect("summary").runs_today, 1);

    let stats = client
        .analyze_agents(Request::new(pb::AnalyzeAgentsRequest::default()))
        .await
        .expect("analyze_agents")
        .into_inner();
    assert_eq!(stats.total, 1);
    assert_eq!(stats.degraded, 1);
}

#[tokio::test]
async fn unknown_agent_reads_report_not_found() {
    let mut client = serve_with(Vec::new()).await;

    let status = client
        .get_agent(Request::new(pb::GetAgentRequest {
            name: "agents/ghost".to_string(),
        }))
        .await
        .expect_err("missing agent");
    assert_eq!(status.code(), tonic::Code::NotFound);

    let status = client
        .delete_agent(Request::new(pb::DeleteAgentRequest {
            name: "agents/ghost".to_string(),
        }))
        .await
        .expect_err("missing agent");
    assert_eq!(status.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn update_agent_never_writes_harness_owned_identity() {
    let mut client = serve_with(denied_run("run-1")).await;

    let stored = client
        .get_agent(Request::new(pb::GetAgentRequest {
            name: "agents/claude-code".to_string(),
        }))
        .await
        .expect("get_agent")
        .into_inner()
        .summary
        .expect("summary");

    let spoofed = pb::AgentSummary {
        provider: "attacker".to_string(),
        platform: "attacker".to_string(),
        health_score: 100,
        deny_rate: 0.0,
        ..stored
    };
    let updated = client
        .update_agent(Request::new(pb::UpdateAgentRequest {
            agent: Some(spoofed),
            update_mask: None,
        }))
        .await
        .expect("update_agent")
        .into_inner();

    assert_eq!(updated.provider, "anthropic");
    assert_eq!(updated.platform, "claude-code");
    assert_eq!(updated.deny_rate, 1.0);
}

#[tokio::test]
async fn trajectory_surface_projects_the_run_and_folds_its_adjudication() {
    let mut client = serve_with(denied_run("run-1")).await;

    let summary = client
        .get_trajectory(Request::new(pb::GetTrajectoryRequest {
            name: "trajectories/run-1".to_string(),
        }))
        .await
        .expect("get_trajectory")
        .into_inner();
    assert_eq!(summary.name, "trajectories/run-1");
    assert_eq!(summary.agent, "agents/claude-code");
    assert_eq!(summary.status, "completed");
    assert_eq!(
        summary.decision,
        sondera_schema::harness_v1::Decision::Deny as i32
    );
    assert_eq!(summary.policy_hits, vec!["policies/no-shell".to_string()]);

    let events = client
        .list_trajectory_events(Request::new(pb::ListTrajectoryEventsRequest {
            trajectory: "trajectories/run-1".to_string(),
            ..Default::default()
        }))
        .await
        .expect("list_trajectory_events")
        .into_inner();
    // The adjudication is folded onto the shell action, not listed separately.
    assert_eq!(events.total_size, 2);
    let first = events.details[0].event.as_ref().expect("event");
    assert_eq!(first.category, pb::TrajectoryEventCategory::Action as i32);
    assert_eq!(
        events.details[0]
            .adjudication
            .as_ref()
            .expect("folded adjudication")
            .decision,
        sondera_schema::harness_v1::Decision::Deny as i32
    );

    let sparklines = client
        .batch_get_trajectory_sparklines(Request::new(pb::BatchGetTrajectorySparklinesRequest {
            names: vec!["trajectories/run-1".to_string()],
        }))
        .await
        .expect("batch_get_trajectory_sparklines")
        .into_inner();
    assert_eq!(sparklines.sparklines.len(), 1);
    assert_eq!(
        sparklines.sparklines[0].cells[0].policy_hit,
        "policies/no-shell"
    );
}

#[tokio::test]
async fn the_semantic_summary_reaches_both_trajectory_read_surfaces() {
    // The scanner writes to its own tables; the console composes them onto the
    // run and its events. This asserts the whole chain over the wire — store
    // join, domain projection, DTO conversion — for the list, the detail, and
    // the event ledger, because each is a separate projection and the list one
    // in particular used to be left unenriched.
    let events = denied_run("run-1");
    let scanned_event_id = events[0].event_id.clone();
    let trigger_event_id = events[2].event_id.clone();

    let scanned = scanned_event_id.clone();
    let trigger = trigger_event_id.clone();
    let mut client = serve_seeded(events, move |store| async move {
        fn source(event_id: &str) -> ScanSource<'_> {
            ScanSource {
                event_id,
                trajectory_id: "run-1",
                agent_id: "claude-code",
            }
        }

        store
            .insert_event_scan(
                source(&scanned),
                &EventScanResult {
                    explanation: "A destructive shell command.".to_string(),
                    message_type: MessageType::ToolCall,
                    intent: AgentIntent::Implement,
                    description: "Attempted 'rm -rf /'".to_string(),
                    key_entities: vec!["/".to_string()],
                    is_side_effecting: true,
                    signals: Vec::new(),
                    confidence: 0.95,
                    embedding: None,
                },
            )
            .await
            .expect("event scan write");

        store
            .insert_transcript_digest(
                source(&trigger),
                &TranscriptDigest {
                    trajectory_id: "run-1".to_string(),
                    title: "Attempted a destructive cleanup".to_string(),
                    summary: "Ran rm -rf, was denied, then completed.".to_string(),
                    interim: false,
                    phases: vec![TranscriptPhase {
                        name: "Implementation".to_string(),
                        description: "Issued the delete".to_string(),
                        event_indices: vec![0],
                    }],
                    files_modified: Vec::new(),
                    tools_used: vec!["Bash".to_string()],
                    total_events: 2,
                    side_effecting_count: 1,
                },
            )
            .await
            .expect("digest write");

        store
            .insert_transcript_scan(
                source(&trigger),
                &TranscriptScanResult {
                    explanation: "One policy denial.".to_string(),
                    outcome: TranscriptOutcome::Partial,
                    outcome_description: "Blocked by policy.".to_string(),
                    aggregate_severity: SignalSeverity::High,
                    signals: vec![Signal {
                        focus: SignalFocus::Governance,
                        category: SignalCategory::DestructiveOperation,
                        severity: SignalSeverity::High,
                        description: "rm -rf against the filesystem root".to_string(),
                        evidence_indices: vec![0],
                    }],
                    adjudication_summary: "1 deny.".to_string(),
                    behavioral_notes: vec!["Did not retry after the denial".to_string()],
                    confidence: 0.9,
                },
            )
            .await
            .expect("scan write");
    })
    .await;

    // ── ListTrajectories ────────────────────────────────────────────────────
    let listed = client
        .list_trajectories(Request::new(pb::ListTrajectoriesRequest::default()))
        .await
        .expect("list_trajectories")
        .into_inner();
    let row = &listed.trajectories[0];
    let digest = row
        .digest
        .as_ref()
        .expect("the list row carries the digest");
    assert_eq!(digest.title, "Attempted a destructive cleanup");
    assert_eq!(digest.phases.len(), 1);
    // The one-line summary follows the digest title once the scanner has one.
    assert_eq!(row.summary, "Attempted a destructive cleanup");
    let scan = row.scan.as_ref().expect("the list row carries the scan");
    assert_eq!(scan.source_event_id, trigger_event_id);
    let result = scan.result.as_ref().expect("scan result");
    assert_eq!(result.signals.len(), 1);
    assert_eq!(
        result.aggregate_severity,
        hb::SignalSeverity::High as i32,
        "the severity enum must survive the domain -> proto conversion"
    );

    // ── GetTrajectory ───────────────────────────────────────────────────────
    let detail = client
        .get_trajectory(Request::new(pb::GetTrajectoryRequest {
            name: "trajectories/run-1".to_string(),
        }))
        .await
        .expect("get_trajectory")
        .into_inner();
    assert_eq!(
        detail.digest.as_ref().map(|d| d.title.as_str()),
        Some("Attempted a destructive cleanup")
    );
    assert!(detail.scan.is_some());

    // ── ListTrajectoryEvents ────────────────────────────────────────────────
    let page = client
        .list_trajectory_events(Request::new(pb::ListTrajectoryEventsRequest {
            trajectory: "trajectories/run-1".to_string(),
            ..Default::default()
        }))
        .await
        .expect("list_trajectory_events")
        .into_inner();
    let scanned = page
        .details
        .iter()
        .find(|d| {
            d.event
                .as_ref()
                .is_some_and(|e| e.event_id == scanned_event_id)
        })
        .expect("the scanned action is still a visible row");
    let summary = scanned
        .summary
        .as_ref()
        .expect("the event carries its scanner summary");
    assert_eq!(summary.description, "Attempted 'rm -rf /'");
    assert_eq!(summary.intent, hb::AgentIntent::Implement as i32);
    // The adjudication fold still works alongside it.
    assert!(scanned.adjudication.is_some());
    // The unscanned lifecycle bookend gets no summary invented for it.
    assert!(
        page.details
            .iter()
            .any(|d| d.summary.is_none() && d.adjudication.is_none())
    );
}

#[tokio::test]
async fn an_unscanned_run_reports_no_summary_rather_than_an_empty_one() {
    // "not scanned" and "scanned, found nothing" are different claims, and only
    // the first is what an un-configured scanner produces.
    let mut client = serve_with(denied_run("run-1")).await;

    let listed = client
        .list_trajectories(Request::new(pb::ListTrajectoriesRequest::default()))
        .await
        .expect("list_trajectories")
        .into_inner();
    assert!(listed.trajectories[0].digest.is_none());
    assert!(listed.trajectories[0].scan.is_none());

    let page = client
        .list_trajectory_events(Request::new(pb::ListTrajectoryEventsRequest {
            trajectory: "trajectories/run-1".to_string(),
            ..Default::default()
        }))
        .await
        .expect("list_trajectory_events")
        .into_inner();
    assert!(page.details.iter().all(|d| d.summary.is_none()));
}

#[tokio::test]
async fn list_trajectories_honors_filters_and_rejects_unknown_keys() {
    let mut events = denied_run("denied");
    events.push(event(
        "clean",
        TrajectoryEvent::Observation(Observation::Thought(Thought::new("thinking"))),
    ));
    let mut client = serve_with(events).await;

    let denied = client
        .list_trajectories(Request::new(pb::ListTrajectoriesRequest {
            filter: "decision=deny".to_string(),
            ..Default::default()
        }))
        .await
        .expect("list_trajectories")
        .into_inner();
    assert_eq!(denied.total_size, 1);
    assert_eq!(denied.trajectories[0].name, "trajectories/denied");

    // An unsupported key is an error, not a silently ignored clause — otherwise
    // a caller filtering on something this deployment does not model would get
    // back the whole ledger and believe it was narrowed.
    let status = client
        .list_trajectories(Request::new(pb::ListTrajectoriesRequest {
            filter: "fleet=fleets/a".to_string(),
            ..Default::default()
        }))
        .await
        .expect_err("unsupported filter key");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn malformed_resource_names_are_invalid_argument_not_not_found() {
    let mut client = serve_with(Vec::new()).await;

    let status = client
        .get_trajectory(Request::new(pb::GetTrajectoryRequest {
            name: "run-1".to_string(),
        }))
        .await
        .expect_err("malformed name");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn stream_trajectory_emits_the_backlog_over_the_wire() {
    let mut client = serve_with(denied_run("run-1")).await;

    let mut stream = client
        .stream_trajectory(Request::new(pb::StreamTrajectoryRequest {
            trajectory: "trajectories/run-1".to_string(),
        }))
        .await
        .expect("stream_trajectory")
        .into_inner();

    // The tail emits every stored row, governance events included: unlike the
    // paged detail list, the stream is the raw ledger.
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), stream.message())
        .await
        .expect("no timeout")
        .expect("stream ok")
        .expect("an event");
    assert_eq!(first.trajectory, "trajectories/run-1");
    assert_eq!(first.category, pb::TrajectoryEventCategory::Action as i32);
}

#[tokio::test]
async fn stream_trajectories_emits_matching_runs() {
    let mut client = serve_with(denied_run("run-1")).await;

    let mut stream = client
        .stream_trajectories(Request::new(pb::StreamTrajectoriesRequest::default()))
        .await
        .expect("stream_trajectories")
        .into_inner();

    let summary = tokio::time::timeout(std::time::Duration::from_secs(5), stream.message())
        .await
        .expect("no timeout")
        .expect("stream ok")
        .expect("a summary");
    assert_eq!(summary.name, "trajectories/run-1");
    assert_eq!(summary.status, "completed");
}
