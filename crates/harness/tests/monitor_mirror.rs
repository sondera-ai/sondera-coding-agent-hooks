//! Integration tests for the monitor mirror.
//!
//! Proves from outside the crate boundary that monitor-derived state is
//! readable from the trajectory log ALONE — JSONL file I/O, no Fjall
//! handle — the data contract the dashboard is built on:
//! - `Control::Started` / `Control::Resumed` produce a synthetic snapshot
//!   record with `Actor::policy("monitor")`, written AFTER the original
//!   event's dual-write (asserted on JSONL line order),
//! - the record's `raw["monitor"]` deserializes back into the typed
//!   [`sondera_harness::MonitorSnapshot`] — the same serde struct both
//!   directions,
//! - the snapshot shape is uniform even on Clean trajectories: verdict
//!   `satisfied`, state `"clean"`, empty `taints` present,
//! - non-state-changing Control events (`Completed`, `Suspended`, …)
//!   produce NO snapshot record — only `Started | Resumed` do,
//! - (Ollama-`#[ignore]`-gated) every Cedar-path Adjudicated record
//!   carries the `"monitor"` block as a sibling of `"request"`/`"response"`,
//!   including the very record whose decision was the multi-hop Deny
//!   (post-observe state mirrored on the trip record).
//!
//! The non-Ollama tier rides Control events, which bypass Cedar and all
//! guardrails — so those tests need no `#[ignore]` gate. The single
//! Cedar-path test lives HERE (not in verdict_backstop.rs) so the mirror
//! tests stay disjoint from the backstop tests' fixtures.
//!
//! Run the non-Ollama tier with:
//!   cargo +stable test -p sondera-harness --test monitor_mirror
//!
//! The Cedar-path test requires Ollama running locally with the
//! gpt-oss-safeguard model:
//!   ollama pull gpt-oss-safeguard:20b
//!   ollama serve
//!   cargo +stable test -p sondera-harness --test monitor_mirror -- --ignored

use sondera_harness::{
    Action, ActorType, Agent, CedarPolicyHarness, Completed, Control, Decision, Event,
    FileOperation, Harness, Monitor, MonitorConfig, MonitorSnapshot, Observation, Resumed, Started,
    TrajectoryEvent, UntrustedThenProtectedWrite, Verdict, WebFetchOutput,
};
use std::path::PathBuf;

const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

/// Protected by the default `.github/workflows/**` glob while carrying
/// benign YAML content unlikely to trip YARA credential rules or the
/// secure-code policy model.
const PROTECTED_TEST_PATH: &str = ".github/workflows/ci.yml";

const BENIGN_YAML: &str = "name: ci\n\
on: [push]\n\
jobs:\n\
  build:\n\
    runs-on: ubuntu-latest\n\
    steps:\n\
      - uses: actions/checkout@v4\n";

fn test_agent() -> Agent {
    Agent {
        id: "test-agent".to_string(),
        provider_id: "test-provider".to_string(),
    }
}

async fn load_harness() -> (CedarPolicyHarness, tempfile::TempDir) {
    let path = PathBuf::from(POLICIES_DIR);
    let temp_dir = tempfile::tempdir().expect("should create temp dir for entity store");
    let harness = CedarPolicyHarness::from_policy_dir_isolated(path, temp_dir.path())
        .await
        .expect("should load policies directory");
    (harness, temp_dir)
}

fn raw_context() -> serde_json::Value {
    serde_json::json!({
        "cwd": "/tmp/test",
        "permission_mode": "default",
        "transcript_path": "/tmp/test-transcript.jsonl",
    })
}

/// Unique trajectory ids keep runs independent: adjudicate appends JSONL
/// under ~/.sondera/trajectories/<id>.jsonl even in isolated mode.
fn new_trajectory_id() -> String {
    format!("test-mirror-{}", uuid::Uuid::new_v4())
}

fn make_event(traj: &str, event_variant: TrajectoryEvent) -> Event {
    Event::new(test_agent(), traj, event_variant).with_raw(raw_context())
}

/// Untrusted read: arms the monitor under the default config.
fn web_fetch_output(traj: &str) -> Event {
    make_event(
        traj,
        TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
            "call-1",
            "https://example.com/weather",
            200,
            "<html>Forecast: sunny, high of 72F.</html>",
        ))),
    )
}

/// Seed a persisted Armed state for `traj` via the harness passthroughs
/// (no Ollama: no adjudicate call involved).
fn seed_armed_state(harness: &CedarPolicyHarness, traj: &str) {
    let mut monitor = UntrustedThenProtectedWrite::new(MonitorConfig::default()).unwrap();
    monitor.observe(&web_fetch_output(traj)).unwrap();
    assert_eq!(monitor.verdict(), Verdict::Pending, "seed must be Armed");
    harness.put_monitor_state(traj, monitor.state()).unwrap();
}

/// Read back the trajectory's JSONL by file I/O ONLY — no EntityStore /
/// Fjall handle is ever touched for readback assertions (PROJECT.md key
/// decision: the dashboard reads Turso/JSONL, never Fjall). Mirrors the
/// storage/file.rs path convention: ~/.sondera/trajectories/<id>.jsonl.
fn read_jsonl(traj: &str) -> Vec<Event> {
    let home = dirs::home_dir().expect("home directory should resolve");
    let path = home
        .join(".sondera")
        .join("trajectories")
        .join(format!("{traj}.jsonl"));
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("trajectory JSONL should exist at {}: {e}", path.display()));
    content
        .lines()
        .map(|line| {
            serde_json::from_str::<Event>(line)
                .expect("every JSONL line must deserialize back into Event")
        })
        .collect()
}

/// True when the record is a Control-branch snapshot record: actor of
/// policy type with id "monitor" — the consumer's discriminator.
fn is_monitor_snapshot_record(event: &Event) -> bool {
    event.actor.actor_type == ActorType::Policy && event.actor.id == "monitor"
}

/// A Started event produces a snapshot record readable from JSONL without
/// opening Fjall, written AFTER the original event's dual-write, with the
/// uniform Clean shape.
#[tokio::test]
async fn started_produces_snapshot_record_readable_without_fjall() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();

    let started = make_event(
        &traj,
        TrajectoryEvent::Control(Control::Started(Started::new("test-agent"))),
    );
    let started_id = started.event_id.clone();
    let result = harness.adjudicate(started).await.unwrap();
    assert_eq!(result.decision, Decision::Allow, "D-26: bypass unchanged");

    let events = read_jsonl(&traj);

    // (a) The FIRST record is the original Started event — the original
    // dual-write precedes the snapshot record.
    assert_eq!(
        events[0].event_id, started_id,
        "original Started event must be the first JSONL record (D-33)"
    );
    assert!(
        matches!(
            events[0].event,
            TrajectoryEvent::Control(Control::Started(_))
        ),
        "first record must be the original Started payload"
    );

    // (b) a subsequent record is the monitor snapshot record with a
    // Control::Adjudicated(allow) payload.
    let original_idx = events
        .iter()
        .position(|e| e.event_id == started_id)
        .unwrap();
    let snapshot_idx = events
        .iter()
        .position(is_monitor_snapshot_record)
        .expect("a snapshot record with actor policy \"monitor\" must exist");
    assert!(
        original_idx < snapshot_idx,
        "snapshot record must come after the original event (D-33), \
         got original at {original_idx}, snapshot at {snapshot_idx}"
    );
    let record = &events[snapshot_idx];
    match &record.event {
        TrajectoryEvent::Control(Control::Adjudicated(adj)) => {
            assert_eq!(
                adj.decision,
                Decision::Allow,
                "snapshot payload is an Allow"
            );
        }
        other => panic!("snapshot record must carry Control::Adjudicated, got {other:?}"),
    }
    assert_eq!(
        record.causality.causation_id.as_deref(),
        Some(started_id.as_str()),
        "snapshot record must be caused by the original event"
    );

    // (c) raw["monitor"] deserializes both directions; uniform Clean shape.
    let raw = record.raw.as_ref().expect("snapshot record must carry raw");
    let snapshot: MonitorSnapshot = serde_json::from_value(raw["monitor"].clone())
        .expect("raw[\"monitor\"] must deserialize into MonitorSnapshot (D-32)");
    assert_eq!(snapshot.verdict, Verdict::Satisfied);
    assert_eq!(snapshot.state, "clean");
    assert!(!snapshot.untrusted_pending);
    assert!(
        snapshot.taints.is_empty(),
        "Clean trajectory mirrors empty taints (D-34 uniform shape)"
    );
}

/// A user-originated Resumed clearing a persisted Armed state mirrors the
/// POST-observe cleared state — the Armed→Clean transition is visible from
/// JSONL alone.
#[tokio::test]
async fn resumed_approval_snapshot_mirrors_cleared_state() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();
    seed_armed_state(&harness, &traj);

    let approval = make_event(
        &traj,
        TrajectoryEvent::Control(Control::Resumed(Resumed::new("user"))),
    );
    let result = harness.adjudicate(approval).await.unwrap();
    assert_eq!(result.decision, Decision::Allow);

    let events = read_jsonl(&traj);
    let record = events
        .iter()
        .find(|e| is_monitor_snapshot_record(e))
        .expect("Resumed must produce a snapshot record");
    let raw = record.raw.as_ref().expect("snapshot record must carry raw");
    let snapshot: MonitorSnapshot = serde_json::from_value(raw["monitor"].clone())
        .expect("raw[\"monitor\"] must deserialize into MonitorSnapshot (D-32)");

    assert_eq!(
        snapshot.verdict,
        Verdict::Satisfied,
        "approval clears Armed — snapshot reflects post-observe state"
    );
    assert_eq!(snapshot.state, "clean");
    assert!(
        snapshot.attributes.cleared_event_id.is_some(),
        "cleared witness id must be mirrored"
    );
    assert!(
        snapshot.attributes.armed_event_id.is_some(),
        "armed witness id must be mirrored"
    );
    assert!(!snapshot.untrusted_pending);
}

/// A NON-approving Resumed (resumed_by not in the allowlist) still produces a
/// snapshot record showing the still-armed obligation, regardless of whether
/// the FSM moved.
#[tokio::test]
async fn non_approving_resumed_still_snapshots_pending() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();
    seed_armed_state(&harness, &traj);

    let non_approval = make_event(
        &traj,
        TrajectoryEvent::Control(Control::Resumed(Resumed::new("agent"))),
    );
    let result = harness.adjudicate(non_approval).await.unwrap();
    assert_eq!(result.decision, Decision::Allow);

    let events = read_jsonl(&traj);
    let record = events
        .iter()
        .find(|e| is_monitor_snapshot_record(e))
        .expect("non-approving Resumed must still produce a snapshot record");
    let raw = record.raw.as_ref().expect("snapshot record must carry raw");
    let snapshot: MonitorSnapshot = serde_json::from_value(raw["monitor"].clone())
        .expect("raw[\"monitor\"] must deserialize into MonitorSnapshot (D-32)");

    assert_eq!(
        snapshot.verdict,
        Verdict::Pending,
        "agent-originated Resumed must NOT clear Armed (D-13)"
    );
    assert_eq!(snapshot.state, "armed");
    assert!(
        snapshot.untrusted_pending,
        "Armed-or-Violated fact mirrored"
    );
    assert!(snapshot.attributes.armed_event_id.is_some());
    assert!(snapshot.attributes.cleared_event_id.is_none());
}

/// Non-state-changing Control events produce NO snapshot record — only
/// Started | Resumed do.
#[tokio::test]
async fn non_state_changing_controls_produce_no_snapshot() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();

    let completed = make_event(
        &traj,
        TrajectoryEvent::Control(Control::Completed(Completed::new())),
    );
    let result = harness.adjudicate(completed).await.unwrap();
    assert_eq!(result.decision, Decision::Allow);

    let events = read_jsonl(&traj);
    assert!(
        !events.iter().any(is_monitor_snapshot_record),
        "Completed must not produce a snapshot record (only Started | Resumed)"
    );
}

/// Ollama-gated: every Cedar-path Adjudicated record carries the "monitor"
/// block — present even when nothing is wrong, and reflecting the
/// post-observe Violated state on the very record whose decision was the
/// multi-hop Deny.
#[tokio::test]
#[ignore = "requires Ollama running locally with gpt-oss-safeguard model"]
async fn every_cedar_adjudicated_record_carries_monitor_block() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();

    // Start the trajectory.
    let started = make_event(
        &traj,
        TrajectoryEvent::Control(Control::Started(Started::new("test-agent"))),
    );
    harness.adjudicate(started).await.unwrap();

    // Benign non-protected write on a clean trajectory (no arm yet).
    let benign = make_event(
        &traj,
        TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(
            "docs/notes.txt",
            "Meeting notes: discussed roadmap priorities and next steps.\n",
        ))),
    );
    let benign_id = benign.event_id.clone();
    let result = harness.adjudicate(benign).await.unwrap();
    assert_eq!(
        result.decision,
        Decision::Allow,
        "benign unprotected write on a clean trajectory must be allowed"
    );

    let events = read_jsonl(&traj);
    let cedar_record = events
        .iter()
        .find(|e| {
            e.actor.actor_type == ActorType::Policy
                && e.actor.id == "cedar"
                && e.causality.causation_id.as_deref() == Some(benign_id.as_str())
        })
        .expect("Cedar-path Adjudicated record for the benign write must exist");
    let raw = cedar_record
        .raw
        .as_ref()
        .expect("Cedar-path record must carry raw");
    assert!(
        raw.get("request").is_some() && raw.get("response").is_some(),
        "monitor block is a sibling addition — request/response keys must remain"
    );
    let snapshot: MonitorSnapshot = serde_json::from_value(raw["monitor"].clone())
        .expect("raw[\"monitor\"] must deserialize into MonitorSnapshot (D-32)");
    assert_eq!(
        snapshot.verdict,
        Verdict::Satisfied,
        "D-34: snapshot present even when nothing is wrong"
    );
    assert_eq!(snapshot.state, "clean");

    // Arm, then trip: the trip record itself mirrors the post-observe
    // Violated state.
    harness.adjudicate(web_fetch_output(&traj)).await.unwrap();
    let trip = make_event(
        &traj,
        TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(
            PROTECTED_TEST_PATH,
            BENIGN_YAML,
        ))),
    );
    let trip_id = trip.event_id.clone();
    let result = harness.adjudicate(trip).await.unwrap();
    assert_eq!(
        result.decision,
        Decision::Deny,
        "protected write while armed must be denied by multi_hop.cedar"
    );

    let events = read_jsonl(&traj);
    let trip_record = events
        .iter()
        .find(|e| {
            e.actor.actor_type == ActorType::Policy
                && e.actor.id == "cedar"
                && e.causality.causation_id.as_deref() == Some(trip_id.as_str())
        })
        .expect("Cedar-path Adjudicated record for the tripping write must exist");
    let raw = trip_record
        .raw
        .as_ref()
        .expect("trip record must carry raw");
    let snapshot: MonitorSnapshot = serde_json::from_value(raw["monitor"].clone())
        .expect("raw[\"monitor\"] must deserialize into MonitorSnapshot (D-32)");
    assert_eq!(
        snapshot.verdict,
        Verdict::Violated,
        "post-observe state mirrored on the very record whose decision \
         was the multi-hop Deny (Pitfall 6)"
    );
    assert_eq!(snapshot.state, "violated");
    assert!(
        snapshot.attributes.tripped_event_id.is_some(),
        "trip witness id must be mirrored"
    );
}
