//! End-to-end verdict backstop proof shape.
//!
//! Replays a violated trajectory (untrusted read → protected write → benign
//! NON-protected writes) as SEPARATE `adjudicate` calls through the full
//! production path, proving:
//!
//! - a Cedar-Allowed event in a Violated trajectory is forced to `Escalate`
//!   by the backstop — never `Deny`. The post-violation events are
//!   deliberately NON-protected: Cedar allows them, so the outcome can only
//!   come from `backstop::merge`, not `multi_hop.cedar`.
//! - `Violated` is latching — EVERY subsequent Cedar-Allow escalates,
//!   asserted with a second benign write.
//! - the tripping write's Cedar `Deny` passes through the merge untouched,
//!   still citing the multi-hop forbid.
//! - Cedar's own `default-permit` annotation is preserved with the backstop
//!   annotation appended — never replaced.
//! - the persisted JSONL `Control::Adjudicated` records carry the SAME
//!   post-merge `Escalate` as the returned values — the audit record equals
//!   the enforced decision.
//!
//! Requires Ollama running locally with the gpt-oss-safeguard model:
//!   ollama pull gpt-oss-safeguard:20b
//!   ollama serve
//!
//! Run with:
//!   cargo +stable test -p sondera-harness --test verdict_backstop -- --ignored

use sondera_harness::monitors::backstop::BACKSTOP_POLICY_ID;
use sondera_harness::{
    Action, ActorType, Adjudicated, Agent, Annotation, CedarPolicyHarness, Control, Decision,
    Event, FileOperation, Harness, Observation, Started, TrajectoryEvent, WebFetchOutput,
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

/// Paths OUTSIDE every default protected glob (`.env*`, `.ssh`, `.aws`,
/// `*.pem`, `id_rsa*`, `.github/workflows/**`, `Dockerfile*`, `/etc/**`)
/// with neutral prose content that dodges YARA and the secure-code policy
/// model — Cedar must Allow these so only the backstop can escalate them.
const BENIGN_PATH_1: &str = "docs/notes.txt";
const BENIGN_PATH_2: &str = "docs/changelog.md";

const BENIGN_PROSE: &str =
    "Meeting notes: discussed the quarterly roadmap and the team offsite agenda.\n";

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
    format!("test-backstop-{}", uuid::Uuid::new_v4())
}

fn make_event(traj: &str, event_variant: TrajectoryEvent) -> Event {
    Event::new(test_agent(), traj, event_variant).with_raw(raw_context())
}

/// Start a trajectory by sending a Control::Started event.
async fn start_trajectory(harness: &CedarPolicyHarness, trajectory_id: &str) {
    let started = make_event(
        trajectory_id,
        TrajectoryEvent::Control(Control::Started(Started::new("test-agent"))),
    );
    let result = harness.adjudicate(started).await.unwrap();
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Started events should always be allowed"
    );
}

/// Untrusted read that arms the monitor: any WebFetchOutput is
/// unconditionally untrusted. Benign URL + content so no unrelated guardrail
/// interferes with the arming event itself.
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

/// Protected file write: matches the default `.github/workflows/**` glob —
/// trips the FSM into Violated and is denied by multi_hop.cedar.
fn protected_file_write(traj: &str) -> Event {
    make_event(
        traj,
        TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(
            PROTECTED_TEST_PATH,
            BENIGN_YAML,
        ))),
    )
}

/// Benign file write OUTSIDE the protected glob set: Cedar allows it, so
/// any non-Allow outcome must come from the backstop merge.
fn benign_file_write(traj: &str, path: &str) -> Event {
    make_event(
        traj,
        TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(
            path,
            BENIGN_PROSE,
        ))),
    )
}

/// Extract the policy ids cited in the decision annotations
/// (containment-assertion pattern — other policies may also fire).
fn policy_ids(result: &Adjudicated) -> Vec<&str> {
    result
        .annotations
        .iter()
        .filter_map(|a| a.policy_id.as_deref())
        .collect()
}

/// Find the backstop annotation by its anti-spoofing PAIR: reserved
/// `monitor-backstop-` prefixed policy id AND `source == "monitor"`.
fn backstop_annotation(result: &Adjudicated) -> &Annotation {
    result
        .annotations
        .iter()
        .find(|a| {
            a.policy_id.as_deref() == Some(BACKSTOP_POLICY_ID)
                && a.annotations.get("source").map(String::as_str) == Some("monitor")
        })
        .expect("backstop annotation (reserved id + source=monitor pair) present")
}

/// Assert the full backstop escalation shape on a merged result.
fn assert_backstop_escalation(result: &Adjudicated, step: &str) {
    assert_eq!(
        result.decision,
        Decision::Escalate,
        "{step}: Cedar-allowed event in a Violated trajectory must escalate \
         (D-23), got reason: {:?}, annotations: {:?}",
        result.reason,
        policy_ids(result)
    );
    let ids = policy_ids(result);
    // Cedar's own Allow annotation is preserved...
    assert!(
        ids.contains(&"default-permit"),
        "{step}: Cedar's default-permit annotation must be preserved (D-30), got: {ids:?}"
    );
    // ...with the backstop annotation appended.
    assert!(
        ids.contains(&BACKSTOP_POLICY_ID),
        "{step}: backstop annotation must be appended (D-30), got: {ids:?}"
    );
    let backstop = backstop_annotation(result);
    // Both witness ids present and non-empty in a tripped trajectory.
    assert!(
        backstop
            .annotations
            .get("armed_event_id")
            .is_some_and(|id| !id.is_empty()),
        "{step}: backstop annotation must carry a non-empty armed_event_id (D-28)"
    );
    assert!(
        backstop
            .annotations
            .get("tripped_event_id")
            .is_some_and(|id| !id.is_empty()),
        "{step}: backstop annotation must carry a non-empty tripped_event_id (D-28)"
    );
    // Human-readable reason.
    assert!(
        result.reason.as_deref().is_some_and(|r| !r.is_empty()),
        "{step}: forced Escalate must carry a non-empty reason (D-27)"
    );
}

/// Full proof shape: arm → trip (Deny, untouched) → benign non-protected
/// write (Escalate via backstop) → second benign write (Escalate again,
/// latching) → JSONL readback (the persisted Adjudicated records equal the
/// enforced decisions).
#[tokio::test]
#[ignore = "requires Ollama running locally with gpt-oss-safeguard model"]
async fn violated_trajectory_cedar_allows_escalate_via_backstop() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();

    // Step 1: start the trajectory.
    start_trajectory(&harness, &traj).await;

    // Step 2: arm the monitor with the untrusted read.
    let result = harness.adjudicate(web_fetch_output(&traj)).await.unwrap();
    assert_eq!(
        result.decision,
        Decision::Allow,
        "the benign untrusted read itself should be allowed, got reason: {:?}",
        result.reason
    );

    // Step 3: trip — the protected write is denied by multi_hop.cedar and
    // the Cedar Deny passes through the merge untouched.
    let result = harness
        .adjudicate(protected_file_write(&traj))
        .await
        .unwrap();
    assert_eq!(
        result.decision,
        Decision::Deny,
        "protected file write after an unapproved untrusted read must be denied"
    );
    let ids = policy_ids(&result);
    assert!(
        ids.contains(&"multi-hop-forbid-file-protected-write-untrusted-pending"),
        "deny must cite the multi-hop file forbid (Cedar deny untouched by \
         the backstop — D-25), got: {ids:?}"
    );
    assert!(
        !ids.contains(&BACKSTOP_POLICY_ID),
        "the Cedar Deny must NOT carry the backstop annotation (D-25), got: {ids:?}"
    );

    // Step 4: benign NON-protected write — Cedar allows, backstop escalates.
    let result = harness
        .adjudicate(benign_file_write(&traj, BENIGN_PATH_1))
        .await
        .unwrap();
    assert_backstop_escalation(&result, "step 4 (first benign write)");

    // Step 5: a second benign write also escalates — Violated latches.
    let result = harness
        .adjudicate(benign_file_write(&traj, BENIGN_PATH_2))
        .await
        .unwrap();
    assert_backstop_escalation(&result, "step 5 (second benign write)");

    // Step 6: persisted-record readback — the JSONL audit log's
    // Control::Adjudicated records carry the SAME post-merge decisions.
    let jsonl_path = dirs::home_dir()
        .expect("home directory resolvable")
        .join(".sondera")
        .join("trajectories")
        .join(format!("{traj}.jsonl"));
    let contents =
        std::fs::read_to_string(&jsonl_path).expect("trajectory JSONL file should exist");
    let adjudicated_records: Vec<(Adjudicated, Option<serde_json::Value>)> = contents
        .lines()
        .map(|line| serde_json::from_str::<Event>(line).expect("each JSONL line is an Event"))
        // Consumer discriminator: Cedar-path Adjudicated records carry
        // Actor::policy("cedar"); the mirror's synthetic Started snapshot
        // record carries Actor::policy("monitor") and is excluded.
        .filter(|event| event.actor.actor_type == ActorType::Policy && event.actor.id == "cedar")
        .filter_map(|event| match event.event {
            TrajectoryEvent::Control(Control::Adjudicated(adj)) => Some((adj, event.raw)),
            _ => None,
        })
        .collect();

    // Cedar-path events (steps 2–5) each persist one Adjudicated record;
    // Control events (step 1) early-return without one (their monitor
    // snapshot record is filtered out by the actor discriminator above).
    assert_eq!(
        adjudicated_records.len(),
        4,
        "expected one persisted Cedar-actor Adjudicated record per Cedar-path event"
    );
    let escalated = &adjudicated_records[2..4];
    for (i, (record, raw)) in escalated.iter().enumerate() {
        let step = format!("persisted record for step {}", i + 4);
        assert_backstop_escalation(record, &step);
        // Zero-diagnostics discipline: the recorded Cedar response carries
        // no evaluation errors.
        let errors = raw
            .as_ref()
            .and_then(|r| r.pointer("/response/errors"))
            .and_then(|e| e.as_array())
            .expect("persisted record raw_json carries response.errors");
        assert!(
            errors.is_empty(),
            "{step}: response.errors must be empty, got: {errors:?}"
        );
    }
}
