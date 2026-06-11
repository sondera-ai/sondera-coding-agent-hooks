//! End-to-end multi-hop monitor enforcement tests.
//!
//! Replays a tripping trajectory (untrusted read → protected write, no
//! approval) and an approved trajectory (untrusted read → `Resumed("user")`
//! → the SAME protected write) as SEPARATE `adjudicate` calls through the
//! full production path — guardrails (YARA + IFC + policy) included —
//! proving the monitor's temporal fact survives across calls and actually
//! changes adjudication via `policies/multi_hop.cedar`.
//!
//! The tripping event ITSELF is denied: `observe` runs before
//! `build_request`, so the FSM is already Violated when Cedar evaluates the
//! tripping write, and `untrusted_pending` is derived Armed-or-Violated —
//! the deny comes from `multi_hop.cedar`, with no backstop mechanism. The
//! approval is synthesized as `Control::Resumed(Resumed::new("user"))`
//! directly, since no adapter emits Resumed today.
//!
//! Requires Ollama running locally with the gpt-oss-safeguard model:
//!   ollama pull gpt-oss-safeguard:20b
//!   ollama serve
//!
//! Run with:
//!   cargo +stable test -p sondera-harness --test multi_hop_integration -- --ignored

use sondera_harness::{
    Action, Adjudicated, Agent, CedarPolicyHarness, Control, Decision, Event, FileOperation,
    Harness, Observation, Resumed, ShellCommand, Started, TrajectoryEvent, WebFetchOutput,
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
    format!("test-multihop-{}", uuid::Uuid::new_v4())
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

/// Protected file write: matches the default `.github/workflows/**` glob.
fn protected_file_write(traj: &str) -> Event {
    make_event(
        traj,
        TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(
            PROTECTED_TEST_PATH,
            BENIGN_YAML,
        ))),
    )
}

/// Protected shell write: `tee` is a write-capable binary and its positional
/// target is checked by the shell heuristic, so the protected path trips
/// `is_protected_write`.
fn protected_shell_write(traj: &str) -> Event {
    make_event(
        traj,
        TrajectoryEvent::Action(Action::ShellCommand(
            ShellCommand::new(format!("tee {PROTECTED_TEST_PATH}")).with_cwd("/tmp/test"),
        )),
    )
}

/// Arm the monitor via a SEPARATE adjudicate call carrying the untrusted
/// read. The read itself is benign and must be allowed — only the
/// obligation it creates affects later events.
async fn arm_monitor(harness: &CedarPolicyHarness, traj: &str) {
    let result = harness.adjudicate(web_fetch_output(traj)).await.unwrap();
    assert_eq!(
        result.decision,
        Decision::Allow,
        "the benign untrusted read itself should be allowed, got reason: {:?}",
        result.reason
    );
}

/// Extract the policy ids cited in the decision annotations
/// (containment-assertion pattern — other forbids may also fire).
fn policy_ids(result: &Adjudicated) -> Vec<&str> {
    result
        .annotations
        .iter()
        .filter_map(|a| a.policy_id.as_deref())
        .collect()
}

/// Untrusted read then protected file write as separate adjudicate calls, no
/// approval → the tripping write ITSELF is denied citing the multi-hop file
/// forbid. observe runs before build_request, so the FSM is already Violated
/// when Cedar evaluates this event — the deny must come from multi_hop.cedar,
/// no backstop exists.
#[tokio::test]
#[ignore = "requires Ollama running locally with gpt-oss-safeguard model"]
async fn tripping_trajectory_file_write_denied_citing_multi_hop_forbid() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();

    start_trajectory(&harness, &traj).await;
    arm_monitor(&harness, &traj).await;

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
        "deny must cite the multi-hop file forbid, got: {ids:?}"
    );
}

/// The SAME protected write on the SAME path is ALLOWED when a user-originated
/// approval arrives between the untrusted read and the write — the
/// discriminating proof that the deny above came from monitor state, not the
/// path. reason.is_none() on the Allow is the e2e zero-diagnostics proxy (a
/// non-None reason on Allow carries joined Cedar evaluation errors).
#[tokio::test]
#[ignore = "requires Ollama running locally with gpt-oss-safeguard model"]
async fn approved_trajectory_same_protected_write_allowed() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();

    start_trajectory(&harness, &traj).await;
    arm_monitor(&harness, &traj).await;

    // Synthesized approval: a user-originated Resumed as its own adjudicate
    // call clears the armed obligation through the real ingest path.
    let approval = make_event(
        &traj,
        TrajectoryEvent::Control(Control::Resumed(Resumed::new("user"))),
    );
    let result = harness.adjudicate(approval).await.unwrap();
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Control::Resumed should be allowed (Control bypass)"
    );

    let result = harness
        .adjudicate(protected_file_write(&traj))
        .await
        .unwrap();
    assert_eq!(
        result.decision,
        Decision::Allow,
        "the SAME protected write must be allowed after user approval, \
         got reason: {:?}, annotations: {:?}",
        result.reason,
        policy_ids(&result)
    );
    assert!(
        result.reason.is_none(),
        "Allow must carry no joined Cedar evaluation errors (e2e \
         zero-diagnostics proxy), got: {:?}",
        result.reason
    );
}

/// Untrusted read then a write-capable shell command targeting the protected
/// path → denied citing the multi-hop shell forbid (resource.untrusted_pending
/// lives on the Trajectory entity for shell).
#[tokio::test]
#[ignore = "requires Ollama running locally with gpt-oss-safeguard model"]
async fn tripping_trajectory_shell_write_denied_citing_multi_hop_forbid() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();

    start_trajectory(&harness, &traj).await;
    arm_monitor(&harness, &traj).await;

    let result = harness
        .adjudicate(protected_shell_write(&traj))
        .await
        .unwrap();
    assert_eq!(
        result.decision,
        Decision::Deny,
        "protected shell write after an unapproved untrusted read must be denied"
    );
    let ids = policy_ids(&result);
    assert!(
        ids.contains(&"multi-hop-forbid-shell-protected-write-untrusted-pending"),
        "deny must cite the multi-hop shell forbid, got: {ids:?}"
    );
}
