//! Integration tests for multi-hop monitor persistence.
//!
//! Proves from outside the crate boundary that:
//! - monitor state survives across separately-constructed monitor instances
//!   via the harness Fjall `monitor_state` keyspace,
//! - the monitor block runs and persists strictly BEFORE the Control-event
//!   Cedar bypass in `adjudicate`,
//! - a user-originated `Control::Resumed` arriving as a separate adjudicate
//!   call clears a persisted Armed state, while an agent-originated one does
//!   not, through the real ingest path,
//! - the `Trajectory.untrusted_pending` Cedar attribute roundtrips and
//!   defaults to false for older entities lacking it,
//! - the `multi_hop.cedar` forbids deny exactly when the temporal fact and
//!   a protected-path write coincide, allow otherwise, with ZERO Cedar
//!   evaluation diagnostics in every case — the guard against Cedar's
//!   fail-open-on-missing-attribute,
//! - request construction is fail-closed: omitting the required
//!   `untrusted_pending`/`protected_path` context attributes makes
//!   `validate_request` return `Err` at `Request::new`.
//!
//! No Ollama required: Control events bypass Cedar/guardrails, the
//! store/entity tests never call `adjudicate` at all, and the Cedar-layer
//! tests drive `validate_request`/`is_authorized` directly — so none of
//! these tests are `#[ignore]`-gated.
//!
//! Run with: cargo test -p sondera-harness --test monitor_persistence

use sondera_harness::{
    Action, Agent, CedarPolicyHarness, Control, Decision, EntityBuilder, Event, FileOperation,
    Harness, Label, Monitor, MonitorConfig, Observation, Resumed, Started, Trajectory,
    TrajectoryEvent, UntrustedThenProtectedWrite, Verdict, WebFetchOutput, euid,
};
use std::collections::HashSet;
use std::path::PathBuf;

const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

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
    format!("test-monpersist-{}", uuid::Uuid::new_v4())
}

fn make_event(traj: &str, event_variant: TrajectoryEvent) -> Event {
    Event::new(test_agent(), traj, event_variant)
}

/// Untrusted read: arms the monitor under the default config.
fn web_fetch_output(traj: &str) -> Event {
    make_event(
        traj,
        TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
            "call-1",
            "https://evil.example.com",
            200,
            "payload",
        ))),
    )
}

/// Protected write: trips an Armed monitor under the default config.
fn protected_write(traj: &str) -> Event {
    make_event(
        traj,
        TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(".env", "X=1"))),
    )
}

/// Seed a persisted Armed state for `traj` via the harness passthroughs.
fn seed_armed_state(harness: &CedarPolicyHarness, traj: &str) {
    let mut monitor = UntrustedThenProtectedWrite::new(MonitorConfig::default()).unwrap();
    monitor.observe(&web_fetch_output(traj)).unwrap();
    assert_eq!(monitor.verdict(), Verdict::Pending, "seed must be Armed");
    harness.put_monitor_state(traj, monitor.state()).unwrap();
}

/// Re-hydrate the persisted state for `traj` and return its verdict.
fn rehydrated_verdict(harness: &CedarPolicyHarness, traj: &str) -> Verdict {
    let state = harness
        .get_monitor_state(traj)
        .expect("monitor state read should succeed")
        .expect("monitor state should exist");
    UntrustedThenProtectedWrite::with_state(MonitorConfig::default(), state)
        .unwrap()
        .verdict()
}

/// The temporal fact crosses two separately-constructed monitor instances via
/// the harness store — arm in instance one, persist, re-hydrate into instance
/// two, and the protected write trips it.
#[tokio::test]
async fn monitor_state_roundtrip_crosses_monitor_instances() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();

    let mut first = UntrustedThenProtectedWrite::new(MonitorConfig::default()).unwrap();
    first.observe(&web_fetch_output(&traj)).unwrap();
    assert_eq!(first.verdict(), Verdict::Pending);
    harness.put_monitor_state(&traj, first.state()).unwrap();

    let state = harness
        .get_monitor_state(&traj)
        .unwrap()
        .expect("persisted state should be readable");
    let mut second =
        UntrustedThenProtectedWrite::with_state(MonitorConfig::default(), state).unwrap();
    assert_eq!(
        second.verdict(),
        Verdict::Pending,
        "re-hydrated monitor must carry the armed obligation"
    );
    second.observe(&protected_write(&traj)).unwrap();
    assert_eq!(
        second.verdict(),
        Verdict::Violated,
        "temporal fact must cross separately-constructed monitor instances (D-16)"
    );
}

/// An unknown trajectory id has no persisted state — the first event of a
/// trajectory constructs a fresh Clean monitor.
#[tokio::test]
async fn unknown_trajectory_has_no_monitor_state() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();
    assert!(
        harness.get_monitor_state(&traj).unwrap().is_none(),
        "fresh trajectory must have no persisted monitor state"
    );
}

/// A Control-only adjudicate call is Allowed AND leaves persisted monitor
/// state behind — proving the monitor block ran (load → observe → persist)
/// BEFORE the Control bypass returned. No Ollama involved: Control events
/// never reach guardrails or Cedar.
#[tokio::test]
async fn monitor_block_runs_before_control_bypass() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();

    let started = make_event(
        &traj,
        TrajectoryEvent::Control(Control::Started(Started::new("test-agent"))),
    )
    .with_raw(raw_context());
    let result = harness.adjudicate(started).await.unwrap();

    assert_eq!(
        result.decision,
        Decision::Allow,
        "Started events should always be allowed"
    );
    assert!(
        harness.get_monitor_state(&traj).unwrap().is_some(),
        "monitor must observe + persist BEFORE the Control bypass (MON-04)"
    );
}

/// A user-originated Resumed arriving as a separate adjudicate call clears a
/// persisted Armed state through the real ingest path.
#[tokio::test]
async fn user_resumed_clears_armed_through_ingest_path() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();
    seed_armed_state(&harness, &traj);

    let approval = make_event(
        &traj,
        TrajectoryEvent::Control(Control::Resumed(Resumed::new("user"))),
    )
    .with_raw(raw_context());
    let result = harness.adjudicate(approval).await.unwrap();
    assert_eq!(result.decision, Decision::Allow);

    assert_eq!(
        rehydrated_verdict(&harness, &traj),
        Verdict::Satisfied,
        "user-originated Resumed must clear Armed (D-13)"
    );
}

/// An agent-originated Resumed does NOT clear a persisted Armed state — the
/// allowlist gates approval (fail-closed).
#[tokio::test]
async fn agent_resumed_does_not_clear_armed_through_ingest_path() {
    let (harness, _temp_dir) = load_harness().await;
    let traj = new_trajectory_id();
    seed_armed_state(&harness, &traj);

    let non_approval = make_event(
        &traj,
        TrajectoryEvent::Control(Control::Resumed(Resumed::new("agent"))),
    )
    .with_raw(raw_context());
    let result = harness.adjudicate(non_approval).await.unwrap();
    assert_eq!(result.decision, Decision::Allow);

    assert_eq!(
        rehydrated_verdict(&harness, &traj),
        Verdict::Pending,
        "agent-originated Resumed must NOT clear Armed (D-13 fail-closed)"
    );
}

/// untrusted_pending=true survives the entity store roundtrip
/// (into_entity → upsert → get → TryFrom).
#[tokio::test]
async fn trajectory_untrusted_pending_roundtrips() {
    let (harness, _temp_dir) = load_harness().await;
    let traj_id = new_trajectory_id();

    let mut traj = Trajectory::new(&traj_id);
    traj.untrusted_pending = true;
    harness.upsert_entity(traj.into_entity().unwrap()).unwrap();

    let entity = harness
        .get_entity(&euid("Trajectory", &traj_id).unwrap())
        .unwrap()
        .expect("trajectory entity should exist");
    let readback = Trajectory::try_from(entity).unwrap();
    assert!(
        readback.untrusted_pending,
        "untrusted_pending=true must survive the entity store roundtrip"
    );
}

/// Backward compat: an older Trajectory entity — step_count/label/taints but
/// NO untrusted_pending attribute — converts via TryFrom with
/// untrusted_pending defaulting to false.
#[tokio::test]
async fn pre_phase3_entity_defaults_untrusted_pending_false() {
    let traj_id = new_trajectory_id();
    let entity = sondera_harness::EntityBuilder::from_type_and_id("Trajectory", &traj_id)
        .unwrap()
        .long("step_count", 3)
        .entity_ref("label", "Label", &Label::Public.to_string())
        .unwrap()
        .entity_set("taints", &HashSet::new())
        .build()
        .unwrap();

    let traj = Trajectory::try_from(entity).unwrap();
    assert_eq!(traj.step_count, 3);
    assert!(
        !traj.untrusted_pending,
        "pre-Phase-3 entities must deserialize with untrusted_pending=false"
    );
}

// ─────────────────────────────────────────────────────
// Cedar-layer multi-hop enforcement
//
// These tests drive validate_request → is_authorized directly with fully
// specified context JSON, proving the multi_hop.cedar forbids key on the
// temporal fact + protected path — with a zero-diagnostics assertion on
// every test (including Allow cases) guarding against Cedar's
// fail-open-on-missing-attribute.
// ─────────────────────────────────────────────────────

/// Test path that is glob-protected by default config but triggers no YARA
/// signature category (unlike `.env`, which may flag credential_access).
const PROTECTED_TEST_PATH: &str = ".github/workflows/ci.yml";

/// Full FileOperationContext JSON: every required attribute of the context
/// type, with zeroed guardrail results so no unrelated forbid can fire on
/// Allow-case fixtures.
fn file_op_context_json(untrusted_pending: bool, protected_path: bool) -> serde_json::Value {
    serde_json::json!({
        "workspace": {"cwd": "/tmp/test", "permission_mode": "default", "transcript_path": ""},
        "signature": {"matches": 0, "categories": [], "severity": 0},
        "policy": {"compliant": true, "violations": []},
        "label": {"__entity": {"type": "Label", "id": "Public"}},
        "path": PROTECTED_TEST_PATH,
        "operation": "Write",
        "protected_path": protected_path,
        "untrusted_pending": untrusted_pending,
    })
}

/// Full ShellCommandContext JSON (the trajectory fact lives on the
/// resource entity for shell, so only protected_path is parameterized).
fn shell_context_json(protected_path: bool) -> serde_json::Value {
    serde_json::json!({
        "workspace": {"cwd": "/tmp/test", "permission_mode": "default", "transcript_path": ""},
        "signature": {"matches": 0, "categories": [], "severity": 0},
        "policy": {"compliant": true, "violations": []},
        "label": {"__entity": {"type": "Label", "id": "Public"}},
        "command": "echo hello",
        "working_dir": "/tmp/test",
        "protected_path": protected_path,
    })
}

/// Upsert a Trajectory entity with the given untrusted_pending fact.
fn upsert_trajectory(harness: &CedarPolicyHarness, traj_id: &str, untrusted_pending: bool) {
    let mut traj = Trajectory::new(traj_id);
    traj.untrusted_pending = untrusted_pending;
    harness.upsert_entity(traj.into_entity().unwrap()).unwrap();
}

/// Upsert the File resource entity — File has a required `label` attribute
/// (same EntityBuilder pattern transform.rs uses).
fn upsert_file(harness: &CedarPolicyHarness, path: &str) {
    let file = EntityBuilder::new(euid("File", path).unwrap())
        .entity_ref("label", "Label", &Label::Public.to_string())
        .unwrap()
        .build()
        .unwrap();
    harness.upsert_entity(file).unwrap();
}

/// Build a schema-validated FileWrite request with full context.
fn file_write_request(
    harness: &CedarPolicyHarness,
    untrusted_pending: bool,
    protected_path: bool,
) -> anyhow::Result<cedar_policy::Request> {
    let context = cedar_policy::Context::from_json_value(
        file_op_context_json(untrusted_pending, protected_path),
        None,
    )?;
    harness.validate_request(
        euid("Agent", "test-agent")?,
        euid("Action", "FileWrite")?,
        euid("File", PROTECTED_TEST_PATH)?,
        Some(context),
    )
}

/// Build a schema-validated ShellCommand request with full context.
fn shell_request(
    harness: &CedarPolicyHarness,
    traj_id: &str,
    protected_path: bool,
) -> anyhow::Result<cedar_policy::Request> {
    let context = cedar_policy::Context::from_json_value(shell_context_json(protected_path), None)?;
    harness.validate_request(
        euid("Agent", "test-agent")?,
        euid("Action", "ShellCommand")?,
        euid("Trajectory", traj_id)?,
        Some(context),
    )
}

/// Authorize and return (decision, reason policy-ids); asserts the
/// zero-diagnostics guard on EVERY evaluation.
fn authorize_zero_diagnostics(
    harness: &CedarPolicyHarness,
    request: &cedar_policy::Request,
) -> (cedar_policy::Decision, Vec<String>) {
    let response = harness.is_authorized(request).unwrap();
    let errors: Vec<String> = response
        .diagnostics()
        .errors()
        .map(|e| e.to_string())
        .collect();
    assert_eq!(
        response.diagnostics().errors().count(),
        0,
        "CEDAR-02 zero-diagnostics guard: Cedar evaluation must produce no \
         errors (fail-open indicator), got: {errors:?}"
    );
    let reasons = response
        .diagnostics()
        .reason()
        .map(|p| p.to_string())
        .collect();
    (response.decision(), reasons)
}

/// untrusted_pending && protected_path on a FileWrite → Deny citing the
/// multi-hop file forbid, zero diagnostics.
#[tokio::test]
async fn multi_hop_forbid_denies_protected_file_write_when_pending() {
    let (harness, _temp_dir) = load_harness().await;
    let traj_id = new_trajectory_id();
    upsert_trajectory(&harness, &traj_id, true);
    upsert_file(&harness, PROTECTED_TEST_PATH);

    let request = file_write_request(&harness, true, true).unwrap();
    let (decision, reasons) = authorize_zero_diagnostics(&harness, &request);

    assert_eq!(decision, cedar_policy::Decision::Deny);
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("multi-hop-forbid-file-protected-write-untrusted-pending")),
        "deny must cite the multi-hop file forbid, got: {reasons:?}"
    );
}

/// resource.untrusted_pending && context.protected_path on a ShellCommand →
/// Deny citing the multi-hop shell forbid, zero diagnostics.
#[tokio::test]
async fn multi_hop_forbid_denies_protected_shell_write_when_pending() {
    let (harness, _temp_dir) = load_harness().await;
    let traj_id = new_trajectory_id();
    upsert_trajectory(&harness, &traj_id, true);

    let request = shell_request(&harness, &traj_id, true).unwrap();
    let (decision, reasons) = authorize_zero_diagnostics(&harness, &request);

    assert_eq!(decision, cedar_policy::Decision::Deny);
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("multi-hop-forbid-shell-protected-write-untrusted-pending")),
        "deny must cite the multi-hop shell forbid, got: {reasons:?}"
    );
}

/// The same protected-path requests with untrusted_pending=false (entity AND
/// context) are Allowed — proving the forbids key on the temporal fact, not
/// the path alone.
#[tokio::test]
async fn multi_hop_allows_protected_write_when_not_pending() {
    let (harness, _temp_dir) = load_harness().await;
    let traj_id = new_trajectory_id();
    upsert_trajectory(&harness, &traj_id, false);
    upsert_file(&harness, PROTECTED_TEST_PATH);

    let file_req = file_write_request(&harness, false, true).unwrap();
    let (decision, _) = authorize_zero_diagnostics(&harness, &file_req);
    assert_eq!(
        decision,
        cedar_policy::Decision::Allow,
        "protected write on a clean trajectory must be allowed"
    );

    let shell_req = shell_request(&harness, &traj_id, true).unwrap();
    let (decision, _) = authorize_zero_diagnostics(&harness, &shell_req);
    assert_eq!(
        decision,
        cedar_policy::Decision::Allow,
        "protected shell write on a clean trajectory must be allowed"
    );
}

/// untrusted_pending=true with protected_path=false is Allowed — the
/// obligation alone does not block unprotected writes.
#[tokio::test]
async fn multi_hop_allows_unprotected_write_when_pending() {
    let (harness, _temp_dir) = load_harness().await;
    let traj_id = new_trajectory_id();
    upsert_trajectory(&harness, &traj_id, true);
    upsert_file(&harness, PROTECTED_TEST_PATH);

    let file_req = file_write_request(&harness, true, false).unwrap();
    let (decision, _) = authorize_zero_diagnostics(&harness, &file_req);
    assert_eq!(
        decision,
        cedar_policy::Decision::Allow,
        "unprotected file write must be allowed even while pending"
    );

    let shell_req = shell_request(&harness, &traj_id, false).unwrap();
    let (decision, _) = authorize_zero_diagnostics(&harness, &shell_req);
    assert_eq!(
        decision,
        cedar_policy::Decision::Allow,
        "unprotected shell command must be allowed even while pending"
    );
}

/// Fail-closed at construction: a FileWrite context missing the required
/// untrusted_pending/protected_path attributes makes validate_request return
/// Err at Request::new — a would-be silent fail-open becomes a hard error.
#[tokio::test]
async fn request_construction_fails_closed_without_required_context_attrs() {
    let (harness, _temp_dir) = load_harness().await;

    // Older context shape: every attribute EXCEPT untrusted_pending/protected_path.
    let context = cedar_policy::Context::from_json_value(
        serde_json::json!({
            "workspace": {"cwd": "/tmp/test", "permission_mode": "default", "transcript_path": ""},
            "signature": {"matches": 0, "categories": [], "severity": 0},
            "policy": {"compliant": true, "violations": []},
            "label": {"__entity": {"type": "Label", "id": "Public"}},
            "path": PROTECTED_TEST_PATH,
            "operation": "Write",
        }),
        None,
    )
    .unwrap();

    let result = harness.validate_request(
        euid("Agent", "test-agent").unwrap(),
        euid("Action", "FileWrite").unwrap(),
        euid("File", PROTECTED_TEST_PATH).unwrap(),
        Some(context),
    );
    assert!(
        result.is_err(),
        "Request::new must reject a context missing the required \
         untrusted_pending/protected_path attributes (fail-closed)"
    );
}
