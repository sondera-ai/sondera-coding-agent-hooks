//! End-to-end check that a refused file read does not leave its bytes in the
//! ledger.
//!
//! A hook attaches a file's content so content-keyed policy can match it — the
//! VS Code adapter does exactly this for `@`-mentioned files, which never
//! produce a read tool call. Adjudication consumes that content in memory; the
//! store must not keep it once the verdict says the read was not allowed.
//!
//! Both halves matter and neither is covered elsewhere:
//!
//! * **A deny redacts.** Otherwise the harness ends up holding the secret it
//!   just blocked, in a database that outlives the run.
//! * **An allow does not.** Redacting unconditionally would be easy and would
//!   silently gut the transcript view and the transcript scanner, which read
//!   file bodies back out of the store.
//!
//! These tests run without a model provider: both verdicts come from
//! path-matching Cedar policy in the repo's own `.sondera` directory.

use sondera_cedar_policy::CedarPolicyHarness;
use sondera_storage::TrajectoryStore;
use sondera_types::{
    Action, Agent, Decision, Event, FileOpType, FileOperation, Harness, TrajectoryEvent,
    TrajectoryReaderWriter, redaction_marker,
};
use std::path::{Path, PathBuf};

const CONFIG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../.sondera");

/// Distinctive enough that finding it anywhere in the serialized ledger is
/// proof the body leaked, not a coincidence.
const SECRET: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5LEAKCANARY deploy@meridian";

fn test_agent() -> Agent {
    Agent {
        id: "test-agent".to_string(),
        provider: "test-provider".to_string(),
        platform: String::new(),
    }
}

fn read_event(trajectory_id: &str, path: &str) -> Event {
    Event::new(
        test_agent(),
        trajectory_id,
        TrajectoryEvent::Action(Action::FileOperation(FileOperation {
            call_id: "call-1".to_string(),
            operation: FileOpType::Read,
            path: path.to_string(),
            content: Some(SECRET.to_string()),
            old_content: None,
        })),
    )
}

async fn load(storage_dir: &Path) -> CedarPolicyHarness {
    CedarPolicyHarness::from_config_dir_isolated(PathBuf::from(CONFIG_DIR), storage_dir)
        .await
        .expect("should load policies directory")
}

/// Read one run's events back out of the isolated database the harness wrote
/// to. Going through the store is the point: these tests assert on what was
/// persisted, not on what was passed around in memory.
///
/// The harness does not lend out its store, so this reopens the file. Callers
/// drop their harness first — the reopen is a second connection otherwise, and
/// nothing here needs to hold two.
async fn stored_events(storage_dir: &Path, trajectory_id: &str) -> Vec<Event> {
    let store = TrajectoryStore::open(storage_dir.join("trajectories.db"))
        .await
        .expect("reopen the isolated store");

    store
        .trajectory_events(trajectory_id)
        .await
        .expect("read the persisted run")
}

/// The single file operation a run persisted.
async fn stored_read(storage_dir: &Path, trajectory_id: &str) -> FileOperation {
    stored_events(storage_dir, trajectory_id)
        .await
        .into_iter()
        .find_map(|event| match event.event {
            TrajectoryEvent::Action(Action::FileOperation(op)) => Some(op),
            _ => None,
        })
        .expect("the run should have persisted its file read")
}

#[tokio::test]
async fn a_denied_read_persists_a_marker_instead_of_the_file_body() {
    let temp = tempfile::tempdir().expect("temp dir for the store");
    let trajectory_id = format!("test-redaction-deny-{}", uuid::Uuid::new_v4());

    let harness = load(temp.path()).await;
    let decision = harness
        .adjudicate(read_event(
            &trajectory_id,
            "/Users/dev/project/.ssh/authorized_keys",
        ))
        .await
        .expect("the read must reach a decision");
    drop(harness);

    assert_eq!(
        decision.decision,
        Decision::Deny,
        "reading .ssh/authorized_keys is denied by baseline policy; without a \
         deny this test proves nothing: {decision:?}"
    );

    let stored = stored_read(temp.path(), &trajectory_id).await;

    assert_eq!(
        stored.content.as_deref(),
        Some(redaction_marker(SECRET).as_str()),
        "a denied read must persist the marker, not the bytes"
    );
    assert_eq!(
        stored.path, "/Users/dev/project/.ssh/authorized_keys",
        "redaction must leave the audit trail intact"
    );
    assert_eq!(stored.call_id, "call-1");
    assert_eq!(stored.operation, FileOpType::Read);
}

#[tokio::test]
async fn a_denied_read_leaves_no_copy_of_the_body_anywhere_in_the_run() {
    let temp = tempfile::tempdir().expect("temp dir for the store");
    let trajectory_id = format!("test-redaction-sweep-{}", uuid::Uuid::new_v4());

    let harness = load(temp.path()).await;
    let _decision = harness
        .adjudicate(read_event(&trajectory_id, "/Users/dev/project/.ssh/id_rsa"))
        .await
        .expect("the read must reach a decision");
    drop(harness);

    // The adjudication control event is written to the same run, and a future
    // change could just as easily carry the body there. Sweep the whole run
    // rather than only the event redaction was applied to.
    let events = stored_events(temp.path(), &trajectory_id).await;
    let serialized = serde_json::to_string(&events).expect("serialize the run");

    assert!(
        !serialized.contains("LEAKCANARY"),
        "the denied file body must not survive anywhere in the run: {serialized}"
    );
}

#[tokio::test]
async fn an_allowed_read_persists_the_file_body_unchanged() {
    let temp = tempfile::tempdir().expect("temp dir for the store");
    let trajectory_id = format!("test-redaction-allow-{}", uuid::Uuid::new_v4());

    let harness = load(temp.path()).await;
    let decision = harness
        .adjudicate(read_event(&trajectory_id, "/Users/dev/project/src/main.rs"))
        .await
        .expect("the read must reach a decision");
    drop(harness);

    assert_eq!(
        decision.decision,
        Decision::Allow,
        "an ordinary source file read is not governed: {decision:?}"
    );

    let stored = stored_read(temp.path(), &trajectory_id).await;
    assert_eq!(
        stored.content.as_deref(),
        Some(SECRET),
        "an allowed read must persist what the agent actually saw"
    );
}
