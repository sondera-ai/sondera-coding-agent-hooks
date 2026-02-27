//! Integration test for trajectory label persistence across adjudications.
//!
//! Verifies that the high-water mark label on a Trajectory entity survives
//! multiple adjudication calls within the same harness instance.
//!
//! Requires Ollama running locally with the gpt-oss-safeguard model:
//!   ollama pull gpt-oss-safeguard:20b
//!   ollama serve
//!
//! Run with: cargo test -p sondera-harness -- --ignored trajectory_label

use sondera_harness::{
    Action, Actor, Agent, CedarPolicyHarness, Control, Decision, Event, Harness, Label,
    Observation, Prompt, Started, Trajectory, TrajectoryEvent, WebFetch, euid,
};
use std::path::PathBuf;
const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

fn test_agent() -> Agent {
    Agent {
        id: "test-agent".to_string(),
        provider_id: "test-provider".to_string(),
    }
}

async fn load_harness() -> CedarPolicyHarness {
    let path = PathBuf::from(POLICIES_DIR);
    CedarPolicyHarness::from_policy_dir(path)
        .await
        .expect("should load policies directory")
}

fn raw_context() -> serde_json::Value {
    serde_json::json!({
        "cwd": "/tmp/test",
        "permission_mode": "default",
        "transcript_path": "/tmp/test-transcript.jsonl",
    })
}

/// Start a trajectory by sending a Control::Started event.
async fn start_trajectory(harness: &CedarPolicyHarness, trajectory_id: &str) {
    let started = TrajectoryEvent::Control(Control::Started(Started::new("test-agent")));
    let event = Event::new(test_agent(), trajectory_id, started).with_raw(raw_context());
    let result = harness.adjudicate(event).await.unwrap();
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Started events should always be allowed"
    );
}

/// Read the Trajectory entity back from the harness entity store.
fn get_trajectory(harness: &CedarPolicyHarness, trajectory_id: &str) -> Trajectory {
    let uid = euid("Trajectory", trajectory_id).unwrap();
    let entity = harness
        .get_entity(&uid)
        .expect("entity store read should succeed")
        .expect("trajectory entity should exist");
    Trajectory::try_from(entity).expect("trajectory entity should be valid")
}

/// Verify that the entity store correctly roundtrips a Trajectory with a
/// non-default label. This test does NOT require Ollama.
#[tokio::test]
async fn trajectory_entity_store_roundtrip_preserves_label() {
    let harness = load_harness().await;
    let trajectory_id = format!("test-roundtrip-{}", uuid::Uuid::new_v4());

    // Create a trajectory with HighlyConfidential label and upsert it.
    let mut traj = Trajectory::new(&trajectory_id);
    traj.label = Label::HighlyConfidential;

    let entity: cedar_policy::Entity = traj.into_entity().unwrap();
    harness.upsert_entity(entity).unwrap();

    // Read it back and verify the label survived.
    let readback = get_trajectory(&harness, &trajectory_id);
    assert_eq!(
        readback.label,
        Label::HighlyConfidential,
        "label should survive entity store roundtrip"
    );
}

#[tokio::test]
#[ignore = "requires Ollama running locally with gpt-oss-safeguard model"]
async fn trajectory_label_raised_to_highly_confidential_by_pii_prompt() {
    let harness = load_harness().await;
    let trajectory_id = format!("test-ifc-{}", uuid::Uuid::new_v4());

    // 1. Start the trajectory — label should be Public (default).
    start_trajectory(&harness, &trajectory_id).await;
    let traj = get_trajectory(&harness, &trajectory_id);
    assert_eq!(
        traj.label,
        Label::Public,
        "new trajectory should start as Public"
    );

    // 2. Submit a user prompt containing PII (fake birthday and location).
    let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(
        "My name is Jane Doe. My birthday is March 15, 1989. \
         I live at 742 Evergreen Terrace, Philadelphia, PA 19104. \
         My social security number is 123-45-6789.",
    )));
    let event = Event::new(test_agent(), &trajectory_id, prompt)
        .with_actor(Actor::human("test-agent"))
        .with_raw(raw_context());
    let result = harness.adjudicate(event).await.unwrap();
    assert_eq!(
        result.decision,
        Decision::Allow,
        "prompt observation should be allowed"
    );

    // 3. Verify the trajectory label was raised to HighlyConfidential.
    let traj = get_trajectory(&harness, &trajectory_id);
    assert_eq!(
        traj.label,
        Label::HighlyConfidential,
        "trajectory should be HighlyConfidential after PII prompt"
    );
}

#[tokio::test]
#[ignore = "requires Ollama running locally with gpt-oss-safeguard model"]
async fn trajectory_label_persists_across_adjudications() {
    let harness = load_harness().await;
    let trajectory_id = format!("test-ifc-{}", uuid::Uuid::new_v4());

    // 1. Start trajectory.
    start_trajectory(&harness, &trajectory_id).await;

    // 2. Taint the trajectory with PII.
    let prompt = TrajectoryEvent::Observation(Observation::Prompt(Prompt::user(
        "My date of birth is June 22, 1985. I live in Boston, MA 02101. \
         My passport number is X12345678.",
    )));
    let event = Event::new(test_agent(), &trajectory_id, prompt)
        .with_actor(Actor::human("test-agent"))
        .with_raw(raw_context());
    harness.adjudicate(event).await.unwrap();

    let traj = get_trajectory(&harness, &trajectory_id);
    assert_eq!(
        traj.label,
        Label::HighlyConfidential,
        "trajectory should be HighlyConfidential after PII prompt"
    );

    // 3. Send a benign WebFetch action — the trajectory label must NOT reset.
    let web_fetch = TrajectoryEvent::Action(Action::WebFetch(WebFetch::new(
        "https://www.google.com",
        "search for weather",
    )));
    let event = Event::new(test_agent(), &trajectory_id, web_fetch).with_raw(raw_context());
    let result = harness.adjudicate(event).await.unwrap();

    // 4. Verify the trajectory label is STILL HighlyConfidential.
    let traj = get_trajectory(&harness, &trajectory_id);
    assert_eq!(
        traj.label,
        Label::HighlyConfidential,
        "trajectory label must persist as HighlyConfidential across adjudications"
    );

    // 5. The IFC policy should have denied the WebFetch on a HighlyConfidential trajectory.
    assert_eq!(
        result.decision,
        Decision::Deny,
        "WebFetch should be denied on HighlyConfidential trajectory by ifc-forbid-webfetch-highly-confidential"
    );

    // 6. Verify the denying policy is identified in annotations.
    let policy_ids: Vec<&str> = result
        .annotations
        .iter()
        .filter_map(|a| a.policy_id.as_deref())
        .collect();
    assert!(
        policy_ids.contains(&"ifc-forbid-webfetch-highly-confidential"),
        "deny should cite ifc-forbid-webfetch-highly-confidential, got: {policy_ids:?}"
    );
}
