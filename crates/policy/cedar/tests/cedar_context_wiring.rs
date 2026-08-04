//! End-to-end check that the context the engine BUILDS is a context the
//! active schema ACCEPTS, and that the parser-derived records actually reach
//! the policies that read them.
//!
//! This is the only coverage of that contract. Everything else either loads the
//! policy directory without adjudicating (`cedar_policy_loading`) or is
//! `#[ignore]`d behind a local Ollama (`trajectory_label_persistence`). Two
//! whole classes of silent breakage live here and nowhere else:
//!
//! * **Required context fields.** `ShellCommandContext.file_signature` and
//!   `FileOperationContext.path_normalized` are non-optional. Omitting either
//!   fails `Request::new` context validation before a single policy runs, so
//!   every governed shell/file call errors out.
//! * **Namespace qualification.** The base schema declares
//!   `namespace Sondera { … }`. An unqualified `Agent::"x"` is a *different,
//!   undeclared* type; `euid` qualifies centrally and this pins that it worked.
//!
//! These tests run without a model provider. The deterministic context/schema
//! contract must remain testable in CI even when optional classifiers are off.

use sondera_cedar_policy::CedarPolicyHarness;
use sondera_types::{
    Action, Agent, Decision, Event, FileOperation, FileOperationResult, Harness, Observation,
    Prompt, ShellCommand, ShellCommandOutput, ToolCall, ToolOutput, TrajectoryEvent, WebFetch,
    WebFetchOutput,
};
use std::path::PathBuf;

const CONFIG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../.sondera");

fn test_agent() -> Agent {
    Agent {
        id: "test-agent".to_string(),
        provider: "test-provider".to_string(),
        platform: String::new(),
    }
}

async fn load() -> (CedarPolicyHarness, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("temp dir for entity store");
    let harness =
        CedarPolicyHarness::from_config_dir_isolated(PathBuf::from(CONFIG_DIR), temp_dir.path())
            .await
            .expect("should load policies directory");
    (harness, temp_dir)
}

async fn assert_allows(event: Event) {
    let (harness, _temp) = load().await;
    let out = harness
        .adjudicate(event)
        .await
        .expect("event context must reach a policy decision");
    assert_eq!(out.reason, None, "context must typecheck cleanly");
    assert_eq!(out.decision, Decision::Allow, "{out:?}");
}

#[tokio::test]
async fn prompt_context_typechecks_without_a_model() {
    assert_allows(Event::new(
        test_agent(),
        "traj-prompt",
        TrajectoryEvent::Observation(Observation::Prompt(Prompt::user("hello"))),
    ))
    .await;
}

#[tokio::test]
async fn shell_output_context_typechecks_without_a_model() {
    assert_allows(Event::new(
        test_agent(),
        "traj-shell-output",
        TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput::new(
            "call-1", 0, "ok", "",
        ))),
    ))
    .await;
}

#[tokio::test]
async fn web_fetch_output_context_typechecks_without_a_model() {
    assert_allows(Event::new(
        test_agent(),
        "traj-web-output",
        TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
            "call-1",
            "https://example.com",
            200,
            "ok",
        ))),
    ))
    .await;
}

#[tokio::test]
async fn file_operation_result_context_typechecks_without_a_model() {
    assert_allows(Event::new(
        test_agent(),
        "traj-file-output",
        TrajectoryEvent::Observation(Observation::FileOperationResult(
            FileOperationResult::success("call-1")
                .with_path("/tmp/result.txt")
                .with_content("ok"),
        )),
    ))
    .await;
}

#[tokio::test]
async fn tool_output_context_typechecks_without_a_model() {
    assert_allows(Event::new(
        test_agent(),
        "traj-tool-output",
        TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput::success("call-1", "ok"))),
    ))
    .await;
}

#[tokio::test]
async fn generic_toolcall_reaches_a_policy_decision() {
    let (harness, _temp) = load().await;
    let event = Event::new(
        test_agent(),
        "traj-toolcall",
        TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
            "mcp__linear__get_issue",
            serde_json::json!({"issue_id": "ENG-1"}),
        ))),
    );

    let out = harness
        .adjudicate(event)
        .await
        .expect("a generic ToolCall must reach a policy decision");

    assert_eq!(out.reason, None, "context must typecheck cleanly");
    assert_eq!(out.decision, Decision::Allow, "{out:?}");
}

/// `rm -rf /` must be denied by `forbid-rm-rf`, which matches on
/// `context.parse.program_flags` rather than globbing `command` — so a Deny
/// attributed to that policy proves the tree-sitter `parse` record was emitted
/// and populated, not merely that some rule fired.
#[tokio::test]
async fn shell_command_context_reaches_the_structural_parse_policy() {
    let (harness, _temp) = load().await;
    let event = Event::new(
        test_agent(),
        "traj-shell",
        TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("rm -rf /"))),
    );

    let out = harness.adjudicate(event).await.expect("adjudicate shell");

    assert_eq!(
        out.reason, None,
        "no policy may error at evaluation time; a reason here means the context \
         failed to typecheck and the engine fell back to a fail-closed Deny"
    );
    assert_eq!(out.decision, Decision::Deny, "`rm -rf /` must be denied");
    assert!(
        out.metadata
            .iter()
            .any(|m| m.policy_id.as_deref() == Some("forbid-rm-rf")),
        "expected the structural parse policy to fire; got {:?}",
        out.metadata
    );
}

/// Reading an SSH private key must be denied by `lol-forbid-read-ssh-private-keys`,
/// which matches on `context.path_normalized`. A Deny attributed to that policy
/// proves the required normalized-path field was emitted.
#[tokio::test]
async fn file_operation_context_reaches_the_normalized_path_policy() {
    let (harness, _temp) = load().await;
    let event = Event::new(
        test_agent(),
        "traj-file",
        TrajectoryEvent::Action(Action::FileOperation(FileOperation::read(
            "/home/u/.ssh/id_rsa",
        ))),
    );

    let out = harness.adjudicate(event).await.expect("adjudicate file");

    assert_eq!(out.reason, None, "context must typecheck cleanly");
    assert_eq!(out.decision, Decision::Deny);
    assert!(
        out.metadata
            .iter()
            .any(|m| m.policy_id.as_deref() == Some("lol-forbid-read-ssh-private-keys")),
        "expected the normalized-path policy to fire; got {:?}",
        out.metadata
    );
}

/// A benign fetch exercises the optional `url_parse` record. The assertion that
/// matters is `reason == None` plus a clean Allow: an ill-typed `url_parse`
/// would surface as an evaluation error and the fail-closed Deny.
#[tokio::test]
async fn web_fetch_context_typechecks_with_url_parse() {
    let (harness, _temp) = load().await;
    let event = Event::new(
        test_agent(),
        "traj-web",
        TrajectoryEvent::Action(Action::WebFetch(WebFetch::new(
            "https://example.com/x",
            "summarize",
        ))),
    );

    let out = harness
        .adjudicate(event)
        .await
        .expect("adjudicate webfetch");

    assert_eq!(out.reason, None, "context must typecheck cleanly");
    assert_eq!(
        out.decision,
        Decision::Allow,
        "a benign fetch has no matching forbid; got {:?}",
        out.metadata
    );
}
