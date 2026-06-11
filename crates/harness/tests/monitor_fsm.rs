//! Integration tests for the `UntrustedThenProtectedWrite` monitor FSM,
//! exercised from outside the crate boundary:
//! - replay determinism: two independent instances fed the same event
//!   sequence yield identical verdicts at every step,
//! - `Control::Adjudicated` and `State::Snapshot` are no-ops,
//! - `MonitorState` survives a serde round-trip and `with_state` re-hydration
//!   (the precondition for Fjall persistence),
//! - `Violated` latches across every plausible "undo" event.
//!
//! The monitor is pure and synchronous, so these are plain (non-async,
//! non-ignored) tests — no Ollama or harness server required.
//!
//! Run with: cargo test -p sondera-harness --test monitor_fsm

use sondera_harness::{
    Action, Adjudicated, Agent, Control, Event, FileOperation, Monitor, MonitorConfig,
    MonitorState, Observation, Resumed, Snapshot, Started, State, Think, ToolCall, ToolOutput,
    TrajectoryEvent, UntrustedThenProtectedWrite, Verdict, WebFetchOutput,
};

fn make_event(event_variant: TrajectoryEvent) -> Event {
    let agent = Agent {
        id: "agent-1".into(),
        provider_id: "test".into(),
    };
    Event::new(agent, "traj-replay-1", event_variant)
}

fn default_monitor() -> UntrustedThenProtectedWrite {
    UntrustedThenProtectedWrite::new(MonitorConfig::default()).unwrap()
}

fn web_fetch_output() -> TrajectoryEvent {
    TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
        "c1",
        "https://evil.com",
        200,
        "data",
    )))
}

fn protected_write() -> TrajectoryEvent {
    TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(".env", "X=1")))
}

#[test]
fn public_api_symbols_resolve() {
    // The public monitor symbols (Monitor, MonitorAttributes, MonitorConfig,
    // MonitorState, Verdict, UntrustedThenProtectedWrite) are reachable from
    // `sondera_harness::*` by an external consumer.
    let monitor = default_monitor();
    assert_eq!(monitor.verdict(), Verdict::Satisfied);
    let state: &MonitorState = monitor.state();
    assert!(state.pending_calls.is_empty());
    let attrs = monitor.attributes();
    assert!(attrs.armed_event_id.is_none());
}

/// Two independent monitor instances fed the same sequence (including the
/// harness-emitted `Control::Adjudicated` between the untrusted read and the
/// protected write) agree at every step and both end Violated. If
/// `Adjudicated` spuriously cleared the Armed state, the final verdict would
/// be Satisfied — so this also guards that no-op behavior.
#[test]
fn replay_deterministic_tripping_trajectory() {
    let events = [
        TrajectoryEvent::Control(Control::Started(Started::new("a"))),
        web_fetch_output(),
        TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
        protected_write(),
    ];

    let mut m1 = default_monitor();
    let mut m2 = default_monitor();
    for evt in &events {
        let event = make_event(evt.clone());
        m1.observe(&event).unwrap();
        m2.observe(&event).unwrap();
        assert_eq!(m1.verdict(), m2.verdict(), "verdicts diverged mid-replay");
    }
    assert_eq!(m1.verdict(), Verdict::Violated);
    assert_eq!(m2.verdict(), Verdict::Violated);
}

/// Approval (`Control::Resumed`) between the untrusted read and the protected
/// write clears the obligation, so the write does NOT trip — both replicas
/// end Satisfied.
#[test]
fn replay_deterministic_approved_trajectory() {
    let events = [
        TrajectoryEvent::Control(Control::Started(Started::new("a"))),
        web_fetch_output(),
        TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
        TrajectoryEvent::Control(Control::Resumed(Resumed::new("user"))),
        TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
        protected_write(),
    ];

    let mut m1 = default_monitor();
    let mut m2 = default_monitor();
    for evt in &events {
        let event = make_event(evt.clone());
        m1.observe(&event).unwrap();
        m2.observe(&event).unwrap();
        assert_eq!(m1.verdict(), m2.verdict(), "verdicts diverged mid-replay");
    }
    assert_eq!(m1.verdict(), Verdict::Satisfied);
    assert_eq!(m2.verdict(), Verdict::Satisfied);
}

/// The harness self-writes `Control::Adjudicated` after every non-Control
/// adjudication; observed while Armed it must NOT clear the obligation.
#[test]
fn adjudicated_event_is_noop_on_armed_monitor() {
    let mut monitor = default_monitor();
    monitor.observe(&make_event(web_fetch_output())).unwrap();
    assert_eq!(monitor.verdict(), Verdict::Pending);

    let adjudicated = make_event(TrajectoryEvent::Control(Control::Adjudicated(
        Adjudicated::allow(),
    )));
    monitor.observe(&adjudicated).unwrap();
    assert_eq!(monitor.verdict(), Verdict::Pending);
}

/// `State::Snapshot` events carry environment context only and must not
/// trigger arm/clear/trip logic.
#[test]
fn state_snapshot_is_noop() {
    let mut monitor = default_monitor();
    monitor.observe(&make_event(web_fetch_output())).unwrap();
    assert_eq!(monitor.verdict(), Verdict::Pending);

    let snapshot = make_event(TrajectoryEvent::State(State::Snapshot(
        Snapshot::new()
            .with_cwd("/tmp/work")
            .with_git_branch("main"),
    )));
    monitor.observe(&snapshot).unwrap();
    assert_eq!(monitor.verdict(), Verdict::Pending);
}

/// The Fjall persistence path: arm, extract state via `.state()`, round-trip
/// through JSON, re-hydrate via `with_state`, and confirm the armed
/// obligation (verdict + witness id) survives intact.
#[test]
fn monitor_state_serde_roundtrip() {
    let mut monitor = default_monitor();
    monitor.observe(&make_event(web_fetch_output())).unwrap();
    assert_eq!(monitor.verdict(), Verdict::Pending);

    let json = serde_json::to_string(monitor.state()).unwrap();
    let deserialized: MonitorState = serde_json::from_str(&json).unwrap();
    let rehydrated =
        UntrustedThenProtectedWrite::with_state(MonitorConfig::default(), deserialized).unwrap();

    assert_eq!(rehydrated.verdict(), Verdict::Pending);
    assert!(rehydrated.attributes().armed_event_id.is_some());
    assert_eq!(
        rehydrated.attributes().armed_event_id,
        monitor.attributes().armed_event_id
    );
}

/// The `call_id → tool-name` correlation table populated by the
/// ToolCall/ToolOutput path survives the JSON round-trip, so a re-hydrated
/// monitor can still classify in-flight outputs.
#[test]
fn monitor_state_pending_calls_serde() {
    let mut monitor = default_monitor();
    let tool_call = make_event(TrajectoryEvent::Action(Action::ToolCall(ToolCall {
        call_id: "call-rt-1".to_string(),
        tool: "mcp_fetch".to_string(),
        arguments: serde_json::json!({}),
    })));
    monitor.observe(&tool_call).unwrap();
    let output = make_event(TrajectoryEvent::Observation(Observation::ToolOutput(
        ToolOutput::success("call-rt-1", serde_json::json!({"body": "payload"})),
    )));
    monitor.observe(&output).unwrap();
    assert_eq!(monitor.verdict(), Verdict::Pending);
    assert!(!monitor.state().pending_calls.is_empty());

    let json = serde_json::to_string(monitor.state()).unwrap();
    let deserialized: MonitorState = serde_json::from_str(&json).unwrap();
    let rehydrated =
        UntrustedThenProtectedWrite::with_state(MonitorConfig::default(), deserialized).unwrap();

    assert_eq!(rehydrated.verdict(), Verdict::Pending);
    assert!(!rehydrated.state().pending_calls.is_empty());
    assert_eq!(
        rehydrated.state().pending_calls.get("call-rt-1"),
        Some(&"mcp_fetch".to_string())
    );
}

/// Once Violated, every plausible "undo" event — approval, a fresh untrusted
/// read, a harness Adjudicated record, internal reasoning — leaves the
/// verdict Violated.
#[test]
fn violated_verdict_stable_across_any_subsequent_event() {
    let mut monitor = default_monitor();
    monitor.observe(&make_event(web_fetch_output())).unwrap();
    monitor.observe(&make_event(protected_write())).unwrap();
    assert_eq!(monitor.verdict(), Verdict::Violated);

    let subsequent = [
        TrajectoryEvent::Control(Control::Resumed(Resumed::new("user"))),
        web_fetch_output(),
        TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
        TrajectoryEvent::Observation(Observation::Think(Think::new("anything"))),
    ];
    for evt in subsequent {
        monitor.observe(&make_event(evt)).unwrap();
        assert_eq!(
            monitor.verdict(),
            Verdict::Violated,
            "Violated must latch across every subsequent event"
        );
    }
}
