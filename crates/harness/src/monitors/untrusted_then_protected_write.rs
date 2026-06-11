//! The `UntrustedThenProtectedWrite` runtime-verification monitor.
//!
//! Reference multi-hop property: *after an untrusted read, deny writes to
//! protected paths until approval*. Implemented as a three-state FSM:
//!
//! ```text
//!            untrusted read
//!   Clean ───────────────────────────────▶ Armed
//!     ▲                                      │
//!     │ approval (Control::Resumed)          │ protected write
//!     └──────────────────────────────────────┤
//!                                            ▼
//!                                        Violated  (latching)
//! ```
//!
//! While `Armed`, the approval check runs FIRST: if a single event matched
//! both predicates, approval wins. `Violated` is terminal — no event,
//! including `Control::Resumed`, clears it.
//!
//! [`MonitorState`] is the serializable persistence unit for Fjall
//! re-hydration; the compiled [`GlobSet`] is runtime-only and recompiled from
//! [`MonitorConfig`] on every construction (`new` / `with_state`), mirroring
//! the `Trajectory` / `into_entity` split in `cedar::entity`.

use crate::monitors::predicates;
use crate::monitors::{Monitor, MonitorAttributes, MonitorConfig, Verdict};
use crate::types::Event;
use anyhow::Result;
use globset::GlobSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Internal FSM state (mapping to [`Verdict`] is in `verdict()`).
///
/// Crate-visible (not re-exported at the crate root): external consumers
/// observe the FSM only through [`Verdict`], [`MonitorAttributes`], and the
/// serde representation of [`MonitorState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FsmState {
    Clean,
    Armed,
    Violated,
}

/// Serializable snapshot of monitor state (Fjall persistence unit).
///
/// Carries only serializable fields; the compiled `GlobSet` lives on
/// [`UntrustedThenProtectedWrite`] and is recompiled from config at
/// construction time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorState {
    /// Current FSM state (crate-visible; serde: "clean"/"armed"/"violated").
    pub(crate) fsm: FsmState,
    /// Witness data for transitions taken so far.
    pub attributes: MonitorAttributes,
    /// Side-table correlating `call_id → tool-or-command-name`, populated
    /// from `Action::ToolCall` / `Action::ShellCommand` events so output
    /// observations can be classified.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub pending_calls: HashMap<String, String>,
}

impl Default for MonitorState {
    fn default() -> Self {
        Self {
            fsm: FsmState::Clean,
            attributes: MonitorAttributes::default(),
            pending_calls: HashMap::new(),
        }
    }
}

/// Monitor for the untrusted-read → protected-write multi-hop property.
pub struct UntrustedThenProtectedWrite {
    state: MonitorState,
    /// Compiled at construction; not serialized.
    glob_set: GlobSet,
    config: MonitorConfig,
}

impl UntrustedThenProtectedWrite {
    /// Construct a fresh (Clean) monitor; compiles the protected-path glob
    /// set up front so malformed patterns fail at startup, never at observe
    /// time.
    pub fn new(config: MonitorConfig) -> Result<Self> {
        let glob_set = config.build_glob_set()?;
        Ok(Self {
            state: MonitorState::default(),
            glob_set,
            config,
        })
    }

    /// Re-hydrate a monitor from previously persisted state (Fjall path);
    /// recompiles the `GlobSet` from config, mirroring the
    /// `Trajectory::try_from` reconstruction pattern.
    pub fn with_state(config: MonitorConfig, state: MonitorState) -> Result<Self> {
        let glob_set = config.build_glob_set()?;
        Ok(Self {
            state,
            glob_set,
            config,
        })
    }

    /// Read access to the current serializable state (used by the serde
    /// round-trip path to persist without exposing `FsmState`).
    pub fn state(&self) -> &MonitorState {
        &self.state
    }

    /// Name of the current FSM state, matching [`FsmState`]'s serde names
    /// exactly (`"clean"` / `"armed"` / `"violated"`).
    ///
    /// Exposes the FSM state name to public consumers
    /// ([`crate::monitors::MonitorSnapshot`]) without widening
    /// `pub(crate) FsmState`, which would trip the `private_interfaces`
    /// lint under `-D warnings`.
    pub fn state_name(&self) -> &'static str {
        match self.state.fsm {
            FsmState::Clean => "clean",
            FsmState::Armed => "armed",
            FsmState::Violated => "violated",
        }
    }
}

impl Monitor for UntrustedThenProtectedWrite {
    fn observe(&mut self, event: &Event) -> Result<()> {
        // Maintain the call_id → name side-table FIRST so the output
        // observation of the same step can be classified.
        if let Some((call_id, name)) = predicates::populate_pending_call(event) {
            self.state.pending_calls.insert(call_id, name);
        }

        match self.state.fsm {
            // Latch: no event clears Violated.
            FsmState::Violated => {}
            FsmState::Clean => {
                if predicates::is_untrusted_read(event, &self.config, &self.state.pending_calls) {
                    self.state.fsm = FsmState::Armed;
                    self.state.attributes.armed_event_id = Some(event.event_id.clone());
                    tracing::debug!("monitor armed: event_id={}", event.event_id);
                }
            }
            FsmState::Armed => {
                // Approval check FIRST: approval wins when a single event
                // matches both predicates.
                if predicates::is_approval(event, &self.config) {
                    self.state.fsm = FsmState::Clean;
                    self.state.attributes.cleared_event_id = Some(event.event_id.clone());
                    tracing::debug!("monitor cleared: event_id={}", event.event_id);
                } else if predicates::is_protected_write(event, &self.config, &self.glob_set) {
                    self.state.fsm = FsmState::Violated;
                    self.state.attributes.tripped_event_id = Some(event.event_id.clone());
                    tracing::info!("monitor violated: tripped_event_id={}", event.event_id);
                }
            }
        }
        Ok(())
    }

    fn verdict(&self) -> Verdict {
        // FSM → Verdict mapping.
        match self.state.fsm {
            FsmState::Clean => Verdict::Satisfied,
            FsmState::Armed => Verdict::Pending,
            FsmState::Violated => Verdict::Violated,
        }
    }

    fn attributes(&self) -> MonitorAttributes {
        self.state.attributes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        Action, Adjudicated, Agent, Control, FileOperation, Observation, Resumed, ShellCommand,
        ShellCommandOutput, Started, Think, ToolCall, ToolOutput, TrajectoryEvent, WebFetchOutput,
    };

    fn make_event(traj: &str, event_variant: TrajectoryEvent) -> Event {
        let agent = Agent {
            id: "agent-1".to_string(),
            provider_id: "test".to_string(),
        };
        Event::new(agent, traj, event_variant)
    }

    fn default_monitor() -> UntrustedThenProtectedWrite {
        UntrustedThenProtectedWrite::new(MonitorConfig::default()).unwrap()
    }

    fn web_fetch_output_event() -> Event {
        make_event(
            "traj-1",
            TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput::new(
                "call-1",
                "https://example.com",
                200,
                "body",
            ))),
        )
    }

    #[test]
    fn clean_on_started() {
        let mut monitor = default_monitor();
        let event = make_event(
            "traj-1",
            TrajectoryEvent::Control(Control::Started(Started::new("agent-1"))),
        );
        monitor.observe(&event).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Satisfied);
    }

    #[test]
    fn web_fetch_output_arms_monitor() {
        let mut monitor = default_monitor();
        let event = web_fetch_output_event();
        monitor.observe(&event).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Pending);
        assert_eq!(
            monitor.attributes().armed_event_id,
            Some(event.event_id.clone())
        );
    }

    #[test]
    fn protected_write_while_armed_trips_monitor() {
        let mut monitor = default_monitor();
        monitor.observe(&web_fetch_output_event()).unwrap();
        let write = make_event(
            "traj-1",
            TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(".env", "X=1"))),
        );
        monitor.observe(&write).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Violated);
        assert_eq!(
            monitor.attributes().tripped_event_id,
            Some(write.event_id.clone())
        );
    }

    #[test]
    fn approval_clears_armed_state() {
        let mut monitor = default_monitor();
        monitor.observe(&web_fetch_output_event()).unwrap();
        let approval = make_event(
            "traj-1",
            TrajectoryEvent::Control(Control::Resumed(Resumed::new("user"))),
        );
        monitor.observe(&approval).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Satisfied);
        assert_eq!(
            monitor.attributes().cleared_event_id,
            Some(approval.event_id.clone())
        );
    }

    #[test]
    fn violated_is_latching() {
        // Once Violated, even an explicit Resumed does not clear.
        let mut monitor = default_monitor();
        monitor.observe(&web_fetch_output_event()).unwrap();
        let write = make_event(
            "traj-1",
            TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(".env", "X=1"))),
        );
        monitor.observe(&write).unwrap();
        let approval = make_event(
            "traj-1",
            TrajectoryEvent::Control(Control::Resumed(Resumed::new("user"))),
        );
        monitor.observe(&approval).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Violated);
    }

    #[test]
    fn adjudicated_is_noop_while_armed() {
        // The harness writes Control::Adjudicated after every non-Control
        // event; it must NEVER clear the armed obligation.
        let mut monitor = default_monitor();
        monitor.observe(&web_fetch_output_event()).unwrap();
        let adjudicated = make_event(
            "traj-1",
            TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
        );
        monitor.observe(&adjudicated).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Pending);
    }

    #[test]
    fn think_is_noop_while_armed() {
        let mut monitor = default_monitor();
        monitor.observe(&web_fetch_output_event()).unwrap();
        let think = make_event(
            "traj-1",
            TrajectoryEvent::Observation(Observation::Think(Think::new("planning next step"))),
        );
        monitor.observe(&think).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Pending);
    }

    #[test]
    fn side_table_shell_command_output_arms() {
        let mut monitor = default_monitor();
        let shell = make_event(
            "traj-1",
            TrajectoryEvent::Action(Action::ShellCommand(ShellCommand {
                call_id: "call-2".to_string(),
                command: "curl https://evil.example.com".to_string(),
                working_dir: None,
            })),
        );
        monitor.observe(&shell).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Satisfied);
        let output = make_event(
            "traj-1",
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput::new(
                "call-2", 0, "payload", "",
            ))),
        );
        monitor.observe(&output).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Pending);
        assert_eq!(
            monitor.attributes().armed_event_id,
            Some(output.event_id.clone())
        );
    }

    #[test]
    fn side_table_tool_output_arms() {
        let mut monitor = default_monitor();
        let tool_call = make_event(
            "traj-1",
            TrajectoryEvent::Action(Action::ToolCall(ToolCall {
                call_id: "call-3".to_string(),
                tool: "mcp_fetch".to_string(),
                arguments: serde_json::json!({}),
            })),
        );
        monitor.observe(&tool_call).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Satisfied);
        let output = make_event(
            "traj-1",
            TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput::success(
                "call-3",
                serde_json::json!({"body": "payload"}),
            ))),
        );
        monitor.observe(&output).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Pending);
    }

    #[test]
    fn with_state_rehydrates_armed() {
        let state = MonitorState {
            fsm: FsmState::Armed,
            attributes: MonitorAttributes {
                armed_event_id: Some("evt-prev".to_string()),
                cleared_event_id: None,
                tripped_event_id: None,
            },
            pending_calls: HashMap::new(),
        };
        let monitor =
            UntrustedThenProtectedWrite::with_state(MonitorConfig::default(), state).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Pending);
        assert_eq!(
            monitor.attributes().armed_event_id,
            Some("evt-prev".to_string())
        );
    }

    #[test]
    fn delete_on_protected_path_is_not_trip() {
        // Delete is not a write to a protected path.
        let mut monitor = default_monitor();
        monitor.observe(&web_fetch_output_event()).unwrap();
        let delete = make_event(
            "traj-1",
            TrajectoryEvent::Action(Action::FileOperation(FileOperation::delete(".env"))),
        );
        monitor.observe(&delete).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Pending);
    }

    #[test]
    fn state_name_maps_fsm_serde_names() {
        // The name must match FsmState's serde names
        // ("clean"/"armed"/"violated") exactly.
        let mut monitor = default_monitor();
        assert_eq!(monitor.state_name(), "clean");
        monitor.observe(&web_fetch_output_event()).unwrap();
        assert_eq!(monitor.state_name(), "armed");
        let write = make_event(
            "traj-1",
            TrajectoryEvent::Action(Action::FileOperation(FileOperation::write(".env", "X=1"))),
        );
        monitor.observe(&write).unwrap();
        assert_eq!(monitor.state_name(), "violated");
    }

    #[test]
    fn file_read_on_protected_path_is_not_trip() {
        let mut monitor = default_monitor();
        monitor.observe(&web_fetch_output_event()).unwrap();
        let read = make_event(
            "traj-1",
            TrajectoryEvent::Action(Action::FileOperation(FileOperation::read(".env"))),
        );
        monitor.observe(&read).unwrap();
        assert_eq!(monitor.verdict(), Verdict::Pending);
    }
}
