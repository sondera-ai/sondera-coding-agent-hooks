//! The trajectory sparkline: a console UI composite, not a domain type.
//!
//! A strip is a *distillation* of a run's events for a single row of pixels —
//! adjudications and transcript scans never get their own cells, control
//! lifecycle collapses to two bookends, and a deny/escalate verdict is folded
//! onto the action it governed so the strip shows *what the agent did* with
//! policy fires marked in place.
//!
//! That editorial judgement is a property of this display, so it lives here
//! rather than in `sondera_types`: [`sparkline`] is a pure fold over the domain
//! [`Event`] list any caller can read from the store, and the store has no idea
//! strips exist. The proto conversions live here too, for the same reason.

use sondera_schema::console_v1 as pb;
use sondera_schema::decision_to_proto;
use sondera_schema::names::trajectory_name;
use sondera_types::{
    Action, Control, Decision, Event, Observation, PromptRole, State, TrajectoryEvent,
    adjudication_policy_hit, decision_severity, run_decision,
};
use std::collections::HashMap;
use std::collections::hash_map::Entry;

/// Cells past this count are bucketed so a strip stays one row wide.
pub const MAX_SPARKLINE_CELLS: usize = 64;

/// How many strips one `BatchGetTrajectorySparklines` call may ask for.
pub const MAX_SPARKLINE_BATCH: usize = 100;

/// UI event-strip vocabulary.
///
/// The strip is a distillation, not a 1:1 event replay: prompts are split by who
/// spoke, adjudications and transcript scans are never their own cells (a fire
/// folds onto [`SparklineCell::decision`] of the governed action), and control
/// lifecycle collapses to two bookends. There is therefore no `Policy` kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SparklineEventKind {
    #[default]
    Unspecified,
    /// Prompt authored by the user (task / human input).
    PromptUser,
    /// Model-side prompt turn — model output or system instructions.
    PromptModel,
    Thought,
    Tool,
    Shell,
    Web,
    File,
    /// First start / last terminal lifecycle bookend.
    Control,
    State,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SparklineCell {
    pub kind: SparklineEventKind,
    pub duration_ms: i64,
    /// Identifier (or description) of the policy that fired on this cell's
    /// action, folded from the adjudication the action caused. `None` unless a
    /// deny/escalate adjudication governed this event.
    pub policy_hit: Option<String>,
    /// The adjudication verdict folded onto this cell's action, set only when a
    /// deny/escalate adjudication governed it. `None` for ordinary work.
    pub decision: Option<Decision>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TrajectorySparkline {
    /// Bare id of the run this strip describes.
    pub trajectory_id: String,
    pub cells: Vec<SparklineCell>,
    /// The run-level verdict, carried so a row can be tinted without a second
    /// read.
    pub decision: Option<Decision>,
    pub truncated: bool,
}

/// Distil a run's events into a sparkline strip.
pub fn sparkline(trajectory_id: &str, events: &[Event]) -> TrajectorySparkline {
    // 1. Fold deny/escalate adjudications back onto the event they governed. The
    //    harness links each `Adjudicated` control event to its source via
    //    `causation_id == <source event_id>`, so the fire rides the action's cell
    //    instead of a standalone adjudication cell.
    let folds = folded_adjudications(events);

    // 2. Control lifecycle keeps only two bookends: the first start and the last
    //    terminal (completed / failed / terminated). Everything between —
    //    intermediate lifecycle, suspend/resume — is distilled out.
    let first_start = events
        .iter()
        .position(|event| matches!(&event.event, TrajectoryEvent::Control(c) if c.is_initial()));
    let last_terminal = events
        .iter()
        .rposition(|event| matches!(&event.event, TrajectoryEvent::Control(c) if c.is_terminal()));

    // 3. Retain, in order, the events that earn a cell.
    let retained: Vec<(&Event, SparklineEventKind)> = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            cell_kind(&event.event, index, first_start, last_terminal).map(|kind| (event, kind))
        })
        .collect();

    // 4. Build cells. Duration spans to the *next retained* event so widths
    //    absorb distilled-out gaps and still sum across the run; fold any
    //    governing verdict onto the cell.
    let mut cells: Vec<_> = retained
        .iter()
        .enumerate()
        .map(|(pos, (event, kind))| {
            let duration_ms = retained
                .get(pos + 1)
                .map(|(next, _)| (next.timestamp - event.timestamp).num_milliseconds())
                .unwrap_or_default()
                .max(0);
            let fold = folds.get(event.event_id.as_str());
            SparklineCell {
                kind: *kind,
                duration_ms,
                policy_hit: fold.and_then(|fold| fold.policy_hit.clone()),
                decision: fold.map(|fold| fold.decision),
            }
        })
        .collect();

    let truncated = cells.len() > MAX_SPARKLINE_CELLS;
    if truncated {
        cells = bucket_cells(cells);
    }
    TrajectorySparkline {
        trajectory_id: trajectory_id.to_string(),
        cells,
        decision: run_decision(events),
        truncated,
    }
}

/// A deny/escalate verdict folded onto the action it governed.
struct FoldedAdjudication {
    decision: Decision,
    policy_hit: Option<String>,
}

/// Index source `event_id` → the strongest deny/escalate adjudication that
/// governed it. Allow verdicts are cleared checks and are dropped; an
/// adjudication with no `causation_id` is orphaned and dropped (the run-level
/// decision still reflects it). When several policies fire on one action, deny
/// outranks escalate and a verdict that names a policy is preferred.
fn folded_adjudications(events: &[Event]) -> HashMap<String, FoldedAdjudication> {
    let mut folds: HashMap<String, FoldedAdjudication> = HashMap::new();
    for event in events {
        let TrajectoryEvent::Control(Control::Adjudicated(adjudicated)) = &event.event else {
            continue;
        };
        if adjudicated.decision == Decision::Allow {
            continue;
        }
        let Some(source) = event.causality.causation_id.clone() else {
            continue;
        };
        let fold = FoldedAdjudication {
            decision: adjudicated.decision,
            policy_hit: adjudication_policy_hit(adjudicated),
        };
        match folds.entry(source) {
            Entry::Vacant(slot) => {
                slot.insert(fold);
            }
            Entry::Occupied(mut slot) => {
                let existing = slot.get_mut();
                if decision_severity(fold.decision) > decision_severity(existing.decision) {
                    existing.policy_hit = fold.policy_hit.or_else(|| existing.policy_hit.take());
                    existing.decision = fold.decision;
                } else if existing.policy_hit.is_none() {
                    existing.policy_hit = fold.policy_hit;
                }
            }
        }
    }
    folds
}

/// The sparkline kind for an event, or `None` if the event is distilled out of
/// the strip. Adjudications fold onto the action they governed (never a cell of
/// their own); `Scanned` is analysis noise; control lifecycle is reduced to the
/// first-start and last-terminal bookends.
fn cell_kind(
    event: &TrajectoryEvent,
    index: usize,
    first_start: Option<usize>,
    last_terminal: Option<usize>,
) -> Option<SparklineEventKind> {
    match event {
        TrajectoryEvent::Action(Action::ToolCall(_)) => Some(SparklineEventKind::Tool),
        TrajectoryEvent::Action(Action::ShellCommand(_)) => Some(SparklineEventKind::Shell),
        TrajectoryEvent::Action(Action::WebFetch(_)) => Some(SparklineEventKind::Web),
        TrajectoryEvent::Action(Action::FileOperation(_)) => Some(SparklineEventKind::File),
        TrajectoryEvent::Observation(Observation::Prompt(prompt)) => Some(prompt_kind(prompt.role)),
        TrajectoryEvent::Observation(Observation::Thought(_)) => Some(SparklineEventKind::Thought),
        TrajectoryEvent::Observation(Observation::ToolOutput(_)) => Some(SparklineEventKind::Tool),
        TrajectoryEvent::Observation(Observation::ShellCommandOutput(_)) => {
            Some(SparklineEventKind::Shell)
        }
        TrajectoryEvent::Observation(Observation::WebFetchOutput(_)) => {
            Some(SparklineEventKind::Web)
        }
        TrajectoryEvent::Observation(Observation::FileOperationResult(_)) => {
            Some(SparklineEventKind::File)
        }
        // Adjudications fold onto the action they governed; scans are noise.
        // Neither earns a standalone cell.
        TrajectoryEvent::Control(Control::Adjudicated(_) | Control::Scanned(_)) => None,
        // Lifecycle collapses to two bookends; everything else (suspend/resume,
        // intermediate starts/completes) is distilled out.
        TrajectoryEvent::Control(_) => (Some(index) == first_start || Some(index) == last_terminal)
            .then_some(SparklineEventKind::Control),
        TrajectoryEvent::State(State::Snapshot(_)) => Some(SparklineEventKind::State),
    }
}

/// Map a prompt role to its strip kind. User input is its own anchor; system
/// instructions and assistant output are both model-side turns.
fn prompt_kind(role: PromptRole) -> SparklineEventKind {
    match role {
        PromptRole::User => SparklineEventKind::PromptUser,
        PromptRole::System | PromptRole::Assistant => SparklineEventKind::PromptModel,
    }
}

fn bucket_cells(cells: Vec<SparklineCell>) -> Vec<SparklineCell> {
    // Only called past the cap, so the first/last anchors and a non-empty
    // interior between them always exist.
    debug_assert!(cells.len() > MAX_SPARKLINE_CELLS);
    // Pin the opening and closing cells as anchors — the run's start and its
    // terminal bookend — and bucket only the interior, so truncation never drops
    // where the run began or how it ended.
    let bucket_budget = MAX_SPARKLINE_CELLS - 2;
    let interior = &cells[1..cells.len() - 1];
    let mut bucketed = Vec::with_capacity(MAX_SPARKLINE_CELLS);
    bucketed.push(cells[0].clone());
    for bucket_index in 0..bucket_budget {
        let start = bucket_index * interior.len() / bucket_budget;
        let end = (bucket_index + 1) * interior.len() / bucket_budget;
        if start < end {
            bucketed.push(summarize_bucket(&interior[start..end]));
        }
    }
    bucketed.push(cells[cells.len() - 1].clone());
    bucketed
}

fn summarize_bucket(cells: &[SparklineCell]) -> SparklineCell {
    let duration_ms = cells.iter().map(|cell| cell.duration_ms).sum();
    // A policy fire (deny/escalate folded onto an action) must survive
    // truncation: carry the most severe verdict in the bucket and the policy it
    // named, so a block is never hidden behind a bucket summary.
    let fire = cells
        .iter()
        .filter_map(|cell| cell.decision.map(|decision| (decision, cell)))
        .max_by_key(|(decision, _)| decision_severity(*decision));
    // The kind reads as the most substantive work in the bucket (Shell/File/…
    // outrank lifecycle Control), so the strip shows what the agent did.
    let kind = cells
        .iter()
        .map(|cell| cell.kind)
        .max_by_key(|kind| salience(*kind))
        .unwrap_or_default();
    SparklineCell {
        kind,
        duration_ms,
        policy_hit: fire.and_then(|(_, cell)| cell.policy_hit.clone()),
        decision: fire.map(|(decision, _)| decision),
    }
}

// Ranks the *work* in a mixed bucket: substantive events outrank `Control`
// (lifecycle bookends), so a bucket reads as what the agent did, not as
// governance housekeeping. A fire is carried separately on the cell's
// `decision`, so it survives regardless of which kind wins here.
fn salience(kind: SparklineEventKind) -> u8 {
    match kind {
        SparklineEventKind::Shell => 9,
        SparklineEventKind::File => 8,
        SparklineEventKind::Web => 7,
        SparklineEventKind::Tool => 6,
        SparklineEventKind::PromptUser => 5,
        SparklineEventKind::PromptModel => 4,
        SparklineEventKind::Thought => 3,
        SparklineEventKind::State => 2,
        SparklineEventKind::Control => 1,
        SparklineEventKind::Unspecified => 0,
    }
}

// ============================================================================
// Wire encoding
// ============================================================================

fn kind_to_proto(value: SparklineEventKind) -> i32 {
    match value {
        SparklineEventKind::Unspecified => pb::SparklineEventKind::Unspecified.into(),
        SparklineEventKind::PromptUser => pb::SparklineEventKind::PromptUser.into(),
        SparklineEventKind::PromptModel => pb::SparklineEventKind::PromptModel.into(),
        SparklineEventKind::Thought => pb::SparklineEventKind::Thought.into(),
        SparklineEventKind::Tool => pb::SparklineEventKind::Tool.into(),
        SparklineEventKind::Shell => pb::SparklineEventKind::Shell.into(),
        SparklineEventKind::Web => pb::SparklineEventKind::Web.into(),
        SparklineEventKind::File => pb::SparklineEventKind::File.into(),
        SparklineEventKind::Control => pb::SparklineEventKind::Control.into(),
        SparklineEventKind::State => pb::SparklineEventKind::State.into(),
    }
}

impl From<&SparklineCell> for pb::SparklineCell {
    fn from(value: &SparklineCell) -> Self {
        Self {
            kind: kind_to_proto(value.kind),
            duration_ms: value.duration_ms,
            policy_hit: value.policy_hit.clone().unwrap_or_default(),
            decision: decision_to_proto(value.decision),
        }
    }
}

impl From<&TrajectorySparkline> for pb::TrajectorySparkline {
    fn from(value: &TrajectorySparkline) -> Self {
        Self {
            trajectory: trajectory_name(&value.trajectory_id),
            cells: value.cells.iter().map(pb::SparklineCell::from).collect(),
            decision: decision_to_proto(value.decision),
            truncated: value.truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use sondera_types::{
        Actor, Adjudicated, Agent, Causality, Completed, Failed, PolicyMetadata, Prompt, Scanned,
        ShellCommand, Started, Terminated,
    };

    fn event_scan_result() -> sondera_types::EventScanResult {
        sondera_types::EventScanResult {
            explanation: String::new(),
            message_type: sondera_types::MessageType::ToolResult,
            intent: sondera_types::AgentIntent::Investigate,
            description: String::new(),
            key_entities: Vec::new(),
            is_side_effecting: false,
            signals: Vec::new(),
            confidence: 0.0,
            embedding: None,
        }
    }

    fn event(index: i64, payload: TrajectoryEvent) -> Event {
        Event {
            event_id: format!("event-{index}"),
            trajectory_id: "run-1".to_string(),
            agent: Agent::new("agent-1", "test", ""),
            timestamp: Utc.timestamp_millis_opt(index * 1_000).unwrap(),
            event: payload,
            actor: Actor::agent("agent-1"),
            causality: Causality::default(),
        }
    }

    /// An adjudication causally linked to the source event at `source_index`.
    fn adjudication(index: i64, source_index: i64, adjudicated: Adjudicated) -> Event {
        let mut event = event(
            index,
            TrajectoryEvent::Control(Control::Adjudicated(adjudicated)),
        );
        event.causality = event.causality.caused_by(format!("event-{source_index}"));
        event
    }

    fn started() -> TrajectoryEvent {
        TrajectoryEvent::Control(Control::Started(Started::new(Agent::new(
            "agent-1", "test", "",
        ))))
    }

    fn shell(command: &str) -> TrajectoryEvent {
        TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new(command)))
    }

    #[test]
    fn deny_adjudication_folds_onto_the_action_it_governed() {
        // The adjudication is not its own cell; the shell command it blocked
        // carries the fire (kind stays Shell, decision = Deny, policy id present).
        let events = vec![
            event(0, shell("rm -rf /")), // t=0
            adjudication(
                1, // t=1000 — folded onto event-0 and dropped
                0,
                Adjudicated::deny()
                    .with_metadata(PolicyMetadata::new().with_id("policies/no-shell".into())),
            ),
            event(
                2,
                TrajectoryEvent::Control(Control::Completed(Completed::new())),
            ), // t=2000
        ];
        let strip = sparkline("run-1", &events);
        assert_eq!(strip.cells.len(), 2);
        assert_eq!(strip.cells[0].kind, SparklineEventKind::Shell);
        // Duration spans to the next *retained* event (the completed bookend),
        // absorbing the distilled-out adjudication's gap.
        assert_eq!(strip.cells[0].duration_ms, 2_000);
        assert_eq!(strip.cells[0].decision, Some(Decision::Deny));
        assert_eq!(
            strip.cells[0].policy_hit.as_deref(),
            Some("policies/no-shell")
        );
        assert_eq!(strip.cells[1].kind, SparklineEventKind::Control);
        assert_eq!(strip.decision, Some(Decision::Deny));
    }

    #[test]
    fn allow_adjudication_is_dropped_not_a_cell() {
        // A permit is a cleared check: no standalone cell, and it never marks the
        // action it cleared with a decision or hit id.
        let events = vec![
            event(0, shell("date")),
            adjudication(
                1,
                0,
                Adjudicated::allow()
                    .with_metadata(PolicyMetadata::new().with_id("policies/no-shell".into())),
            ),
        ];
        let strip = sparkline("run-1", &events);
        assert_eq!(strip.cells.len(), 1);
        assert_eq!(strip.cells[0].kind, SparklineEventKind::Shell);
        assert_eq!(strip.cells[0].decision, None);
        assert_eq!(strip.cells[0].policy_hit, None);
    }

    #[test]
    fn deny_outranks_escalate_when_multiple_policies_fire() {
        let events = vec![
            event(0, shell("curl evil.sh")),
            adjudication(
                1,
                0,
                Adjudicated::escalate()
                    .with_metadata(PolicyMetadata::new().with_id("policies/review".into())),
            ),
            adjudication(
                2,
                0,
                Adjudicated::deny()
                    .with_metadata(PolicyMetadata::new().with_id("policies/no-net".into())),
            ),
        ];
        let strip = sparkline("run-1", &events);
        assert_eq!(strip.cells.len(), 1);
        assert_eq!(strip.cells[0].decision, Some(Decision::Deny));
        assert_eq!(
            strip.cells[0].policy_hit.as_deref(),
            Some("policies/no-net")
        );
        assert_eq!(strip.decision, Some(Decision::Deny));
    }

    #[test]
    fn prompts_split_by_role() {
        let events = vec![
            event(
                0,
                TrajectoryEvent::Observation(Observation::Prompt(Prompt::user("do x"))),
            ),
            event(
                1,
                TrajectoryEvent::Observation(Observation::Prompt(Prompt::assistant("ok"))),
            ),
            event(
                2,
                TrajectoryEvent::Observation(Observation::Prompt(Prompt::system("rules"))),
            ),
        ];
        let strip = sparkline("run-1", &events);
        assert_eq!(strip.cells[0].kind, SparklineEventKind::PromptUser);
        assert_eq!(strip.cells[1].kind, SparklineEventKind::PromptModel);
        // System instructions are a model-side turn.
        assert_eq!(strip.cells[2].kind, SparklineEventKind::PromptModel);
    }

    #[test]
    fn control_lifecycle_collapses_to_first_start_and_last_terminal() {
        let events = vec![
            event(0, started()),
            event(1, shell("a")),
            event(2, started()), // intermediate start — distilled out
            event(3, shell("b")),
            event(
                4,
                TrajectoryEvent::Control(Control::Completed(Completed::new())),
            ),
            event(
                5,
                TrajectoryEvent::Control(Control::Completed(Completed::new())), // last terminal kept
            ),
        ];
        let strip = sparkline("run-1", &events);
        let kinds: Vec<_> = strip.cells.iter().map(|cell| cell.kind).collect();
        assert_eq!(
            kinds,
            vec![
                SparklineEventKind::Control, // first start
                SparklineEventKind::Shell,
                SparklineEventKind::Shell,
                SparklineEventKind::Control, // last terminal (completed)
            ]
        );
    }

    #[test]
    fn failed_run_keeps_its_terminal_bookend() {
        // A crashed run still shows it ended: Failed is a terminal bookend.
        let events = vec![
            event(0, started()),
            event(1, shell("boom")),
            event(
                2,
                TrajectoryEvent::Control(Control::Failed(Failed::new("oom"))),
            ),
        ];
        let strip = sparkline("run-1", &events);
        assert_eq!(strip.cells.len(), 3);
        assert_eq!(
            strip.cells.last().unwrap().kind,
            SparklineEventKind::Control
        );

        // Terminated is terminal too.
        let events = vec![
            event(0, shell("x")),
            event(
                1,
                TrajectoryEvent::Control(Control::Terminated(Terminated::new("timeout", "system"))),
            ),
        ];
        let strip = sparkline("run-1", &events);
        assert_eq!(strip.cells.len(), 2);
        assert_eq!(
            strip.cells.last().unwrap().kind,
            SparklineEventKind::Control
        );
    }

    #[test]
    fn scanned_events_are_dropped() {
        let events = vec![
            event(0, shell("x")),
            event(
                1,
                TrajectoryEvent::Control(Control::Scanned(Scanned::message(
                    "event-0",
                    event_scan_result(),
                ))),
            ),
        ];
        let strip = sparkline("run-1", &events);
        assert_eq!(strip.cells.len(), 1);
        assert_eq!(strip.cells[0].kind, SparklineEventKind::Shell);
    }

    #[test]
    fn bucket_cells_caps_preserves_fire_and_both_anchors() {
        let mut cells = vec![
            SparklineCell {
                kind: SparklineEventKind::Thought,
                duration_ms: 1,
                policy_hit: None,
                decision: None,
            };
            MAX_SPARKLINE_CELLS + 7
        ];
        cells.first_mut().unwrap().kind = SparklineEventKind::Control;
        cells[30].kind = SparklineEventKind::Shell;
        cells[30].policy_hit = Some("policies/no-shell".to_string());
        cells[30].decision = Some(Decision::Deny);
        cells.last_mut().unwrap().kind = SparklineEventKind::State;

        let bucketed = bucket_cells(cells);
        assert_eq!(bucketed.len(), MAX_SPARKLINE_CELLS);
        // Both anchors survive verbatim.
        assert_eq!(bucketed.first().unwrap().kind, SparklineEventKind::Control);
        assert_eq!(bucketed.last().unwrap().kind, SparklineEventKind::State);
        // The fire survives truncation, decision and all.
        let fire = bucketed
            .iter()
            .find(|cell| cell.policy_hit.as_deref() == Some("policies/no-shell"))
            .expect("fire preserved");
        assert_eq!(fire.decision, Some(Decision::Deny));
    }

    #[test]
    fn mixed_bucket_reads_as_work_but_carries_the_fire() {
        // A bucket of work + a fire summarises its kind as the work, while still
        // carrying the verdict on `decision` so the block is never hidden.
        let cell = |kind, decision: Option<Decision>| SparklineCell {
            kind,
            duration_ms: 1,
            policy_hit: decision.map(|_| "policies/x".to_string()),
            decision,
        };
        let summarized = summarize_bucket(&[
            cell(SparklineEventKind::Control, None),
            cell(SparklineEventKind::Tool, Some(Decision::Escalate)),
            cell(SparklineEventKind::Control, None),
        ]);
        assert_eq!(summarized.kind, SparklineEventKind::Tool);
        assert_eq!(summarized.decision, Some(Decision::Escalate));
        assert_eq!(summarized.policy_hit.as_deref(), Some("policies/x"));
    }

    #[test]
    fn a_strip_encodes_its_run_id_as_a_resource_name() {
        let strip = sparkline("run-1", &[event(0, shell("ls"))]);
        let wire = pb::TrajectorySparkline::from(&strip);
        assert_eq!(wire.trajectory, "trajectories/run-1");
        assert_eq!(wire.cells.len(), 1);
        assert_eq!(wire.cells[0].kind, pb::SparklineEventKind::Shell as i32);
        // An uncontested cell carries no policy id and no verdict.
        assert!(wire.cells[0].policy_hit.is_empty());
    }
}
