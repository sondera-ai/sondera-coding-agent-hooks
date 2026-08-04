//! View models: the console wire types projected into what the two screens
//! actually draw.
//!
//! Nothing above this module matches on a prost `oneof`. The console surface
//! hands back `TrajectorySummary` and `TrajectoryEventDetail`; this module turns
//! them into a [`TrajectoryRow`] and a [`Transcript`], and the UI reads only
//! those. That boundary is what keeps a proto field rename out of every screen.
//!
//! The transcript is a **tree**, not a list. The console already folds each
//! event's adjudication and scanner summary onto the event itself, so the one
//! structure left to recover is the call/response pairing: a `ToolCall` and the
//! `ToolOutput` answering it share a `call_id`, and reading them as one step
//! with a child is how an operator thinks about the run. Events with no partner
//! stand alone as childless roots.

use crate::content::{Block, governance_blocks, payload_blocks};
use crate::theme::Tone;
use sondera_schema::console_v1 as pb;
use sondera_schema::harness_v1 as hb;
use sondera_schema::wire::format_timestamp;
use std::collections::HashMap;

// ============================================================================
// Scalars
// ============================================================================

/// A policy verdict. `None` at the call sites means "nothing was adjudicated",
/// which must never render as allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Escalate,
}

impl Decision {
    /// Decode the wire enum. `UNSPECIFIED` is absence, not a verdict.
    pub fn from_proto(value: i32) -> Option<Self> {
        match hb::Decision::try_from(value).ok()? {
            hb::Decision::Allow => Some(Self::Allow),
            hb::Decision::Deny => Some(Self::Deny),
            hb::Decision::Escalate => Some(Self::Escalate),
            hb::Decision::Unspecified => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Escalate => "escalate",
        }
    }

    pub const fn tone(self) -> Tone {
        match self {
            Self::Allow => Tone::Allow,
            Self::Deny => Tone::Deny,
            Self::Escalate => Tone::Warn,
        }
    }

    /// Whether this verdict is a policy fire worth surfacing on its own.
    pub const fn is_fire(self) -> bool {
        matches!(self, Self::Deny | Self::Escalate)
    }
}

/// Signal severity, ordered so `max` picks the loudest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_proto(value: i32) -> Self {
        match hb::SignalSeverity::try_from(value) {
            Ok(hb::SignalSeverity::Critical) => Self::Critical,
            Ok(hb::SignalSeverity::High) => Self::High,
            Ok(hb::SignalSeverity::Medium) => Self::Medium,
            Ok(hb::SignalSeverity::Low) => Self::Low,
            _ => Self::Info,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Severity shares the tone vocabulary rather than inventing a second
    /// color ramp: high and critical make the same claim a deny does.
    pub const fn tone(self) -> Tone {
        match self {
            Self::Info => Tone::Info,
            Self::Low => Tone::Info,
            Self::Medium => Tone::Warn,
            Self::High => Tone::Deny,
            Self::Critical => Tone::Deny,
        }
    }
}

/// What a tree node is, which decides its glyph and how its detail renders.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Kind {
    ToolCall,
    Shell,
    WebFetch,
    FileOp,
    Prompt,
    Thought,
    Output,
    Control,
    State,
    /// A payload this build does not recognize — a newer harness writing a
    /// variant this reader predates. It still gets a row rather than vanishing.
    #[default]
    Unknown,
}

impl Kind {
    /// A per-kind glyph, so the tree is scannable with color off.
    ///
    /// Every one of these must occupy exactly one terminal column. An emoji is
    /// two columns wide, which shifts every following cell on that row and
    /// leaves the tree visibly ragged — so this set is drawn from ASCII, Latin-1
    /// and the narrow geometric/arrow blocks, and a test holds it to one column.
    /// The Dingbats block is avoided where there is an alternative: its coverage
    /// in monospace fonts is thin enough that a terminal may substitute a
    /// proportional glyph whose advance no width table predicts.
    pub const fn glyph(self) -> &'static str {
        match self {
            Self::ToolCall => "⚙",
            Self::Shell => "$",
            Self::WebFetch => "⇄",
            Self::FileOp => "¶",
            Self::Prompt => "»",
            Self::Thought => "✻",
            Self::Output => "↳",
            Self::Control => "◉",
            Self::State => "▤",
            Self::Unknown => "·",
        }
    }

    /// Every kind, for exhaustive tests.
    pub const ALL: [Self; 10] = [
        Self::ToolCall,
        Self::Shell,
        Self::WebFetch,
        Self::FileOp,
        Self::Prompt,
        Self::Thought,
        Self::Output,
        Self::Control,
        Self::State,
        Self::Unknown,
    ];
}

// ============================================================================
// Trajectory list row
// ============================================================================

/// One row of the Trajectories screen.
#[derive(Clone, Debug, Default)]
pub struct TrajectoryRow {
    /// The `trajectories/{id}` resource name — what every follow-up RPC takes.
    pub name: String,
    /// Bare trajectory id, for display.
    pub id: String,
    /// Bare agent id, for display.
    pub agent: String,
    pub decision: Option<Decision>,
    pub status: String,
    pub event_count: i32,
    pub duration_ms: i64,
    pub started_at: Option<String>,
    pub update_time: Option<String>,
    pub summary: String,
    pub score: f64,
    pub policy_hits: Vec<String>,
    /// The scanner's hierarchical read of this run. The console projects it
    /// onto every list row, not only onto detail reads, so the feed can say
    /// what a run was without opening it.
    pub digest: Option<DigestView>,
    /// The scanner's behavioral read of this run. Terminal-only: a run still in
    /// flight has not finished behaving, so this stays absent until it ends.
    pub scan: Option<ScanView>,
}

impl From<&pb::TrajectorySummary> for TrajectoryRow {
    fn from(value: &pb::TrajectorySummary) -> Self {
        Self {
            name: value.name.clone(),
            id: short(&value.name).to_string(),
            agent: short(&value.agent).to_string(),
            decision: Decision::from_proto(value.decision),
            status: value.status.clone(),
            event_count: value.event_count,
            duration_ms: value.duration_ms,
            started_at: value.started_at.as_ref().map(format_timestamp),
            update_time: value.update_time.as_ref().map(format_timestamp),
            summary: value.summary.clone(),
            score: value.score,
            policy_hits: value.policy_hits.clone(),
            digest: value.digest.as_ref().map(DigestView::from),
            scan: value.scan.as_ref().map(ScanView::from),
        }
    }
}

impl TrajectoryRow {
    /// Whether this row matches a free-text filter, case-insensitively.
    ///
    /// The scanner's vocabulary is searchable alongside the run's own: typing
    /// `credential` or `exfiltration` has to find the runs whose signals say
    /// so, because those words appear nowhere else in the feed and a filter
    /// that silently cannot express them is worse than no filter.
    pub fn matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let needle = query.to_lowercase();
        let plain = [&self.agent, &self.id, &self.status, &self.summary]
            .iter()
            .any(|field| field.to_lowercase().contains(&needle));
        plain
            || self
                .policy_hits
                .iter()
                .any(|hit| hit.to_lowercase().contains(&needle))
            || self.digest.as_ref().is_some_and(|digest| {
                digest.title.to_lowercase().contains(&needle)
                    || digest.summary.to_lowercase().contains(&needle)
                    || digest
                        .files_modified
                        .iter()
                        .chain(digest.tools_used.iter())
                        .any(|item| item.to_lowercase().contains(&needle))
            })
            || self.scan.as_ref().is_some_and(|scan| {
                scan.outcome.to_lowercase().contains(&needle)
                    || scan.signals.iter().any(|signal| {
                        signal.category.to_lowercase().contains(&needle)
                            || signal.description.to_lowercase().contains(&needle)
                    })
            })
    }

    /// The loudest thing the scanner found in this run, or `None` when no
    /// behavioral scan has landed.
    ///
    /// `None` and `info` are different claims — "nothing has looked" against
    /// "something looked and found nothing" — so this never defaults.
    pub fn risk(&self) -> Option<Severity> {
        self.scan.as_ref().map(|scan| scan.aggregate_severity)
    }

    /// How the run went, as the scanner graded it. Distinct from `status`,
    /// which is the harness lifecycle: a run can complete and still fail.
    pub fn outcome(&self) -> Option<&str> {
        self.scan
            .as_ref()
            .map(|scan| scan.outcome.as_str())
            .filter(|outcome| !outcome.is_empty())
    }

    pub fn signal_count(&self) -> usize {
        self.scan.as_ref().map_or(0, |scan| scan.signals.len())
    }

    /// Whether the summary on this row came from a digest of a run that was
    /// still going. A provisional summary that reads as a final one is how a
    /// mid-run guess gets quoted as an outcome.
    pub fn is_interim(&self) -> bool {
        self.digest.as_ref().is_some_and(|digest| digest.interim)
    }

    /// Keep `previous`'s scanner output where this row carries none.
    ///
    /// `StreamTrajectories` and `ListTrajectories` do not project the same
    /// row. The list attaches the digest and behavioral scan from the scan
    /// tables; the stream is built from `Trajectory::summarize`, which leaves
    /// both unset because projecting them costs a read per run per tick. A
    /// streamed update therefore says nothing about the scanner rather than
    /// saying the scanner found nothing — and overwriting with it would flip a
    /// graded run's risk to `—`, which is the one claim this feed makes that
    /// has to be true.
    ///
    /// Scans only ever accumulate: a run that has been digested never stops
    /// having been digested, so carrying the older value forward cannot go
    /// stale in the direction that matters. The run's own `summary` follows the
    /// digest title, so it travels with it.
    pub fn carry_scanner_output_from(&mut self, previous: &Self) {
        if self.digest.is_none() && previous.digest.is_some() {
            self.digest = previous.digest.clone();
            if self.summary.is_empty() {
                self.summary = previous.summary.clone();
            }
        }
        if self.scan.is_none() {
            self.scan = previous.scan.clone();
        }
    }
}

// ============================================================================
// Agent identity
// ============================================================================

/// Who ran a trajectory: the model provider and the runtime platform the
/// harness registered when the agent's hook first reported in.
///
/// Deliberately *not* a field on [`TrajectoryRow`], because it is not a field on
/// the wire beside one. `TrajectorySummary` names a run's agent and says nothing
/// else about it — identity lives on the agent roster — so the feed joins the
/// two client-side through [`crate::state::App::agent_identity`]. A run whose
/// agent the roster does not cover therefore has no identity to show, which is a
/// different claim from an agent with none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentIdentity {
    /// Who makes the model, e.g. `anthropic`, `openai`, `github`.
    pub provider: String,
    /// What the agent runs as, e.g. `claude-code`, `codex`, `copilot-cli`.
    pub platform: String,
}

impl From<&pb::AgentSummary> for AgentIdentity {
    fn from(value: &pb::AgentSummary) -> Self {
        Self {
            provider: value.provider.clone(),
            platform: value.platform.clone(),
        }
    }
}

impl AgentIdentity {
    /// Whether the harness registered neither half. Both are `OUTPUT_ONLY`
    /// strings, so an agent recorded before the fields existed reads empty
    /// rather than absent, and the feed has to render that as *unknown*.
    pub fn is_empty(&self) -> bool {
        self.provider.is_empty() && self.platform.is_empty()
    }
}

// ============================================================================
// Trajectory sparkline
// ============================================================================

/// What one cell of a run's strip depicts.
///
/// This is the console's strip vocabulary, not [`Kind`]: the strip splits
/// prompts by who spoke, never gives an adjudication or a scan a cell of its
/// own, and collapses lifecycle to two bookends. Decoding it into its own enum
/// rather than folding it into `Kind` keeps that editorial difference visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SparkKind {
    #[default]
    Unspecified,
    PromptUser,
    PromptModel,
    Thought,
    Tool,
    Shell,
    Web,
    File,
    Control,
    State,
}

impl SparkKind {
    pub fn from_proto(value: i32) -> Self {
        match pb::SparklineEventKind::try_from(value) {
            Ok(pb::SparklineEventKind::PromptUser) => Self::PromptUser,
            Ok(pb::SparklineEventKind::PromptModel) => Self::PromptModel,
            Ok(pb::SparklineEventKind::Thought) => Self::Thought,
            Ok(pb::SparklineEventKind::Tool) => Self::Tool,
            Ok(pb::SparklineEventKind::Shell) => Self::Shell,
            Ok(pb::SparklineEventKind::Web) => Self::Web,
            Ok(pb::SparklineEventKind::File) => Self::File,
            Ok(pb::SparklineEventKind::Control) => Self::Control,
            Ok(pb::SparklineEventKind::State) => Self::State,
            _ => Self::Unspecified,
        }
    }

    /// The cell's glyph. One column, like every glyph in this crate: a strip is
    /// laid out by counting cells, so a two-column glyph would push the tail of
    /// every affected row past its column budget.
    ///
    /// `»` and `«` pair deliberately — a turn going into the run and one coming
    /// back out — and the rest are the [`Kind`] glyphs, so a strip and the
    /// transcript it summarizes speak the same alphabet.
    pub const fn glyph(self) -> &'static str {
        match self {
            Self::PromptUser => "»",
            Self::PromptModel => "«",
            Self::Thought => "✻",
            Self::Tool => "⚙",
            Self::Shell => "$",
            Self::Web => "⇄",
            Self::File => "¶",
            Self::Control => "◉",
            Self::State => "▤",
            Self::Unspecified => "·",
        }
    }

    /// Rank of the *work* a kind represents, for the cell that wins when
    /// several collapse into one column.
    ///
    /// Deliberately the console's own ranking (`crates/console/src/sparkline.rs`):
    /// a strip narrowed twice — once by the console's cell cap, once to fit this
    /// column — must not read differently from one narrowed only here.
    const fn salience(self) -> u8 {
        match self {
            Self::Shell => 9,
            Self::File => 8,
            Self::Web => 7,
            Self::Tool => 6,
            Self::PromptUser => 5,
            Self::PromptModel => 4,
            Self::Thought => 3,
            Self::State => 2,
            Self::Control => 1,
            Self::Unspecified => 0,
        }
    }

    /// Every kind, for exhaustive tests.
    pub const ALL: [Self; 10] = [
        Self::Unspecified,
        Self::PromptUser,
        Self::PromptModel,
        Self::Thought,
        Self::Tool,
        Self::Shell,
        Self::Web,
        Self::File,
        Self::Control,
        Self::State,
    ];
}

/// One column of a run's strip.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SparkCell {
    pub kind: SparkKind,
    /// The verdict folded onto this cell's action. Only ever a fire: the
    /// console drops allow verdicts, because a cleared check is not something
    /// the strip is claiming happened.
    pub decision: Option<Decision>,
    /// The policy that fired, when one did.
    pub policy_hit: Option<String>,
}

impl SparkCell {
    /// The tone this cell claims. Ordinary work is [`Tone::Neutral`]: only a
    /// policy fire earns color in the feed's densest column.
    pub fn tone(&self) -> Tone {
        match self.decision {
            Some(decision) if decision.is_fire() => decision.tone(),
            _ => Tone::Neutral,
        }
    }
}

/// One run's activity strip: what the agent did, in order, with policy fires
/// marked where they landed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sparkline {
    pub cells: Vec<SparkCell>,
    /// Whether the console already bucketed this strip to its own cell cap, so
    /// a cell stands for a span of the run rather than one event.
    pub truncated: bool,
}

impl From<&pb::TrajectorySparkline> for Sparkline {
    fn from(value: &pb::TrajectorySparkline) -> Self {
        Self {
            cells: value
                .cells
                .iter()
                .map(|cell| SparkCell {
                    kind: SparkKind::from_proto(cell.kind),
                    decision: Decision::from_proto(cell.decision),
                    policy_hit: Some(cell.policy_hit.clone()).filter(|hit| !hit.is_empty()),
                })
                .collect(),
            truncated: value.truncated,
        }
    }
}

impl Sparkline {
    /// The strip narrowed to exactly `width` columns.
    ///
    /// Narrowing buckets rather than truncates. A strip cut off at the column
    /// edge would silently hide the end of the run — and with it any deny near
    /// the end, which is precisely what a reader scanning this column is
    /// looking for.
    pub fn strip(&self, width: usize) -> Vec<SparkCell> {
        if width == 0 {
            return Vec::new();
        }
        if self.cells.len() <= width {
            return self.cells.clone();
        }
        // Under three columns there is no room for both anchors and an
        // interior, so everything buckets together.
        if width < 3 {
            return bucket(&self.cells, width);
        }
        // Pin the opening and closing cells, as the console does: how a run
        // began and how it ended must survive being narrowed.
        let interior = &self.cells[1..self.cells.len() - 1];
        let mut cells = Vec::with_capacity(width);
        cells.push(self.cells[0].clone());
        cells.extend(bucket(interior, width - 2));
        cells.push(self.cells[self.cells.len() - 1].clone());
        cells
    }

    /// How many cells carry a policy fire.
    pub fn fires(&self) -> usize {
        self.cells
            .iter()
            .filter(|cell| cell.decision.is_some())
            .count()
    }
}

/// Fold `cells` into at most `width` buckets, preserving order.
fn bucket(cells: &[SparkCell], width: usize) -> Vec<SparkCell> {
    if cells.is_empty() || width == 0 {
        return Vec::new();
    }
    if cells.len() <= width {
        return cells.to_vec();
    }
    (0..width)
        .filter_map(|index| {
            let start = index * cells.len() / width;
            let end = (index + 1) * cells.len() / width;
            (start < end).then(|| summarize(&cells[start..end]))
        })
        .collect()
}

/// One cell standing for a span of the run.
///
/// The kind reads as the most substantive work in the span, and the loudest
/// fire in it rides along regardless — a deny that a bucket swallowed would be
/// a blocked action this column never showed.
fn summarize(cells: &[SparkCell]) -> SparkCell {
    let fire = cells
        .iter()
        .filter(|cell| cell.decision.is_some())
        .max_by_key(|cell| cell.decision.map(fire_rank).unwrap_or(0));
    SparkCell {
        kind: cells
            .iter()
            .map(|cell| cell.kind)
            .max_by_key(|kind| kind.salience())
            .unwrap_or_default(),
        decision: fire.and_then(|cell| cell.decision),
        policy_hit: fire.and_then(|cell| cell.policy_hit.clone()),
    }
}

/// How loud a verdict is, so the strongest survives a bucket.
const fn fire_rank(decision: Decision) -> u8 {
    match decision {
        Decision::Deny => 3,
        Decision::Escalate => 2,
        Decision::Allow => 1,
    }
}

// ============================================================================
// Transcript
// ============================================================================

/// One event, projected for both the tree row and the detail pane.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EventNode {
    pub event_id: String,
    pub timestamp: String,
    pub kind: Kind,
    /// The tree row's headline — "Bash", "Read", "prompt · user".
    pub title: String,
    /// The tree row's second column — the command, path, tool, or URL.
    pub subtitle: String,
    /// The `call_id` pairing an action with its observation, when it has one.
    pub call_id: Option<String>,
    pub decision: Option<Decision>,
    /// Why the adjudicator decided as it did.
    pub reason: Option<String>,
    /// The scanner's one-sentence description of the event.
    pub scan_summary: String,
    pub intent: Option<String>,
    pub side_effecting: bool,
    pub severity: Severity,
    pub signals: Vec<SignalView>,
    /// The rendered detail — markdown, code, fields — for the main panel.
    pub blocks: Vec<Block>,
    /// How many leading [`Self::blocks`] describe the payload itself.
    ///
    /// Everything after them is the folded governance tail, which a live tail
    /// rebuilds when a verdict or a scan lands after the event it grades.
    pub payload_blocks: usize,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SignalView {
    pub severity: Severity,
    /// Whether the signal is about the environment, the agent, or governance.
    /// Same category means different owners depending on this.
    pub focus: String,
    pub category: String,
    pub description: String,
}

/// A tree step: one root event plus the observations that answer it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub root: usize,
    pub children: Vec<usize>,
}

/// One rendered line of the tree, after expansion state is applied.
#[derive(Clone, Copy, Debug)]
pub struct TreeRow {
    /// Index into [`Transcript::nodes`].
    pub node: usize,
    /// Index into [`Transcript::steps`].
    pub step: usize,
    pub depth: u8,
    pub expandable: bool,
    pub expanded: bool,
}

/// The whole reading view for one run.
///
/// The digest and the behavioral scan live on [`Transcript::summary`], not
/// beside it: the console projects both onto `TrajectorySummary`, so the feed
/// row and the transcript header are reading the same two values. Keeping one
/// copy is what stops the feed and the transcript from disagreeing about how a
/// run went.
#[derive(Clone, Debug, Default)]
pub struct Transcript {
    pub summary: TrajectoryRow,
    /// Every event, chronological. Tree structure is expressed as indices into
    /// this vector so nothing is cloned per row.
    pub nodes: Vec<EventNode>,
    pub steps: Vec<Step>,
}

/// One logical work phase the scanner segmented the run into.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PhaseView {
    pub name: String,
    pub description: String,
    /// How many events the scanner assigned to this phase.
    ///
    /// The wire carries the indices themselves, and they are deliberately not
    /// kept: they index the *raw ledger* the scanner was handed, which includes
    /// the `Adjudicated` and `Scanned` control events this surface folds away.
    /// The offset between the two lists depends on how many governance events
    /// preceded each phase, so the client cannot recover it — a band drawn from
    /// these indices would sit on the wrong steps. See the module docs on
    /// [`Transcript`] for what would fix it.
    pub event_count: usize,
}

/// The scanner's hierarchical read of the whole run: what it set out to do, how
/// the work broke down, and what it touched.
#[derive(Clone, Debug, Default)]
pub struct DigestView {
    pub title: String,
    pub summary: String,
    /// Whether this digest describes a run still in flight. A reader has to be
    /// able to tell a mid-run summary from a final one before quoting it.
    pub interim: bool,
    pub phases: Vec<PhaseView>,
    pub tools_used: Vec<String>,
    pub files_modified: Vec<String>,
    pub total_events: i32,
    pub side_effecting_count: i32,
}

impl DigestView {
    /// Whether there is anything here worth a panel.
    pub fn is_empty(&self) -> bool {
        self.title.is_empty()
            && self.summary.is_empty()
            && self.phases.is_empty()
            && self.tools_used.is_empty()
            && self.files_modified.is_empty()
    }
}

/// How the scanner graded a run, as a readable label.
///
/// Public because the feed's outcome column is sized to the widest value this
/// can return, and a test that asserts that has to ask the same function the
/// projection does rather than restate the vocabulary and drift from it.
pub fn outcome_label(value: i32) -> String {
    enum_label(
        hb::TranscriptOutcome::try_from(value)
            .ok()
            .map(|outcome| outcome.as_str_name()),
    )
}

/// The tone a scanner outcome claims.
///
/// A failed or interrupted run is not a policy denial, so it never borrows the
/// deny tone: it earns warning, which is what "look at this" means here. Lives
/// beside the model rather than in one screen because the feed, the run
/// inspector, and the transcript header all render the same word and must not
/// color it three different ways.
pub fn outcome_tone(outcome: &str) -> Tone {
    match outcome {
        "success" => Tone::Allow,
        "partial" | "failure" | "interrupted" => Tone::Warn,
        "in progress" => Tone::Info,
        _ => Tone::Neutral,
    }
}

/// The scanner's behavioral read of the whole run: how it went, what it flagged,
/// and how the policy engine treated it.
#[derive(Clone, Debug, Default)]
pub struct ScanView {
    pub outcome: String,
    pub outcome_description: String,
    pub aggregate_severity: Severity,
    pub confidence: f64,
    /// The reasoning the scanner produced *before* grading, which is the part
    /// that makes the grade arguable rather than oracular.
    pub explanation: String,
    pub signals: Vec<SignalView>,
    pub adjudication_summary: String,
    pub behavioral_notes: Vec<String>,
}

impl Transcript {
    /// Build the reading view from a summary plus its full event page.
    pub fn build(summary: &pb::TrajectorySummary, details: &[pb::TrajectoryEventDetail]) -> Self {
        let nodes: Vec<EventNode> = details.iter().map(EventNode::from_detail).collect();
        let steps = build_steps(&nodes);
        Self {
            summary: TrajectoryRow::from(summary),
            nodes,
            steps,
        }
    }

    /// The scanner's hierarchical read of this run, when it has produced one.
    pub fn digest(&self) -> Option<&DigestView> {
        self.summary.digest.as_ref()
    }

    /// The scanner's behavioral read of this run, when it has produced one.
    pub fn scan(&self) -> Option<&ScanView> {
        self.summary.scan.as_ref()
    }

    /// Flatten the tree into drawable rows, honouring which steps are expanded.
    ///
    /// A step with no children is never expandable, so the caller's expansion
    /// set is consulted only where it can matter.
    pub fn rows(&self, expanded: &dyn Fn(usize) -> bool) -> Vec<TreeRow> {
        let mut rows = Vec::with_capacity(self.nodes.len());
        for (step_idx, step) in self.steps.iter().enumerate() {
            let expandable = !step.children.is_empty();
            let is_expanded = expandable && expanded(step_idx);
            rows.push(TreeRow {
                node: step.root,
                step: step_idx,
                depth: 0,
                expandable,
                expanded: is_expanded,
            });
            if is_expanded {
                for &child in &step.children {
                    rows.push(TreeRow {
                        node: child,
                        step: step_idx,
                        depth: 1,
                        expandable: false,
                        expanded: false,
                    });
                }
            }
        }
        rows
    }

    /// Whether the scanner has produced anything about this run as a whole.
    ///
    /// The insight panel appears only when this holds. A scanner that is not
    /// configured, or has not reached this run yet, must cost the transcript no
    /// rows — an empty panel claiming a heading is worse than no panel.
    pub fn has_insight(&self) -> bool {
        self.digest().is_some_and(|d| !d.is_empty()) || self.scan().is_some()
    }

    /// Indices of every step whose root or children carry a deny/escalate.
    pub fn fired_steps(&self) -> Vec<usize> {
        self.steps_where(|node| node.decision.is_some_and(Decision::is_fire))
    }

    /// Indices of every step whose root or children the scanner flagged at
    /// `medium` or louder.
    ///
    /// Per-*event* signals, not the run-level ones: the console folds each
    /// event's scan onto the event it describes, so these land on the right
    /// step by construction. The run-level scan's `evidence_indices` cannot be
    /// resolved here — see [`PhaseView::event_count`] — which is why this walks
    /// the nodes instead.
    pub fn signalled_steps(&self) -> Vec<usize> {
        self.steps_where(|node| node.severity >= Severity::Medium)
    }

    fn steps_where(&self, predicate: impl Fn(&EventNode) -> bool) -> Vec<usize> {
        self.steps
            .iter()
            .enumerate()
            .filter(|(_, step)| {
                std::iter::once(step.root)
                    .chain(step.children.iter().copied())
                    .any(|idx| predicate(&self.nodes[idx]))
            })
            .map(|(idx, _)| idx)
            .collect()
    }
}

/// Pair each observation with the action it answers.
///
/// Observations are matched to the *most recent* unclaimed action carrying the
/// same `call_id`. Ids are only required to be unique within a run, and a
/// retried tool call can legitimately reuse one — taking the nearest preceding
/// action keeps a retry's output attached to the retry rather than to the
/// original. An observation whose `call_id` matches nothing (its action was
/// never recorded, or the page starts mid-run) becomes its own root instead of
/// being dropped.
fn build_steps(nodes: &[EventNode]) -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    // call_id → index into `steps` of the newest action still awaiting output.
    let mut open: HashMap<&str, usize> = HashMap::new();

    for (idx, node) in nodes.iter().enumerate() {
        let call_id = node.call_id.as_deref();
        match (node.kind, call_id) {
            // An observation with a live partner nests under it.
            (Kind::Output, Some(id)) if open.contains_key(id) => {
                let step = open[id];
                steps[step].children.push(idx);
            }
            // An action opens a step that a later observation can claim.
            (Kind::ToolCall | Kind::Shell | Kind::WebFetch | Kind::FileOp, Some(id)) => {
                open.insert(id, steps.len());
                steps.push(Step {
                    root: idx,
                    children: Vec::new(),
                });
            }
            _ => steps.push(Step {
                root: idx,
                children: Vec::new(),
            }),
        }
    }
    steps
}

// ============================================================================
// Live tail
// ============================================================================

/// What ingesting one streamed event did to the transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingested {
    /// A step was appended, at this index into [`Transcript::steps`].
    Step(usize),
    /// An observation nested under the step at this index.
    Child(usize),
    /// A verdict or scan was folded onto the event it grades, or parked until
    /// that event arrives. Governance is never a row of its own.
    Governance,
    /// An event already in the transcript. Nothing changed.
    Duplicate,
}

/// The incremental counterpart to [`Transcript::build`], for `StreamTrajectory`.
///
/// `ListTrajectoryEvents` returns events with their adjudication and scan
/// already folded on. The stream returns the raw ledger grain instead —
/// governance control events included — so the fold has to happen here, one
/// event at a time, and it has to reach the same answer the console would:
/// `Adjudicated` and `Scanned` never become rows, they attach to the event
/// their `causation_id` names.
///
/// Governance naming an event that has not arrived is parked rather than
/// dropped. Ledger order (timestamp, then insertion id) puts a verdict after
/// the action it governs, so this should not happen — but a dropped verdict
/// would silently under-report a deny, which is the one thing this view may
/// never do.
#[derive(Clone, Debug, Default)]
pub struct TranscriptTail {
    /// `event_id` → index into [`Transcript::nodes`].
    nodes: HashMap<String, usize>,
    /// `call_id` → index into [`Transcript::steps`] of the newest action with
    /// that id, which is the step an output carrying it nests under. This is
    /// [`build_steps`]'s `open` map, maintained one event at a time: it is
    /// never cleared, so a retried call's output attaches to the retry.
    open: HashMap<String, usize>,
    /// Verdicts and scans by the `event_id` they grade, retained so a
    /// re-adjudication rebuilds its node from both parts instead of appending a
    /// second verdict beneath the first.
    adjudications: HashMap<String, hb::Adjudicated>,
    scans: HashMap<String, hb::EventScanResult>,
}

impl TranscriptTail {
    /// Apply one streamed event to `transcript`.
    ///
    /// The transcript this is called with must be the one this tail has been
    /// fed all along — the indices it holds are into that node list.
    pub fn ingest(&mut self, transcript: &mut Transcript, event: &pb::TrajectoryEvent) -> Ingested {
        if let Some(governance) = governance(event) {
            // A governance event with no causation names nothing to grade. The
            // console hides it either way, so it is dropped here too rather
            // than surfacing as a row this reader would not otherwise show.
            if event.causation_id.is_empty() {
                return Ingested::Governance;
            }
            match governance {
                Governance::Adjudicated(adjudication) => {
                    self.adjudications
                        .insert(event.causation_id.clone(), adjudication.clone());
                }
                Governance::Scanned(scan) => {
                    self.scans.insert(event.causation_id.clone(), scan.clone());
                }
            }
            self.refold(transcript, &event.causation_id);
            return Ingested::Governance;
        }

        if !event.event_id.is_empty() && self.nodes.contains_key(&event.event_id) {
            return Ingested::Duplicate;
        }

        let mut node = EventNode::from_event(event);
        node.apply_governance(
            self.adjudications.get(&event.event_id),
            self.scans.get(&event.event_id),
        );

        let index = transcript.nodes.len();
        // The same three cases `build_steps` splits a whole page into: an
        // observation nests under the action it answers, an action opens a step
        // a later observation can claim, and everything else stands alone.
        let outcome = match (node.kind, node.call_id.as_deref()) {
            (Kind::Output, Some(call_id)) => match self.open.get(call_id) {
                Some(&step) => {
                    transcript.steps[step].children.push(index);
                    Ingested::Child(step)
                }
                None => push_step(transcript, index),
            },
            (Kind::ToolCall | Kind::Shell | Kind::WebFetch | Kind::FileOp, Some(call_id)) => {
                self.open
                    .insert(call_id.to_string(), transcript.steps.len());
                push_step(transcript, index)
            }
            _ => push_step(transcript, index),
        };

        if !node.event_id.is_empty() {
            self.nodes.insert(node.event_id.clone(), index);
        }
        transcript.nodes.push(node);
        outcome
    }

    /// Rebuild whatever is folded onto `event_id`, if that event has arrived.
    fn refold(&self, transcript: &mut Transcript, event_id: &str) {
        let Some(&index) = self.nodes.get(event_id) else {
            return;
        };
        let Some(node) = transcript.nodes.get_mut(index) else {
            return;
        };
        node.apply_governance(self.adjudications.get(event_id), self.scans.get(event_id));
    }
}

/// The governance an event carries, if it is one of the two control events the
/// console folds away.
enum Governance<'a> {
    Adjudicated(&'a hb::Adjudicated),
    Scanned(&'a hb::EventScanResult),
}

fn governance(event: &pb::TrajectoryEvent) -> Option<Governance<'_>> {
    let hb::trajectory_event::Category::Control(control) =
        event.payload.as_ref()?.category.as_ref()?
    else {
        return None;
    };
    match control.kind.as_ref()? {
        hb::control::Kind::Adjudicated(adjudicated) => Some(Governance::Adjudicated(adjudicated)),
        // Only a per-event scan grades an event; the transcript-level digest
        // and scan belong to the run and already reach the header through
        // `TrajectorySummary`.
        hb::control::Kind::Scanned(scanned) => match scanned.scan.as_ref()? {
            hb::scanned::Scan::Message(message) => {
                Some(Governance::Scanned(message.result.as_ref()?))
            }
            _ => None,
        },
        _ => None,
    }
}

fn push_step(transcript: &mut Transcript, node: usize) -> Ingested {
    transcript.steps.push(Step {
        root: node,
        children: Vec::new(),
    });
    Ingested::Step(transcript.steps.len() - 1)
}

impl EventNode {
    fn from_detail(detail: &pb::TrajectoryEventDetail) -> Self {
        let Some(event) = detail.event.as_ref() else {
            return Self {
                title: "malformed event".to_string(),
                ..Self::default()
            };
        };

        let mut node = Self::from_event(event);
        node.apply_governance(detail.adjudication.as_ref(), detail.summary.as_ref());
        node
    }

    /// The node for one raw event, before any verdict or scan is folded onto
    /// it. This is the grain the console's event stream delivers.
    pub(crate) fn from_event(event: &pb::TrajectoryEvent) -> Self {
        let payload = event.payload.as_ref();
        let (kind, title, subtitle, call_id) = describe(payload);
        let blocks = payload_blocks(payload);

        Self {
            event_id: event.event_id.clone(),
            timestamp: event
                .timestamp
                .as_ref()
                .map(format_timestamp)
                .unwrap_or_default(),
            kind,
            title,
            subtitle,
            call_id,
            payload_blocks: blocks.len(),
            blocks,
            ..Self::default()
        }
    }

    /// Fold a verdict and a scanner summary onto this node, *replacing* whatever
    /// was folded before.
    ///
    /// Replacing rather than accumulating is what makes a re-adjudication read
    /// correctly: the console's rule is that the last verdict recorded for an
    /// event is the one that governed it, so a second verdict arriving on the
    /// stream must leave the detail pane showing one adjudication section, not
    /// two.
    pub(crate) fn apply_governance(
        &mut self,
        adjudication: Option<&hb::Adjudicated>,
        scan: Option<&hb::EventScanResult>,
    ) {
        self.blocks.truncate(self.payload_blocks);
        self.blocks.extend(governance_blocks(adjudication, scan));

        self.decision = adjudication.and_then(|a| Decision::from_proto(a.decision));
        self.reason = adjudication.and_then(|a| a.reason.clone().filter(|r| !r.is_empty()));

        self.scan_summary = scan.map(|s| s.description.clone()).unwrap_or_default();
        self.side_effecting = scan.is_some_and(|s| s.is_side_effecting);
        self.intent = scan.and_then(|s| intent_label(s.intent));
        self.signals = scan
            .map(|s| s.signals.iter().map(SignalView::from).collect())
            .unwrap_or_default();
        self.severity = self
            .signals
            .iter()
            .map(|signal| signal.severity)
            .max()
            .unwrap_or_default();
    }

    /// The tone this row claims: a policy fire wins over a scan severity, since
    /// a verdict is a stronger statement than an observation.
    pub fn tone(&self) -> Tone {
        match self.decision {
            Some(decision) if decision.is_fire() => decision.tone(),
            _ if self.severity >= Severity::Medium => self.severity.tone(),
            Some(Decision::Allow) => Tone::Allow,
            _ => Tone::Neutral,
        }
    }

    /// Whether this node matches a free-text search over its visible text.
    pub fn matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let needle = query.to_lowercase();
        [
            &self.title,
            &self.subtitle,
            &self.scan_summary,
            &self.event_id,
        ]
        .iter()
        .any(|field| field.to_lowercase().contains(&needle))
    }
}

/// Derive a node's kind, headline, subtitle, and call id from its payload.
fn describe(payload: Option<&hb::TrajectoryEvent>) -> (Kind, String, String, Option<String>) {
    use hb::action::Kind as A;
    use hb::control::Kind as C;
    use hb::observation::Kind as O;
    use hb::trajectory_event::Category;

    let Some(category) = payload.and_then(|p| p.category.as_ref()) else {
        return (Kind::Unknown, "event".into(), String::new(), None);
    };

    match category {
        Category::Action(action) => match action.kind.as_ref() {
            Some(A::ToolCall(call)) => (
                Kind::ToolCall,
                call.tool.clone(),
                tool_call_subtitle(call),
                Some(call.call_id.clone()),
            ),
            Some(A::ShellCommand(cmd)) => (
                Kind::Shell,
                "shell".into(),
                first_line(&cmd.command),
                Some(cmd.call_id.clone()),
            ),
            Some(A::WebFetch(fetch)) => (
                Kind::WebFetch,
                "fetch".into(),
                fetch.url.clone(),
                Some(fetch.call_id.clone()),
            ),
            Some(A::FileOperation(op)) => (
                Kind::FileOp,
                file_op_label(op.operation).to_string(),
                op.path.clone(),
                Some(op.call_id.clone()),
            ),
            None => (Kind::Unknown, "action".into(), String::new(), None),
        },
        Category::Observation(observation) => match observation.kind.as_ref() {
            Some(O::Prompt(prompt)) => (
                Kind::Prompt,
                format!("prompt · {}", prompt_role_label(prompt.role)),
                first_line(&prompt.content),
                None,
            ),
            Some(O::Thought(thought)) => (
                Kind::Thought,
                "thought".into(),
                first_line(&thought.thought),
                None,
            ),
            Some(O::ToolOutput(output)) => (
                Kind::Output,
                if output.success {
                    "output"
                } else {
                    "output · failed"
                }
                .into(),
                output.error.clone().unwrap_or_default(),
                Some(output.call_id.clone()),
            ),
            Some(O::ShellCommandOutput(output)) => (
                Kind::Output,
                format!("exit {}", output.exit_code),
                first_line(if output.stdout.is_empty() {
                    &output.stderr
                } else {
                    &output.stdout
                }),
                Some(output.call_id.clone()),
            ),
            Some(O::WebFetchOutput(output)) => (
                Kind::Output,
                format!("http {}", output.code),
                output.url.clone(),
                Some(output.call_id.clone()),
            ),
            Some(O::FileOperationResult(result)) => (
                Kind::Output,
                if result.success {
                    "result"
                } else {
                    "result · failed"
                }
                .into(),
                result
                    .path
                    .clone()
                    .or_else(|| result.error.clone())
                    .unwrap_or_default(),
                Some(result.call_id.clone()),
            ),
            None => (Kind::Unknown, "observation".into(), String::new(), None),
        },
        Category::Control(control) => {
            let (title, subtitle) = match control.kind.as_ref() {
                Some(C::Started(started)) => (
                    "started",
                    started
                        .task
                        .clone()
                        .or_else(|| started.agent.as_ref().map(|a| a.id.clone()))
                        .unwrap_or_default(),
                ),
                Some(C::Completed(done)) => ("completed", done.summary.clone().unwrap_or_default()),
                Some(C::Failed(failed)) => ("failed", failed.reason.clone()),
                Some(C::Terminated(term)) => ("terminated", term.reason.clone()),
                Some(C::Suspended(susp)) => ("suspended", susp.reason.clone()),
                Some(C::Resumed(res)) => ("resumed", res.resumed_by.clone()),
                Some(C::Adjudicated(adj)) => {
                    ("adjudicated", adj.reason.clone().unwrap_or_default())
                }
                Some(C::Scanned(_)) => ("scanned", String::new()),
                None => ("control", String::new()),
            };
            (Kind::Control, title.into(), first_line(&subtitle), None)
        }
        Category::State(state) => {
            let subtitle = match state.kind.as_ref() {
                Some(hb::state::Kind::Snapshot(snap)) => snap
                    .working_dir
                    .clone()
                    .or_else(|| snap.git_branch.clone())
                    .unwrap_or_else(|| snap.snapshot_id.clone()),
                None => String::new(),
            };
            (Kind::State, "snapshot".into(), subtitle, None)
        }
    }
}

/// A tool call's most identifying argument, for the tree's second column.
///
/// Falls back through the argument names coding agents actually use before
/// giving up, so a `Read` shows its path rather than a `{…}` placeholder.
fn tool_call_subtitle(call: &hb::ToolCall) -> String {
    let Some(args) = call.arguments.as_ref() else {
        return String::new();
    };
    for key in ["command", "file_path", "path", "url", "pattern", "query"] {
        if let Some(value) = args.fields.get(key)
            && let Some(prost_types::value::Kind::StringValue(text)) = value.kind.as_ref()
        {
            return first_line(text);
        }
    }
    format!("{} args", args.fields.len())
}

fn file_op_label(value: i32) -> &'static str {
    match hb::file_operation::FileOpType::try_from(value) {
        Ok(hb::file_operation::FileOpType::Read) => "read",
        Ok(hb::file_operation::FileOpType::Write) => "write",
        Ok(hb::file_operation::FileOpType::Edit) => "edit",
        Ok(hb::file_operation::FileOpType::Delete) => "delete",
        _ => "file",
    }
}

pub(crate) fn prompt_role_label(value: i32) -> &'static str {
    match hb::prompt::PromptRole::try_from(value) {
        Ok(hb::prompt::PromptRole::User) => "user",
        Ok(hb::prompt::PromptRole::System) => "system",
        Ok(hb::prompt::PromptRole::Assistant) => "assistant",
        _ => "unspecified",
    }
}

fn intent_label(value: i32) -> Option<String> {
    let label = match hb::AgentIntent::try_from(value).ok()? {
        hb::AgentIntent::Investigate => "investigate",
        hb::AgentIntent::Plan => "plan",
        hb::AgentIntent::Implement => "implement",
        hb::AgentIntent::Verify => "verify",
        hb::AgentIntent::Debug => "debug",
        hb::AgentIntent::Communicate => "communicate",
        hb::AgentIntent::Lifecycle => "lifecycle",
        hb::AgentIntent::Govern => "govern",
        hb::AgentIntent::Unspecified => return None,
    };
    Some(label.to_string())
}

impl From<&hb::Signal> for SignalView {
    fn from(value: &hb::Signal) -> Self {
        Self {
            severity: Severity::from_proto(value.severity),
            focus: enum_label(
                hb::SignalFocus::try_from(value.focus)
                    .ok()
                    .map(|f| f.as_str_name()),
            ),
            category: enum_label(
                hb::SignalCategory::try_from(value.category)
                    .ok()
                    .map(|c| c.as_str_name()),
            ),
            description: value.description.clone(),
        }
    }
}

impl From<&hb::TranscriptDigest> for DigestView {
    fn from(value: &hb::TranscriptDigest) -> Self {
        Self {
            title: value.title.clone(),
            summary: value.summary.clone(),
            interim: value.interim,
            phases: value.phases.iter().map(PhaseView::from).collect(),
            tools_used: value.tools_used.clone(),
            files_modified: value.files_modified.clone(),
            total_events: value.total_events,
            side_effecting_count: value.side_effecting_count,
        }
    }
}

impl From<&hb::TranscriptPhase> for PhaseView {
    fn from(value: &hb::TranscriptPhase) -> Self {
        Self {
            name: value.name.clone(),
            description: value.description.clone(),
            // The wire carries the indices themselves; a panel has room for
            // how many, not which, and the transcript below already shows the
            // events in order.
            event_count: value.event_indices.len(),
        }
    }
}

impl From<&hb::TranscriptScan> for ScanView {
    fn from(value: &hb::TranscriptScan) -> Self {
        let Some(result) = value.result.as_ref() else {
            return Self::default();
        };
        Self {
            outcome: outcome_label(result.outcome),
            outcome_description: result.outcome_description.clone(),
            aggregate_severity: Severity::from_proto(result.aggregate_severity),
            confidence: result.confidence,
            explanation: result.explanation.clone(),
            signals: result.signals.iter().map(SignalView::from).collect(),
            adjudication_summary: result.adjudication_summary.clone(),
            behavioral_notes: result.behavioral_notes.clone(),
        }
    }
}

/// Turn a generated `SCREAMING_SNAKE` enum name into a readable label.
///
/// prost's `as_str_name` yields the full proto constant
/// (`SIGNAL_CATEGORY_TOOL_MISUSE`); the leading enum-name prefix is noise once
/// the value sits in a column headed "category", so only the tail is kept.
fn enum_label(name: Option<&str>) -> String {
    let Some(name) = name else {
        return String::new();
    };
    let tail = name
        .rsplit_once("CATEGORY_")
        .or_else(|| name.rsplit_once("FOCUS_"))
        .or_else(|| name.rsplit_once("OUTCOME_"))
        .map(|(_, tail)| tail)
        .unwrap_or(name);
    tail.to_lowercase().replace('_', " ")
}

// ============================================================================
// Formatting helpers
// ============================================================================

/// Strip a `kind/{id}` resource prefix down to its bare id.
pub fn short(resource: &str) -> &str {
    resource
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty())
        .unwrap_or(resource)
}

/// The first non-empty line of a block of text, for one-line summaries.
pub fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .to_string()
}

/// Truncate to `width` display characters with an ellipsis.
pub fn fit(value: &str, width: usize) -> String {
    let count = value.chars().count();
    if count <= width {
        value.to_string()
    } else if width <= 1 {
        "…".to_string()
    } else {
        format!("{}…", value.chars().take(width - 1).collect::<String>())
    }
}

/// Format a millisecond duration compactly (4200 → 4.2s).
pub fn duration(ms: i64) -> String {
    if ms <= 0 {
        "—".to_string()
    } else if ms < 1_000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1_000.0)
    } else {
        format!("{:.1}m", ms as f64 / 60_000.0)
    }
}

/// Extract `HH:MM:SS` from an RFC3339 timestamp for fixed-width columns.
pub fn clock(timestamp: Option<&str>) -> String {
    let Some(ts) = timestamp.map(str::trim).filter(|t| !t.is_empty()) else {
        return "—".to_string();
    };
    match ts.split_once('T') {
        Some((_, rest)) => {
            let time = rest.split(['+', 'Z', '.']).next().unwrap_or(rest);
            if time.is_empty() {
                ts.to_string()
            } else {
                time.to_string()
            }
        }
        None => ts.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A feed row the scanner has graded.
    fn graded() -> TrajectoryRow {
        TrajectoryRow {
            agent: "claude-code".into(),
            id: "run-a".into(),
            status: "completed".into(),
            summary: "refactored the storage layer".into(),
            policy_hits: vec!["no-recursive-delete".into()],
            digest: Some(DigestView {
                title: "Refactor the storage layer".into(),
                files_modified: vec!["crates/storage/src/turso/agent.rs".into()],
                tools_used: vec!["Bash".into()],
                ..DigestView::default()
            }),
            scan: Some(ScanView {
                outcome: "partial".into(),
                aggregate_severity: Severity::High,
                signals: vec![SignalView {
                    severity: Severity::High,
                    focus: "agent".into(),
                    category: "credential exposure".into(),
                    description: "Read a private key into the context.".into(),
                }],
                ..ScanView::default()
            }),
            ..TrajectoryRow::default()
        }
    }

    /// The scanner's vocabulary appears nowhere else in the feed, so a filter
    /// that cannot reach it cannot answer the question an operator actually
    /// arrives with: *which runs touched credentials?*
    #[test]
    fn the_filter_reaches_the_words_only_the_scanner_uses() {
        let row = graded();
        for needle in [
            "credential",          // a signal category
            "private key",         // a signal description
            "partial",             // the outcome grade
            "turso",               // a file the digest says was modified
            "no-recursive-delete", // a policy that fired
        ] {
            assert!(row.matches(needle), "the filter missed {needle:?}");
        }
        assert!(!row.matches("nothing here says this"));
    }

    /// Every scanner-derived accessor has to distinguish "not scanned" from a
    /// benign grade, because the feed colors them differently and one of them
    /// is a claim the console has no evidence for.
    #[test]
    fn an_ungraded_run_reports_absence_rather_than_a_default_grade() {
        let ungraded = TrajectoryRow::default();
        assert_eq!(ungraded.risk(), None);
        assert_eq!(ungraded.outcome(), None);
        assert_eq!(ungraded.signal_count(), 0);
        assert!(!ungraded.is_interim());

        let row = graded();
        assert_eq!(row.risk(), Some(Severity::High));
        assert_eq!(row.outcome(), Some("partial"));
        assert_eq!(row.signal_count(), 1);
    }

    /// An empty outcome string is the proto's absent value, not a grade.
    #[test]
    fn an_empty_outcome_string_reads_as_no_outcome() {
        let row = TrajectoryRow {
            scan: Some(ScanView::default()),
            ..TrajectoryRow::default()
        };
        assert_eq!(row.outcome(), None);
        // The severity is still real: a scan that graded nothing still ran.
        assert_eq!(row.risk(), Some(Severity::Info));
    }

    /// The two jumps answer different questions and must not collapse into one.
    #[test]
    fn fired_and_signalled_steps_are_independent() {
        let transcript = Transcript {
            nodes: vec![
                EventNode {
                    decision: Some(Decision::Deny),
                    ..EventNode::default()
                },
                EventNode {
                    severity: Severity::High,
                    ..EventNode::default()
                },
                EventNode {
                    severity: Severity::Low,
                    ..EventNode::default()
                },
            ],
            steps: vec![
                Step {
                    root: 0,
                    children: vec![],
                },
                Step {
                    root: 1,
                    children: vec![],
                },
                Step {
                    root: 2,
                    children: vec![],
                },
            ],
            ..Transcript::default()
        };
        assert_eq!(transcript.fired_steps(), vec![0]);
        // `low` is below the bar: a marker on every row means nothing.
        assert_eq!(transcript.signalled_steps(), vec![1]);
    }

    /// The digest and the scan have one home. A feed row and the transcript
    /// header reading different copies is how the two screens come to disagree
    /// about how a run went.
    #[test]
    fn the_transcript_reads_its_scanner_output_from_the_summary() {
        let transcript = Transcript {
            summary: graded(),
            ..Transcript::default()
        };
        assert_eq!(
            transcript.digest().map(|digest| digest.title.as_str()),
            Some("Refactor the storage layer"),
        );
        assert_eq!(
            transcript.scan().map(|scan| scan.outcome.as_str()),
            Some("partial"),
        );
        assert!(transcript.has_insight());
    }

    fn node(kind: Kind, call_id: Option<&str>) -> EventNode {
        EventNode {
            kind,
            call_id: call_id.map(str::to_string),
            ..EventNode::default()
        }
    }

    #[test]
    fn observation_nests_under_the_action_it_answers() {
        let nodes = vec![
            node(Kind::Shell, Some("c1")),
            node(Kind::Output, Some("c1")),
        ];
        let steps = build_steps(&nodes);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].root, 0);
        assert_eq!(steps[0].children, vec![1]);
    }

    #[test]
    fn a_retry_reusing_a_call_id_keeps_its_own_output() {
        // Two calls share `c1`; the second output must attach to the second
        // call, not to the first.
        let nodes = vec![
            node(Kind::Shell, Some("c1")),
            node(Kind::Output, Some("c1")),
            node(Kind::Shell, Some("c1")),
            node(Kind::Output, Some("c1")),
        ];
        let steps = build_steps(&nodes);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].children, vec![1]);
        assert_eq!(steps[1].children, vec![3]);
    }

    #[test]
    fn an_orphan_observation_stands_alone_rather_than_vanishing() {
        let nodes = vec![node(Kind::Output, Some("missing"))];
        let steps = build_steps(&nodes);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].root, 0);
        assert!(steps[0].children.is_empty());
    }

    #[test]
    fn prompts_and_control_never_nest() {
        let nodes = vec![
            node(Kind::Prompt, None),
            node(Kind::Thought, None),
            node(Kind::Control, None),
        ];
        assert_eq!(build_steps(&nodes).len(), 3);
    }

    #[test]
    fn rows_hide_children_until_the_step_is_expanded() {
        let transcript = Transcript {
            nodes: vec![
                node(Kind::Shell, Some("c1")),
                node(Kind::Output, Some("c1")),
            ],
            steps: vec![Step {
                root: 0,
                children: vec![1],
            }],
            ..Transcript::default()
        };
        assert_eq!(transcript.rows(&|_| false).len(), 1);
        assert_eq!(transcript.rows(&|_| true).len(), 2);
    }

    #[test]
    fn a_childless_step_is_never_expandable() {
        let transcript = Transcript {
            nodes: vec![node(Kind::Prompt, None)],
            steps: vec![Step {
                root: 0,
                children: vec![],
            }],
            ..Transcript::default()
        };
        let rows = transcript.rows(&|_| true);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].expandable);
        assert!(!rows[0].expanded);
    }

    #[test]
    fn unspecified_decision_is_absence_not_allow() {
        assert_eq!(Decision::from_proto(0), None);
        assert_eq!(Decision::from_proto(1), Some(Decision::Allow));
    }

    #[test]
    fn a_policy_fire_outranks_a_scan_severity_for_tone() {
        let node = EventNode {
            decision: Some(Decision::Deny),
            severity: Severity::Info,
            ..EventNode::default()
        };
        assert_eq!(node.tone(), Tone::Deny);
    }

    #[test]
    fn enum_label_drops_the_generated_prefix() {
        assert_eq!(
            enum_label(Some("SIGNAL_CATEGORY_TOOL_MISUSE")),
            "tool misuse"
        );
        assert_eq!(enum_label(None), "");
    }

    #[test]
    fn fit_and_duration_stay_within_budget() {
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("ab", 4), "ab");
        assert_eq!(duration(0), "—");
        assert_eq!(duration(950), "950ms");
        assert_eq!(duration(4_200), "4.2s");
    }

    /// Alignment in the tree depends on every kind glyph being one column.
    /// Measured with Ratatui's own width function, which is what the layout
    /// engine uses — an emoji here silently ruins every row below it.
    #[test]
    fn every_kind_glyph_is_exactly_one_column_wide() {
        for kind in Kind::ALL {
            let glyph = kind.glyph();
            assert_eq!(
                ratatui::text::Span::raw(glyph).width(),
                1,
                "{kind:?} glyph {glyph:?} is not one column wide",
            );
        }
    }

    /// The tone glyphs ride inside chips, where the same rule applies.
    #[test]
    fn every_tone_glyph_is_exactly_one_column_wide() {
        for tone in [
            Tone::Allow,
            Tone::Warn,
            Tone::Info,
            Tone::Deny,
            Tone::Rare,
            Tone::Neutral,
        ] {
            assert_eq!(ratatui::text::Span::raw(tone.glyph()).width(), 1);
        }
    }

    // ── the sparkline strip ─────────────────────────────────────────────────

    fn spark_cell(kind: SparkKind) -> SparkCell {
        SparkCell {
            kind,
            ..SparkCell::default()
        }
    }

    fn spark(len: usize) -> Sparkline {
        Sparkline {
            cells: (0..len).map(|_| spark_cell(SparkKind::Thought)).collect(),
            truncated: false,
        }
    }

    /// A strip is laid out by counting cells against a fixed column budget, so
    /// a two-column glyph would push every following column out of place.
    #[test]
    fn every_spark_glyph_is_exactly_one_column_wide() {
        for kind in SparkKind::ALL {
            let glyph = kind.glyph();
            assert_eq!(
                ratatui::text::Span::raw(glyph).width(),
                1,
                "{kind:?} glyph {glyph:?} is not one column wide",
            );
        }
    }

    /// Kinds are told apart by shape, not color — two kinds sharing a glyph
    /// would be indistinguishable under `NO_COLOR`.
    #[test]
    fn every_spark_kind_has_a_distinct_glyph() {
        let glyphs: HashMap<&str, SparkKind> = SparkKind::ALL
            .iter()
            .map(|kind| (kind.glyph(), *kind))
            .collect();
        assert_eq!(glyphs.len(), SparkKind::ALL.len());
    }

    #[test]
    fn a_strip_that_already_fits_is_left_alone() {
        let strip = spark(6);
        assert_eq!(strip.strip(16).len(), 6);
        assert_eq!(strip.strip(6).len(), 6);
    }

    #[test]
    fn narrowing_fills_the_column_and_keeps_both_anchors() {
        let mut strip = spark(40);
        strip.cells[0].kind = SparkKind::Control;
        strip.cells[39].kind = SparkKind::State;

        let narrowed = strip.strip(16);
        assert_eq!(narrowed.len(), 16);
        assert_eq!(narrowed[0].kind, SparkKind::Control);
        assert_eq!(narrowed[15].kind, SparkKind::State);
    }

    /// The one thing this column may never do: bucket a deny out of sight. A
    /// fire anywhere in the run has to survive being narrowed to any width.
    #[test]
    fn narrowing_never_swallows_a_fire() {
        for width in 1..=32 {
            let mut strip = spark(200);
            strip.cells[97].kind = SparkKind::Shell;
            strip.cells[97].decision = Some(Decision::Deny);
            strip.cells[97].policy_hit = Some("policies/no-shell".into());

            let narrowed = strip.strip(width);
            assert!(narrowed.len() <= width, "width {width} overflowed");
            let fire = narrowed
                .iter()
                .find(|cell| cell.decision == Some(Decision::Deny))
                .unwrap_or_else(|| panic!("the deny vanished at width {width}"));
            assert_eq!(fire.policy_hit.as_deref(), Some("policies/no-shell"));
            assert_eq!(fire.tone(), Tone::Deny);
        }
    }

    /// Deny outranks escalate when both land in one bucket, matching how the
    /// console ranks them when it caps a strip.
    #[test]
    fn a_bucket_reports_its_loudest_fire_and_its_most_substantive_work() {
        let summarized = summarize(&[
            SparkCell {
                kind: SparkKind::Control,
                ..SparkCell::default()
            },
            SparkCell {
                kind: SparkKind::Tool,
                decision: Some(Decision::Escalate),
                policy_hit: Some("policies/review".into()),
            },
            SparkCell {
                kind: SparkKind::Shell,
                decision: Some(Decision::Deny),
                policy_hit: Some("policies/no-shell".into()),
            },
        ]);
        assert_eq!(summarized.kind, SparkKind::Shell);
        assert_eq!(summarized.decision, Some(Decision::Deny));
        assert_eq!(summarized.policy_hit.as_deref(), Some("policies/no-shell"));
    }

    #[test]
    fn a_zero_width_strip_is_empty_rather_than_a_panic() {
        assert!(spark(10).strip(0).is_empty());
        assert!(Sparkline::default().strip(16).is_empty());
    }

    /// An allow verdict is a cleared check, and the console never sends one on
    /// a cell. Ordinary work must therefore read as neutral, not as allow.
    #[test]
    fn an_uncontested_cell_claims_no_tone() {
        assert_eq!(spark_cell(SparkKind::Shell).tone(), Tone::Neutral);
    }

    #[test]
    fn a_wire_strip_decodes_its_kinds_and_folded_verdicts() {
        let wire = pb::TrajectorySparkline {
            trajectory: "trajectories/run-1".into(),
            cells: vec![
                pb::SparklineCell {
                    kind: pb::SparklineEventKind::Shell as i32,
                    duration_ms: 10,
                    policy_hit: "policies/no-shell".into(),
                    decision: hb::Decision::Deny as i32,
                },
                pb::SparklineCell {
                    kind: pb::SparklineEventKind::PromptUser as i32,
                    duration_ms: 0,
                    policy_hit: String::new(),
                    decision: hb::Decision::Unspecified as i32,
                },
            ],
            decision: hb::Decision::Deny as i32,
            truncated: true,
        };

        let strip = Sparkline::from(&wire);
        assert!(strip.truncated);
        assert_eq!(strip.fires(), 1);
        assert_eq!(strip.cells[0].kind, SparkKind::Shell);
        assert_eq!(strip.cells[0].decision, Some(Decision::Deny));
        assert_eq!(strip.cells[1].kind, SparkKind::PromptUser);
        // No fire means no policy id, rather than an empty string rendered as
        // if a policy had been named.
        assert_eq!(strip.cells[1].policy_hit, None);
    }

    #[test]
    fn clock_extracts_the_time_component() {
        assert_eq!(clock(Some("2026-08-01T12:34:56Z")), "12:34:56");
        assert_eq!(clock(None), "—");
    }

    // ── the live tail ───────────────────────────────────────────────────────

    fn wire(id: &str, causation: &str, payload: hb::TrajectoryEvent) -> pb::TrajectoryEvent {
        pb::TrajectoryEvent {
            event_id: id.to_string(),
            causation_id: causation.to_string(),
            payload: Some(payload),
            ..pb::TrajectoryEvent::default()
        }
    }

    fn shell_command(call_id: &str, command: &str) -> hb::TrajectoryEvent {
        hb::TrajectoryEvent {
            category: Some(hb::trajectory_event::Category::Action(hb::Action {
                kind: Some(hb::action::Kind::ShellCommand(hb::ShellCommand {
                    call_id: call_id.to_string(),
                    command: command.to_string(),
                    ..hb::ShellCommand::default()
                })),
            })),
        }
    }

    fn shell_output(call_id: &str, exit_code: i32) -> hb::TrajectoryEvent {
        hb::TrajectoryEvent {
            category: Some(hb::trajectory_event::Category::Observation(
                hb::Observation {
                    kind: Some(hb::observation::Kind::ShellCommandOutput(
                        hb::ShellCommandOutput {
                            call_id: call_id.to_string(),
                            exit_code,
                            ..hb::ShellCommandOutput::default()
                        },
                    )),
                },
            )),
        }
    }

    fn verdict(decision: hb::Decision, reason: &str) -> hb::Adjudicated {
        hb::Adjudicated {
            decision: decision as i32,
            reason: Some(reason.to_string()),
            ..hb::Adjudicated::default()
        }
    }

    fn adjudicated(adjudication: hb::Adjudicated) -> hb::TrajectoryEvent {
        hb::TrajectoryEvent {
            category: Some(hb::trajectory_event::Category::Control(hb::Control {
                kind: Some(hb::control::Kind::Adjudicated(adjudication)),
            })),
        }
    }

    fn detail(
        event: &pb::TrajectoryEvent,
        adjudication: Option<hb::Adjudicated>,
    ) -> pb::TrajectoryEventDetail {
        pb::TrajectoryEventDetail {
            event: Some(event.clone()),
            adjudication,
            summary: None,
        }
    }

    fn streamed(events: &[pb::TrajectoryEvent]) -> Transcript {
        let mut transcript = Transcript::default();
        let mut tail = TranscriptTail::default();
        for event in events {
            tail.ingest(&mut transcript, event);
        }
        transcript
    }

    /// The whole point of the tail: reading a run event by event off the stream
    /// must land on the same transcript as reading it as a page, or the two
    /// paths disagree about what a run did.
    #[test]
    fn the_streamed_fold_agrees_with_the_paged_build() {
        let action = wire("e1", "", shell_command("c1", "rm -rf /tmp/build"));
        let denial = wire("e2", "e1", adjudicated(verdict(hb::Decision::Deny, "no")));
        let output = wire("e3", "", shell_output("c1", 1));

        let streamed = streamed(&[action.clone(), denial, output.clone()]);
        let built = Transcript::build(
            &pb::TrajectorySummary::default(),
            &[
                detail(&action, Some(verdict(hb::Decision::Deny, "no"))),
                detail(&output, None),
            ],
        );

        assert_eq!(streamed.nodes, built.nodes);
        assert_eq!(streamed.steps, built.steps);
        assert_eq!(streamed.nodes[0].decision, Some(Decision::Deny));
    }

    #[test]
    fn a_governance_event_never_becomes_a_row() {
        let transcript = streamed(&[
            wire("e1", "", shell_command("c1", "ls")),
            wire(
                "e2",
                "e1",
                adjudicated(verdict(hb::Decision::Allow, "fine")),
            ),
        ]);
        assert_eq!(transcript.nodes.len(), 1);
        assert_eq!(transcript.steps.len(), 1);
    }

    /// The console's rule is that the last verdict recorded governs. A second
    /// adjudication must therefore replace the first in the detail pane, not
    /// stack a second verdict under it.
    #[test]
    fn a_re_adjudication_replaces_the_verdict_rather_than_appending_one() {
        let once = streamed(&[
            wire("e1", "", shell_command("c1", "ls")),
            wire(
                "e2",
                "e1",
                adjudicated(verdict(hb::Decision::Allow, "fine")),
            ),
        ]);
        let twice = streamed(&[
            wire("e1", "", shell_command("c1", "ls")),
            wire(
                "e2",
                "e1",
                adjudicated(verdict(hb::Decision::Allow, "fine")),
            ),
            wire("e3", "e1", adjudicated(verdict(hb::Decision::Deny, "no"))),
        ]);

        assert_eq!(twice.nodes[0].decision, Some(Decision::Deny));
        assert_eq!(twice.nodes[0].reason.as_deref(), Some("no"));
        assert_eq!(twice.nodes[0].blocks.len(), once.nodes[0].blocks.len());
    }

    /// Ledger order puts a verdict after the event it governs, but a verdict
    /// this reader dropped would be a deny it never showed.
    #[test]
    fn a_verdict_arriving_before_its_event_is_parked_not_dropped() {
        let transcript = streamed(&[
            wire("e2", "e1", adjudicated(verdict(hb::Decision::Deny, "no"))),
            wire("e1", "", shell_command("c1", "ls")),
        ]);
        assert_eq!(transcript.nodes.len(), 1);
        assert_eq!(transcript.nodes[0].decision, Some(Decision::Deny));
    }

    #[test]
    fn a_replayed_event_is_ignored_rather_than_duplicated() {
        let action = wire("e1", "", shell_command("c1", "ls"));
        let mut transcript = Transcript::default();
        let mut tail = TranscriptTail::default();

        assert_eq!(tail.ingest(&mut transcript, &action), Ingested::Step(0));
        assert_eq!(tail.ingest(&mut transcript, &action), Ingested::Duplicate);
        assert_eq!(transcript.nodes.len(), 1);
    }

    /// The same rule the paged build follows: an output attaches to the newest
    /// action carrying its call id, so a retry keeps its own output.
    #[test]
    fn a_streamed_retry_reusing_a_call_id_keeps_its_own_output() {
        let transcript = streamed(&[
            wire("e1", "", shell_command("c1", "ls")),
            wire("e2", "", shell_output("c1", 0)),
            wire("e3", "", shell_command("c1", "ls")),
            wire("e4", "", shell_output("c1", 0)),
        ]);

        assert_eq!(transcript.steps.len(), 2);
        assert_eq!(transcript.steps[0].children, vec![1]);
        assert_eq!(transcript.steps[1].children, vec![3]);
    }

    #[test]
    fn an_orphan_streamed_output_stands_alone_rather_than_vanishing() {
        let transcript = streamed(&[wire("e1", "", shell_output("missing", 0))]);
        assert_eq!(transcript.steps.len(), 1);
        assert_eq!(transcript.steps[0].root, 0);
    }
}
