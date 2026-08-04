//! Application state and the transitions the key handler drives.
//!
//! State is deliberately plain data with plain methods: the event loop applies
//! key events to it, the screens read it, and nothing here touches the network
//! or the terminal. That is what lets every navigation rule below be tested
//! without a running console or a TTY.
//!
//! The two widget states are the one exception. `TableState`/`ListState` own
//! the scroll offset that keeps the selected row on screen, and that offset has
//! to survive between frames — rebuilding them per render would snap every
//! downward step to the bottom edge of the viewport.

use crate::brand::Mark;
use crate::client::TRAJECTORY_PAGE;
use crate::model::{
    AgentIdentity, Ingested, Sparkline, TrajectoryRow, Transcript, TranscriptTail, TreeRow,
};
use crate::theme::Theme;
use ratatui::widgets::{ListState, TableState};
use sondera_schema::console_v1 as pb;
use std::collections::{HashMap, HashSet};

/// Which screen is on top.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// The run feed.
    Trajectories,
    /// One run's transcript: tree on the left, event detail on the right.
    Transcript,
}

/// Which pane takes navigation keys on the transcript screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    Tree,
    /// The scanner's read of the run as a whole. Only reachable when the
    /// scanner has produced one — see [`App::has_insight`].
    Insight,
    Detail,
}

/// The lifecycle of an async fetch, so a pane can tell "nothing here" apart
/// from "not loaded yet" and from "the load failed".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Load {
    #[default]
    Idle,
    Loading,
    Ready,
    /// Loaded and still being updated over a console stream. A reader has to be
    /// able to tell this from a snapshot, because it decides whether what is
    /// missing means "did not happen" or "press r".
    Live,
    Failed(String),
}

impl Load {
    pub fn label(&self) -> &str {
        match self {
            Self::Idle => "idle",
            Self::Loading => "loading",
            Self::Ready => "ready",
            Self::Live => "live",
            Self::Failed(_) => "error",
        }
    }
}

/// A strip plus the revision of the run it was built from.
///
/// Building a strip costs the console a full read of the run's events, so the
/// feed re-asks only for runs that have actually moved. A finished run is
/// fetched once; a running one is refetched as it grows.
struct CachedSpark {
    revision: String,
    spark: Sparkline,
}

/// What a strip is invalidated by: a run whose event count or last update has
/// moved has a different shape than the one on screen.
fn revision(row: &TrajectoryRow) -> String {
    format!(
        "{}:{}",
        row.event_count,
        row.update_time.as_deref().unwrap_or("")
    )
}

/// Everything the two screens draw from.
pub struct App {
    pub theme: Theme,
    /// The animated brand mark in the header.
    pub brand: Mark,
    pub screen: Screen,
    pub pane: Pane,
    pub should_quit: bool,

    // ── run feed ────────────────────────────────────────────────────────────
    pub trajectories: Vec<TrajectoryRow>,
    pub trajectories_load: Load,
    pub selected_run: usize,
    /// Activity strips by trajectory resource name, kept across refreshes so a
    /// feed update does not blank the column it just redrew.
    sparklines: HashMap<String, CachedSpark>,
    /// Names asked for by the batch currently in flight, against the revision
    /// they were asked at.
    pending: HashMap<String, String>,
    pub sparklines_load: Load,
    /// Provider and platform by bare agent id, joined onto the feed's rows.
    ///
    /// Its own map rather than a field on [`TrajectoryRow`], because it arrives
    /// from a different call and on a different schedule: a run's summary comes
    /// from the trajectory surface, its agent's identity from the agent roster.
    agents: HashMap<String, AgentIdentity>,
    /// Agent ids the console has already been asked about.
    ///
    /// An agent the roster does not return — one deleted between the run and the
    /// read, or a console that predates the identity fields — would otherwise
    /// make every streamed update on that agent re-fetch the whole roster.
    agents_asked: HashSet<String>,
    pub agents_load: Load,
    /// Free-text filter over the feed, applied client-side.
    pub filter: String,
    /// Whether keystrokes are being typed into the filter rather than
    /// interpreted as navigation.
    pub filter_editing: bool,
    /// Whether the run inspector is open over the feed.
    ///
    /// The feed is a table and a table has columns; the digest's phases, files,
    /// and the scan's signals are lists, and no width makes them into columns.
    /// The inspector is where they are readable without leaving the feed — and
    /// it is the only place the narrow column sets can show them at all.
    pub inspecting: bool,
    pub inspect_scroll: u16,
    pub inspect_max_scroll: u16,
    /// Resource name of the run the open panel is showing, so a selection that
    /// moves underneath it — a live update reordering the feed, or dropping the
    /// run off the page — is noticed rather than silently inherited along with
    /// the previous run's scroll offset.
    inspected: String,

    // ── transcript ──────────────────────────────────────────────────────────
    /// Resource name of the run the transcript screen opened.
    transcript_name: Option<String>,
    pub transcript: Option<Transcript>,
    pub transcript_load: Load,
    /// Incremental fold state for the live tail, when one is attached.
    /// Meaningless without it.
    tail: TranscriptTail,
    /// Index into the *visible* tree rows, not into the node list.
    pub selected_row: usize,
    /// Steps whose children are shown.
    expanded: HashSet<usize>,
    /// Vertical scroll offset of the detail pane, in rendered lines.
    pub detail_scroll: u16,
    /// The greatest scroll offset the last render could use, so paging cannot
    /// run off the end of a short event.
    pub detail_max_scroll: u16,
    /// The same pair for the run-insight pane, kept separately so moving
    /// between events does not reset where the reader was in the run summary.
    pub insight_scroll: u16,
    pub insight_max_scroll: u16,

    /// A transient line in the header.
    pub status: Option<String>,

    /// Viewport offsets, owned across frames so scrolling stays smooth.
    pub runs_state: TableState,
    pub tree_state: ListState,
}

impl App {
    pub fn new(theme: Theme) -> Self {
        Self {
            theme,
            brand: Mark::detect(&theme),
            screen: Screen::Trajectories,
            pane: Pane::Tree,
            should_quit: false,
            trajectories: Vec::new(),
            trajectories_load: Load::Loading,
            sparklines: HashMap::new(),
            pending: HashMap::new(),
            sparklines_load: Load::Idle,
            agents: HashMap::new(),
            agents_asked: HashSet::new(),
            agents_load: Load::Idle,
            selected_run: 0,
            filter: String::new(),
            filter_editing: false,
            inspecting: false,
            inspect_scroll: 0,
            inspect_max_scroll: 0,
            inspected: String::new(),
            transcript_name: None,
            transcript: None,
            transcript_load: Load::Idle,
            tail: TranscriptTail::default(),
            selected_row: 0,
            expanded: HashSet::new(),
            detail_scroll: 0,
            detail_max_scroll: 0,
            insight_scroll: 0,
            insight_max_scroll: 0,
            status: None,
            runs_state: TableState::default(),
            tree_state: ListState::default(),
        }
    }

    // ── run feed ────────────────────────────────────────────────────────────

    /// The rows the feed actually shows, after the filter.
    pub fn visible_runs(&self) -> Vec<&TrajectoryRow> {
        self.trajectories
            .iter()
            .filter(|row| row.matches(&self.filter))
            .collect()
    }

    pub fn selected_run(&self) -> Option<&TrajectoryRow> {
        self.visible_runs().get(self.selected_run).copied()
    }

    // ── agent roster ────────────────────────────────────────────────────────

    /// Who ran a trajectory, by its bare agent id.
    ///
    /// `None` means the roster cannot say — it has not arrived, or it does not
    /// cover this agent. The feed renders that as absent rather than blank,
    /// because "nobody has told this console who ran this" and "this run had no
    /// agent" are different claims.
    pub fn agent_identity(&self, agent: &str) -> Option<&AgentIdentity> {
        self.agents
            .get(agent)
            .filter(|identity| !identity.is_empty())
    }

    /// Install a freshly read roster, replacing whatever was held.
    ///
    /// Wholesale rather than merged: this is always the console's full agent
    /// list, so an agent it no longer reports is one this console should stop
    /// claiming to know.
    pub fn set_agents(&mut self, agents: Vec<(String, AgentIdentity)>) {
        self.agents = agents.into_iter().collect();
        self.agents_load = Load::Ready;
    }

    /// Whether the feed mentions an agent the roster cannot name, recording the
    /// ask so each unknown agent costs at most one re-read.
    ///
    /// The live feed introduces agents the roster predates — a hook reporting in
    /// for the first time mid-session — and without this their runs would show
    /// `—` until the next manual refresh.
    ///
    /// Called on every streamed update, so it filters before it clones: a live
    /// run updates constantly, and cloning a full page of agent ids per tick to
    /// throw all but none of them away is work this loop does not need to do.
    pub fn needs_agent_roster(&mut self) -> bool {
        let missing: Vec<String> = self
            .trajectories
            .iter()
            .map(|row| row.agent.as_str())
            .filter(|agent| {
                !agent.is_empty()
                    && !self.agents.contains_key(*agent)
                    && !self.agents_asked.contains(*agent)
            })
            .map(str::to_owned)
            .collect();
        if missing.is_empty() {
            return false;
        }
        self.agents_asked.extend(missing);
        true
    }

    /// Forget which agents have been asked about, so a full roster read is not
    /// suppressed by the per-agent guard above.
    pub fn reset_agent_requests(&mut self) {
        self.agents_asked.clear();
    }

    // ── run inspector ───────────────────────────────────────────────────────

    /// Open or close the inspector over the highlighted run.
    ///
    /// Opening on a run the scanner has not reached is allowed: the panel says
    /// so, which is the answer to "why is this row blank" and is exactly what a
    /// reader who pressed the key wants to know.
    pub fn toggle_inspect(&mut self) {
        let Some(name) = self.selected_run().map(|row| row.name.clone()) else {
            return;
        };
        self.inspecting = !self.inspecting;
        self.inspect_scroll = 0;
        self.inspected = name;
    }

    pub fn close_inspect(&mut self) {
        self.inspecting = false;
        self.inspect_scroll = 0;
        self.inspected.clear();
    }

    /// Keep the open panel pointed at whatever the feed is highlighting.
    ///
    /// Called once per frame while the panel is open, because the selection can
    /// move without a keypress: the live feed reorders the page as runs update
    /// and drops the oldest off the end. Two things have to happen when it does
    /// — the panel closes if there is nothing left to show, and the scroll
    /// offset rewinds if it is now over a different run's document. Inheriting
    /// an offset across runs opens a short summary scrolled past its own end.
    pub fn follow_inspect(&mut self) {
        if !self.inspecting {
            return;
        }
        match self.selected_run().map(|row| row.name.clone()) {
            None => self.close_inspect(),
            Some(name) if name != self.inspected => {
                self.inspected = name;
                self.inspect_scroll = 0;
            }
            Some(_) => {}
        }
    }

    pub fn scroll_inspect(&mut self, delta: i32) {
        let next = self.inspect_scroll as i32 + delta;
        self.inspect_scroll = next.clamp(0, self.inspect_max_scroll as i32) as u16;
    }

    /// Move the feed selection while the inspector is open, so the panel reads
    /// as a lens on the row rather than as a frozen snapshot of one.
    pub fn move_run_inspecting(&mut self, delta: isize) {
        self.move_run(delta);
        self.follow_inspect();
    }

    /// Replace the feed, keeping the selection on the same run where possible.
    ///
    /// A refresh that reorders or extends the feed must not silently move the
    /// user onto a different run; only a run that has disappeared forces the
    /// selection to move.
    pub fn set_trajectories(&mut self, mut rows: Vec<TrajectoryRow>) {
        let anchor = self.selected_run().map(|row| row.name.clone());
        rows.truncate(TRAJECTORY_PAGE as usize);
        self.trajectories = rows;
        self.trajectories_load = Load::Ready;
        // A strip whose run has left the feed is dropped; the rest are kept, so
        // a refresh redraws the column it already had rather than blanking it
        // and filling it back in a moment later.
        let live: HashSet<&str> = self
            .trajectories
            .iter()
            .map(|row| row.name.as_str())
            .collect();
        self.sparklines
            .retain(|name, _| live.contains(name.as_str()));
        self.restore_run_selection(anchor);
    }

    /// Insert or replace one summary from `StreamTrajectories`.
    pub fn upsert_trajectory(&mut self, mut row: TrajectoryRow) {
        let anchor = self.selected_run().map(|row| row.name.clone());
        match self
            .trajectories
            .iter()
            .position(|current| current.name == row.name)
        {
            Some(position) => {
                row.carry_scanner_output_from(&self.trajectories[position]);
                self.trajectories[position] = row;
            }
            None => self.trajectories.push(row),
        }
        self.trajectories
            .sort_by(|left, right| right.started_at.cmp(&left.started_at));
        self.trajectories.truncate(TRAJECTORY_PAGE as usize);
        let live: HashSet<&str> = self
            .trajectories
            .iter()
            .map(|row| row.name.as_str())
            .collect();
        self.sparklines
            .retain(|name, _| live.contains(name.as_str()));
        self.restore_run_selection(anchor);
    }

    fn restore_run_selection(&mut self, anchor: Option<String>) {
        self.selected_run = anchor
            .and_then(|name| self.visible_runs().iter().position(|row| row.name == name))
            .unwrap_or(0);
        self.clamp_run_selection();
    }

    /// The strip for one run, if one has been fetched.
    pub fn sparkline(&self, name: &str) -> Option<&Sparkline> {
        self.sparklines.get(name).map(|cached| &cached.spark)
    }

    /// The runs whose strip is missing or out of date, newest first, recorded
    /// as asked for.
    ///
    /// Every run in the feed is offered, not just the ones on screen: the whole
    /// point of the revision check is that a settled run is asked for once, so
    /// scrolling never has to wait on a fetch.
    ///
    /// The revision each name is asked *at* is remembered here rather than read
    /// again when the strip lands. A run can grow while its request is in
    /// flight, and a strip stamped with the revision it arrived at would then
    /// pass as current forever — permanently hiding whatever the run did after
    /// the strip was built, up to and including a deny.
    pub fn request_sparklines(&mut self) -> Vec<String> {
        // Feed order is kept, not the map's: the request is chunked to the
        // console's batch limit, so order decides which runs get a strip first,
        // and the newest runs are the ones a reader is looking at.
        let stale: Vec<(String, String)> = self
            .trajectories
            .iter()
            .filter(|row| {
                self.sparklines
                    .get(&row.name)
                    .is_none_or(|cached| cached.revision != revision(row))
            })
            .map(|row| (row.name.clone(), revision(row)))
            .collect();
        self.pending = stale.iter().cloned().collect();
        stale.into_iter().map(|(name, _)| name).collect()
    }

    /// Install the strips from one batch.
    ///
    /// Only what was asked for is installed: the console skips names it cannot
    /// resolve, and a name nobody asked for belongs to a feed this screen has
    /// already replaced. Whatever the batch did not answer is forgotten, so the
    /// next request asks again.
    pub fn set_sparklines(&mut self, strips: Vec<(String, Sparkline)>) {
        for (name, spark) in strips {
            let Some(revision) = self.pending.remove(&name) else {
                continue;
            };
            self.sparklines
                .insert(name, CachedSpark { revision, spark });
        }
        self.pending.clear();
        self.sparklines_load = Load::Ready;
    }

    fn clamp_run_selection(&mut self) {
        let len = self.visible_runs().len();
        self.selected_run = self.selected_run.min(len.saturating_sub(1));
    }

    pub fn move_run(&mut self, delta: isize) {
        let len = self.visible_runs().len();
        self.selected_run = step(self.selected_run, delta, len);
    }

    /// Apply an edit to the filter and re-anchor the selection, since the row
    /// under the cursor is very likely no longer the same run.
    pub fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        self.selected_run = 0;
    }

    // ── transcript ──────────────────────────────────────────────────────────

    pub(crate) fn transcript_name(&self) -> Option<&str> {
        self.transcript_name.as_deref()
    }

    pub(crate) fn opened_run(&self) -> Option<&TrajectoryRow> {
        match self.transcript_name() {
            Some(name) => self
                .trajectories
                .iter()
                .find(|row| row.name.as_str() == name),
            None => self.selected_run(),
        }
    }

    /// Install a freshly loaded transcript, expanding every step that has
    /// children so the run reads as a transcript rather than as a folded index.
    pub fn set_transcript(&mut self, transcript: Transcript) {
        self.expanded = (0..transcript.steps.len())
            .filter(|idx| !transcript.steps[*idx].children.is_empty())
            .collect();
        self.transcript = Some(transcript);
        self.transcript_load = Load::Ready;
        self.selected_row = 0;
        self.detail_scroll = 0;
        // A new run is a new run summary: carrying the old offset would open it
        // scrolled into the middle of a document the reader has not seen.
        self.insight_scroll = 0;
        self.insight_max_scroll = 0;
        // Focus must not survive onto a pane the new run does not draw. A run
        // the scanner has not reached has no insight panel, and leaving the
        // cursor there would send every scroll key to a document that is not on
        // screen.
        if self.pane == Pane::Insight && !self.has_insight() {
            self.pane = Pane::Tree;
        }
        self.tail = TranscriptTail::default();
    }

    /// Install the header of a run about to be streamed: the summary, digest,
    /// and scan the chrome needs, with the events still to arrive.
    pub fn begin_live_transcript(&mut self, header: Transcript) {
        self.set_transcript(header);
        self.transcript_load = Load::Live;
    }

    /// Whether the open transcript is keeping itself up to date.
    pub fn is_live(&self) -> bool {
        self.transcript_load == Load::Live
    }

    /// Fold a batch of streamed events into the open transcript.
    ///
    /// The cursor stays on the event it was on. A live tail that dragged the
    /// selection along would make the screen unreadable exactly when it matters
    /// — while a run is still going — so new events accumulate below and `End`
    /// jumps to them.
    ///
    /// Takes a batch rather than one event because re-anchoring walks the whole
    /// tree: doing that per event would make a backlog replay quadratic in the
    /// length of the run.
    pub fn ingest_live_events(&mut self, events: &[pb::TrajectoryEvent]) {
        if self.transcript.is_none() || events.is_empty() {
            return;
        }
        let anchor = self.selected_tree_row().map(|row| row.node);

        let mut rows_shifted = false;
        if let Some(transcript) = self.transcript.as_mut() {
            for event in events {
                match self.tail.ingest(transcript, event) {
                    // A step is expanded as it appears, so a streamed run reads
                    // the way a loaded one does: as a transcript, not as a
                    // folded index. Steps only ever append, so no row above the
                    // cursor moves.
                    Ingested::Step(step) => {
                        self.expanded.insert(step);
                    }
                    // A child landing under an earlier step shifts every row
                    // beneath it, which is the one case the cursor has to be
                    // re-found rather than kept by index.
                    Ingested::Child(_) => rows_shifted = true,
                    Ingested::Governance | Ingested::Duplicate => {}
                }
            }
        }

        if rows_shifted
            && let Some(node) = anchor
            && let Some(position) = self.tree_rows().iter().position(|row| row.node == node)
        {
            self.selected_row = position;
        }
        self.clamp_row_selection_keeping_scroll();
    }

    /// The tail stopped: the transcript on screen is now a snapshot, and the
    /// chrome must stop claiming otherwise. A failed load keeps its failure.
    pub fn end_live(&mut self) {
        if self.transcript_load == Load::Live {
            self.transcript_load = Load::Ready;
        }
    }

    pub fn is_expanded(&self, step: usize) -> bool {
        self.expanded.contains(&step)
    }

    /// The tree's currently visible rows.
    pub fn tree_rows(&self) -> Vec<TreeRow> {
        match self.transcript.as_ref() {
            Some(transcript) => transcript.rows(&|step| self.expanded.contains(&step)),
            None => Vec::new(),
        }
    }

    pub fn selected_tree_row(&self) -> Option<TreeRow> {
        self.tree_rows().get(self.selected_row).copied()
    }

    /// The node the detail pane is showing.
    pub fn selected_node(&self) -> Option<&crate::model::EventNode> {
        let row = self.selected_tree_row()?;
        self.transcript.as_ref()?.nodes.get(row.node)
    }

    pub fn move_row(&mut self, delta: isize) {
        let len = self.tree_rows().len();
        self.selected_row = step(self.selected_row, delta, len);
        // A new event means a new document; carrying the old offset would open
        // it scrolled into the middle of nowhere.
        self.detail_scroll = 0;
    }

    /// Collapse or expand the selected step.
    ///
    /// Toggling from a child row acts on the parent step and moves the cursor
    /// up to it, because collapsing while standing on a row that is about to
    /// disappear would strand the selection.
    pub fn toggle_expanded(&mut self) {
        let Some(row) = self.selected_tree_row() else {
            return;
        };
        if row.depth > 0
            && let Some(parent) = self
                .tree_rows()
                .iter()
                .position(|candidate| candidate.step == row.step && candidate.depth == 0)
        {
            self.selected_row = parent;
        }
        if self.expanded.contains(&row.step) {
            self.expanded.remove(&row.step);
        } else {
            self.expanded.insert(row.step);
        }
        self.clamp_row_selection();
    }

    pub fn expand_all(&mut self) {
        if let Some(transcript) = self.transcript.as_ref() {
            self.expanded = (0..transcript.steps.len()).collect();
        }
    }

    pub fn collapse_all(&mut self) {
        self.expanded.clear();
        self.clamp_row_selection();
    }

    fn clamp_row_selection(&mut self) {
        self.clamp_row_selection_keeping_scroll();
        self.detail_scroll = 0;
    }

    /// Clamp without touching the detail scroll, for the live tail: an event
    /// arriving elsewhere in the run must not throw away where the reader is in
    /// the document they are reading.
    fn clamp_row_selection_keeping_scroll(&mut self) {
        let len = self.tree_rows().len();
        self.selected_row = self.selected_row.min(len.saturating_sub(1));
    }

    /// Move the selection to the next step carrying a deny or escalate,
    /// wrapping at the end. Triage is the reason this screen exists, so it gets
    /// a key of its own rather than making the user scroll for fires.
    pub fn jump_to_next_fire(&mut self) {
        let steps = self
            .transcript
            .as_ref()
            .map(crate::model::Transcript::fired_steps)
            .unwrap_or_default();
        self.jump_to_next_step(&steps, "No deny or escalate decisions in this run.");
    }

    /// Move the selection to the next step the scanner flagged at `medium` or
    /// louder, wrapping at the end.
    ///
    /// The companion to [`App::jump_to_next_fire`], and a different question: a
    /// fire is what the policy engine stopped, a signal is what the scanner
    /// noticed and nothing stopped. A run with no fires and four `high` signals
    /// is the case this key exists for.
    pub fn jump_to_next_signal(&mut self) {
        let steps = self
            .transcript
            .as_ref()
            .map(crate::model::Transcript::signalled_steps)
            .unwrap_or_default();
        self.jump_to_next_step(&steps, "No scanner signals above `low` in this run.");
    }

    /// Move to the next step in `steps` after the cursor, wrapping, or say why
    /// nothing moved.
    fn jump_to_next_step(&mut self, steps: &[usize], empty: &str) {
        if self.transcript.is_none() {
            return;
        }
        if steps.is_empty() {
            self.status = Some(empty.to_string());
            return;
        }
        let current = self.selected_tree_row().map(|row| row.step).unwrap_or(0);
        let next = steps
            .iter()
            .find(|step| **step > current)
            .or_else(|| steps.first())
            .copied()
            .unwrap_or(current);
        let rows = self.tree_rows();
        if let Some(position) = rows
            .iter()
            .position(|row| row.step == next && row.depth == 0)
        {
            self.selected_row = position;
            self.detail_scroll = 0;
        }
    }

    // ── reading-pane scrolling ──────────────────────────────────────────────

    /// Whether the run-insight pane has anything to show.
    ///
    /// Gates both the panel and the Tab cycle: a pane with no content must not
    /// be focusable, or Tab lands the reader somewhere blank.
    pub fn has_insight(&self) -> bool {
        self.transcript
            .as_ref()
            .is_some_and(crate::model::Transcript::has_insight)
    }

    /// Scroll whichever reading pane has focus.
    ///
    /// The two panes are different documents at different altitudes — one run,
    /// one event — so they keep separate offsets and the key handler routes
    /// rather than the panes sharing one.
    pub fn scroll_focused(&mut self, delta: i32) {
        match self.pane {
            Pane::Insight => {
                let next = self.insight_scroll as i32 + delta;
                self.insight_scroll = next.clamp(0, self.insight_max_scroll as i32) as u16;
            }
            _ => self.scroll_detail(delta),
        }
    }

    pub fn scroll_focused_to_top(&mut self) {
        match self.pane {
            Pane::Insight => self.insight_scroll = 0,
            _ => self.detail_scroll = 0,
        }
    }

    pub fn scroll_focused_to_bottom(&mut self) {
        match self.pane {
            Pane::Insight => self.insight_scroll = self.insight_max_scroll,
            _ => self.detail_scroll = self.detail_max_scroll,
        }
    }

    pub fn scroll_detail(&mut self, delta: i32) {
        let next = self.detail_scroll as i32 + delta;
        self.detail_scroll = next.clamp(0, self.detail_max_scroll as i32) as u16;
    }

    pub fn scroll_detail_to_top(&mut self) {
        self.detail_scroll = 0;
    }

    pub fn scroll_detail_to_bottom(&mut self) {
        self.detail_scroll = self.detail_max_scroll;
    }

    // ── navigation ──────────────────────────────────────────────────────────

    pub fn open_transcript(&mut self) {
        let Some(name) = self.selected_run().map(|row| row.name.clone()) else {
            return;
        };
        self.screen = Screen::Transcript;
        self.pane = Pane::Tree;
        // The inspector is a lens on the feed; it must not survive onto a
        // screen that draws its own, wider version of the same document.
        self.close_inspect();
        self.transcript_name = Some(name);
        self.transcript = None;
        self.transcript_load = Load::Loading;
        self.tail = TranscriptTail::default();
        self.insight_scroll = 0;
    }

    pub fn back_to_feed(&mut self) {
        self.screen = Screen::Trajectories;
        self.status = None;
        self.transcript_name = None;
        self.end_live();
    }

    /// Cycle focus: tree → run insight → event detail → tree.
    ///
    /// The insight pane is skipped entirely when the scanner has produced
    /// nothing for this run, so Tab never stops on an empty panel.
    pub fn toggle_pane(&mut self) {
        self.pane = match self.pane {
            Pane::Tree if self.has_insight() => Pane::Insight,
            Pane::Tree => Pane::Detail,
            Pane::Insight => Pane::Detail,
            Pane::Detail => Pane::Tree,
        };
    }

    pub fn toggle_theme(&mut self) {
        self.theme = self.theme.toggled();
    }
}

/// Move `current` by `delta` within `len`, saturating at both ends.
///
/// Saturating rather than wrapping: in a long transcript, an accidental extra
/// `k` at the top should not teleport the reader to the last event.
fn step(current: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let next = current as isize + delta;
    next.clamp(0, len as isize - 1) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EventNode, Kind, Step};
    use crate::theme::{Depth, Theme};

    fn app() -> App {
        App::new(Theme::dark(Depth::TrueColor))
    }

    fn run(name: &str, agent: &str) -> TrajectoryRow {
        TrajectoryRow {
            name: format!("trajectories/{name}"),
            id: name.into(),
            agent: agent.into(),
            ..TrajectoryRow::default()
        }
    }

    /// A run with one shell step (with output) and one standalone prompt.
    fn transcript() -> Transcript {
        Transcript {
            nodes: vec![
                EventNode {
                    kind: Kind::Shell,
                    ..EventNode::default()
                },
                EventNode {
                    kind: Kind::Output,
                    ..EventNode::default()
                },
                EventNode {
                    kind: Kind::Prompt,
                    ..EventNode::default()
                },
            ],
            steps: vec![
                Step {
                    root: 0,
                    children: vec![1],
                },
                Step {
                    root: 2,
                    children: vec![],
                },
            ],
            ..Transcript::default()
        }
    }

    /// The inspector reads the highlighted run, so it must not open when there
    /// is no highlighted run to read.
    #[test]
    fn the_inspector_does_not_open_on_an_empty_feed() {
        let mut app = app();
        app.toggle_inspect();
        assert!(!app.inspecting);

        app.set_trajectories(vec![run("a", "claude")]);
        app.toggle_inspect();
        assert!(app.inspecting);
    }

    /// Opening a run is leaving the feed. An inspector still flagged open would
    /// draw itself over the transcript the moment the reader came back.
    #[test]
    fn opening_a_transcript_closes_the_inspector() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "claude")]);
        app.toggle_inspect();
        app.open_transcript();
        assert!(!app.inspecting);
    }

    /// The live feed and the paged read do not project the same row: the
    /// stream's rollup leaves the digest and scan unset. An update must
    /// therefore not turn a graded run into an ungraded one, because the feed
    /// renders that absence as `—`, meaning "nothing has looked at this".
    #[test]
    fn a_streamed_update_does_not_erase_a_run_that_was_already_graded() {
        let mut app = app();
        let mut graded = run("a", "claude");
        graded.summary = "Refactor the storage layer".into();
        graded.digest = Some(crate::model::DigestView {
            title: "Refactor the storage layer".into(),
            ..crate::model::DigestView::default()
        });
        graded.scan = Some(crate::model::ScanView {
            outcome: "partial".into(),
            aggregate_severity: crate::model::Severity::High,
            ..crate::model::ScanView::default()
        });
        app.set_trajectories(vec![graded]);

        // What the stream actually sends: the same run, no scanner output.
        let mut update = run("a", "claude");
        update.event_count = 99;
        app.upsert_trajectory(update);

        let row = app.selected_run().unwrap();
        assert_eq!(row.event_count, 99, "the update itself was not applied");
        assert_eq!(row.risk(), Some(crate::model::Severity::High));
        assert_eq!(row.outcome(), Some("partial"));
        assert_eq!(row.summary, "Refactor the storage layer");
    }

    /// Carrying forward may never overwrite scanner output the update *does*
    /// carry, or a finished run keeps showing its interim digest for ever.
    #[test]
    fn a_streamed_update_that_carries_a_newer_digest_wins() {
        let mut app = app();
        let mut interim = run("a", "claude");
        interim.digest = Some(crate::model::DigestView {
            title: "in progress".into(),
            interim: true,
            ..crate::model::DigestView::default()
        });
        app.set_trajectories(vec![interim]);

        let mut finished = run("a", "claude");
        finished.digest = Some(crate::model::DigestView {
            title: "Refactor the storage layer".into(),
            interim: false,
            ..crate::model::DigestView::default()
        });
        app.upsert_trajectory(finished);

        let row = app.selected_run().unwrap();
        assert!(!row.is_interim());
        assert_eq!(
            row.digest.as_ref().unwrap().title,
            "Refactor the storage layer"
        );
    }

    /// Scrolling is clamped to what the last frame actually laid out, so a held
    /// key cannot page past the end of a short panel.
    #[test]
    fn the_inspector_scroll_is_clamped_to_what_was_rendered() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "claude")]);
        app.toggle_inspect();
        app.inspect_max_scroll = 4;
        app.scroll_inspect(100);
        assert_eq!(app.inspect_scroll, 4);
        app.scroll_inspect(-100);
        assert_eq!(app.inspect_scroll, 0);
    }

    /// Moving to another run while the panel is open resets where the reader
    /// is in it: the panel is a lens on the row, and carrying the old offset
    /// would open the next run scrolled into its middle.
    #[test]
    fn moving_runs_with_the_inspector_open_rewinds_it() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "x"), run("b", "y")]);
        app.toggle_inspect();
        app.inspect_max_scroll = 10;
        app.scroll_inspect(5);
        app.move_run_inspecting(1);
        assert_eq!(app.selected_run().unwrap().id, "b");
        assert_eq!(app.inspect_scroll, 0);
    }

    /// A signal jump and a fire jump answer different questions, and a run can
    /// have one without the other. The signal jump must find a flagged step in
    /// a run where nothing was ever denied.
    #[test]
    fn the_signal_jump_finds_a_step_no_policy_fired_on() {
        let mut app = app();
        let mut transcript = transcript();
        transcript.nodes[2].severity = crate::model::Severity::High;
        app.set_transcript(transcript);

        assert!(app.transcript.as_ref().unwrap().fired_steps().is_empty());
        app.jump_to_next_signal();
        assert_eq!(app.selected_tree_row().unwrap().step, 1);
    }

    /// A run with nothing to jump to says so, rather than moving the cursor
    /// somewhere arbitrary and letting the reader conclude that is the signal.
    #[test]
    fn a_signal_jump_with_no_signals_reports_rather_than_moves() {
        let mut app = app();
        app.set_transcript(transcript());
        app.jump_to_next_signal();
        assert_eq!(app.selected_row, 0);
        assert!(app.status.as_ref().unwrap().contains("signal"));
    }

    #[test]
    fn the_filter_narrows_the_feed() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "claude"), run("b", "cursor")]);
        app.set_filter("curs".into());
        assert_eq!(app.visible_runs().len(), 1);
        assert_eq!(app.selected_run().unwrap().agent, "cursor");
    }

    #[test]
    fn a_refresh_keeps_the_selection_on_the_same_run() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "x"), run("b", "y")]);
        app.move_run(1);
        assert_eq!(app.selected_run().unwrap().id, "b");

        // A newer run arrives at the top; the cursor must stay on "b".
        app.set_trajectories(vec![run("c", "z"), run("a", "x"), run("b", "y")]);
        assert_eq!(app.selected_run().unwrap().id, "b");
    }

    #[test]
    fn a_streamed_summary_updates_a_run_without_moving_the_selection() {
        let mut app = app();
        let mut first = run("a", "x");
        first.started_at = Some("2026-08-01T12:00:00Z".into());
        let mut selected = run("b", "y");
        selected.started_at = Some("2026-08-01T11:00:00Z".into());
        app.set_trajectories(vec![first, selected]);
        app.move_run(1);

        let mut update = run("a", "x");
        update.started_at = Some("2026-08-01T12:00:00Z".into());
        update.event_count = 12;
        app.upsert_trajectory(update);

        assert_eq!(app.trajectories.len(), 2);
        assert_eq!(app.trajectories[0].event_count, 12);
        assert_eq!(app.selected_run().unwrap().id, "b");
    }

    #[test]
    fn a_new_streamed_run_is_inserted_in_start_time_order() {
        let mut app = app();
        let mut old = run("old", "x");
        old.started_at = Some("2026-08-01T11:00:00Z".into());
        app.set_trajectories(vec![old]);

        let mut new = run("new", "y");
        new.started_at = Some("2026-08-01T12:00:00Z".into());
        app.upsert_trajectory(new);

        assert_eq!(
            app.trajectories
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            vec!["new", "old"]
        );
        assert_eq!(app.selected_run().unwrap().id, "old");
    }

    #[test]
    fn streamed_history_is_capped_to_the_feed_budget() {
        let mut app = app();
        for index in 0..=TRAJECTORY_PAGE {
            let mut row = run(&index.to_string(), "x");
            row.started_at = Some(format!("2026-08-01T12:{index:03}:00Z"));
            app.upsert_trajectory(row);
        }

        assert_eq!(app.trajectories.len(), TRAJECTORY_PAGE as usize);
        assert_eq!(app.trajectories.first().unwrap().id, "200");
        assert_eq!(app.trajectories.last().unwrap().id, "1");
    }

    #[test]
    fn a_selection_whose_run_vanished_falls_back_to_the_top() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "x"), run("b", "y")]);
        app.move_run(1);
        app.set_trajectories(vec![run("a", "x")]);
        assert_eq!(app.selected_run().unwrap().id, "a");
    }

    // ── agent roster ────────────────────────────────────────────────────────

    fn anthropic() -> AgentIdentity {
        AgentIdentity {
            provider: "anthropic".into(),
            platform: "claude-code".into(),
        }
    }

    /// An agent the roster does not cover must be asked about once, not once per
    /// streamed update: the live feed updates a running agent constantly, and a
    /// console that cannot name it would otherwise re-read the whole roster on
    /// every tick, for ever.
    #[test]
    fn an_agent_the_roster_cannot_name_is_asked_about_once() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "claude-code-dev")]);
        assert!(app.needs_agent_roster());

        // The roster comes back without it — deleted, or a console too old to
        // report identity at all.
        app.set_agents(Vec::new());
        assert!(!app.needs_agent_roster());

        // Every subsequent update on the same agent is also silent.
        app.upsert_trajectory(run("a", "claude-code-dev"));
        assert!(!app.needs_agent_roster());

        // A different agent is a new question, and gets asked.
        app.upsert_trajectory(run("b", "codex-dev"));
        assert!(app.needs_agent_roster());
    }

    /// A full roster read supersedes the per-agent guard, so `r` re-asks for
    /// everyone rather than being suppressed by an earlier miss.
    #[test]
    fn a_manual_refresh_re_asks_for_an_agent_that_was_already_missed() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "claude-code-dev")]);
        app.needs_agent_roster();
        app.set_agents(Vec::new());
        assert!(!app.needs_agent_roster());

        app.reset_agent_requests();
        assert!(app.needs_agent_roster());
    }

    /// The roster is what the feed joins against, and the two halves of an
    /// identity are only ever read together.
    #[test]
    fn the_roster_answers_by_bare_agent_id_and_reports_absence_honestly() {
        let mut app = app();
        app.set_agents(vec![
            ("claude-code-dev".into(), anthropic()),
            // An agent the harness recorded before it had identity fields.
            ("legacy-dev".into(), AgentIdentity::default()),
        ]);

        assert_eq!(
            app.agent_identity("claude-code-dev").unwrap().platform,
            "claude-code"
        );
        // Registered but unidentified reads the same as unknown: nobody said.
        assert!(app.agent_identity("legacy-dev").is_none());
        assert!(app.agent_identity("never-seen").is_none());
    }

    // ── activity strips ─────────────────────────────────────────────────────

    /// A run at a given size, so a refresh can be made to look like the run grew.
    fn sized_run(name: &str, events: i32) -> TrajectoryRow {
        TrajectoryRow {
            event_count: events,
            update_time: Some(format!("2026-08-01T12:00:{events:02}Z")),
            ..run(name, "claude")
        }
    }

    fn one_cell() -> Sparkline {
        Sparkline {
            cells: vec![crate::model::SparkCell::default()],
            truncated: false,
        }
    }

    /// One round trip: ask for whatever is stale, answer all of it.
    fn fetch_sparklines(app: &mut App) {
        let asked = app.request_sparklines();
        app.set_sparklines(asked.into_iter().map(|name| (name, one_cell())).collect());
    }

    /// Building a strip costs the console a full read of the run's events, so a
    /// run that has not moved must not be asked for twice.
    #[test]
    fn a_settled_run_is_asked_for_once_and_then_left_alone() {
        let mut app = app();
        app.set_trajectories(vec![sized_run("a", 5)]);
        assert_eq!(app.request_sparklines(), vec!["trajectories/a".to_string()]);

        app.set_sparklines(vec![("trajectories/a".into(), one_cell())]);
        assert!(app.sparkline("trajectories/a").is_some());
        assert!(app.request_sparklines().is_empty());

        // The same run again, unchanged.
        app.set_trajectories(vec![sized_run("a", 5)]);
        assert!(app.request_sparklines().is_empty());
        assert!(app.sparkline("trajectories/a").is_some());
    }

    /// A run that grew has a different shape than the strip on screen.
    #[test]
    fn a_run_that_moved_is_asked_for_again() {
        let mut app = app();
        app.set_trajectories(vec![sized_run("a", 5)]);
        fetch_sparklines(&mut app);

        app.set_trajectories(vec![sized_run("a", 9)]);
        assert_eq!(app.request_sparklines(), vec!["trajectories/a".to_string()]);
        // The strip it already has stays on screen until the new one lands: a
        // poll must not blank the column it just drew.
        assert!(app.sparkline("trajectories/a").is_some());
    }

    /// A strip built for a run that moved on while the request was in flight is
    /// recorded as already stale, rather than shown forever as if it were
    /// current.
    #[test]
    fn a_strip_that_landed_behind_its_run_is_immediately_stale() {
        let mut app = app();
        app.set_trajectories(vec![sized_run("a", 5)]);
        let asked = app.request_sparklines();

        // A streamed update says the run grew before the strip arrives.
        app.set_trajectories(vec![sized_run("a", 12)]);
        app.set_sparklines(asked.into_iter().map(|name| (name, one_cell())).collect());

        assert!(app.sparkline("trajectories/a").is_some());
        assert_eq!(app.request_sparklines(), vec!["trajectories/a".to_string()]);
    }

    #[test]
    fn a_strip_whose_run_left_the_feed_is_dropped() {
        let mut app = app();
        app.set_trajectories(vec![sized_run("a", 5), sized_run("b", 5)]);
        fetch_sparklines(&mut app);

        app.set_trajectories(vec![sized_run("a", 5)]);
        assert!(app.sparkline("trajectories/a").is_some());
        assert!(app.sparkline("trajectories/b").is_none());
    }

    /// Only what was asked for is installed. The console skips names it cannot
    /// resolve, and a strip nobody asked for belongs to a feed this screen has
    /// already replaced — neither may plant a row the feed does not have.
    #[test]
    fn a_strip_nobody_asked_for_is_ignored() {
        let mut app = app();
        app.set_trajectories(vec![sized_run("a", 5)]);
        app.request_sparklines();
        app.set_sparklines(vec![("trajectories/ghost".into(), one_cell())]);
        assert!(app.sparkline("trajectories/ghost").is_none());
        // The run that *was* asked for and went unanswered is asked again.
        assert_eq!(app.request_sparklines(), vec!["trajectories/a".to_string()]);
    }

    #[test]
    fn navigation_saturates_instead_of_wrapping() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "x"), run("b", "y")]);
        app.move_run(-5);
        assert_eq!(app.selected_run, 0);
        app.move_run(50);
        assert_eq!(app.selected_run, 1);
    }

    #[test]
    fn navigation_on_an_empty_feed_does_not_panic() {
        let mut app = app();
        app.set_trajectories(Vec::new());
        app.move_run(1);
        assert_eq!(app.selected_run, 0);
        assert!(app.selected_run().is_none());
    }

    #[test]
    fn a_loaded_transcript_starts_expanded() {
        let mut app = app();
        app.set_transcript(transcript());
        assert_eq!(app.tree_rows().len(), 3);
        assert!(app.is_expanded(0));
        // The childless prompt step is not marked expanded.
        assert!(!app.is_expanded(1));
    }

    #[test]
    fn collapsing_hides_children() {
        let mut app = app();
        app.set_transcript(transcript());
        app.toggle_expanded();
        assert_eq!(app.tree_rows().len(), 2);
    }

    #[test]
    fn collapsing_from_a_child_row_moves_up_to_its_parent() {
        let mut app = app();
        app.set_transcript(transcript());
        app.move_row(1); // onto the child output row
        assert_eq!(app.selected_tree_row().unwrap().depth, 1);

        app.toggle_expanded();
        let row = app.selected_tree_row().unwrap();
        assert_eq!(row.depth, 0);
        assert_eq!(row.step, 0);
        assert_eq!(app.tree_rows().len(), 2);
    }

    #[test]
    fn collapse_all_clamps_a_selection_that_would_be_out_of_range() {
        let mut app = app();
        app.set_transcript(transcript());
        app.move_row(2); // last visible row
        app.collapse_all();
        assert_eq!(app.tree_rows().len(), 2);
        assert!(app.selected_row < 2);
    }

    #[test]
    fn moving_between_events_resets_the_detail_scroll() {
        let mut app = app();
        app.set_transcript(transcript());
        app.detail_max_scroll = 100;
        app.scroll_detail(40);
        assert_eq!(app.detail_scroll, 40);
        app.move_row(1);
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn detail_scroll_is_clamped_to_what_was_rendered() {
        let mut app = app();
        app.detail_max_scroll = 10;
        app.scroll_detail(999);
        assert_eq!(app.detail_scroll, 10);
        app.scroll_detail(-999);
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn jumping_to_a_fire_wraps_and_reports_when_there_are_none() {
        let mut app = app();
        app.set_transcript(transcript());
        app.jump_to_next_fire();
        assert!(app.status.as_deref().unwrap().contains("No deny"));
    }

    #[test]
    fn jumping_lands_on_the_step_that_fired() {
        let mut transcript = transcript();
        transcript.nodes[2].decision = Some(crate::model::Decision::Deny);
        let mut app = app();
        app.set_transcript(transcript);
        app.jump_to_next_fire();
        assert_eq!(app.selected_tree_row().unwrap().step, 1);
    }

    #[test]
    fn opening_a_transcript_clears_the_previous_run() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "x")]);
        app.set_transcript(transcript());
        app.open_transcript();
        assert_eq!(app.screen, Screen::Transcript);
        assert_eq!(app.transcript_load, Load::Loading);
        assert!(app.transcript.is_none());
    }

    #[test]
    fn opening_a_transcript_with_no_run_selected_is_a_no_op() {
        let mut app = app();
        app.open_transcript();
        assert_eq!(app.screen, Screen::Trajectories);
    }

    #[test]
    fn an_open_transcript_stays_pinned_when_the_feed_changes() {
        let mut app = app();
        app.set_trajectories(vec![run("a", "x"), run("b", "y")]);
        app.move_run(1);
        app.open_transcript();

        app.set_trajectories(vec![run("a", "x")]);

        assert_eq!(app.transcript_name(), Some("trajectories/b"));
    }

    // ── the live tail ───────────────────────────────────────────────────────

    /// A streamed shell command, as the console's event stream delivers it.
    fn streamed_call(event_id: &str, call_id: &str) -> pb::TrajectoryEvent {
        use sondera_schema::harness_v1 as hb;
        pb::TrajectoryEvent {
            event_id: event_id.into(),
            payload: Some(hb::TrajectoryEvent {
                category: Some(hb::trajectory_event::Category::Action(hb::Action {
                    kind: Some(hb::action::Kind::ShellCommand(hb::ShellCommand {
                        call_id: call_id.into(),
                        command: "ls".into(),
                        ..hb::ShellCommand::default()
                    })),
                })),
            }),
            ..pb::TrajectoryEvent::default()
        }
    }

    fn live_app() -> App {
        let mut app = app();
        app.begin_live_transcript(Transcript::default());
        app
    }

    #[test]
    fn a_streamed_run_reports_itself_as_live_until_the_tail_stops() {
        let mut app = live_app();
        assert!(app.is_live());
        assert_eq!(app.transcript_load, Load::Live);

        app.end_live();
        assert!(!app.is_live());
        assert_eq!(app.transcript_load, Load::Ready);
    }

    #[test]
    fn a_streamed_step_arrives_expanded_and_holds_the_cursor_where_it_was() {
        let mut app = live_app();
        app.ingest_live_events(&[streamed_call("e1", "c1")]);
        app.ingest_live_events(&[streamed_call("e2", "c2")]);
        app.move_row(1);
        assert_eq!(app.selected_row, 1);

        app.ingest_live_events(&[streamed_call("e3", "c3")]);

        // Three steps, all expanded as they arrived, and the reader is still on
        // the event they were reading.
        assert_eq!(app.tree_rows().len(), 3);
        assert!(app.is_expanded(2));
        assert_eq!(app.selected_row, 1);
        assert_eq!(app.selected_tree_row().unwrap().node, 1);
    }

    #[test]
    fn a_streamed_event_does_not_throw_away_the_readers_place_in_the_document() {
        let mut app = live_app();
        app.ingest_live_events(&[streamed_call("e1", "c1")]);
        app.detail_max_scroll = 100;
        app.scroll_detail(40);

        app.ingest_live_events(&[streamed_call("e2", "c2")]);
        assert_eq!(app.detail_scroll, 40);
    }

    #[test]
    fn leaving_a_live_run_stops_claiming_it_is_live() {
        let mut app = live_app();
        app.back_to_feed();
        assert!(!app.is_live());
    }

    #[test]
    fn a_paged_transcript_is_never_marked_live() {
        let mut app = live_app();
        app.set_transcript(transcript());
        assert!(!app.is_live());
    }
}
