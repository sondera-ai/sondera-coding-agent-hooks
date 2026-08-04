//! Trajectories screen — the run feed.
//!
//! One table of recent runs: verdict, agent — with the provider and platform
//! behind it where the terminal is wide enough — activity, the scanner's risk
//! and outcome, status, size, duration, and the digest summary. Enter opens the
//! selected run's transcript; `i` opens the run inspector over it.
//!
//! Three claims, deliberately kept apart, because they are three different
//! questions and a reader who conflates them will act on the wrong one:
//!
//! - **verdict** — what the policy engine decided. Allow, deny, escalate.
//! - **status** — where the harness lifecycle got to. Completed, failed, running.
//! - **outcome** and **risk** — what the scanner made of the run afterwards.
//!   A run can complete, be allowed at every step, and still have failed the
//!   task with four `high` signals against it.

use crate::model::{
    AgentIdentity, Severity, SparkCell, SparkKind, Sparkline, TrajectoryRow, clock, duration, fit,
    outcome_tone,
};
use crate::state::{App, Load};
use crate::theme::{Theme, Tone};
use crate::ui;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row, Table};

const HINTS: &[(&str, &str)] = &[
    ("↑↓/jk", "move"),
    ("enter", "open"),
    ("i", "inspect"),
    ("/", "filter"),
    ("r", "refresh"),
    ("t", "theme"),
    ("q", "quit"),
];

/// Hints while the inspector is open, replacing the feed's own: the movement
/// keys mean something different, and a footer that still says `↑↓ move` while
/// they scroll a panel is a footer that lies.
const INSPECT_HINTS: &[(&str, &str)] = &[
    ("↑↓/jk", "scroll"),
    ("n/p", "next run"),
    ("enter", "open"),
    ("i/esc", "close"),
    ("q", "quit"),
];

pub fn render(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();

    // The selection can move under the open panel without a keypress, because
    // the live feed reorders the page and drops runs off its end. Reconciled
    // before the hints are chosen, so the footer never spends a frame promising
    // keys that scroll a panel nobody can see.
    app.follow_inspect();

    let hints = if app.inspecting { INSPECT_HINTS } else { HINTS };
    let [head, body, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(6),
        Constraint::Length(ui::footer_height(app, hints, area.width)),
    ])
    .areas(area);

    header(frame, head, app);

    // Built before the mutable borrow the stateful render needs. The rows own
    // their spans, so nothing here keeps borrowing `app`.
    let columns = Columns::for_width(body.width);
    let rows: Vec<Row<'static>> = app
        .visible_runs()
        .iter()
        .map(|row| {
            build_row(
                &app.theme,
                row,
                columns,
                app.sparkline(&row.name),
                app.agent_identity(&row.agent),
            )
        })
        .collect();

    if rows.is_empty() {
        ui::placeholder(
            frame,
            body,
            &app.theme,
            "runs",
            &app.trajectories_load,
            &empty_message(app),
        );
    } else {
        table(frame, body, app, rows, columns);
    }

    // Drawn last and over the body, so it is genuinely on top of the feed
    // rather than sharing rows with it.
    if app.inspecting {
        super::inspect::render(frame, body, app);
    }

    ui::footer(frame, foot, app, hints);
}

/// Which columns the feed shows at a given width.
///
/// A narrow terminal drops whole columns rather than shrinking all of them into
/// illegibility — Ratatui divides an overflowing budget proportionally, which
/// would leave the verdict chip reading `● AL`. The verdict and the agent are
/// what the feed exists to show, so they are the last to go.
///
/// The activity strip is the other way round: it is the first thing to arrive
/// as the terminal widens, and it needs a real span of columns to say anything,
/// so it appears only from [`Columns::Wide`] up. Below that the feed reports the
/// event *count* instead, which is the same magnitude without the shape.
///
/// The scanner's two columns arrive on the same schedule. **Risk** appears from
/// [`Columns::Wide`], where it takes the slot `UPDATED` used to hold: at that
/// width the feed has to choose, and *how loud was this run* outranks *when was
/// it last touched* — `STATUS` already distinguishes a running run from a
/// finished one. **Outcome** waits for [`Columns::Full`], because it is the
/// wordiest column in the table (`interrupted`, `in progress`) and abbreviating
/// a grade is how a grade stops being one.
///
/// Below `Wide` the scanner is not silent, it is compressed: the summary cell
/// carries a severity glyph and a signal count, and `i` opens the inspector,
/// which shows the whole digest and scan at every width including sixty
/// columns.
///
/// **Provider** and **platform** — who makes the model and what the agent runs
/// as — arrive last, at [`Columns::Ultra`]. They qualify the agent rather than
/// describing the run, so they are worth two columns only once nothing about the
/// run itself is being given up for them; between them they need twenty-five
/// columns, which is why the band that carries them starts where it does. The
/// inspector shows them at every width, the same bargain the scanner's own
/// columns strike.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Columns {
    Narrow,
    Medium,
    Wide,
    Full,
    /// The ultrawide band: [`Columns::Full`] plus the agent's identity.
    Ultra,
}

impl Columns {
    fn for_width(width: u16) -> Self {
        match width {
            0..=74 => Self::Narrow,
            75..=101 => Self::Medium,
            102..=139 => Self::Wide,
            140..=163 => Self::Full,
            _ => Self::Ultra,
        }
    }

    fn headers(self) -> &'static [&'static str] {
        match self {
            Self::Narrow => &["VERDICT", "AGENT", "SUMMARY"],
            Self::Medium => &["VERDICT", "AGENT", "STATUS", "EVENTS", "DUR", "SUMMARY"],
            Self::Wide => &[
                "VERDICT", "AGENT", "ACTIVITY", "RISK", "STATUS", "DUR", "SUMMARY",
            ],
            Self::Full => &[
                "VERDICT", "AGENT", "ACTIVITY", "RISK", "OUTCOME", "STATUS", "EVENTS", "DUR",
                "UPDATED", "SUMMARY",
            ],
            Self::Ultra => &[
                "VERDICT", "AGENT", "PROVIDER", "PLATFORM", "ACTIVITY", "RISK", "OUTCOME",
                "STATUS", "EVENTS", "DUR", "UPDATED", "SUMMARY",
            ],
        }
    }

    fn constraints(self) -> Vec<Constraint> {
        match self {
            Self::Narrow => vec![
                Constraint::Length(11),
                Constraint::Length(14),
                Constraint::Min(12),
            ],
            Self::Medium => vec![
                Constraint::Length(11),
                Constraint::Length(16),
                Constraint::Length(10),
                Constraint::Length(6),
                Constraint::Length(7),
                Constraint::Min(14),
            ],
            Self::Wide => vec![
                Constraint::Length(11),
                Constraint::Length(18),
                Constraint::Length(SPARK_WIDE as u16),
                Constraint::Length(RISK_WIDTH),
                Constraint::Length(10),
                Constraint::Length(7),
                Constraint::Min(18),
            ],
            Self::Full => vec![
                Constraint::Length(11),
                Constraint::Length(18),
                Constraint::Length(SPARK_FULL as u16),
                Constraint::Length(RISK_WIDTH),
                Constraint::Length(OUTCOME_WIDTH),
                Constraint::Length(10),
                Constraint::Length(7),
                Constraint::Length(7),
                Constraint::Length(9),
                Constraint::Min(20),
            ],
            Self::Ultra => vec![
                Constraint::Length(11),
                Constraint::Length(18),
                Constraint::Length(PROVIDER_WIDTH),
                Constraint::Length(PLATFORM_WIDTH),
                Constraint::Length(SPARK_FULL as u16),
                Constraint::Length(RISK_WIDTH),
                Constraint::Length(OUTCOME_WIDTH),
                Constraint::Length(10),
                Constraint::Length(7),
                Constraint::Length(7),
                Constraint::Length(9),
                Constraint::Min(20),
            ],
        }
    }

    /// Width budget for the agent cell, matching its constraint above.
    fn agent_width(self) -> usize {
        match self {
            Self::Narrow => 14,
            Self::Medium => 16,
            Self::Wide | Self::Full | Self::Ultra => 18,
        }
    }

    /// How many cells the activity strip gets, or `None` where the feed is too
    /// narrow to carry one.
    ///
    /// This has to be exact rather than a lower bound: the strip is condensed to
    /// fit, and a strip laid out wider than its column would be *clipped* at the
    /// right edge — silently hiding the end of the run, and with it any deny
    /// that landed there.
    fn spark_width(self) -> Option<usize> {
        match self {
            Self::Narrow | Self::Medium => None,
            Self::Wide => Some(SPARK_WIDE),
            Self::Full | Self::Ultra => Some(SPARK_FULL),
        }
    }

    /// Whether this set has a column for the scanner's aggregate severity.
    fn has_risk(self) -> bool {
        matches!(self, Self::Wide | Self::Full | Self::Ultra)
    }

    /// Whether this set has a column for the scanner's outcome grade.
    fn has_outcome(self) -> bool {
        matches!(self, Self::Full | Self::Ultra)
    }

    /// Whether this set has columns for the agent's provider and platform.
    fn has_identity(self) -> bool {
        matches!(self, Self::Ultra)
    }
}

/// Cells in the activity strip, per column set.
///
/// Both shrank when the risk and outcome columns arrived. The strip is already
/// a condensation — it buckets a four-hundred-event run into whatever it is
/// given — and a fire survives bucketing by construction, so the cost of the
/// trade is resolution in the ordinary work between fires, not a lost deny.
const SPARK_WIDE: usize = 14;
const SPARK_FULL: usize = 20;

/// Width of the risk chip column: the longest severity (`critical`) plus the
/// chip's own glyph, spaces, and padding.
const RISK_WIDTH: u16 = 12;

/// Width of the outcome column, sized to the longest grade (`interrupted`).
const OUTCOME_WIDTH: u16 = 11;

/// Widths of the two identity columns, sized to the longest value the hooks in
/// this workspace register: `antigravity` and `opencode-bun`.
///
/// A third-party hook may register something longer, so the cells still fit to
/// their budget — but an identity truncated to `anthro…` is a value a reader
/// cannot match against a policy, so the common vocabulary gets to be whole.
const PROVIDER_WIDTH: u16 = 11;
const PLATFORM_WIDTH: u16 = 12;

fn header(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let theme = &app.theme;
    // The filter is always shown, active or not: a narrowed feed that looks
    // like the whole feed is how an operator concludes a run is missing.
    let filter = Line::from(vec![
        Span::styled("filter ", theme.subtle()),
        Span::styled(
            if app.filter.is_empty() {
                "all runs".to_string()
            } else {
                format!("{}▏", app.filter)
            },
            if app.filter_editing {
                theme.eyebrow_style()
            } else if app.filter.is_empty() {
                theme.subtle()
            } else {
                theme.body()
            },
        ),
        Span::styled(
            format!(
                "   {} of {}",
                app.visible_runs().len(),
                app.trajectories.len()
            ),
            theme.subtle(),
        ),
    ]);
    ui::header(
        frame,
        area,
        app,
        &["trajectories"],
        vec![filter],
        &app.trajectories_load,
    );
}

fn empty_message(app: &App) -> String {
    if !app.filter.is_empty() && app.trajectories_load == Load::Ready {
        format!("No run matches '{}'.", app.filter)
    } else {
        "No trajectories recorded yet. Run a coding agent with Sondera hooks installed.".into()
    }
}

fn table(
    frame: &mut Frame<'_>,
    area: ratatui::layout::Rect,
    app: &mut App,
    rows: Vec<Row<'static>>,
    columns: Columns,
) {
    let theme = app.theme;
    let count = rows.len();

    let table = Table::new(rows, columns.constraints())
        .header(Row::new(columns.headers().to_vec()).style(theme.subtle()))
        .row_highlight_style(theme.selected())
        .block(theme.panel_focused(&format!("runs · {count}")));

    app.runs_state.select(Some(app.selected_run));
    frame.render_stateful_widget(table, area, &mut app.runs_state);
}

fn build_row<'a>(
    theme: &Theme,
    row: &TrajectoryRow,
    columns: Columns,
    spark: Option<&Sparkline>,
    identity: Option<&AgentIdentity>,
) -> Row<'a> {
    Row::new(row_cells(theme, row, columns, spark, identity))
}

/// The cells for one feed row, in the same order as [`Columns::headers`].
fn row_cells<'a>(
    theme: &Theme,
    row: &TrajectoryRow,
    columns: Columns,
    spark: Option<&Sparkline>,
    identity: Option<&AgentIdentity>,
) -> Vec<Cell<'a>> {
    // An unadjudicated run gets a neutral chip rather than being left blank:
    // "nothing was evaluated" is a different claim from "it was allowed", and
    // an empty cell reads as neither.
    let verdict = match row.decision {
        Some(decision) => theme.chip(decision.tone(), decision.label()),
        None => theme.chip(Tone::Neutral, "none"),
    };

    let status = Cell::from(Span::styled(
        row.status.clone(),
        status_style(theme, &row.status),
    ));
    let events = Cell::from(Line::from(Span::styled(
        row.event_count.to_string(),
        theme.metric(),
    )));
    let dur = Cell::from(Span::styled(duration(row.duration_ms), theme.subtle()));
    let updated = Cell::from(Span::styled(
        clock(row.update_time.as_deref()),
        theme.subtle(),
    ));

    // Cells are emitted in the same order as `Columns::headers`; a mismatch
    // would silently label the wrong data, so a test pins the two together.
    let mut cells = vec![
        Cell::from(Line::from(verdict)),
        Cell::from(Span::styled(
            fit(&row.agent, columns.agent_width()),
            theme.body(),
        )),
    ];
    // Identity sits with the agent it qualifies, not off at the end of the row:
    // who ran this is one claim across three columns.
    if columns.has_identity() {
        cells.push(Cell::from(provider(theme, identity)));
        cells.push(Cell::from(platform(theme, identity)));
    }
    if let Some(width) = columns.spark_width() {
        cells.push(Cell::from(activity(theme, spark, width)));
    }
    if columns.has_risk() {
        cells.push(Cell::from(Line::from(risk(theme, row))));
    }
    if columns.has_outcome() {
        cells.push(Cell::from(outcome(theme, row)));
    }
    match columns {
        Columns::Narrow => {}
        Columns::Medium => cells.extend([status, events, dur]),
        Columns::Wide => cells.extend([status, dur]),
        Columns::Full | Columns::Ultra => cells.extend([status, events, dur, updated]),
    }
    cells.push(Cell::from(summary(theme, row, columns)));
    cells
}

/// Who makes the model this run's agent drives.
fn provider(theme: &Theme, identity: Option<&AgentIdentity>) -> Span<'static> {
    field(
        theme,
        identity.map(|identity| identity.provider.as_str()),
        PROVIDER_WIDTH as usize,
    )
}

/// What this run's agent runs as.
fn platform(theme: &Theme, identity: Option<&AgentIdentity>) -> Span<'static> {
    field(
        theme,
        identity.map(|identity| identity.platform.as_str()),
        PLATFORM_WIDTH as usize,
    )
}

/// One half of the agent's identity, fitted to its column.
///
/// Muted rather than body: the agent id is the claim, and the provider and
/// platform are what qualify it. Absent and empty both read `—` — a console that
/// has not heard from the agent roster, and a run whose agent registered before
/// the harness recorded identity, are equally "nobody has said", and a blank
/// cell would read instead as "this agent has no provider".
fn field(theme: &Theme, value: Option<&str>, width: usize) -> Span<'static> {
    match value.filter(|text| !text.is_empty()) {
        Some(text) => Span::styled(fit(text, width), theme.muted()),
        None => Span::styled("—", theme.subtle()),
    }
}

/// The scanner's aggregate severity for a run.
///
/// A run the scanner has not graded reads `—`, never `info`: "nothing has
/// looked at this" and "something looked and found nothing" are different
/// claims, and a feed that renders them identically is telling one of them
/// falsely on every unscanned row.
fn risk(theme: &Theme, row: &TrajectoryRow) -> Span<'static> {
    match row.risk() {
        Some(severity) => theme.chip(severity.tone(), severity.label()),
        None => Span::styled("—", theme.subtle()),
    }
}

/// How the scanner graded the run, colored by what the grade claims.
fn outcome<'a>(theme: &Theme, row: &TrajectoryRow) -> Line<'a> {
    match row.outcome() {
        Some(outcome) => Line::from(Span::styled(
            outcome.to_string(),
            Style::new().fg(theme.tone(outcome_tone(outcome))),
        )),
        None => Line::from(Span::styled("—", theme.subtle())),
    }
}

/// The digest's one-line read of the run, with the two qualifiers a reader
/// needs before trusting it.
///
/// `~` marks a summary taken from an *interim* digest — a mid-run guess, which
/// must not read as the outcome. Below the width where the `RISK` column
/// exists, the loudest signal and how many there were ride here as a glyph and
/// a count, because that is the whole triage signal and a sixty-column terminal
/// would otherwise never see it.
fn summary<'a>(theme: &Theme, row: &TrajectoryRow, columns: Columns) -> Line<'a> {
    let mut spans = Vec::new();

    if row.is_interim() {
        spans.push(Span::styled("~ ", theme.subtle()));
    }

    if !columns.has_risk()
        && let Some(severity) = row.risk().filter(|s| *s >= Severity::Medium)
    {
        let count = row.signal_count();
        spans.push(Span::styled(
            if count > 0 {
                format!("{}{count} ", severity.tone().glyph())
            } else {
                format!("{} ", severity.tone().glyph())
            },
            Style::new()
                .fg(theme.tone(severity.tone()))
                .add_modifier(Modifier::BOLD),
        ));
    }

    if row.summary.is_empty() {
        spans.push(Span::styled("—", theme.subtle()));
    } else {
        // An interim summary is dimmer as well as marked: the glyph is the
        // claim, the dimness is the second channel that survives `NO_COLOR`
        // and a reader who has not learned the glyph yet.
        let style = if row.is_interim() {
            theme.subtle()
        } else {
            theme.muted()
        };
        spans.push(Span::styled(row.summary.clone(), style));
    }

    Line::from(spans)
}

/// The activity strip for one run, condensed to `width` cells.
fn activity<'a>(theme: &Theme, spark: Option<&Sparkline>, width: usize) -> Line<'a> {
    // A strip that has not arrived — or that this console cannot build — is
    // marked absent rather than left blank. An empty column reads as "this run
    // did nothing", which is a different claim from "nothing is known yet".
    let Some(spark) = spark.filter(|spark| !spark.cells.is_empty()) else {
        return Line::from(Span::styled("—", theme.subtle()));
    };
    Line::from(
        spark
            .strip(width)
            .iter()
            .map(|cell| spark_span(theme, cell))
            .collect::<Vec<_>>(),
    )
}

/// One cell of the strip.
///
/// A policy fire trades its kind glyph for the tone's own. At feed altitude the
/// claim the strip is making is *that* a policy fired and where in the run it
/// landed — and the tone glyph is what carries that where color cannot, since
/// on a monochrome terminal a coral cell is just another grey one. What fired is
/// one keypress away, in the transcript.
fn spark_span(theme: &Theme, cell: &SparkCell) -> Span<'static> {
    match cell.tone() {
        Tone::Neutral => Span::styled(cell.kind.glyph(), work_style(theme, cell.kind)),
        tone => Span::styled(
            tone.glyph(),
            theme.tone_row(tone).add_modifier(Modifier::BOLD),
        ),
    }
}

/// How loudly an ordinary cell is drawn.
///
/// Brightness, not hue: the five tones state what a verdict claims, and giving
/// event kinds a second color vocabulary would turn the densest column in the
/// feed into decoration. Shape carries the kind; brightness carries whether the
/// agent was acting on the world or thinking about it.
fn work_style(theme: &Theme, kind: SparkKind) -> Style {
    match kind {
        SparkKind::Shell | SparkKind::File | SparkKind::Web | SparkKind::Tool => theme.body(),
        SparkKind::PromptUser | SparkKind::PromptModel => theme.muted(),
        SparkKind::Thought | SparkKind::Control | SparkKind::State | SparkKind::Unspecified => {
            theme.subtle()
        }
    }
}

/// Lifecycle status color. Only the states that carry a warning claim get a
/// tone; the ordinary ones stay muted so the verdict column keeps the emphasis.
fn status_style(theme: &Theme, status: &str) -> ratatui::style::Style {
    match status {
        "failed" | "terminated" => ratatui::style::Style::new().fg(theme.tone(Tone::Deny)),
        "suspended" => ratatui::style::Style::new().fg(theme.tone(Tone::Warn)),
        "running" => ratatui::style::Style::new().fg(theme.tone(Tone::Allow)),
        _ => theme.muted(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Decision;
    use crate::theme::Depth;

    const SETS: [Columns; 5] = [
        Columns::Narrow,
        Columns::Medium,
        Columns::Wide,
        Columns::Full,
        Columns::Ultra,
    ];

    fn theme() -> Theme {
        Theme::dark(Depth::TrueColor)
    }

    fn identity() -> AgentIdentity {
        AgentIdentity {
            provider: "anthropic".into(),
            platform: "claude-code".into(),
        }
    }

    /// Headers, constraints, and emitted cells are three parallel lists. If they
    /// ever disagree, every column after the divergence is labelled with the
    /// wrong header — a silent, very believable wrong answer.
    #[test]
    fn every_column_set_agrees_on_its_width() {
        for columns in SETS {
            let headers = columns.headers().len();
            assert_eq!(
                headers,
                columns.constraints().len(),
                "{columns:?}: header/constraint count differs",
            );
            for spark in [None, Some(&strip(40))] {
                for identity in [None, Some(&identity())] {
                    let cells = row_cells(
                        &theme(),
                        &TrajectoryRow::default(),
                        columns,
                        spark,
                        identity,
                    );
                    assert_eq!(
                        cells.len(),
                        headers,
                        "{columns:?}: cell/header count differs"
                    );
                }
            }
        }
    }

    #[test]
    fn every_column_set_keeps_the_verdict_and_the_agent() {
        for columns in SETS {
            assert_eq!(columns.headers()[0], "VERDICT");
            assert_eq!(columns.headers()[1], "AGENT");
            assert_eq!(*columns.headers().last().unwrap(), "SUMMARY");
        }
    }

    /// The strip is announced by a header, so the column it labels has to be the
    /// one the strip is actually emitted into.
    #[test]
    fn the_activity_column_is_headed_where_it_is_drawn() {
        for columns in SETS {
            let headed = columns
                .headers()
                .iter()
                .position(|head| *head == "ACTIVITY");
            assert_eq!(
                headed.is_some(),
                columns.spark_width().is_some(),
                "{columns:?}: header and strip disagree about the activity column",
            );
            if let Some(index) = headed {
                // Verdict, who did it, then what they did — where "who" is the
                // agent plus, on the widest band, the identity behind it.
                let who = if columns.has_identity() { 3 } else { 1 };
                assert_eq!(
                    index,
                    1 + who,
                    "{columns:?}: activity does not follow the identity columns",
                );
            }
        }
    }

    /// The fixed columns plus a readable summary must fit the width that
    /// selects them, or Ratatui shrinks every column proportionally and the
    /// verdict chip degrades to `● AL`. Each band is checked at its *narrowest*
    /// width, which is the only one that can overflow.
    #[test]
    fn each_column_set_fits_the_width_it_is_chosen_for() {
        for (width, expected) in [
            (60, Columns::Narrow),
            (75, Columns::Medium),
            (80, Columns::Medium),
            (102, Columns::Wide),
            (120, Columns::Wide),
            (140, Columns::Full),
            (163, Columns::Full),
            (164, Columns::Ultra),
            (200, Columns::Ultra),
        ] {
            let columns = Columns::for_width(width);
            assert_eq!(columns, expected, "width {width} chose the wrong set");
            let demanded: u16 = columns
                .constraints()
                .iter()
                .map(|constraint| match constraint {
                    Constraint::Length(n) | Constraint::Min(n) => *n,
                    _ => 0,
                })
                .sum();
            // Borders, padding, and the inter-column gaps Ratatui inserts.
            let overhead = 4 + columns.headers().len() as u16;
            assert!(
                demanded + overhead <= width,
                "{} columns need {demanded}+{overhead} at width {width}",
                columns.headers().len(),
            );
        }
    }

    /// A row the scanner graded.
    fn scanned(severity: Severity, outcome: &str, signals: usize) -> TrajectoryRow {
        TrajectoryRow {
            summary: "did a thing".into(),
            scan: Some(crate::model::ScanView {
                outcome: outcome.into(),
                aggregate_severity: severity,
                signals: vec![crate::model::SignalView::default(); signals],
                ..crate::model::ScanView::default()
            }),
            ..TrajectoryRow::default()
        }
    }

    fn text_of(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    /// Same contract the activity column has: a header may only label a column
    /// that is actually emitted, or every column after it is mislabelled.
    #[test]
    fn the_scanner_columns_are_headed_where_they_are_drawn() {
        for columns in SETS {
            for (head, drawn) in [
                ("RISK", columns.has_risk()),
                ("OUTCOME", columns.has_outcome()),
            ] {
                assert_eq!(
                    columns.headers().contains(&head),
                    drawn,
                    "{columns:?}: header and cell disagree about {head}",
                );
            }
        }
    }

    /// Same contract again for the identity pair: a header that labels a column
    /// nobody emits mislabels every column after it.
    #[test]
    fn the_identity_columns_are_headed_where_they_are_drawn() {
        for columns in SETS {
            for head in ["PROVIDER", "PLATFORM"] {
                assert_eq!(
                    columns.headers().contains(&head),
                    columns.has_identity(),
                    "{columns:?}: header and cell disagree about {head}",
                );
            }
        }
    }

    /// Both identity columns hold the whole vocabulary the hooks in this
    /// workspace register. A truncated `anthro…` is a value a reader cannot
    /// match against a policy or a filter.
    #[test]
    fn the_identity_columns_fit_the_vocabulary_the_hooks_register() {
        for provider in [
            "anthropic",
            "openai",
            "github",
            "microsoft",
            "google",
            "cursor",
            "gemini",
            "hermes",
            "opencode",
            "openhands",
            "antigravity",
        ] {
            assert_eq!(fit(provider, PROVIDER_WIDTH as usize), provider);
        }
        for platform in [
            "claude-code",
            "codex",
            "copilot-cli",
            "vscode",
            "cursor",
            "gemini",
            "hermes-agent",
            "opencode-bun",
            "openhands",
            "antigravity",
        ] {
            assert_eq!(fit(platform, PLATFORM_WIDTH as usize), platform);
        }
    }

    /// The one thing these columns may never do: report an agent nobody has
    /// identified as an agent with no provider. `—` is the honest reading —
    /// nothing has told this console who ran the run — and a blank cell is not.
    #[test]
    fn an_unidentified_agent_reads_as_absent_rather_than_blank() {
        // Nothing has told this console who ran the run…
        assert_eq!(provider(&theme(), None).content.as_ref(), "—");
        assert_eq!(platform(&theme(), None).content.as_ref(), "—");

        // …and an agent registered before the harness recorded identity carries
        // the fields as empty strings, which is the same claim.
        let blank = AgentIdentity::default();
        assert_eq!(provider(&theme(), Some(&blank)).content.as_ref(), "—");
        assert_eq!(platform(&theme(), Some(&blank)).content.as_ref(), "—");

        let known = identity();
        assert_eq!(
            provider(&theme(), Some(&known)).content.as_ref(),
            "anthropic"
        );
        assert_eq!(
            platform(&theme(), Some(&known)).content.as_ref(),
            "claude-code"
        );
    }

    /// Both scanner columns are sized to their widest possible value, exactly.
    /// A sixth severity or a longer outcome grade would be truncated by the
    /// table with no warning — `CRITICA`, `interrupte` — so the widths are
    /// pinned against the value sets themselves rather than against a guess
    /// made when they were written.
    #[test]
    fn the_scanner_columns_fit_every_value_they_can_hold() {
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let drawn = theme().chip(severity.tone(), severity.label());
            assert!(
                drawn.content.chars().count() <= RISK_WIDTH as usize,
                "{severity:?} needs {} of {RISK_WIDTH} columns",
                drawn.content.chars().count(),
            );
        }

        // The outcome vocabulary as the model projects it, straight off the
        // wire enum, so a grade added to the proto shows up here.
        for grade in [
            sondera_schema::harness_v1::TranscriptOutcome::Success,
            sondera_schema::harness_v1::TranscriptOutcome::Partial,
            sondera_schema::harness_v1::TranscriptOutcome::Failure,
            sondera_schema::harness_v1::TranscriptOutcome::Interrupted,
            sondera_schema::harness_v1::TranscriptOutcome::InProgress,
        ] {
            let row = TrajectoryRow {
                scan: Some(crate::model::ScanView {
                    outcome: crate::model::outcome_label(grade as i32),
                    ..crate::model::ScanView::default()
                }),
                ..TrajectoryRow::default()
            };
            let drawn = text_of(&outcome(&theme(), &row));
            assert!(
                drawn.chars().count() <= OUTCOME_WIDTH as usize,
                "{grade:?} draws {drawn:?}, {} of {OUTCOME_WIDTH} columns",
                drawn.chars().count(),
            );
            assert_ne!(drawn, "—", "{grade:?} did not project to a label");
        }
    }

    /// The one thing the risk column may never do: report a run nobody graded
    /// as a run that graded clean.
    #[test]
    fn an_ungraded_run_reads_as_absent_not_as_info() {
        let ungraded = risk(&theme(), &TrajectoryRow::default());
        assert_eq!(ungraded.content.as_ref(), "—");

        let graded = risk(&theme(), &scanned(Severity::Info, "success", 0));
        assert!(graded.content.contains("INFO"));
    }

    /// Below the width that carries a `RISK` column the severity still has to
    /// reach the reader, so it rides in the summary cell instead. Above it, it
    /// must *not*, or the same claim is made twice on one row.
    #[test]
    fn the_severity_marker_appears_exactly_where_the_risk_column_does_not() {
        let row = scanned(Severity::High, "failure", 3);
        for columns in SETS {
            let drawn = text_of(&summary(&theme(), &row, columns));
            let marked = drawn.contains(Tone::Deny.glyph());
            assert_eq!(
                marked,
                !columns.has_risk(),
                "{columns:?}: severity marker in the summary cell: {drawn:?}",
            );
            if marked {
                assert!(drawn.contains('3'), "{columns:?}: signal count is missing");
            }
        }
    }

    /// A quiet run does not earn a marker: the glyph means "look at this", and
    /// a glyph on every row means nothing.
    #[test]
    fn a_low_severity_run_gets_no_marker_in_a_narrow_feed() {
        let drawn = text_of(&summary(
            &theme(),
            &scanned(Severity::Low, "success", 1),
            Columns::Narrow,
        ));
        assert!(!drawn.contains(Tone::Deny.glyph()));
        assert!(!drawn.contains(Tone::Warn.glyph()));
    }

    /// A mid-run digest is a guess. It has to look like one at every width, or
    /// it gets quoted as the outcome.
    #[test]
    fn an_interim_summary_is_marked_at_every_width() {
        let row = TrajectoryRow {
            summary: "wiring the spans".into(),
            digest: Some(crate::model::DigestView {
                interim: true,
                ..crate::model::DigestView::default()
            }),
            ..TrajectoryRow::default()
        };
        for columns in SETS {
            assert!(
                text_of(&summary(&theme(), &row, columns)).starts_with("~ "),
                "{columns:?}: an interim summary reads as a final one",
            );
        }
    }

    /// A strip of `len` ordinary shell cells.
    fn strip(len: usize) -> Sparkline {
        Sparkline {
            cells: (0..len)
                .map(|_| SparkCell {
                    kind: SparkKind::Shell,
                    ..SparkCell::default()
                })
                .collect(),
            truncated: false,
        }
    }

    /// The strip is condensed to fit rather than clipped, because a table cell
    /// wider than its column is truncated at the right edge — which would drop
    /// the end of every long run.
    #[test]
    fn a_strip_never_overruns_the_column_it_is_drawn_in() {
        for columns in SETS {
            let Some(width) = columns.spark_width() else {
                continue;
            };
            for len in [0, 1, 5, width, width + 1, 400] {
                let cell = activity(&theme(), Some(&strip(len)), width);
                let drawn = cell.width();
                assert!(
                    drawn <= width,
                    "{columns:?}: a {len}-cell strip drew {drawn} of {width} columns",
                );
            }
        }
    }

    /// Absent and empty are different claims, and the column has to make them
    /// look different.
    #[test]
    fn a_run_with_no_strip_yet_is_marked_absent_rather_than_left_blank() {
        for spark in [None, Some(&Sparkline::default())] {
            assert_eq!(activity(&theme(), spark, SPARK_WIDE).to_string(), "—");
        }
    }

    /// A fire is told from ordinary work by *shape*, not only by color. On a
    /// monochrome terminal, or under `NO_COLOR`, a coral cell is just another
    /// grey one — so no work glyph may collide with a tone glyph.
    #[test]
    fn a_fire_is_distinguishable_from_every_kind_of_work_without_color() {
        for kind in SparkKind::ALL {
            for tone in [Tone::Deny, Tone::Warn] {
                assert_ne!(
                    kind.glyph(),
                    tone.glyph(),
                    "{kind:?} is indistinguishable from a {tone:?} fire",
                );
            }
        }
    }

    /// The one thing this column may never do: render a deny as ordinary work.
    #[test]
    fn a_fire_reads_as_its_tone_even_condensed_into_a_wide_run() {
        let mut spark = strip(400);
        spark.cells[200].decision = Some(Decision::Deny);

        let drawn = activity(&theme(), Some(&spark), SPARK_WIDE).to_string();
        assert!(
            drawn.contains(Tone::Deny.glyph()),
            "the deny did not survive into the strip: {drawn:?}",
        );
    }
}
