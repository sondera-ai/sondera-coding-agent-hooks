//! Trajectory Events screen — the transcript reading view.
//!
//! Two panels, one third / two thirds. The left is a tree of the run: one row
//! per step, with the observation answering an action nested beneath it, and a
//! summary line under each step's headline. The right is the full event —
//! prompts as markdown, shell as shell, file writes in their own language,
//! payloads as JSON — plus the verdict and the scanner's read of it.
//!
//! Detail lives on the right and only summary lives on the left, so a long
//! transcript stays scannable while the selected event stays legible in full.

use crate::model::{EventNode, Severity, Transcript, TreeRow, clock, fit, outcome_tone, short};
use crate::render::render_blocks;
use crate::state::{App, Pane};
use crate::theme::{Theme, Tone};
use crate::ui;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{List, ListItem, Paragraph};

const HINTS: &[(&str, &str)] = &[
    ("↑↓/jk", "step"),
    ("tab", "pane"),
    ("←→/hl", "fold"),
    ("n", "next fire"),
    ("s", "next signal"),
    ("r", "refresh"),
    ("esc", "back"),
    ("q", "quit"),
];

/// What `tab` cycles through when the run carries scanner output, naming the
/// third pane so a reader knows it is there.
const INSIGHT_TAB: &str = "tree · run · event";

pub fn render(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    // Measured against the hints actually drawn: the insight set is wider, so
    // reserving space for the short one would let the footer wrap past its own
    // panel and eat a row of the body.
    let hints = hints(app);
    let [head, body, foot] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(6),
        Constraint::Length(ui::footer_height(app, &hints, area.width)),
    ])
    .areas(area);

    header(frame, head, app);

    // One third / two thirds, exactly as the reading view is specified: the
    // tree is an index, the detail pane is the document.
    let [left, right] =
        Layout::horizontal([Constraint::Ratio(1, 3), Constraint::Ratio(2, 3)]).areas(body);

    tree(frame, left, app);

    // The scanner's read of the run sits above the selected event, on the
    // document side, because it is the same kind of reading at a wider
    // altitude: what the run was, then what this step in it was. It appears
    // only when the scanner has produced something — a run with no digest and
    // no scan gives every row back to the transcript.
    match insight_height(right).filter(|_| app.has_insight()) {
        Some(height) => {
            let [top, bottom] = Layout::vertical([
                Constraint::Length(height),
                Constraint::Min(MIN_DETAIL_HEIGHT),
            ])
            .areas(right);
            insight(frame, top, app);
            detail(frame, bottom, app);
        }
        None => {
            // The panel is not on screen, so nothing may behave as though it
            // is: focus falls back to the event, and the scroll bound goes to
            // zero so a held key cannot page a document nobody can see. This is
            // the one thing the layout knows and the state cannot — whether the
            // terminal is tall enough — so it is corrected here.
            if app.pane == Pane::Insight {
                app.pane = Pane::Detail;
            }
            app.insight_max_scroll = 0;
            detail(frame, right, app);
        }
    }

    ui::footer(frame, foot, app, &hints);
}

/// Hints for the transcript screen, naming the insight pane only when there is
/// one to tab into.
///
/// Derived from [`HINTS`] rather than kept as a second array: the two differ in
/// exactly one label, and holding them as separate constants is how a hint
/// added to one goes missing from the other.
fn hints(app: &App) -> Vec<(&'static str, &'static str)> {
    let tab = if app.has_insight() {
        INSIGHT_TAB
    } else {
        "pane"
    };
    HINTS
        .iter()
        .map(|&(key, label)| {
            if key == "tab" {
                (key, tab)
            } else {
                (key, label)
            }
        })
        .collect()
}

/// Rows the insight panel needs before it is worth drawing at all: two borders
/// plus enough content to make a claim.
const MIN_INSIGHT_HEIGHT: u16 = 6;

/// Rows the event detail keeps no matter what. The transcript is what this
/// screen is for; the run summary is context around it, never instead of it.
const MIN_DETAIL_HEIGHT: u16 = 6;

/// How many rows the run-insight panel gets, or `None` when the body is too
/// short to give it any.
///
/// A third of the body, bounded at both ends: enough to be worth reading, never
/// so much that the event it contextualizes is pushed off screen. The panel
/// scrolls, so this bounds what is *visible*, not what is reachable.
///
/// Returning `None` rather than shrinking to fit is the point. A panel clamped
/// down to its two border rows draws a titled box with no content in it — it
/// spends rows the transcript needs to say nothing, and its scroll marker
/// claims there is more below while showing none of it.
fn insight_height(body: Rect) -> Option<u16> {
    let height = (body.height / 3).clamp(MIN_INSIGHT_HEIGHT, 14);
    (body.height >= height + MIN_DETAIL_HEIGHT).then_some(height)
}

fn header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let theme = &app.theme;
    let (agent, run) = match app.transcript.as_ref() {
        Some(transcript) => (
            transcript.summary.agent.clone(),
            transcript.summary.id.clone(),
        ),
        None => (
            app.opened_run()
                .map(|row| row.agent.clone())
                .unwrap_or_else(|| "agent".into()),
            app.opened_run()
                .map(|row| row.id.clone())
                .unwrap_or_else(|| "run".into()),
        ),
    };

    let mut lines = Vec::new();
    if let Some(transcript) = app.transcript.as_ref() {
        lines.push(summary_line(
            theme,
            transcript,
            ui::header_width(area.width),
        ));
    }

    ui::header(
        frame,
        area,
        app,
        &["trajectories", &agent, &run],
        lines,
        &app.transcript_load,
    );
}

/// The run's headline, fitted to `width`.
///
/// A header line is drawn without wrapping, so anything past the right edge is
/// not shortened — it is gone, silently. Rather than let the terminal decide
/// which fact to lose, the segments are added in priority order and the first
/// one that does not fit ends the line.
///
/// The order is the order the claims matter in. The verdict is what the policy
/// engine did and is never dropped. The scanner's severity and outcome come
/// next: they are the reason to read this transcript differently, and they are
/// the two facts no other row of this screen carries. Lifecycle, size, and
/// duration follow, and the digest title is last — it is also the first line of
/// the insight panel two rows below, so it is the one fact that losing costs
/// nothing.
fn summary_line(theme: &Theme, transcript: &Transcript, width: u16) -> Line<'static> {
    let summary = &transcript.summary;

    // The verdict is never dropped, so it is outside the budget: at a width
    // that cannot hold it, a clipped chip is still better than a blank header.
    let mut spans = vec![match summary.decision {
        Some(decision) => theme.chip(decision.tone(), decision.label()),
        None => theme.chip(Tone::Neutral, "none"),
    }];
    let mut used: usize = spans[0].content.chars().count();

    // Optional segments, most important first.
    let mut optional: Vec<Vec<Span<'static>>> = Vec::new();
    if let Some(severity) = summary.risk() {
        optional.push(vec![
            Span::raw(" "),
            theme.chip(severity.tone(), severity.label()),
        ]);
    }
    if let Some(outcome) = summary.outcome() {
        optional.push(vec![Span::styled(
            format!("  {outcome}"),
            Style::new().fg(theme.tone(outcome_tone(outcome))),
        )]);
    }
    optional.push(vec![Span::styled(
        format!("  {}", summary.status),
        theme.muted(),
    )]);
    optional.push(vec![Span::styled(
        format!("   {} events", summary.event_count),
        theme.subtle(),
    )]);
    optional.push(vec![Span::styled(
        format!("   {}", crate::model::duration(summary.duration_ms)),
        theme.subtle(),
    )]);

    // A prefix, not a best fit. Packing whatever happens to fit would show the
    // duration of a run whose status did not make the cut, and a header whose
    // contents change shape with every column is one a reader cannot learn.
    for segment in optional {
        let cost: usize = segment.iter().map(|s| s.content.chars().count()).sum();
        if used + cost > width as usize {
            break;
        }
        used += cost;
        spans.extend(segment);
    }

    if let Some(digest) = transcript.digest()
        && !digest.title.is_empty()
    {
        // An interim title is a mid-run guess and is marked as one here for
        // the same reason it is in the feed. The title is fitted to whatever
        // room is left rather than to a fixed budget, so it fills a wide
        // header and simply does not appear on a narrow one.
        let marker = if digest.interim { "   ~ " } else { "   " };
        let room = (width as usize).saturating_sub(used + marker.chars().count());
        if room >= MIN_TITLE {
            spans.push(Span::styled(marker.to_string(), theme.subtle()));
            spans.push(Span::styled(fit(&digest.title, room), theme.body()));
        }
    }

    Line::from(spans)
}

/// Columns below which a digest title is not worth the room: an ellipsis and
/// four characters names nothing.
const MIN_TITLE: usize = 12;

// ============================================================================
// Left panel — the tree
// ============================================================================

fn tree(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let theme = app.theme;
    let focused = app.pane == Pane::Tree;

    let Some(transcript) = app.transcript.as_ref() else {
        ui::placeholder(
            frame,
            area,
            &theme,
            "transcript",
            &app.transcript_load,
            "No events in this run.",
        );
        return;
    };

    let rows = app.tree_rows();
    if rows.is_empty() {
        ui::placeholder(
            frame,
            area,
            &theme,
            "transcript",
            &app.transcript_load,
            "No events in this run.",
        );
        return;
    }

    // The panel border and padding cost four columns; the rows are laid out
    // against what is left so nothing is written into the frame.
    let inner = area.width.saturating_sub(4) as usize;
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| tree_item(&theme, &transcript.nodes[row.node], *row, inner))
        .collect();

    // Short title: this pane is a third of the frame, and a long eyebrow is the
    // first thing a narrow terminal eats.
    let title = format!("steps · {}", transcript.steps.len());
    let list = List::new(items)
        .highlight_style(theme.selected())
        .block(theme.panel_for(&title, focused));

    app.tree_state.select(Some(app.selected_row));
    frame.render_stateful_widget(list, area, &mut app.tree_state);
}

/// One tree row: a headline and, for a step root, a summary line beneath it.
fn tree_item<'a>(theme: &Theme, node: &EventNode, row: TreeRow, width: usize) -> ListItem<'a> {
    let tone = node.tone();

    // The fold marker occupies a column even when a step cannot fold, so
    // headlines stay aligned and the eye can run straight down the titles.
    let marker = match (row.expandable, row.expanded, row.depth) {
        (true, true, _) => "▾ ",
        (true, false, _) => "▸ ",
        (false, _, 0) => "  ",
        (false, _, _) => "   ",
    };

    let mut headline = vec![
        Span::styled(marker.to_string(), theme.subtle()),
        Span::styled(
            format!("{} ", node.kind.glyph()),
            ratatui::style::Style::new().fg(theme.tone(tone)),
        ),
    ];

    // A fire or a loud signal earns a chip; everything else stays quiet so the
    // chips that do appear mean something.
    let chip = match node.decision {
        Some(decision) if decision.is_fire() => Some(theme.chip(decision.tone(), decision.label())),
        _ if node.severity >= Severity::High => {
            Some(theme.chip(node.severity.tone(), node.severity.label()))
        }
        _ => None,
    };
    let chip_width = chip
        .as_ref()
        .map(|span| span.content.chars().count())
        .unwrap_or(0);

    let title_budget = width
        .saturating_sub(marker.chars().count() + 2 + chip_width)
        .max(4);
    headline.push(Span::styled(fit(&node.title, title_budget), theme.body()));
    if let Some(chip) = chip {
        headline.push(chip);
    }

    let mut lines = vec![Line::from(headline)];

    // Root rows carry a summary line: when it happened, and the concrete thing
    // it acted on — the command, path, or URL — falling back to the scanner's
    // sentence when the payload has no single subject.
    if row.depth == 0 {
        let detail = if node.subtitle.is_empty() {
            node.scan_summary.clone()
        } else {
            node.subtitle.clone()
        };
        let time = clock(Some(&node.timestamp));
        let budget = width.saturating_sub(time.chars().count() + 5).max(4);
        let mut summary = vec![
            Span::raw("    "),
            Span::styled(time, theme.subtle()),
            Span::raw(" "),
            Span::styled(fit(&detail, budget), theme.muted()),
        ];
        if node.side_effecting {
            summary.push(Span::styled(
                " ⟐",
                ratatui::style::Style::new().fg(theme.tone(Tone::Warn)),
            ));
        }
        lines.push(Line::from(summary));
    }

    ListItem::new(lines)
}

// ============================================================================
// Right panel, top — the scanner's read of the run
// ============================================================================

/// The run-level digest and behavioral scan, as one scrollable document.
///
/// Structured the same way the event detail is — chips, then prose, then
/// fielded sections — because it is the same act of reading at a wider
/// altitude. Prose goes through the markdown renderer: the scanner is a
/// language model writing for a human, and its summaries and reasoning arrive
/// with headings, lists, and backticked paths in them.
fn insight(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let theme = app.theme;
    let focused = app.pane == Pane::Insight;

    let Some(transcript) = app.transcript.as_ref() else {
        return;
    };

    // The eyebrow names which halves arrived. A run in flight has a digest and
    // no scan yet, and saying so is the difference between "nothing was found"
    // and "nothing has run".
    let mut title = String::from("run");
    if let Some(digest) = transcript.digest() {
        title.push_str(if digest.interim {
            " · interim digest"
        } else {
            " · digest"
        });
    }
    if transcript.scan().is_some() {
        title.push_str(" · scan");
    }

    // Laid out against a provisional block first: the title gains a scroll
    // marker only once the content is measured, and the marker cannot change
    // the width the content was wrapped to.
    let inner = theme.panel_for(&title, focused).inner(area);

    let mut lines = insight_chips(&theme, transcript, inner.width);
    lines.extend(
        render_blocks(
            &theme,
            &crate::content::insight_blocks(transcript.digest(), transcript.scan()),
            inner.width,
        )
        .lines,
    );

    // Measured from what was actually laid out, exactly as the detail pane
    // does it, so paging cannot run past the end of a short summary.
    app.insight_max_scroll = (lines.len() as u16).saturating_sub(inner.height);
    let scroll = app.insight_scroll.min(app.insight_max_scroll);

    // This panel is short by design, so it usually has more than it shows.
    // Saying which way is the difference between a clipped panel and a
    // scrollable one.
    match (scroll > 0, scroll < app.insight_max_scroll) {
        (true, true) => title.push_str(" ▴▾"),
        (true, false) => title.push_str(" ▴"),
        (false, true) => title.push_str(" ▾"),
        (false, false) => {}
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(theme.panel_for(&title, focused))
            .scroll((scroll, 0)),
        area,
    );
}

/// The run's headline: the digest title, then the claims the scan makes about
/// how the run went.
fn insight_chips(theme: &Theme, transcript: &Transcript, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    if let Some(digest) = transcript.digest()
        && !digest.title.is_empty()
    {
        lines.extend(crate::render::wrap_spans(
            vec![Span::styled(digest.title.clone(), theme.body())],
            width,
            0,
        ));
    }

    if let Some(scan) = transcript.scan() {
        let mut chips = Vec::new();
        if !scan.outcome.is_empty() {
            chips.push(theme.chip(outcome_tone(&scan.outcome), &scan.outcome));
            chips.push(Span::raw(" "));
        }
        chips.push(theme.chip(
            scan.aggregate_severity.tone(),
            scan.aggregate_severity.label(),
        ));
        let signals = scan.signals.len();
        if signals > 0 {
            let plural = if signals == 1 { "" } else { "s" };
            chips.push(Span::styled(
                format!("  {signals} signal{plural}"),
                theme.subtle(),
            ));
        }
        lines.extend(crate::render::wrap_spans(chips, width, 1));
    }

    lines
}

// ============================================================================
// Right panel, bottom — the event detail
// ============================================================================

fn detail(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let theme = app.theme;
    let focused = app.pane == Pane::Detail;

    let Some(node) = app.selected_node().cloned() else {
        ui::placeholder(
            frame,
            area,
            &theme,
            "event",
            &app.transcript_load,
            "Select a step to read it.",
        );
        return;
    };

    let position = app.selected_row + 1;
    let total = app.tree_rows().len();
    let title = format!("event {position}/{total} · {}", node.title);
    let block = theme.panel_for(&title, focused);
    let inner = block.inner(area);

    let mut lines: Vec<Line<'static>> = summary_lines(&theme, &node, inner.width);
    lines.extend(render_blocks(&theme, &node.blocks, inner.width).lines);

    // The scroll bound is whatever this layout actually produced. Measuring it
    // here — rather than guessing from the block count — is what keeps paging
    // from running past the end of a short event or stopping short of a long
    // one. Content is pre-wrapped, so one line of text is one row on screen.
    app.detail_max_scroll = (lines.len() as u16).saturating_sub(inner.height);
    let scroll = app.detail_scroll.min(app.detail_max_scroll);

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(block)
            .scroll((scroll, 0)),
        area,
    );
}

/// The detail pane's own header: what this event is and how it was judged,
/// before the payload itself.
fn summary_lines(theme: &Theme, node: &EventNode, width: u16) -> Vec<Line<'static>> {
    let mut chips: Vec<Span<'static>> = Vec::new();
    match node.decision {
        Some(decision) => chips.push(theme.chip(decision.tone(), decision.label())),
        None => chips.push(theme.chip(Tone::Neutral, "unadjudicated")),
    }
    if node.severity > Severity::Info {
        chips.push(Span::raw(" "));
        chips.push(theme.chip(node.severity.tone(), node.severity.label()));
    }
    if let Some(intent) = node.intent.as_ref() {
        chips.push(Span::raw(" "));
        chips.push(theme.chip(Tone::Info, intent));
    }
    if node.side_effecting {
        chips.push(Span::styled(
            "  ⟐ side-effecting",
            ratatui::style::Style::new().fg(theme.tone(Tone::Warn)),
        ));
    }

    // Chips wrap rather than clip: at a narrow width the last chip is as likely
    // to be the severity as the verdict, and losing it silently is worse than
    // spending a second row.
    let mut lines = crate::render::wrap_spans(chips, width, 1);

    // A deny that does not say why is an opaque verdict, not a decision aid —
    // so the reason sits at the top of the pane, not buried in the payload.
    if let Some(reason) = node.reason.as_ref() {
        lines.extend(crate::render::prose_lines(theme, reason, width));
    }
    if !node.scan_summary.is_empty() {
        lines.extend(crate::render::prose_lines(theme, &node.scan_summary, width));
    }

    lines.push(Line::from(vec![
        Span::styled(clock(Some(&node.timestamp)), theme.subtle()),
        Span::styled(format!("  {}", short(&node.event_id)), theme.subtle()),
    ]));

    if !node.signals.is_empty() {
        lines.push(Line::default());
        lines.push(theme.eyebrow("signals"));
        for signal in &node.signals {
            // Focus before category: whether a flag is about the environment,
            // the agent, or governance decides who owns it. `tool misuse` with
            // an environment focus is a broken tool; with an agent focus it is
            // the agent misusing a working one, and those go to different
            // people.
            let mut spans = vec![theme.chip(signal.severity.tone(), signal.severity.label())];
            if !signal.focus.is_empty() {
                spans.push(Span::styled(
                    format!(" {} · ", signal.focus),
                    theme.subtle(),
                ));
            } else {
                spans.push(Span::raw(" "));
            }
            spans.push(Span::styled(
                format!("{} — ", signal.category),
                theme.body(),
            ));
            spans.push(Span::styled(signal.description.clone(), theme.muted()));
            lines.extend(crate::render::wrap_spans(spans, width, 2));
        }
    }

    lines.push(Line::from(Span::styled(
        "─".repeat(width.max(1) as usize),
        ratatui::style::Style::new().fg(theme.color(theme.hairline)),
    )));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Decision, ScanView, TrajectoryRow};
    use crate::theme::Depth;

    fn theme() -> Theme {
        Theme::dark(Depth::TrueColor)
    }

    fn transcript() -> Transcript {
        Transcript {
            summary: TrajectoryRow {
                decision: Some(Decision::Deny),
                status: "completed".into(),
                event_count: 42,
                duration_ms: 4_200,
                digest: Some(crate::model::DigestView {
                    title: "Build cleanup blocked by policy".into(),
                    ..crate::model::DigestView::default()
                }),
                scan: Some(ScanView {
                    outcome: "interrupted".into(),
                    aggregate_severity: Severity::High,
                    ..ScanView::default()
                }),
                ..TrajectoryRow::default()
            },
            ..Transcript::default()
        }
    }

    fn width_of(line: &Line<'_>) -> usize {
        line.spans
            .iter()
            .map(|span| span.content.chars().count())
            .sum()
    }

    fn text_of(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    /// The header is drawn without wrapping, so a line laid out wider than its
    /// column is not shortened — it is cut, silently, at whatever character the
    /// edge falls on. Nothing may ever exceed the width it was built for.
    #[test]
    fn the_header_line_never_overruns_the_width_it_was_built_for() {
        for width in [0, 8, 16, 24, 38, 60, 96, 200] {
            let line = summary_line(&theme(), &transcript(), width);
            assert!(
                width_of(&line) <= width as usize || width < 12,
                "width {width}: header drew {} columns",
                width_of(&line),
            );
        }
    }

    /// Order of loss. The verdict survives every width; the scanner's two
    /// claims outrank the lifecycle facts, because they are the only ones this
    /// screen carries nowhere else; and the digest title goes first, since it
    /// is also the first line of the insight panel two rows below.
    #[test]
    fn the_header_drops_facts_in_priority_order() {
        let transcript = transcript();

        let wide = text_of(&summary_line(&theme(), &transcript, 200));
        assert!(wide.contains("DENY"));
        assert!(wide.contains("HIGH"));
        assert!(wide.contains("interrupted"));
        assert!(wide.contains("42 events"));
        assert!(wide.contains("Build cleanup blocked by policy"));

        // Enough for the verdict and the scanner, not for the title.
        let narrow = text_of(&summary_line(&theme(), &transcript, 38));
        assert!(narrow.contains("DENY"));
        assert!(narrow.contains("HIGH"));
        assert!(!narrow.contains("Build cleanup"));

        // The verdict is the one thing that is never dropped.
        let cramped = text_of(&summary_line(&theme(), &transcript, 10));
        assert!(cramped.contains("DENY"));
    }

    /// An interim digest is a mid-run guess, and the header says so wherever it
    /// has room to name the title at all.
    #[test]
    fn an_interim_title_is_marked_in_the_header() {
        let mut transcript = transcript();
        transcript.summary.digest.as_mut().unwrap().interim = true;
        let line = text_of(&summary_line(&theme(), &transcript, 200));
        assert!(line.contains("~ Build cleanup"), "{line}");
    }
}
