//! The run inspector — the scanner's whole read of one run, over the feed.
//!
//! The feed is a table, and a table has columns. The digest's phases, the files
//! a run changed, the tools it reached for, and the scan's signals are *lists*,
//! and no terminal width turns a list into a column. Rather than truncate them
//! into a cell or force a reader onto the transcript screen to see whether a run
//! is worth opening, the inspector renders them in place.
//!
//! It is the same document the transcript screen's insight panel draws, from the
//! same [`crate::content::insight_blocks`] — one vocabulary for the scanner's
//! output, at two altitudes. What it adds is the run-level governance the
//! transcript header already has room for and the feed never did: the policies
//! that fired, and the run's score.
//!
//! This is the only raised surface in the app. Sondera's terminal translation of
//! `raised` is a shadow, and a shadow means *modal* — never a structural panel.

use crate::model::{AgentIdentity, TrajectoryRow, duration, outcome_tone};
use crate::render::{render_blocks, wrap_spans};
use crate::state::App;
use crate::theme::{Theme, Tone};
use ratatui::Frame;
use ratatui::layout::{Constraint, Offset, Rect};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Clear, Paragraph, Shadow};

/// Draw the inspector over `area` for the highlighted run.
///
/// `app` is taken mutably for the same reason the reading panes are: the scroll
/// bound is a property of what was actually laid out, so it is measured here and
/// handed back for the next keypress to clamp against.
pub fn render(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let theme = app.theme;
    // The caller closes the panel when its run leaves the feed, so this is a
    // guard rather than a state change.
    let Some(row) = app.selected_run().cloned() else {
        return;
    };
    let identity = app.agent_identity(&row.agent).cloned();

    let popup = popup_area(area);
    // Clear first, or the table underneath bleeds its symbols and styles
    // through the panel that is supposed to be covering it.
    frame.render_widget(Clear, popup);

    let title = title(&row);
    let block = theme.panel(&title).shadow(shadow());
    let inner = block.inner(popup);

    let mut lines = head_lines(&theme, &row, identity.as_ref(), inner.width);
    lines.extend(
        render_blocks(
            &theme,
            &crate::content::insight_blocks(row.digest.as_ref(), row.scan.as_ref()),
            inner.width,
        )
        .lines,
    );
    if row.digest.is_none() && row.scan.is_none() {
        lines.extend(unscanned_lines(&theme, &row, inner.width));
    }

    app.inspect_max_scroll = (lines.len() as u16).saturating_sub(inner.height);
    let scroll = app.inspect_scroll.min(app.inspect_max_scroll);

    // A panel that has more below than it is showing has to say so, or a
    // reader takes the last visible signal for the last signal there is.
    let mut title = title;
    match (scroll > 0, scroll < app.inspect_max_scroll) {
        (true, true) => title.push_str(" ▴▾"),
        (true, false) => title.push_str(" ▴"),
        (false, true) => title.push_str(" ▾"),
        (false, false) => {}
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(theme.panel(&title).shadow(shadow()))
            .scroll((scroll, 0)),
        popup,
    );
}

/// Where the inspector sits.
///
/// Large rather than centered-and-tiny: the content is prose and file paths, and
/// a narrow modal wraps every path onto three lines.
///
/// The shadow is laid out *before* the panel is, by shrinking the area the popup
/// is centered in by exactly the shadow's offset. A shadow is drawn outside the
/// block's own rect, so a popup centered in the full area puts its shadow over
/// the enclosing panel's bottom border — the modal's depth cue eating the
/// structure it is floating above.
fn popup_area(area: Rect) -> Rect {
    let room = Rect {
        width: area.width.saturating_sub(SHADOW.x as u16),
        height: area.height.saturating_sub(SHADOW.y as u16),
        ..area
    };
    room.centered(Constraint::Percentage(80), Constraint::Percentage(80))
}

/// How far the modal's shadow falls. One row down and two columns right: enough
/// to read as depth in a terminal that has no blur.
const SHADOW: Offset = Offset { x: 2, y: 1 };

fn shadow() -> Shadow {
    Shadow::dark_shade().offset(SHADOW)
}

/// The eyebrow: which halves of the scanner's output this run actually has.
///
/// Naming the absent half is the point. A run in flight has a digest and no
/// scan, and a console that renders that identically to "the scan found
/// nothing" has turned a missing measurement into a clean bill of health.
fn title(row: &TrajectoryRow) -> String {
    let mut title = format!("run · {}", row.id);
    match (row.digest.as_ref(), row.scan.as_ref()) {
        (None, None) => title.push_str(" · not scanned"),
        (digest, scan) => {
            if let Some(digest) = digest {
                title.push_str(if digest.interim {
                    " · interim digest"
                } else {
                    " · digest"
                });
            }
            if scan.is_some() {
                title.push_str(" · scan");
            }
        }
    }
    title
}

/// The run's own facts, above the scanner's read of them: who ran it, the
/// verdict, how it went, and what fired.
fn head_lines(
    theme: &Theme,
    row: &TrajectoryRow,
    identity: Option<&AgentIdentity>,
    width: u16,
) -> Vec<Line<'static>> {
    let mut chips: Vec<Span<'static>> = vec![match row.decision {
        Some(decision) => theme.chip(decision.tone(), decision.label()),
        None => theme.chip(Tone::Neutral, "none"),
    }];

    if let Some(severity) = row.risk() {
        chips.push(Span::raw(" "));
        chips.push(theme.chip(severity.tone(), severity.label()));
    }
    if let Some(outcome) = row.outcome() {
        chips.push(Span::styled(
            format!("  {outcome}"),
            ratatui::style::Style::new().fg(theme.tone(outcome_tone(outcome))),
        ));
    }
    chips.push(Span::styled(format!("  {}", row.status), theme.muted()));
    chips.push(Span::styled(
        format!("  {}", duration(row.duration_ms)),
        theme.subtle(),
    ));

    let mut lines = wrap_spans(chips, width, 1);

    // Who ran it. The feed can only afford the provider and platform columns on
    // an ultrawide terminal, so this is where a sixty-column console reads them
    // — the same bargain the scanner's own columns strike.
    lines.push(theme.field("agent", &agent_line(row, identity)));

    // The policies that fired, listed rather than counted. The feed's activity
    // strip says a policy fired and where; only the id says which, and a fire
    // whose clause is unnameable is an opaque verdict.
    if !row.policy_hits.is_empty() {
        lines.push(theme.field("policy", &row.policy_hits.join(", ")));
    }
    if row.score > 0.0 {
        lines.push(theme.field("score", &format!("{:.2}", row.score)));
    }
    lines.push(Line::default());
    lines
}

/// The agent that ran this, with the provider and platform the harness
/// registered for it.
///
/// The qualifiers are simply left off when the roster cannot supply them, rather
/// than filled with a placeholder: the agent id is a claim this console can make
/// on its own, and appending `— / —` to it would look like an answer.
fn agent_line(row: &TrajectoryRow, identity: Option<&AgentIdentity>) -> String {
    let agent = if row.agent.is_empty() {
        "—"
    } else {
        &row.agent
    };
    match identity {
        Some(identity) if !identity.is_empty() => format!(
            "{agent}   {} / {}",
            or_dash(&identity.provider),
            or_dash(&identity.platform),
        ),
        _ => agent.to_string(),
    }
}

fn or_dash(value: &str) -> &str {
    if value.is_empty() { "—" } else { value }
}

/// What to say when the scanner has produced nothing for this run.
///
/// A blank panel would read as "this run was clean". Naming the two reasons —
/// no scanner configured, or one that has not reached this run — is the answer
/// to the question that made the reader press the key.
fn unscanned_lines(theme: &Theme, row: &TrajectoryRow, width: u16) -> Vec<Line<'static>> {
    let reason = if row.status == "running" || row.status == "pending" {
        "No digest yet. The scanner digests a run as it goes and grades it once \
         it ends, so a run still in flight can legitimately have neither."
    } else {
        "No scanner output for this run. Either no trajectory scanner is \
         configured — see `[scanner]` in `.sondera/sondera.toml` — or it has \
         not reached this run."
    };
    crate::render::prose_lines(theme, reason, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AgentIdentity, DigestView, ScanView};
    use crate::theme::Depth;

    fn theme() -> Theme {
        Theme::dark(Depth::TrueColor)
    }

    fn row() -> TrajectoryRow {
        TrajectoryRow {
            id: "run-1".into(),
            status: "completed".into(),
            ..TrajectoryRow::default()
        }
    }

    /// The three states the eyebrow has to keep apart. A run with no scan and a
    /// run whose scan found nothing are different claims.
    #[test]
    fn the_title_names_which_halves_of_the_scan_arrived() {
        assert!(title(&row()).ends_with("not scanned"));

        let digested = TrajectoryRow {
            digest: Some(DigestView {
                interim: true,
                ..DigestView::default()
            }),
            ..row()
        };
        assert!(title(&digested).contains("interim digest"));
        assert!(!title(&digested).contains("· scan"));

        let scanned = TrajectoryRow {
            digest: Some(DigestView::default()),
            scan: Some(ScanView::default()),
            ..row()
        };
        assert!(scanned_title_has_both(&title(&scanned)));
    }

    fn scanned_title_has_both(title: &str) -> bool {
        title.contains("digest") && title.contains("scan")
    }

    /// The inspector — *including its shadow* — must never draw outside the
    /// body it was handed.
    ///
    /// The shadow is the trap: it is rendered outside the block's own rect, so
    /// a popup that merely fits leaves its shadow on the enclosing panel's
    /// bottom border, and the modal's depth cue erases the structure it is
    /// supposed to be floating above.
    #[test]
    fn the_popup_and_its_shadow_stay_inside_the_area() {
        for (width, height) in [(60, 12), (80, 20), (110, 16), (200, 60), (20, 6), (8, 3)] {
            let area = Rect::new(0, 2, width, height);
            let popup = popup_area(area);
            let shadowed = Rect {
                width: popup.width + SHADOW.x as u16,
                height: popup.height + SHADOW.y as u16,
                ..popup
            };
            assert!(
                shadowed.right() <= area.right() && shadowed.bottom() <= area.bottom(),
                "{width}x{height}: shadow {shadowed:?} escapes {area:?}",
            );
            assert!(popup.left() >= area.left() && popup.top() >= area.top());
        }
    }

    /// A run with no scanner output gets prose explaining which absence it is,
    /// never an empty box.
    #[test]
    fn an_unscanned_run_explains_itself_rather_than_rendering_blank() {
        let lines = unscanned_lines(&theme(), &row(), 60);
        let text: String = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect();
        assert!(text.contains("scanner"));

        let running = TrajectoryRow {
            status: "running".into(),
            ..row()
        };
        let text: String = unscanned_lines(&theme(), &running, 60)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect();
        assert!(text.contains("still in flight"));
    }

    /// A fire the feed showed as a red cell has to be nameable somewhere, and
    /// this panel is that somewhere.
    #[test]
    fn the_head_names_the_policies_that_fired() {
        let fired = TrajectoryRow {
            policy_hits: vec!["no-rm-rf".into(), "no-secrets".into()],
            ..row()
        };
        let text: String = head_lines(&theme(), &fired, None, 60)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect();
        assert!(text.contains("no-rm-rf"));
        assert!(text.contains("no-secrets"));
    }

    /// The feed only affords the identity columns on an ultrawide terminal, so
    /// this panel is where every other width reads them — and where an agent the
    /// roster cannot name must not acquire a made-up provider.
    #[test]
    fn the_head_names_the_provider_and_platform_where_the_roster_knows_them() {
        let row = TrajectoryRow {
            agent: "claude-code-dev".into(),
            ..row()
        };
        let identity = AgentIdentity {
            provider: "anthropic".into(),
            platform: "claude-code".into(),
        };
        let line = agent_line(&row, Some(&identity));
        assert!(line.contains("claude-code-dev"));
        assert!(line.contains("anthropic"));
        assert!(line.contains("claude-code"));

        // No roster entry: the agent id stands alone rather than gaining a
        // placeholder that reads like an answer.
        assert_eq!(agent_line(&row, None), "claude-code-dev");
        assert_eq!(
            agent_line(&row, Some(&AgentIdentity::default())),
            "claude-code-dev"
        );
    }
}
