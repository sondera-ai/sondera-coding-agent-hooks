//! Screen dispatch and the chrome both screens share.

pub mod inspect;
pub mod trajectories;
pub mod transcript;

use crate::state::{App, Load, Screen};
use crate::theme::{Theme, Tone};
use ratatui::Frame;
use ratatui::layout::{Constraint, HorizontalAlignment, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

/// The wordmark. The mark beside it is drawn, not written — see [`crate::brand`].
pub const BRAND: &str = "SONDERA";

/// Stand-in for the mark where it does not fit.
const BRAND_GLYPH: &str = "◆";

/// Columns the mark occupies: four of grid plus a gutter.
const MARK_WIDTH: u16 = 5;

/// Narrowest header that spends five columns on identity. Below this the mark
/// is dropped for the inline glyph.
///
/// Set by the breadcrumb, not by the mark. A header line is clipped rather than
/// wrapped, and at sixty columns the five the mark takes are exactly the five
/// that carry the run id: `trajectories / cursor / run` becomes
/// `trajectories / cursor /`, which reads as a bug rather than as truncation.
/// Eighty leaves the deepest breadcrumb the transcript builds a comfortable
/// margin.
const MARK_MIN_WIDTH: u16 = 80;

/// How the header divides: the mark, then the caller's lines, then the load
/// pill on the right. Named because a caller that has more to say than fits has
/// to know how much room it actually got — a header line is drawn without
/// wrapping, so anything past the split is not shortened, it is *gone*.
const fn mark_width(width: u16) -> u16 {
    if width >= MARK_MIN_WIDTH {
        MARK_WIDTH
    } else {
        0
    }
}

fn header_split(width: u16) -> [Constraint; 3] {
    [
        Constraint::Length(mark_width(width)),
        Constraint::Min(20),
        Constraint::Length(22),
    ]
}

/// The columns a header line has for its own content at `width`.
pub fn header_width(width: u16) -> u16 {
    let [_, left, _] = Layout::horizontal(header_split(width)).areas(Rect {
        x: 0,
        y: 0,
        width,
        height: 1,
    });
    left.width
}

/// Draw one frame.
///
/// `app` is taken mutably because the detail pane's scroll bound is a property
/// of what was actually laid out — the renderer measures it and hands it back
/// so the next keypress can be clamped honestly.
pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    paint_canvas(frame, &app.theme);
    match app.screen {
        Screen::Trajectories => trajectories::render(frame, app),
        Screen::Transcript => transcript::render(frame, app),
    }
}

/// Fill the frame with the canvas color so the surface reads edge to edge
/// regardless of the user's terminal background.
fn paint_canvas(frame: &mut Frame<'_>, theme: &Theme) {
    let canvas = Block::default().style(Style::new().bg(theme.color(theme.canvas)));
    frame.render_widget(canvas, frame.area());
}

/// The app-shell header: brand and breadcrumb on the left, load status on the
/// right, with the caller's own lines beneath.
///
/// `load` is the screen's *own* fetch state, not a global one. A transcript
/// still loading behind a fully loaded run feed must not read as "ready", or
/// the pill becomes a decoration nobody trusts.
pub fn header(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &App,
    breadcrumb: &[&str],
    lines: Vec<Line<'static>>,
    load: &Load,
) {
    let theme = &app.theme;
    let block = Block::default().style(Style::new().bg(theme.color(theme.panel)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [mark, left, right] = Layout::horizontal(header_split(inner.width)).areas(inner);

    // The mark spans both header rows; the wordmark sits on the first line of
    // the text column beside it.
    if mark.width > 0 {
        frame.render_widget(Paragraph::new(app.brand.lines(theme)), mark);
    }

    let mut spans = Vec::with_capacity(4);
    if mark.width == 0 {
        spans.push(Span::styled(BRAND_GLYPH, theme.eyebrow_style()));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(BRAND, theme.eyebrow_style()));
    spans.push(Span::raw("  "));
    for (idx, segment) in breadcrumb.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::styled(" / ", theme.subtle()));
        }
        let style = if idx + 1 == breadcrumb.len() {
            theme.body()
        } else {
            theme.muted()
        };
        spans.push(Span::styled((*segment).to_string(), style));
    }

    let mut left_lines = vec![Line::from(spans)];
    left_lines.extend(lines);
    frame.render_widget(Paragraph::new(left_lines), left);

    frame.render_widget(
        Paragraph::new(load_pill(theme, load)).alignment(HorizontalAlignment::Right),
        right,
    );
}

/// A load-state pill. A failed load says so in the chrome, so an empty pane is
/// never mistaken for an empty result.
fn load_pill(theme: &Theme, load: &Load) -> Line<'static> {
    let tone = match load {
        Load::Ready => Tone::Allow,
        // Info, not Allow: a live tail is a channel that is open, which is an
        // observation about the view rather than a verdict about the run.
        Load::Live => Tone::Info,
        Load::Loading | Load::Idle => Tone::Warn,
        Load::Failed(_) => Tone::Deny,
    };
    Line::from(vec![
        Span::styled("console ", theme.subtle()),
        theme.chip(tone, load.label()),
    ])
}

/// The inner width a footer of `width` columns has for its hints, after the
/// panel's borders and horizontal padding.
fn footer_inner(width: u16) -> u16 {
    width.saturating_sub(4)
}

/// How tall the footer must be to show `hints` in full at `width`.
///
/// Key hints that scroll off the edge are hints the user does not have. Rather
/// than truncate — which silently eats `<q> quit` first, since it sorts last —
/// the footer grows a row and the body gives one up.
pub fn footer_height(app: &App, hints: &[(&str, &str)], width: u16) -> u16 {
    let wrapped = footer_lines(app, hints, width).len() as u16;
    // Two rows of borders, and never more than three rows of hints: past that
    // the footer is eating the screen it exists to annotate.
    wrapped.clamp(1, 3) + 2
}

fn footer_lines(app: &App, hints: &[(&str, &str)], width: u16) -> Vec<Line<'static>> {
    let theme = &app.theme;
    let mut lines = crate::render::wrap_spans(theme.keyhints(hints).spans, footer_inner(width), 0);
    if let Some(status) = app.status.as_ref() {
        lines.push(Line::from(Span::styled(status.clone(), theme.muted())));
    }
    lines
}

/// The key-hints footer.
pub fn footer(frame: &mut Frame<'_>, area: Rect, app: &App, hints: &[(&str, &str)]) {
    let lines = footer_lines(app, hints, area.width);
    frame.render_widget(Paragraph::new(lines).block(app.theme.panel("keys")), area);
}

/// A placeholder for a pane with nothing to show, phrased for the reason.
pub fn placeholder(
    frame: &mut Frame<'_>,
    area: Rect,
    theme: &Theme,
    eyebrow: &str,
    load: &Load,
    empty: &str,
) {
    let line = match load {
        Load::Loading => Line::from(Span::styled("Loading…", theme.muted())),
        Load::Failed(reason) => Line::from(vec![
            theme.chip(Tone::Deny, "error"),
            Span::styled(format!(" {reason}"), theme.body()),
        ]),
        _ => Line::from(Span::styled(empty.to_string(), theme.subtle())),
    };
    frame.render_widget(Paragraph::new(line).block(theme.panel(eyebrow)), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mark_is_drawn_only_at_or_above_its_minimum_width() {
        for width in [20, 40, 60, MARK_MIN_WIDTH - 1] {
            assert_eq!(mark_width(width), 0, "mark drawn at {width} columns");
        }
        for width in [MARK_MIN_WIDTH, 100, 200] {
            assert_eq!(
                mark_width(width),
                MARK_WIDTH,
                "mark missing at {width} columns",
            );
        }
    }

    /// The regression [`header_width`] exists to prevent. Callers size their own
    /// content against it — the transcript's summary line most of all — and a
    /// header line is clipped rather than wrapped, so a width that forgot the
    /// mark would silently eat the end of whatever it was given.
    #[test]
    fn a_header_line_is_told_about_the_columns_the_mark_took() {
        assert_eq!(header_width(120), 120 - MARK_WIDTH - 22);
        assert_eq!(
            header_width(MARK_MIN_WIDTH),
            MARK_MIN_WIDTH - MARK_WIDTH - 22
        );
        // Below the threshold nothing is deducted, because nothing is drawn.
        assert_eq!(header_width(60), 60 - 22);
    }
}
