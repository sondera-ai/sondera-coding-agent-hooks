//! Render tests for both screens.
//!
//! These drive the real widget tree through `TestBackend`, so a layout that
//! panics, a column budget that overflows, or a pane that silently renders
//! nothing fails here rather than in a terminal. Snapshots are asserted at two
//! widths: the comfortable one, and the ~60-column case a dense console has to
//! survive.

use insta::assert_snapshot;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use sondera_tui::App;
use sondera_tui::brand::Mark;
use sondera_tui::content::{Block, Lang};
use sondera_tui::model::{
    AgentIdentity, Decision, DigestView, EventNode, Kind, PhaseView, ScanView, Severity,
    SignalView, SparkCell, SparkKind, Sparkline, Step, TrajectoryRow, Transcript,
};
use sondera_tui::state::{Load, Pane, Screen};
use sondera_tui::theme::{Depth, Theme};
use sondera_tui::ui;

/// A fixed theme, so snapshots do not depend on the host's `COLORTERM`.
///
/// The brand mark is pinned too. It is generated per render and seeded from the
/// clock, so a snapshot that captured whichever mark happened to come up would
/// be a coin flip. Truecolor happens to hide that — every cell is `▀` there and
/// occupancy rides on colour, which the text dump drops — but under `NO_COLOR`
/// occupancy moves onto the glyph and an unpinned mark would flake.
fn app() -> App {
    let mut app = App::new(Theme::dark(Depth::TrueColor));
    app.brand = Mark::new(0, false);
    app
}

fn render(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| ui::draw(frame, app)).unwrap();
    terminal.backend().to_string()
}

fn run(id: &str, agent: &str, decision: Option<Decision>, summary: &str) -> TrajectoryRow {
    TrajectoryRow {
        name: format!("trajectories/{id}"),
        id: id.into(),
        agent: agent.into(),
        decision,
        status: "completed".into(),
        event_count: 42,
        duration_ms: 4_200,
        update_time: Some("2026-08-01T12:34:56Z".into()),
        summary: summary.into(),
        ..TrajectoryRow::default()
    }
}

/// A signal, for fixtures that need one.
fn signal(severity: Severity, category: &str) -> SignalView {
    SignalView {
        severity,
        focus: "governance".into(),
        category: category.into(),
        description: "Recursive delete on an absolute path.".into(),
    }
}

/// The three states of scanner output a feed has to render differently:
/// graded, digested-but-not-yet-graded, and never scanned at all.
///
/// `run-c` is the third: no digest, no scan, and no strip either, so the whole
/// row is the "nothing is known yet" case rather than the "nothing happened"
/// one.
fn feed() -> Vec<TrajectoryRow> {
    let mut clean = run(
        "run-a",
        "claude-code",
        Some(Decision::Allow),
        "refactored the storage layer",
    );
    clean.digest = Some(DigestView {
        title: "Refactor the storage layer".into(),
        total_events: 42,
        side_effecting_count: 6,
        ..DigestView::default()
    });
    clean.scan = Some(ScanView {
        outcome: "success".into(),
        aggregate_severity: Severity::Info,
        confidence: 0.94,
        ..ScanView::default()
    });

    let mut fired = run(
        "run-b",
        "cursor",
        Some(Decision::Deny),
        "attempted a recursive delete",
    );
    fired.policy_hits = vec!["no-recursive-delete".into()];
    fired.score = 0.82;
    fired.digest = Some(DigestView {
        title: "Build cleanup blocked by policy".into(),
        total_events: 12,
        side_effecting_count: 1,
        ..DigestView::default()
    });
    fired.scan = Some(ScanView {
        outcome: "interrupted".into(),
        aggregate_severity: Severity::High,
        confidence: 0.9,
        signals: vec![
            signal(Severity::High, "destructive operation"),
            signal(Severity::Medium, "tool misuse"),
        ],
        ..ScanView::default()
    });

    // Still going: an interim digest and no behavioral scan, which is the
    // normal state of a live run and must not read as a final grade.
    let mut running = run("run-c", "codex", None, "wiring the OTel spans");
    running.status = "running".into();
    running.digest = Some(DigestView {
        title: "Wire OTel spans".into(),
        interim: true,
        ..DigestView::default()
    });

    vec![clean, fired, running]
}

/// The agent roster the feed's identity columns are joined against.
///
/// `codex` is deliberately left out. `run-c` is the row where nothing is known
/// yet, and an agent the roster does not cover has to read as *unidentified*
/// rather than as an agent with no provider.
fn roster() -> Vec<(String, AgentIdentity)> {
    vec![
        (
            "claude-code".into(),
            AgentIdentity {
                provider: "anthropic".into(),
                platform: "claude-code".into(),
            },
        ),
        (
            "cursor".into(),
            AgentIdentity {
                provider: "cursor".into(),
                platform: "cursor".into(),
            },
        ),
    ]
}

/// A strip built from consecutive phases — a run of `n` cells of one kind —
/// bracketed by the lifecycle bookends the console emits.
///
/// Phases rather than an even mix, because that is the shape real runs have and
/// the shape a condensed strip can still show: a run that investigates, then
/// edits, then verifies reads differently across the column, where an evenly
/// interleaved one flattens to whichever kind ranks highest.
fn strip(phases: &[(SparkKind, usize)], fire: Option<(usize, Decision)>) -> Sparkline {
    let cell = |kind| SparkCell {
        kind,
        ..SparkCell::default()
    };
    let mut cells = vec![cell(SparkKind::Control)];
    for (kind, count) in phases {
        cells.extend(std::iter::repeat_n(cell(*kind), *count));
    }
    cells.push(cell(SparkKind::Control));

    if let Some((at, decision)) = fire {
        cells[at].decision = Some(decision);
        cells[at].policy_hit = Some("policies/no-recursive-delete".into());
    }
    Sparkline {
        cells,
        truncated: false,
    }
}

/// The feed's strips. `run-c` is deliberately left without one: a run whose
/// strip has not arrived must look different from one that did nothing.
fn strips() -> Vec<(String, Sparkline)> {
    vec![
        (
            // Investigate, then implement, then report: no fire anywhere.
            "trajectories/run-a".into(),
            strip(
                &[
                    (SparkKind::PromptUser, 1),
                    (SparkKind::Thought, 14),
                    (SparkKind::Tool, 22),
                    (SparkKind::File, 26),
                    (SparkKind::Thought, 8),
                    (SparkKind::PromptModel, 6),
                ],
                None,
            ),
        ),
        (
            // The same shape, until a shell command is denied two thirds in.
            "trajectories/run-b".into(),
            strip(
                &[
                    (SparkKind::PromptUser, 1),
                    (SparkKind::Thought, 10),
                    (SparkKind::Web, 16),
                    (SparkKind::Tool, 18),
                    (SparkKind::Shell, 24),
                    (SparkKind::Thought, 8),
                ],
                Some((55, Decision::Deny)),
            ),
        ),
    ]
}

/// A run with a shell step (denied, with output), a prompt, and a file write —
/// one of each rendering path the detail pane has.
fn transcript() -> Transcript {
    let mut summary = run(
        "run-b",
        "cursor",
        Some(Decision::Deny),
        "attempted a recursive delete",
    );
    summary.score = 0.82;

    let shell = EventNode {
        event_id: "evt-1".into(),
        timestamp: "2026-08-01T12:34:56Z".into(),
        kind: Kind::Shell,
        title: "shell".into(),
        subtitle: "rm -rf /tmp/build".into(),
        call_id: Some("c1".into()),
        decision: Some(Decision::Deny),
        reason: Some("recursive delete outside the workspace".into()),
        scan_summary: "Removed a build directory.".into(),
        intent: Some("implement".into()),
        side_effecting: true,
        severity: Severity::High,
        signals: vec![SignalView {
            severity: Severity::High,
            focus: "governance".into(),
            category: "destructive operation".into(),
            description: "Recursive delete on an absolute path.".into(),
        }],
        blocks: vec![
            Block::Eyebrow("action".into()),
            Block::Field {
                key: "cwd".into(),
                value: "/repo".into(),
            },
            Block::Gap,
            Block::Code {
                lang: Lang::Bash,
                caption: Some("command".into()),
                text: "rm -rf /tmp/build".into(),
            },
        ],
        ..EventNode::default()
    };

    let output = EventNode {
        event_id: "evt-2".into(),
        timestamp: "2026-08-01T12:34:57Z".into(),
        kind: Kind::Output,
        title: "exit 1".into(),
        subtitle: "permission denied".into(),
        call_id: Some("c1".into()),
        blocks: vec![Block::Code {
            lang: Lang::Plain,
            caption: Some("stderr".into()),
            text: "rm: permission denied".into(),
        }],
        ..EventNode::default()
    };

    let prompt = EventNode {
        event_id: "evt-3".into(),
        timestamp: "2026-08-01T12:35:10Z".into(),
        kind: Kind::Prompt,
        title: "prompt · user".into(),
        subtitle: "Clean the build directory".into(),
        blocks: vec![Block::Prose(
            "# Task\n\nClean the **build** directory, then:\n\n- run tests\n- report".into(),
        )],
        ..EventNode::default()
    };

    summary.digest = Some(DigestView {
        title: "Build cleanup blocked by policy".into(),
        // Markdown, because the scanner is a language model writing for a
        // human: it emits emphasis and backticked paths, and rendering
        // those literally would put `**` in a governance console.
        summary: "The agent tried to clear the **build tree** with `rm -rf` \
                      and was denied."
            .into(),
        phases: vec![
            PhaseView {
                name: "Investigation".into(),
                description: "read the build layout".into(),
                event_count: 1,
            },
            PhaseView {
                name: "Implementation".into(),
                description: "issued the delete".into(),
                event_count: 2,
            },
        ],
        tools_used: vec!["Bash".into(), "Read".into()],
        files_modified: vec!["tmp/build/manifest.json".into()],
        total_events: 3,
        side_effecting_count: 1,
        ..DigestView::default()
    });
    summary.scan = Some(ScanView {
        outcome: "interrupted".into(),
        outcome_description: "The run stopped when the delete was denied.".into(),
        aggregate_severity: Severity::High,
        confidence: 0.9,
        explanation: "The agent moved straight to a destructive command \
                      without checking the path."
            .into(),
        signals: vec![signal(Severity::High, "destructive operation")],
        adjudication_summary: "1 deny.".into(),
        behavioral_notes: vec!["Did not retry after the denial.".into()],
    });

    Transcript {
        summary,
        nodes: vec![shell, output, prompt],
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
    }
}

// ── trajectories screen ─────────────────────────────────────────────────────

/// A feed with the strips already fetched, which is what a settled screen looks
/// like a moment after it loads.
fn loaded() -> App {
    let mut app = app();
    app.set_trajectories(feed());
    // The same round trip the event loop makes: ask, then answer. Only what was
    // asked for is installed, so the request is not optional here.
    app.request_sparklines();
    app.set_sparklines(strips());
    app.set_agents(roster());
    app
}

#[test]
fn trajectories_feed() {
    let mut app = loaded();
    assert_snapshot!(render(&mut app, 110, 16));
}

#[test]
fn trajectories_feed_at_sixty_columns() {
    let mut app = loaded();
    assert_snapshot!(render(&mut app, 60, 16));
}

/// The widest column set: the strip gets nearly twice the cells, and the event
/// count comes back alongside it.
#[test]
fn trajectories_feed_at_full_width() {
    let mut app = loaded();
    assert_snapshot!(render(&mut app, 160, 16));
}

/// The ultrawide band, where the feed can finally afford the agent's identity:
/// who makes the model and what it runs as, beside the agent that ran it. The
/// third run's agent is not on the roster, so both of its cells read `—`.
#[test]
fn trajectories_feed_at_ultrawide() {
    let mut app = loaded();
    assert_snapshot!(render(&mut app, 170, 16));
}

/// Below the width that carries a strip, the feed reports the event count
/// instead — the same magnitude without the shape.
#[test]
fn trajectories_feed_at_eighty_columns() {
    let mut app = loaded();
    assert_snapshot!(render(&mut app, 80, 16));
}

/// A feed whose strips have not arrived yet must not read as a feed of runs
/// that did nothing.
#[test]
fn a_feed_without_strips_marks_the_column_absent() {
    let mut app = app();
    app.set_trajectories(feed());
    assert_snapshot!(render(&mut app, 110, 14));
}

#[test]
fn trajectories_feed_with_an_active_filter() {
    let mut app = loaded();
    app.filter_editing = true;
    app.set_filter("curs".into());
    assert_snapshot!(render(&mut app, 110, 14));
}

#[test]
fn an_empty_feed_explains_itself() {
    let mut app = app();
    app.set_trajectories(Vec::new());
    assert_snapshot!(render(&mut app, 110, 12));
}

#[test]
fn a_filtered_empty_feed_names_the_filter() {
    let mut app = app();
    app.set_trajectories(feed());
    app.set_filter("nothing-matches-this".into());
    assert_snapshot!(render(&mut app, 110, 12));
}

#[test]
fn a_failed_load_reports_the_reason_rather_than_looking_empty() {
    let mut app = app();
    app.trajectories_load = Load::Failed("connection refused".into());
    assert_snapshot!(render(&mut app, 110, 12));
}

// ── transcript screen ───────────────────────────────────────────────────────

#[test]
fn transcript_tree_and_detail() {
    let mut app = app();
    app.set_trajectories(feed());
    app.move_run(1);
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    assert_snapshot!(render(&mut app, 120, 30));
}

/// A tailed run says so: the reader has to be able to tell a view that is still
/// filling in from a snapshot they should refresh before trusting.
#[test]
fn a_tailed_transcript_says_it_is_live() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.begin_live_transcript(transcript());
    assert_snapshot!(render(&mut app, 120, 30));
}

/// The narrow case is where an extra chip does damage, so it is snapshotted too.
#[test]
fn a_tailed_transcript_at_sixty_columns() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.begin_live_transcript(transcript());
    assert_snapshot!(render(&mut app, 60, 24));
}

#[test]
fn transcript_at_sixty_columns() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    assert_snapshot!(render(&mut app, 60, 24));
}

#[test]
fn transcript_renders_markdown_in_the_detail_pane() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    // Step 2 is the prompt, whose payload is markdown.
    app.move_row(2);
    assert_snapshot!(render(&mut app, 120, 24));
}

#[test]
fn transcript_collapsed_hides_the_nested_output() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    app.collapse_all();
    assert_snapshot!(render(&mut app, 120, 20));
}

#[test]
fn transcript_shows_focus_on_the_detail_pane() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    app.pane = Pane::Detail;
    assert_snapshot!(render(&mut app, 120, 24));
}

#[test]
fn a_transcript_still_loading_says_so_in_both_panes() {
    let mut app = app();
    app.set_trajectories(feed());
    app.screen = Screen::Transcript;
    app.transcript_load = Load::Loading;
    assert_snapshot!(render(&mut app, 120, 16));
}

// ── invariants that hold at every size ──────────────────────────────────────

#[test]
fn every_screen_survives_narrow_and_short_terminals() {
    // A layout that panics or overflows at an awkward size is a crash in the
    // user's terminal, so the widths that matter are the small ones.
    for (width, height) in [(20, 6), (40, 8), (60, 10), (80, 24), (110, 30), (200, 60)] {
        for screen in [Screen::Trajectories, Screen::Transcript] {
            let mut app = loaded();
            app.screen = screen;
            app.set_transcript(transcript());
            let rendered = render(&mut app, width, height);
            assert!(
                !rendered.is_empty(),
                "{screen:?} rendered nothing at {width}x{height}"
            );
        }
    }
}

#[test]
fn scrolling_the_detail_pane_moves_the_document() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    app.pane = Pane::Detail;

    let top = render(&mut app, 80, 12);
    // The bound is only known once a frame has been laid out.
    assert!(
        app.detail_max_scroll > 0,
        "detail pane reported no overflow"
    );
    app.scroll_detail_to_bottom();
    let bottom = render(&mut app, 80, 12);
    assert_ne!(top, bottom, "scrolling to the bottom changed nothing");
}

#[test]
fn scrolling_never_runs_past_the_end() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    app.pane = Pane::Detail;
    render(&mut app, 80, 12);

    app.scroll_detail(10_000);
    let max = app.detail_max_scroll;
    assert_eq!(app.detail_scroll, max);
    render(&mut app, 80, 12);
    assert!(app.detail_scroll <= app.detail_max_scroll);
}

// ── the run-insight panel ───────────────────────────────────────────────────

/// A run the scanner has not reached: the panel must cost it nothing.
fn unscanned() -> Transcript {
    let mut transcript = transcript();
    transcript.summary.digest = None;
    transcript.summary.scan = None;
    transcript
}

#[test]
fn the_run_insight_panel_shows_the_digest_and_the_scan() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    assert_snapshot!(render(&mut app, 120, 36));
}

#[test]
fn the_run_insight_panel_renders_markdown_in_its_prose() {
    // The digest summary carries `**build tree**` and a backticked command.
    // Rendering it literally would put markup in a governance console.
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    app.pane = Pane::Insight;
    let rendered = render(&mut app, 120, 36);
    assert!(
        !rendered.contains("**build tree**"),
        "emphasis markers reached the screen:\n{rendered}"
    );
    assert!(rendered.contains("build tree"));
}

#[test]
fn an_unscanned_run_gives_every_row_back_to_the_transcript() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(unscanned());
    assert!(!app.has_insight());
    assert_snapshot!(render(&mut app, 120, 36));
}

/// Tab must never stop on a panel that is not drawn.
#[test]
fn tab_skips_the_insight_pane_when_the_run_has_none() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(unscanned());

    app.toggle_pane();
    assert_eq!(app.pane, Pane::Detail);
    app.toggle_pane();
    assert_eq!(app.pane, Pane::Tree);
}

#[test]
fn tab_cycles_through_the_insight_pane_when_the_run_has_one() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());

    app.toggle_pane();
    assert_eq!(app.pane, Pane::Insight);
    app.toggle_pane();
    assert_eq!(app.pane, Pane::Detail);
    app.toggle_pane();
    assert_eq!(app.pane, Pane::Tree);
}

/// The two reading panes are different documents; scrolling one must not move
/// the other, and stepping between events must not lose the reader's place in
/// the run summary.
#[test]
fn the_two_reading_panes_keep_separate_scroll_offsets() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    app.pane = Pane::Insight;
    render(&mut app, 80, 24);

    assert!(
        app.insight_max_scroll > 0,
        "the insight panel reported no overflow to scroll"
    );
    app.scroll_focused_to_bottom();
    assert!(app.insight_scroll > 0);
    assert_eq!(app.detail_scroll, 0, "scrolling the run moved the event");

    // Stepping to another event resets the event document, not the run one.
    let run_offset = app.insight_scroll;
    app.move_row(1);
    assert_eq!(app.insight_scroll, run_offset);
}

#[test]
fn the_insight_panel_survives_narrow_and_short_terminals() {
    for (width, height) in [(20, 6), (40, 8), (60, 10), (60, 24), (120, 36)] {
        let mut app = app();
        app.screen = Screen::Transcript;
        app.set_transcript(transcript());
        app.pane = Pane::Insight;
        let rendered = render(&mut app, width, height);
        assert!(
            !rendered.is_empty(),
            "insight panel rendered nothing at {width}x{height}"
        );
    }
}

#[test]
fn the_insight_panel_at_sixty_columns() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    app.pane = Pane::Insight;
    assert_snapshot!(render(&mut app, 60, 30));
}

/// Regression: focus must not survive onto a pane the new run does not draw.
/// Refreshing from a scanned run onto an unscanned one used to leave the cursor
/// on the insight pane, sending every scroll key to a document off screen.
#[test]
fn refreshing_onto_an_unscanned_run_moves_focus_off_the_insight_pane() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    app.pane = Pane::Insight;
    render(&mut app, 120, 36);
    app.scroll_focused_to_bottom();
    assert!(app.insight_scroll > 0);

    app.set_transcript(unscanned());

    assert!(!app.has_insight());
    assert_eq!(
        app.pane,
        Pane::Tree,
        "focus stayed on a pane that is not drawn"
    );
    assert_eq!(
        app.insight_scroll, 0,
        "the previous run's scroll offset carried onto a new run"
    );
}

/// A new run's summary opens at the top, like every other document here.
#[test]
fn opening_another_scanned_run_rewinds_the_insight_pane() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());
    app.pane = Pane::Insight;
    render(&mut app, 120, 36);
    app.scroll_focused_to_bottom();
    assert!(app.insight_scroll > 0);

    app.set_transcript(transcript());
    assert_eq!(app.insight_scroll, 0);
    assert_eq!(app.pane, Pane::Insight, "a run that has one keeps the pane");
}

/// Regression: a body too short to give the panel any content rows used to draw
/// it anyway — two border rows taken from the transcript to show nothing, under
/// a title claiming there was more below.
#[test]
fn a_short_terminal_gives_the_panel_no_rows_rather_than_an_empty_box() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());

    let rendered = render(&mut app, 80, 14);
    assert!(
        !rendered.contains("RUN · DIGEST"),
        "an empty insight box was drawn at 80x14:\n{rendered}"
    );
    // The rows it would have taken went to the transcript instead.
    assert!(rendered.contains("EVENT 1/3"));

    // And focus cannot be left on it.
    app.pane = Pane::Insight;
    render(&mut app, 80, 14);
    assert_eq!(app.pane, Pane::Detail);
    assert_eq!(app.insight_max_scroll, 0);
}

/// One row taller than the cutoff, the panel appears with content in it.
#[test]
fn the_panel_returns_once_the_terminal_can_hold_it() {
    let mut app = app();
    app.screen = Screen::Transcript;
    app.set_transcript(transcript());

    // One row past the cutoff: head (3) + footer (4, wrapped at this width)
    // leaves a body of 12, which is the panel's 6 plus the detail's 6.
    let rendered = render(&mut app, 80, 19);
    assert!(rendered.contains("RUN · DIGEST"), "{rendered}");
    assert!(
        rendered.contains("Build cleanup blocked by policy"),
        "the panel drew a border but no content:\n{rendered}"
    );
}

/// Regression: the insight variant of the key hints was once a second copy of
/// the array, and a hint added to one silently went missing from the other.
/// The two must differ in exactly the label `tab` carries, and nothing else.
#[test]
fn both_hint_variants_offer_the_same_keys() {
    let mut scanned = app();
    scanned.screen = Screen::Transcript;
    scanned.set_transcript(transcript());

    let mut unscanned_app = app();
    unscanned_app.screen = Screen::Transcript;
    unscanned_app.set_transcript(unscanned());

    let with = render(&mut scanned, 120, 36);
    let without = render(&mut unscanned_app, 120, 36);

    for key in ["↑↓/jk", "tab", "←→/hl", "n", "r", "esc", "q"] {
        assert!(
            with.contains(&format!("<{key}>")),
            "insight footer lost <{key}>:\n{with}"
        );
        assert!(
            without.contains(&format!("<{key}>")),
            "plain footer lost <{key}>:\n{without}"
        );
    }
    // The one intended difference.
    assert!(with.contains("tree · run · event"));
    assert!(without.contains("<tab> pane"));
}

// ── the run inspector ───────────────────────────────────────────────────────

/// The feed with the inspector open over the denied run: the digest, the scan,
/// the signals, and the policy that fired, none of which the table has a column
/// for at any width.
#[test]
fn the_run_inspector_shows_the_whole_scan_over_the_feed() {
    let mut app = loaded();
    app.move_run(1);
    app.toggle_inspect();
    assert_snapshot!(render(&mut app, 110, 24));
}

/// The inspector is the only place a sixty-column terminal can read the scan,
/// so it has to be legible at one.
#[test]
fn the_run_inspector_at_sixty_columns() {
    let mut app = loaded();
    app.move_run(1);
    app.toggle_inspect();
    assert_snapshot!(render(&mut app, 60, 20));
}

/// The three absences the inspector has to keep apart, none of which may read
/// as "this run scanned clean":
///
/// - a run still in flight, digested but not yet graded;
/// - a finished run the scanner never reached;
/// - and, in both cases, an eyebrow that names which one it is.
#[test]
fn the_inspector_names_which_absence_it_is_showing() {
    let mut in_progress = loaded();
    in_progress.move_run(2);
    in_progress.toggle_inspect();
    let in_flight = render(&mut in_progress, 110, 24);
    assert!(in_flight.contains("INTERIM DIGEST"), "{in_flight}");
    assert!(!in_flight.contains("· SCAN"), "{in_flight}");

    // The same row with the digest taken away: a finished run nothing looked
    // at. The panel has to say so rather than draw an empty box.
    let mut rows = feed();
    rows[2].digest = None;
    rows[2].status = "completed".into();
    let mut never_scanned = app();
    never_scanned.set_trajectories(rows);
    never_scanned.move_run(2);
    never_scanned.toggle_inspect();
    let never = render(&mut never_scanned, 110, 24);
    assert!(never.contains("NOT SCANNED"), "{never}");
    assert!(never.contains("scanner"), "{never}");
}

/// The footer has to describe the keys that are live. With the panel open the
/// movement keys scroll it, and a footer still promising `move` is a footer
/// that lies about what the next keypress will do.
#[test]
fn the_inspector_swaps_the_footer_for_its_own_keys() {
    let mut app = loaded();
    let feed = render(&mut app, 110, 20);
    assert!(feed.contains("<i>"));

    app.toggle_inspect();
    let open = render(&mut app, 110, 20);
    assert!(open.contains("<i/esc>"), "{open}");
    assert!(open.contains("scroll"), "{open}");
}

/// The feed can empty under an open inspector — a filter-narrowed live feed
/// whose last run leaves. The panel must close itself, footer included: hints
/// promising `scroll` over a panel that is not drawn send every arrow key to a
/// document nobody can see.
#[test]
fn the_inspector_closes_when_the_feed_empties_under_it() {
    let mut app = loaded();
    app.move_run(1);
    app.toggle_inspect();
    assert!(app.inspecting);

    app.set_trajectories(Vec::new());
    let rendered = render(&mut app, 110, 20);

    assert!(!app.inspecting);
    assert!(!rendered.contains("<i/esc>"), "{rendered}");
    assert!(rendered.contains("<i> inspect"), "{rendered}");
}

/// When a live update moves the selection onto a different run, the open panel
/// follows it — and rewinds. Inheriting the previous run's offset opens a short
/// summary scrolled past its own end.
#[test]
fn the_inspector_rewinds_when_the_selection_moves_under_it() {
    let mut app = loaded();
    app.move_run(1);
    app.toggle_inspect();
    render(&mut app, 110, 20);

    app.inspect_max_scroll = 10;
    app.scroll_inspect(6);
    assert_eq!(app.inspect_scroll, 6);

    // The run it was opened on leaves; the selection clamps onto another.
    let remaining = vec![feed()[0].clone()];
    app.set_trajectories(remaining);
    render(&mut app, 110, 20);

    assert!(app.inspecting);
    assert_eq!(app.selected_run().unwrap().id, "run-a");
    assert_eq!(app.inspect_scroll, 0);
}
