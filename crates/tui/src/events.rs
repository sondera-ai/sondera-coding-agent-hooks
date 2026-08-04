//! The immediate-mode event loop.
//!
//! One `draw` per iteration renders the whole UI, then the loop parks on
//! whichever comes first: a key, a finished fetch, or a streamed event. Every
//! console call runs in a detached task and reports back over a channel, so a
//! slow or hung console never blocks a keystroke or a repaint.
//!
//! Both screens are live: the run feed consumes `StreamTrajectories`, and the
//! open transcript consumes `StreamTrajectory`. Each starts from a complete
//! snapshot so an empty stream still draws an honest empty state.

use crate::args::TuiArgs;
use crate::brand;
use crate::client::{ClientError, ConsoleClient};
use crate::model::{AgentIdentity, Sparkline, TrajectoryRow, Transcript};
use crate::state::{App, Load, Pane, Screen};
use crate::ui;
use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use ratatui::DefaultTerminal;
use sondera_schema::console_v1 as pb;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash as _, Hasher as _};
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A finished fetch or a streamed event, tagged with the request that asked
/// for it.
///
/// The generation is what makes fast navigation safe: arrowing A → B → C fires
/// three loads, and only the newest may install its result. Without it a slow
/// response for A would overwrite the transcript the user is actually looking
/// at, which reads as the UI showing the wrong run's events.
enum Loaded {
    Trajectories {
        generation: u64,
        result: Result<Vec<TrajectoryRow>, ClientError>,
    },
    /// The live feed opened after its initial snapshot landed.
    FeedLive { generation: u64 },
    /// One new or updated summary from the live feed.
    ///
    /// Boxed: a summary carries the scanner's whole digest and behavioral scan,
    /// which makes it much the largest variant, and every other message on this
    /// channel would otherwise be padded to its size.
    FeedUpdate {
        generation: u64,
        row: Box<TrajectoryRow>,
    },
    /// The live feed stopped. `error` is set when the console ended it with a
    /// status rather than closing it cleanly.
    FeedEnded {
        generation: u64,
        error: Option<ClientError>,
    },
    /// The agent roster the feed's identity columns are joined against.
    Agents {
        generation: u64,
        result: Result<Vec<(String, AgentIdentity)>, ClientError>,
    },
    /// Activity strips for the feed that was current when they were asked for.
    Sparklines {
        generation: u64,
        result: Result<Vec<(String, Sparkline)>, ClientError>,
    },
    Transcript {
        generation: u64,
        result: Box<Result<Transcript, ClientError>>,
    },
    /// The header of a run whose events are arriving on the stream.
    TranscriptHeader {
        generation: u64,
        header: Box<Transcript>,
    },
    /// One event from the live tail, at the raw grain the stream delivers.
    LiveEvent {
        generation: u64,
        event: Box<pb::TrajectoryEvent>,
    },
    /// The tail stopped. `error` is set when the console ended it with a
    /// status rather than closing it cleanly.
    LiveEnded {
        generation: u64,
        error: Option<ClientError>,
    },
    /// The tail could not be opened at all; this is the paged read that stood
    /// in for it, and why.
    NoLiveTail {
        generation: u64,
        result: Box<Result<Transcript, ClientError>>,
        reason: String,
    },
}

/// Hash an event's resource name, so the module a pulse lights is stable for a
/// given event rather than wandering between renders. Only per-process
/// stability is needed, which is exactly what `DefaultHasher` promises.
fn name_hash(name: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    hasher.finish()
}

pub struct EventLoop {
    client: ConsoleClient,
    filter: String,
    /// Whether an opened transcript is tailed rather than read as a page.
    live: bool,
    tx: mpsc::UnboundedSender<Loaded>,
    rx: mpsc::UnboundedReceiver<Loaded>,
    feed_generation: u64,
    transcript_generation: u64,
    /// Whether a batch of activity strips is awaiting an answer.
    sparklines_in_flight: bool,
    /// The run-feed stream, kept so refresh and shutdown can stop it.
    feed_task: Option<JoinHandle<()>>,
    /// The running transcript tail, kept so leaving the run can stop it. A
    /// stream nobody reads still costs the console a poll per interval.
    live_task: Option<JoinHandle<()>>,
}

impl EventLoop {
    pub fn new(client: ConsoleClient, args: &TuiArgs) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            client,
            filter: args.filter.clone(),
            live: args.live(),
            tx,
            rx,
            feed_generation: 0,
            transcript_generation: 0,
            sparklines_in_flight: false,
            feed_task: None,
            live_task: None,
        }
    }

    /// Run until the user quits.
    pub async fn run(&mut self, terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
        let mut keys = EventStream::new();
        self.load_trajectories();

        loop {
            terminal.draw(|frame| ui::draw(frame, app))?;
            if app.should_quit {
                self.stop_feed();
                self.stop_live();
                return Ok(());
            }

            tokio::select! {
                Some(event) = keys.next() => match event {
                    Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                        self.on_key(app, key);
                    }
                    // Resize and focus events need no state change: the next
                    // iteration redraws against the new area regardless.
                    Ok(_) => {}
                    Err(error) => {
                        app.status = Some(format!("terminal input error: {error}"));
                    }
                },
                Some(loaded) = self.rx.recv() => {
                    // A backlog replay arrives event by event. Draining what is
                    // already queued before drawing again turns a
                    // thousand-event run into one repaint instead of a
                    // thousand.
                    let mut batch = vec![loaded];
                    while let Ok(next) = self.rx.try_recv() {
                        batch.push(next);
                    }
                    self.on_batch(app, batch);
                }
                // Guarded, and the guard is the point: with nothing animating
                // this branch is disabled and the loop parks on exactly the two
                // futures above, so an idle TUI still costs nothing. `sleep`
                // rather than `interval` because a disabled `interval` banks
                // missed ticks and fires them in a burst when re-enabled.
                () = tokio::time::sleep(brand::FRAME), if app.brand.is_animating() => {
                    app.brand.advance();
                }
            }
        }
    }

    // ── fetches ─────────────────────────────────────────────────────────────

    fn load_trajectories(&mut self) {
        self.stop_feed();
        self.feed_generation += 1;
        let generation = self.feed_generation;
        let client = self.client.clone();
        let filter = self.filter.clone();
        let tx = self.tx.clone();
        self.feed_task = Some(tokio::spawn(async move {
            match client.trajectories(&filter).await {
                Ok(rows) => {
                    if tx
                        .send(Loaded::Trajectories {
                            generation,
                            result: Ok(rows),
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) => {
                    let _ = tx.send(Loaded::Trajectories {
                        generation,
                        result: Err(error),
                    });
                    return;
                }
            }

            let mut stream = match client.stream_trajectories(&filter).await {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = tx.send(Loaded::FeedEnded {
                        generation,
                        error: Some(error),
                    });
                    return;
                }
            };
            if tx.send(Loaded::FeedLive { generation }).is_err() {
                return;
            }

            loop {
                match stream.message().await {
                    Ok(Some(summary)) => {
                        if tx
                            .send(Loaded::FeedUpdate {
                                generation,
                                row: Box::new(TrajectoryRow::from(&summary)),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = tx.send(Loaded::FeedEnded {
                            generation,
                            error: None,
                        });
                        return;
                    }
                    Err(status) => {
                        let _ = tx.send(Loaded::FeedEnded {
                            generation,
                            error: Some(ClientError::from(status)),
                        });
                        return;
                    }
                }
            }
        }));
    }

    /// Re-read the whole agent roster, forgetting which agents have already been
    /// asked about — a full read supersedes every outstanding per-agent ask.
    fn reload_agents(&mut self, app: &mut App) {
        app.reset_agent_requests();
        self.fetch_agents();
    }

    /// Fetch the agent roster the feed's provider and platform columns are
    /// joined against.
    ///
    /// Its own request rather than part of the feed load: the roster is keyed by
    /// agent, not by run, so it is read once when a feed snapshot lands and
    /// again only when a streamed update names an agent it does not cover.
    fn fetch_agents(&mut self) {
        let generation = self.feed_generation;
        let client = self.client.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let result = client.agents().await;
            let _ = tx.send(Loaded::Agents { generation, result });
        });
    }

    /// Fetch the activity strips the feed is missing or has outstanding.
    ///
    /// Runs after the feed lands rather than alongside it: which strips are
    /// wanted is a property of the rows that just arrived. The console builds a
    /// strip by reading the run's whole event list, so asking only for what has
    /// moved keeps streamed updates cheap on a console with a long history.
    /// One batch is in flight at a time. An update landing on top of an
    /// unanswered batch is picked up as soon as that batch completes.
    fn load_sparklines(&mut self, app: &mut App) {
        if self.sparklines_in_flight {
            return;
        }
        let names = app.request_sparklines();
        if names.is_empty() {
            return;
        }
        self.sparklines_in_flight = true;
        let generation = self.feed_generation;
        let client = self.client.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let result = client.sparklines(&names).await;
            let _ = tx.send(Loaded::Sparklines { generation, result });
        });
    }

    /// Load one run's transcript, tailing it when live reads are enabled.
    fn load_transcript(&mut self, name: String) {
        self.stop_live();
        self.transcript_generation += 1;
        let generation = self.transcript_generation;
        let client = self.client.clone();
        let tx = self.tx.clone();

        if !self.live {
            tokio::spawn(async move {
                let result = client.transcript(&name).await;
                let _ = tx.send(Loaded::Transcript {
                    generation,
                    result: Box::new(result),
                });
            });
            return;
        }

        self.live_task = Some(tokio::spawn(async move {
            // The stream is opened before anything is drawn from it: a console
            // that cannot serve it — an older build, a run that has since
            // vanished — falls back to the paged read rather than leaving the
            // screen empty behind an error.
            let stream = match client.stream_transcript(&name).await {
                Ok(stream) => stream,
                Err(error) => {
                    let result = client.transcript(&name).await;
                    let _ = tx.send(Loaded::NoLiveTail {
                        generation,
                        result: Box::new(result),
                        reason: error.to_string(),
                    });
                    return;
                }
            };

            match client.transcript_header(&name).await {
                Ok(header) => {
                    let _ = tx.send(Loaded::TranscriptHeader {
                        generation,
                        header: Box::new(header),
                    });
                }
                Err(error) => {
                    let _ = tx.send(Loaded::Transcript {
                        generation,
                        result: Box::new(Err(error)),
                    });
                    return;
                }
            }

            let mut stream = stream;
            loop {
                match stream.message().await {
                    Ok(Some(event)) => {
                        if tx
                            .send(Loaded::LiveEvent {
                                generation,
                                event: Box::new(event),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = tx.send(Loaded::LiveEnded {
                            generation,
                            error: None,
                        });
                        return;
                    }
                    Err(status) => {
                        let _ = tx.send(Loaded::LiveEnded {
                            generation,
                            error: Some(ClientError::from(status)),
                        });
                        return;
                    }
                }
            }
        }));
    }

    /// Stop the run-feed stream and invalidate updates it already queued.
    fn stop_feed(&mut self) {
        if let Some(task) = self.feed_task.take() {
            task.abort();
            self.feed_generation += 1;
        }
    }

    /// Stop the running tail, if there is one.
    ///
    /// Aborting is not enough on its own: events the tail already queued are
    /// still in the channel, and they belong to a run the user has left. The
    /// generation bump is what makes the loop drop them.
    fn stop_live(&mut self) {
        if let Some(task) = self.live_task.take() {
            task.abort();
            self.transcript_generation += 1;
        }
    }

    /// Apply one drained batch.
    ///
    /// A run of streamed events is folded in together: the transcript re-anchors
    /// the cursor once per call, so applying a backlog one message at a time
    /// would cost a tree walk per event.
    fn on_batch(&mut self, app: &mut App, batch: Vec<Loaded>) {
        let mut live: Vec<pb::TrajectoryEvent> = Vec::new();
        for loaded in batch {
            match loaded {
                Loaded::LiveEvent { generation, event }
                    if generation == self.transcript_generation =>
                {
                    live.push(*event);
                }
                // Anything else can change which run is open, so the events
                // queued ahead of it have to land on the old one first.
                other => {
                    Self::flush_live(app, &mut live);
                    self.on_loaded(app, other);
                }
            }
        }
        Self::flush_live(app, &mut live);
    }

    fn flush_live(app: &mut App, events: &mut Vec<pb::TrajectoryEvent>) {
        // One pulse per batch, not per event: a backlog replay is drained into
        // a single repaint, so lighting a module per event would be invisible
        // anyway. The key is the event's resource name, so the same event
        // always lights the same module.
        if let Some(last) = events.last() {
            app.brand.on_event(name_hash(&last.name), Instant::now());
        }
        app.ingest_live_events(events);
        events.clear();
    }

    fn on_loaded(&mut self, app: &mut App, loaded: Loaded) {
        match loaded {
            Loaded::Trajectories { generation, result } => {
                if generation != self.feed_generation {
                    return;
                }
                match result {
                    Ok(rows) => {
                        app.set_trajectories(rows);
                        self.reload_agents(app);
                        self.load_sparklines(app);
                    }
                    Err(error) => {
                        self.feed_task = None;
                        app.trajectories_load = Load::Failed(error.to_string());
                    }
                }
            }
            Loaded::FeedLive { generation } => {
                if generation == self.feed_generation {
                    app.trajectories_load = Load::Live;
                }
            }
            Loaded::FeedUpdate { generation, row } => {
                if generation != self.feed_generation {
                    return;
                }
                app.upsert_trajectory(*row);
                // A hook reporting in for the first time mid-session brings an
                // agent the roster predates; without this its runs would read
                // as unidentified until the next manual refresh.
                if app.needs_agent_roster() {
                    self.fetch_agents();
                }
                self.load_sparklines(app);
            }
            Loaded::Agents { generation, result } => {
                if generation != self.feed_generation {
                    return;
                }
                match result {
                    Ok(agents) => app.set_agents(agents),
                    // The identity columns fall back to `—`, which is the honest
                    // reading: nobody has told this console who ran these runs.
                    // Said once, like the strips — repeating it after every
                    // update would be noise.
                    Err(error) => {
                        if !matches!(app.agents_load, Load::Failed(_)) {
                            app.status = Some(format!("agent roster unavailable: {error}"));
                        }
                        app.agents_load = Load::Failed(error.to_string());
                    }
                }
            }
            Loaded::FeedEnded { generation, error } => {
                if generation != self.feed_generation {
                    return;
                }
                self.feed_task = None;
                if app.trajectories_load == Load::Live {
                    app.trajectories_load = Load::Ready;
                }
                app.status = Some(match error {
                    Some(error) => format!("live feed stopped: {error} — press r to restart"),
                    None => "live feed stopped — press r to restart".to_string(),
                });
            }
            Loaded::Sparklines { generation, result } => {
                // Cleared whatever the answer was, and before the generation
                // check: a batch answering a feed the reader has moved past has
                // still finished, and leaving the flag set would stop the
                // column ever filling in again.
                self.sparklines_in_flight = false;
                if generation != self.feed_generation {
                    self.load_sparklines(app);
                    return;
                }
                match result {
                    Ok(strips) => {
                        app.set_sparklines(strips);
                        self.load_sparklines(app);
                    }
                    // A console too old to serve strips, or one that failed to
                    // build them, leaves the column empty. Saying so once is
                    // what keeps an empty column from reading as "this run did
                    // nothing"; repeating it after every update would be noise.
                    Err(error) => {
                        if !matches!(app.sparklines_load, Load::Failed(_)) {
                            app.status = Some(format!("activity strips unavailable: {error}"));
                        }
                        app.sparklines_load = Load::Failed(error.to_string());
                    }
                }
            }
            Loaded::Transcript { generation, result } => {
                if generation != self.transcript_generation {
                    return;
                }
                match *result {
                    Ok(transcript) => app.set_transcript(transcript),
                    Err(error) => app.transcript_load = Load::Failed(error.to_string()),
                }
            }
            Loaded::TranscriptHeader { generation, header } => {
                if generation != self.transcript_generation {
                    return;
                }
                app.begin_live_transcript(*header);
            }
            // Fresh events are batched in `on_batch`; one reaching here belongs
            // to a run the reader has left.
            Loaded::LiveEvent { generation, event } => {
                if generation == self.transcript_generation {
                    app.ingest_live_events(std::slice::from_ref(&event));
                }
            }
            Loaded::LiveEnded { generation, error } => {
                if generation != self.transcript_generation {
                    return;
                }
                // The task has already returned; only its handle is left, and
                // dropping it must not invalidate this very message.
                self.live_task = None;
                app.end_live();
                if let Some(error) = error {
                    app.status = Some(format!("live tail stopped: {error} — press r to reload"));
                }
            }
            Loaded::NoLiveTail {
                generation,
                result,
                reason,
            } => {
                if generation != self.transcript_generation {
                    return;
                }
                match *result {
                    Ok(transcript) => {
                        app.set_transcript(transcript);
                        app.status =
                            Some(format!("live tail unavailable ({reason}) — showing a page"));
                    }
                    Err(error) => app.transcript_load = Load::Failed(error.to_string()),
                }
            }
        }
    }

    // ── keys ────────────────────────────────────────────────────────────────

    fn on_key(&mut self, app: &mut App, key: KeyEvent) {
        // Ctrl-C quits from anywhere, including mid-filter, because a terminal
        // app that can trap it must still honour it.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            app.should_quit = true;
            return;
        }
        app.status = None;

        match app.screen {
            Screen::Trajectories => self.on_feed_key(app, key),
            Screen::Transcript => self.on_transcript_key(app, key),
        }
    }

    fn on_feed_key(&mut self, app: &mut App, key: KeyEvent) {
        // While the filter is being typed, every printable key is text. Letting
        // `q` quit mid-filter would be an unrecoverable surprise.
        if app.filter_editing {
            match key.code {
                KeyCode::Esc => {
                    app.filter_editing = false;
                    app.set_filter(String::new());
                }
                KeyCode::Enter => app.filter_editing = false,
                KeyCode::Backspace => {
                    let mut filter = app.filter.clone();
                    filter.pop();
                    app.set_filter(filter);
                }
                KeyCode::Char(c) => {
                    let filter = format!("{}{c}", app.filter);
                    app.set_filter(filter);
                }
                _ => {}
            }
            return;
        }

        // With the inspector open, the movement keys drive it. Esc closes it
        // rather than quitting: a key that both dismisses a panel and exits the
        // app depending on invisible state is how a reader loses their place.
        if app.inspecting {
            match key.code {
                KeyCode::Esc | KeyCode::Char('i') => app.close_inspect(),
                KeyCode::Char('q') => app.should_quit = true,
                KeyCode::Char('j') | KeyCode::Down => app.scroll_inspect(1),
                KeyCode::Char('k') | KeyCode::Up => app.scroll_inspect(-1),
                KeyCode::PageDown | KeyCode::Char(' ') => app.scroll_inspect(10),
                KeyCode::PageUp => app.scroll_inspect(-10),
                KeyCode::Char('n') => app.move_run_inspecting(1),
                KeyCode::Char('p') => app.move_run_inspecting(-1),
                KeyCode::Char('t') => app.toggle_theme(),
                KeyCode::Enter => {
                    if let Some(name) = app.selected_run().map(|row| row.name.clone()) {
                        app.open_transcript();
                        self.load_transcript(name);
                    }
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
            KeyCode::Char('j') | KeyCode::Down => app.move_run(1),
            KeyCode::Char('k') | KeyCode::Up => app.move_run(-1),
            KeyCode::PageDown => app.move_run(10),
            KeyCode::PageUp => app.move_run(-10),
            KeyCode::Home => app.move_run(isize::MIN / 2),
            KeyCode::End => app.move_run(isize::MAX / 2),
            KeyCode::Char('i') => app.toggle_inspect(),
            KeyCode::Char('/') => app.filter_editing = true,
            KeyCode::Char('r') => {
                app.trajectories_load = Load::Loading;
                app.brand.assemble(Instant::now());
                self.load_trajectories();
            }
            KeyCode::Char('t') => app.toggle_theme(),
            KeyCode::Enter => {
                if let Some(name) = app.selected_run().map(|row| row.name.clone()) {
                    app.open_transcript();
                    app.brand.assemble(Instant::now());
                    self.load_transcript(name);
                }
            }
            _ => {}
        }
    }

    fn on_transcript_key(&mut self, app: &mut App, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Esc => {
                // Leaving the run ends its tail: a stream nobody is reading is
                // a poll the console keeps paying for.
                self.stop_live();
                app.back_to_feed();
            }
            KeyCode::Tab | KeyCode::BackTab => app.toggle_pane(),
            KeyCode::Char('t') => app.toggle_theme(),
            KeyCode::Char('r') => {
                if let Some(name) = app.transcript_name().map(str::to_owned) {
                    app.transcript_load = Load::Loading;
                    app.brand.assemble(Instant::now());
                    self.load_transcript(name);
                }
            }
            KeyCode::Char('n') => app.jump_to_next_fire(),
            KeyCode::Char('s') => app.jump_to_next_signal(),
            KeyCode::Char('E') => app.expand_all(),
            KeyCode::Char('C') => app.collapse_all(),
            // Movement keys act on whichever pane has focus: stepping through
            // events on the left, scrolling the document on the right.
            _ => match app.pane {
                Pane::Tree => self.on_tree_key(app, key),
                // Both reading panes scroll the same way; `App` routes the
                // offset to whichever has focus.
                Pane::Insight | Pane::Detail => self.on_reading_key(app, key),
            },
        }
    }

    fn on_tree_key(&mut self, app: &mut App, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => app.move_row(1),
            KeyCode::Char('k') | KeyCode::Up => app.move_row(-1),
            KeyCode::PageDown => app.move_row(10),
            KeyCode::PageUp => app.move_row(-10),
            KeyCode::Home => app.move_row(isize::MIN / 2),
            KeyCode::End => app.move_row(isize::MAX / 2),
            KeyCode::Enter
            | KeyCode::Char(' ')
            | KeyCode::Char('h')
            | KeyCode::Char('l')
            | KeyCode::Left
            | KeyCode::Right => app.toggle_expanded(),
            _ => {}
        }
    }

    fn on_reading_key(&mut self, app: &mut App, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => app.scroll_focused(1),
            KeyCode::Char('k') | KeyCode::Up => app.scroll_focused(-1),
            KeyCode::PageDown | KeyCode::Char(' ') => app.scroll_focused(15),
            KeyCode::PageUp => app.scroll_focused(-15),
            KeyCode::Home | KeyCode::Char('g') => app.scroll_focused_to_top(),
            KeyCode::End | KeyCode::Char('G') => app.scroll_focused_to_bottom(),
            _ => {}
        }
    }
}
