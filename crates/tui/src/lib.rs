//! Terminal reading view over the Sondera console.
//!
//! Two screens, both read-only:
//!
//! - **Trajectories** — the run feed: verdict, agent, status, size, duration,
//!   and, where the terminal is wide enough to carry one, an activity strip
//!   showing what the agent did over the run with policy fires marked in place.
//!   Where the scanner has graded a run, the feed also carries its severity and
//!   outcome, and on an ultrawide terminal the provider and platform behind the
//!   agent, joined from the console's agent roster. `i` opens a run inspector
//!   with the agent's identity plus the whole digest and behavioral scan —
//!   phases, files changed, signals, and the policies that fired — at any width,
//!   including the ones too narrow for those columns.
//! - **Trajectory Events** — one run's transcript, as a tree of steps on the
//!   left and the full selected event on the right, rendered as markdown, shell,
//!   source, or JSON depending on what the event actually holds.
//!
//! Three claims are kept apart throughout, because they answer different
//! questions and a reader who conflates them acts on the wrong one: the policy
//! **verdict**, the harness lifecycle **status**, and the trajectory scanner's
//! **outcome** and severity. A run can complete, be allowed at every step, and
//! still have failed its task with `high` signals against it.
//!
//! # Limits
//!
//! The scanner's `event_indices` and `evidence_indices` — which events a phase
//! spans, which events evidence a run-level signal — are not rendered, because
//! this surface cannot resolve them. They index the raw trajectory ledger the
//! scanner was handed, which includes the `Adjudicated` and `Scanned` control
//! events that `ListTrajectoryEvents` folds away, and the offset between the two
//! lists depends on how much governance preceded each event. Resolving them
//! needs the console to project spans as event ids; until it does, phases render
//! as sizes rather than as bands, and `s` steps through *per-event* signals,
//! which the console folds onto the right event by construction.
//!
//! The crate is a pure gRPC client of `sondera.console.v1`. It opens no
//! database and evaluates no policy: everything on screen is what
//! `sondera serve` reports, which is what keeps this view from ever disagreeing
//! with the console it is a view of.
//!
//! ```no_run
//! # async fn example() -> color_eyre::eyre::Result<()> {
//! sondera_tui::run(sondera_tui::TuiArgs::default()).await
//! # }
//! ```
//!
//! # License
//!
//! MIT — see LICENSE in the repository root.

pub mod args;
pub mod brand;
pub mod client;
pub mod content;
pub mod events;
pub mod model;
pub mod render;
pub mod state;
pub mod terminal;
pub mod theme;
pub mod ui;

pub use args::TuiArgs;
pub use client::ConsoleClient;
pub use state::App;
pub use theme::Theme;

use color_eyre::eyre::{Result, eyre};

/// Connect to the console and run the interactive UI until the user quits.
///
/// The connection is established *before* the terminal enters raw mode, so an
/// unreachable console prints a plain, readable error instead of flashing an
/// alternate screen and vanishing.
pub async fn run(args: TuiArgs) -> Result<()> {
    terminal::install_hooks()?;

    let client = ConsoleClient::connect(&args.endpoint)
        .await
        .map_err(|error| eyre!("{error}"))?;

    let mut session = terminal::Session::enter()?;
    let mut app = App::new(Theme::detect());
    let mut event_loop = events::EventLoop::new(client, &args);

    let outcome = event_loop.run(session.terminal_mut(), &mut app).await;
    session.restore();
    outcome
}
