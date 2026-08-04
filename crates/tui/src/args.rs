//! Command-line arguments for `sondera tui`.

use clap::Args;

/// The console endpoint `sondera serve` binds by default.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:50051";

#[derive(Args, Debug, Clone)]
pub struct TuiArgs {
    /// Console gRPC endpoint to read from.
    ///
    /// This is the same address `sondera serve` binds; the TUI is a read-only
    /// client of it and opens no database of its own.
    #[arg(short, long, env = "SONDERA_CONSOLE_ENDPOINT", default_value = DEFAULT_ENDPOINT)]
    pub endpoint: String,

    /// Console filter applied to the run feed, in the AIP clause grammar:
    /// `agent=agents/{id}`, `decision=allow|deny|escalate`,
    /// `status=running|completed|failed|…`. Clauses are space-separated.
    #[arg(short, long, default_value = "")]
    pub filter: String,

    /// Read the open transcript as a page instead of tailing it.
    ///
    /// By default an opened run is followed over the console's event stream, so
    /// a run still in progress fills in as it happens. This turns that off and
    /// leaves refreshing to `r`.
    #[arg(long)]
    pub no_live: bool,
}

impl TuiArgs {
    /// Whether an opened transcript is tailed over `StreamTrajectory`.
    pub const fn live(&self) -> bool {
        !self.no_live
    }
}

impl Default for TuiArgs {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            filter: String::new(),
            no_live: false,
        }
    }
}
