//! Dashboard-private storage: snapshot-copy isolation plus a read-only
//! typed SELECT surface.
//!
//! Only the [`ReadOnlyStore`] surface escapes this module — no `execute`,
//! no raw-SQL-accepting method, no connection accessor. The live
//! `trajectories.db` is never opened: all reads go through a
//! dashboard-owned snapshot copy.

mod read_only;
mod snapshot;

pub use read_only::{
    AdjudicatedRow, AggregateRow, ControlRow, DbState, ReadOnlyStore, StoreHealth,
};
