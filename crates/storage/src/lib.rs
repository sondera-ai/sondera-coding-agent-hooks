//! Local Turso-backed storage for the Sondera coding-agent stack.
//!
//! One store lives here, persisted under `~/.sondera` by default:
//! [`TrajectoryStore`], a single database holding the trajectory event ledger,
//! the agent registry projected from it, and the Cedar entities the policy
//! engine evaluates against. It implements every store trait —
//! [`sondera_types::TrajectoryReaderWriter`],
//! [`sondera_types::AgentReaderWriter`], and (behind the `cedar` feature)
//! [`sondera_types::EntityReaderWriter`] — which is what lets the harness
//! (writing events and entities on the adjudication path) and the console gRPC
//! service (reading the projections) share one database without either
//! depending on the other. The console builds without `cedar`, so it never
//! links `cedar-policy`.
//!
//! [`file`](mod@file) holds the JSONL trajectory mirror the harness writes alongside the
//! database, and the `~/.sondera` directory resolution the store uses.

pub mod file;
mod turso;

pub use file::{get_storage_dir, write_trajectory_event};
pub use turso::{TrajectoryStore, get_default_db_path};
