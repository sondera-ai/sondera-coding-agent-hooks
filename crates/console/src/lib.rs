//! Console gRPC read surface for the Sondera coding-agent stack.
//!
//! Serves `sondera.console.v1.ConsoleService` — the agent and trajectory
//! collections — over the same local Turso database the harness writes to. The
//! service is generic over [`sondera_types::ReaderWriter`], so it is the
//! store traits, not this crate, that couple the two sides:
//!
//! ```text
//!   hooks ──▶ harness ──(TrajectoryReaderWriter::insert_event)──▶ ┌──────────┐
//!                                                                 │  Turso   │
//!   console UI ──▶ this service ──(Agent/TrajectoryReaderWriter)──▶└──────────┘
//! ```
//!
//! One store serves one machine, so no request carries a scope beyond the
//! resource it names.
//!
//! **No authentication.** Every caller sees the same data, exactly like the
//! harness gRPC service it shares a port with under `sondera serve`. Bind it to
//! loopback; it is not safe to expose on a public interface.
//!
//! # License
//!
//! MIT — see LICENSE in the repository root.

//! This crate owns the shapes the console needs that the domain does not have:
//! the AIP request grammar (`query`) and the trajectory sparkline
//! ([`sparkline`]), both composed from `sondera_types` domain types rather than
//! shadowing them.

mod handlers;
mod query;
mod service;
pub mod sparkline;
mod stream;

pub use handlers::{AgentView, ConsoleHandlers};
pub use query::{agent_filter, agents, limit, next_page_token, offset, trajectories};
pub use service::{ConsoleGrpcService, grpc_service, serve};
pub use stream::MappedStream;

#[cfg(test)]
mod tests;
