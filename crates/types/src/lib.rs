//! Sondera domain types.
//!
//! Proto-free core data structures shared across this workspace: agents,
//! trajectories, policies, guardrails, the harness traits, and the domain error
//! types. The proto/gRPC wire DTOs and the domain ↔ proto conversions live in
//! the sibling `sondera-schema` crate, which depends on this one.
//!
//! This crate is deliberately free of service and wire vocabulary. There are no
//! resource names, page tokens, or per-consumer read models here — a store reads
//! and writes these domain types by bare id, and the shapes a particular
//! surface needs are composed from them at that surface (see `sondera-console`
//! for the console's own composites).

pub mod agent;
pub mod entity;
pub mod error;
pub mod guardrails;
pub mod harness;
pub mod page;
pub mod policy;
pub mod trajectory;

// Re-export commonly used types at the crate root for convenience.
pub use agent::*;
pub use entity::*;
pub use error::*;
// `guardrails::*` is re-exported transitively via `policy::*`.
pub use harness::*;
pub use page::*;
pub use policy::*;
pub use trajectory::*;

/// Convenience supertrait for stores covering every read surface — agents,
/// trajectories, and the scanner's enrichment. Any type implementing the
/// constituent traits satisfies this automatically via the blanket impl below.
pub trait ReaderWriter: AgentReaderWriter + TrajectoryReaderWriter + ScanReaderWriter {}

impl<T> ReaderWriter for T where T: AgentReaderWriter + TrajectoryReaderWriter + ScanReaderWriter {}
