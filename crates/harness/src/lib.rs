//! Sondera Harness — policy adjudication engine and gRPC transport for AI
//! coding agents.
//!
//! This crate has two layers, gated by Cargo features so that hook binaries can
//! depend on the light client without linking the full engine:
//!
//! - **`client`** (lightweight): the domain types re-exported from
//!   [`sondera_types`], the [`HarnessClient`] trait, and [`HarnessGrpcClient`] —
//!   a no-auth gRPC client that speaks the `sondera.harness.v1` protocol. This
//!   is what `crates/hooks/*` consume (aliased as `sondera_harness_client`).
//! - **`engine`** / **`server`**: [`CedarPolicyHarness`], the in-process Cedar
//!   authorization engine, and [`rpc`], the tonic gRPC server that fronts it.
//!   The server converts wire [`sondera_schema`] events into
//!   [`sondera_types::Event`] domain values (via the DTO conversions) and hands
//!   them to the engine, which implements [`sondera_types::Harness`].
//!
//! # License
//!
//! MIT — see LICENSE in the repository root.

// The domain types and the `Harness` / `HarnessClient` traits live in
// `sondera-types`. Re-export them at the crate root so `sondera_harness::Event`
// (and, via the `sondera_harness_client` alias, `sondera_harness_client::Event`)
// resolve, and so internal engine code can keep referring to `crate::Event`.
pub use sondera_types as types;
pub use sondera_types::*;

// The wire-level decode-rejection code, re-exported for diagnostics and log
// pivots. It is a `&'static str`, so this leaks no proto types into consumers.
pub use sondera_schema::UNNORMALIZED_EVENT_MARKER;

// gRPC client — lightweight surface consumed by crates/hooks/*.
//
// `HarnessClientError` is `sondera_types::HarnessClientError`, already in scope
// via the glob above: there is one client error type in the workspace, so a
// caller matches its variants rather than reconciling two taxonomies.
#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
pub use client::{
    HarnessGrpcClient, connect_harness, connect_harness_for_hook,
    connect_harness_for_hook_agent_id, default_endpoint,
};

// Cedar policy engine compatibility surface. New code can depend on
// `sondera-cedar-policy` directly; these re-exports keep existing embedders
// source-compatible.
#[cfg(feature = "engine")]
pub use sondera_cedar_policy::{
    CedarPolicyHarness, EntityBuilder, HarnessSettings, Label, PolicyAssets, Settings,
    SettingsError, Trajectory, euid, json_to_restricted_expr,
};

// Local storage now lives in `sondera-storage`, shared with the console gRPC
// service so both sides read and write the same database without depending on
// each other. Re-exported here so `sondera_harness::TrajectoryStore` keeps
// resolving for existing callers.
#[cfg(feature = "engine")]
pub use sondera_storage::{TrajectoryStore, get_default_db_path};

// gRPC server fronting the engine.
#[cfg(feature = "server")]
pub mod rpc;

// Background trajectory scanning, dispatched from the gRPC server after each
// adjudication. The `ScanDispatch` seam is always present with `server`; the
// scanner-backed implementation behind it needs the `scanner` feature.
#[cfg(feature = "server")]
pub mod scan;
