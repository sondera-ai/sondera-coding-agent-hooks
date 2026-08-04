//! Infrastructure shared by every coding-agent hook adapter.
//!
//! Provider-specific code — event schemas, response envelopes, installers —
//! lives in the per-provider crates alongside `crates/hooks/core`. What stays
//! here is what more than one provider needs: the fail-closed run loop, the
//! hook I/O plumbing, the shared error type and its diagnostics, and the
//! installer scaffolding.
//!
//! Hooks have exactly one error type, [`error::HookError`]. It carries the
//! failure *and* the classification that decides how the hook degrades, so no
//! caller reconstructs a failure mode by inspecting message text.

pub mod adjudication;
pub mod common;
pub mod content;
pub mod diagnostics;
pub mod error;
pub mod event;
pub mod install;
pub mod mention;
pub mod response;
pub mod runner;
pub mod tool;

// The shared hook I/O plumbing (formerly the `sondera-common` crate) now lives
// in `common`; re-export it at the crate root so hooks use `sondera_hooks::…`.
pub use common::{
    agent_id, connect_harness, flush_output, init_tracing, json_string_field, load_sondera_env,
    output_response, read_stdin, sondera_env_path,
};
pub use diagnostics::{HOOK_DEBUG_ENV_VAR, hook_debug_enabled};
