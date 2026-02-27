//! Sondera Copilot hooks application modules.

pub mod hooks;
pub mod install;
pub mod response;
pub mod types;

pub use hooks::Hooks;
pub use install::{install_hooks, uninstall_hooks};
pub use types::*;
