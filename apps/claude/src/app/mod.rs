//! Sondera Claude Code hooks application modules.

pub mod hooks;
pub mod install;
pub mod response;
pub mod types;

pub use hooks::Hooks;
pub use install::{InstallScope, install_hooks, uninstall_hooks};
