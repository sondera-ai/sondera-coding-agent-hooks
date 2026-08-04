//! Terminal entry and exit.
//!
//! [`Session`] is an RAII guard: raw mode and the alternate screen are entered
//! on construction and restored on drop, so every return path — including the
//! error paths and a panic unwinding through the event loop — leaves the user's
//! terminal usable.
//!
//! `ratatui::init()` installs its own terminal-restoring panic hook. The
//! `color_eyre` hook must therefore be installed *before* it, so the pretty
//! report prints after the screen has been handed back rather than into the
//! alternate buffer the user will never see again.

use color_eyre::eyre::Result;
use ratatui::DefaultTerminal;
use std::sync::Once;

static HOOKS: Once = Once::new();

/// Install the error/panic reporting hooks. Idempotent.
pub fn install_hooks() -> Result<()> {
    let mut result = Ok(());
    HOOKS.call_once(|| {
        result = color_eyre::config::HookBuilder::default()
            .panic_section("Sondera restored the terminal before printing this panic.")
            .install();
    });
    result
}

/// A live terminal, restored on drop.
pub struct Session {
    terminal: DefaultTerminal,
    restored: bool,
}

impl Session {
    /// Enter raw mode and the alternate screen.
    pub fn enter() -> Result<Self> {
        install_hooks()?;
        Ok(Self {
            terminal: ratatui::init(),
            restored: false,
        })
    }

    pub fn terminal_mut(&mut self) -> &mut DefaultTerminal {
        &mut self.terminal
    }

    /// Restore the terminal. Safe to call more than once.
    pub fn restore(&mut self) {
        if !self.restored {
            ratatui::restore();
            self.restored = true;
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.restore();
    }
}
