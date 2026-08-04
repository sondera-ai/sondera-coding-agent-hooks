//! Shared scaffolding for provider hook installers.
//!
//! Each provider crate owns its own installer — where its config file lives,
//! what scopes it supports, and the JSON shape its host agent expects. What
//! every one of them does *around* that is identical: locate the `sondera`
//! binary, back the config up, read it (or start empty), splice our hooks in or
//! out, write it back, and narrate the result on stderr. That surrounding flow
//! is [`HookConfigInstaller`], so a provider installer is reduced to the two
//! things that are genuinely provider-specific: the config path and the splice.
//!
//! Submodules:
//! - [`binary`] — locating the `sondera` binary and rendering it into a command
//!   for a specific shell.
//! - [`config`] — backup / read / write of the JSON config document.
//! - [`command`] — recognizing our own hook commands in an existing config.

pub mod binary;
pub mod command;
pub mod config;

use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::error::Result;
use binary::{ResolvedBinary, find_sondera_binary};
use config::ConfigDocument;

/// ANSI-wrapped stderr narration. Installers are interactive commands, so their
/// progress goes to stderr in the same voice across every provider.
mod style {
    pub fn heading(text: &str) {
        eprintln!("\x1b[32m{text}\x1b[0m");
        eprintln!("{}\n", "=".repeat(text.len()));
    }

    pub fn success(text: &str) {
        eprintln!("\x1b[32m✓ {text}\x1b[0m");
    }

    pub fn notice(text: &str) {
        eprintln!("\x1b[33m{text}\x1b[0m");
    }
}

/// The install/uninstall flow for one provider's JSON hook-config file.
///
/// Construct it with the provider's agent name and resolved config path, then
/// call [`install`](Self::install) or [`uninstall`](Self::uninstall) with the
/// closure that splices that provider's hooks in or out.
pub struct HookConfigInstaller {
    agent: &'static str,
    path: PathBuf,
    scope: String,
    next_steps: Vec<String>,
    remove_when: fn(&Map<String, Value>) -> bool,
    document: Box<dyn ConfigDocument>,
}

/// What an uninstall did to the config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    /// The backup taken before rewriting, if there was a config to back up.
    pub backup: Option<PathBuf>,
    /// Whether the config file itself was deleted, per
    /// [`remove_when`](HookConfigInstaller::remove_when), rather than rewritten.
    pub deleted: bool,
}

impl HookConfigInstaller {
    /// Target `path` as the config file for `agent` (a human-facing name such
    /// as `"Cursor"`), describing the destination to the user as `scope`.
    pub fn new(agent: &'static str, path: impl Into<PathBuf>, scope: impl Into<String>) -> Self {
        Self {
            agent,
            path: path.into(),
            scope: scope.into(),
            next_steps: Vec::new(),
            // A config we did not create is a config we do not delete.
            remove_when: |_| false,
            document: Box::new(config::Json),
        }
    }

    /// Read and write the config in `document`'s format instead of JSON.
    #[must_use]
    pub fn with_document(mut self, document: impl ConfigDocument + 'static) -> Self {
        self.document = Box::new(document);
        self
    }

    /// Guidance printed after a successful install, beyond the standard
    /// "restart `<agent>`" step.
    #[must_use]
    pub fn with_next_steps<S: Into<String>>(mut self, steps: impl IntoIterator<Item = S>) -> Self {
        self.next_steps = steps.into_iter().map(Into::into).collect();
        self
    }

    /// Delete the config file when what uninstall leaves behind satisfies
    /// `predicate`, rather than leaving a husk of a document.
    ///
    /// A predicate rather than a flag because "nothing left" is not always
    /// literally empty: Copilot's file keeps a `version` and a
    /// `disableAllHooks: false` that mean nothing on their own. Use
    /// [`Map::is_empty`] for a file that exists solely to hold hooks; omit it
    /// entirely for one shared with the host's own settings.
    #[must_use]
    pub fn remove_when(mut self, predicate: fn(&Map<String, Value>) -> bool) -> Self {
        self.remove_when = predicate;
        self
    }

    /// Back the config up, apply `splice`, and write it back — the file work
    /// alone, with no narration and no binary resolution.
    ///
    /// [`install`](Self::install) is this plus the story it tells the user.
    /// Providers call this directly from tests, where the binary and the config
    /// path are fixtures rather than whatever the host machine happens to have.
    ///
    /// Returns the backup path, if there was an existing config to back up.
    pub fn apply(
        &self,
        binary: &ResolvedBinary,
        splice: impl FnOnce(&mut Map<String, Value>, &ResolvedBinary),
    ) -> Result<Option<PathBuf>> {
        let backup = config::backup(&self.path)?;
        let mut hook_config = self.document.read(&self.path)?;
        splice(&mut hook_config, binary);
        self.document.write(&self.path, &hook_config)?;
        Ok(backup)
    }

    /// Locate the binary, back the config up, apply `splice`, and write it back.
    ///
    /// `splice` receives the config as read from disk (an empty object when it
    /// does not exist yet) and the resolved binary to bake into hook commands.
    /// It must be idempotent: a reinstall replaces our hooks rather than
    /// appending a second copy.
    pub fn install(
        &self,
        splice: impl FnOnce(&mut Map<String, Value>, &ResolvedBinary),
    ) -> Result<()> {
        style::heading(&format!("Sondera {} Hooks Installer", self.agent));

        let binary = find_sondera_binary()?;
        eprintln!("Binary found: {}", binary.display_path());
        eprintln!("Installing to {} scope", self.scope);
        eprintln!("Config file: {}\n", self.path.display());

        self.announce_backup(self.apply(&binary, splice)?);

        style::success(&format!("Installed hooks to {}", self.path.display()));
        eprintln!();
        eprintln!("Configuration details:");
        eprintln!("  - Hook executable: {}", binary.display_path());
        eprintln!("  - Debug logging: enabled (--verbose flag)");
        eprintln!();

        style::notice("Next steps:");
        eprintln!("  1. Restart {} to activate the hooks", self.agent);
        eprintln!("  2. Check hook logs in stderr output");
        for (index, step) in self.next_steps.iter().enumerate() {
            eprintln!("  {}. {step}", index + 3);
        }
        eprintln!();

        style::success("Installation complete!");
        Ok(())
    }

    /// Back the config up, apply `revoke`, and write it back — the file work
    /// alone, with no narration.
    ///
    /// [`uninstall`](Self::uninstall) is this plus the story it tells the user.
    /// Returns `None` when there was nothing of ours to remove, which includes
    /// the config not existing at all.
    pub fn revoke(
        &self,
        revoke: impl FnOnce(&mut Map<String, Value>) -> bool,
    ) -> Result<Option<Revoked>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let mut hook_config = self.document.read(&self.path)?;
        if !revoke(&mut hook_config) {
            return Ok(None);
        }

        // Backed up only now that there is a rewrite to protect: an uninstall
        // that finds nothing of ours should not litter the user's config
        // directory with copies.
        let backup = config::backup(&self.path)?;

        let deleted = (self.remove_when)(&hook_config);
        if deleted {
            std::fs::remove_file(&self.path).map_err(|source| {
                crate::error::HookError::context(
                    format!("failed to remove empty config {}", self.path.display()),
                    source,
                )
            })?;
        } else {
            self.document.write(&self.path, &hook_config)?;
        }
        Ok(Some(Revoked { backup, deleted }))
    }

    /// Back the config up, apply `revoke`, and write it back.
    ///
    /// `revoke` removes this provider's hooks from the config and returns
    /// whether it changed anything; returning `false` leaves the file untouched
    /// (beyond the backup) and reports that nothing was installed. Hooks that
    /// belong to other tools must be preserved.
    pub fn uninstall(&self, revoke: impl FnOnce(&mut Map<String, Value>) -> bool) -> Result<()> {
        style::heading(&format!("Sondera {} Hooks Uninstaller", self.agent));

        eprintln!("Uninstalling from {} scope", self.scope);
        eprintln!("Config file: {}\n", self.path.display());

        if !self.path.exists() {
            eprintln!("Config file does not exist. Nothing to uninstall.");
            return Ok(());
        }

        let Some(revoked) = self.revoke(revoke)? else {
            eprintln!("No Sondera hooks found in the config file.");
            return Ok(());
        };

        self.announce_backup(revoked.backup);
        if revoked.deleted {
            style::success(&format!(
                "Removed Sondera hooks and deleted the now-empty {}",
                self.path.display()
            ));
        } else {
            style::success(&format!(
                "Removed Sondera hooks from {}",
                self.path.display()
            ));
        }

        eprintln!();
        style::notice(&format!(
            "Note: Restart {} for changes to take effect.",
            self.agent
        ));
        Ok(())
    }

    fn announce_backup(&self, backup_path: Option<PathBuf>) {
        if let Some(backup_path) = backup_path {
            style::notice(&format!(
                "Backed up the existing config to: {}",
                backup_path.display()
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn installer(path: PathBuf) -> HookConfigInstaller {
        HookConfigInstaller::new("Test Agent", path, "user (test)")
    }

    #[test]
    fn uninstall_of_a_missing_config_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");

        installer(path.clone())
            .uninstall(|_| panic!("revoke must not run for a missing config"))
            .unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn uninstall_leaves_the_config_alone_when_nothing_was_installed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        std::fs::write(&path, r#"{"other":true}"#).unwrap();

        installer(path.clone()).uninstall(|_| false).unwrap();

        assert_eq!(
            config::read_object(&path).unwrap()["other"],
            json!(true),
            "a no-op revoke must not rewrite the file"
        );
    }

    #[test]
    fn uninstall_preserves_foreign_config_rather_than_deleting_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        std::fs::write(&path, r#"{"sondera":{},"my-linter":{}}"#).unwrap();

        installer(path.clone())
            .remove_when(Map::is_empty)
            .uninstall(|config| config.remove("sondera").is_some())
            .unwrap();

        let remaining = config::read_object(&path).unwrap();
        assert!(remaining.contains_key("my-linter"));
        assert!(!remaining.contains_key("sondera"));
    }

    #[test]
    fn uninstall_deletes_a_config_it_emptied_when_asked_to() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        std::fs::write(&path, r#"{"sondera":{}}"#).unwrap();

        installer(path.clone())
            .remove_when(Map::is_empty)
            .uninstall(|config| config.remove("sondera").is_some())
            .unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn uninstall_keeps_an_emptied_config_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"hooks":{}}"#).unwrap();

        // A shared settings file (Claude, Gemini) must survive uninstall — the
        // user's unrelated settings live in the same document.
        installer(path.clone())
            .uninstall(|config| config.remove("hooks").is_some())
            .unwrap();

        assert!(path.exists());
        assert!(config::read_object(&path).unwrap().is_empty());
    }

    #[test]
    fn uninstall_backs_the_config_up_before_rewriting_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        std::fs::write(&path, r#"{"sondera":{"PreToolUse":[]}}"#).unwrap();

        installer(path.clone())
            .uninstall(|config| config.remove("sondera").is_some())
            .unwrap();

        let backups: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".backup."))
            .collect();
        assert_eq!(backups.len(), 1, "expected one backup, got {backups:?}");
    }
}
