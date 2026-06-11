//! Injected configuration for runtime-verification monitors.
//!
//! The [`MonitorConfig`] struct is constructed (or deserialized) by the
//! caller and injected at monitor construction time. Disk content is parsed
//! via [`MonitorConfig::load_from_toml`]: every field carries a per-field
//! default, so partial or empty documents are valid; a malformed document is
//! an `Err` the caller makes fatal at startup.

use anyhow::Context;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Configuration for the untrusted-read / protected-write monitor.
///
/// Every field carries a serde per-field default so a partial (or empty)
/// document deserializes to the built-in defaults — mirrors the
/// `LabelTemplate` pattern in `crates/guardrails/ifc/src/label.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Shell command binaries whose output observations count as untrusted
    /// reads (`shell:curl` / `shell:wget` map to the binary names).
    #[serde(default = "default_shell_untrusted_commands")]
    pub shell_untrusted_commands: HashSet<String>,
    /// Tool names whose output observations count as untrusted reads.
    #[serde(default = "default_tool_untrusted_names")]
    pub tool_untrusted_names: HashSet<String>,
    /// Glob patterns identifying protected paths (secrets + infra/CI).
    #[serde(default = "default_protected_path_globs")]
    pub protected_path_globs: Vec<String>,
    /// `resumed_by` values accepted as approval signals. Matching is exact
    /// and case-sensitive; any `Control::Resumed` whose `resumed_by` is not
    /// in this set is NOT an approval (fail-closed).
    #[serde(default = "default_resume_approved_by")]
    pub resume_approved_by: HashSet<String>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            shell_untrusted_commands: default_shell_untrusted_commands(),
            tool_untrusted_names: default_tool_untrusted_names(),
            protected_path_globs: default_protected_path_globs(),
            resume_approved_by: default_resume_approved_by(),
        }
    }
}

impl MonitorConfig {
    /// Compile the protected-path globs into a [`GlobSet`].
    ///
    /// Construction-time `?` propagation: a malformed pattern fails here (at
    /// monitor construction / harness startup), never at observe time.
    pub fn build_glob_set(&self) -> anyhow::Result<GlobSet> {
        let mut builder = GlobSetBuilder::new();
        for pattern in &self.protected_path_globs {
            builder.add(Glob::new(pattern)?);
        }
        Ok(builder.build()?)
    }

    /// Parse a `MonitorConfig` from TOML content.
    ///
    /// Per-field serde defaults make partial — and entirely empty —
    /// documents valid. A parse error propagates as `Err` so the caller
    /// (`CedarPolicyHarness::build`) makes a present-but-malformed
    /// `monitor.toml` fatal at startup.
    pub fn load_from_toml(content: &str) -> anyhow::Result<Self> {
        toml::from_str(content).context("malformed monitor.toml")
    }
}

/// Default untrusted shell command binaries.
fn default_shell_untrusted_commands() -> HashSet<String> {
    ["curl", "wget"].iter().map(|s| s.to_string()).collect()
}

/// Default untrusted tool names.
fn default_tool_untrusted_names() -> HashSet<String> {
    ["mcp_fetch"].iter().map(|s| s.to_string()).collect()
}

/// Default approval allowlist: only a user-originated resume approves.
fn default_resume_approved_by() -> HashSet<String> {
    ["user"].iter().map(|s| s.to_string()).collect()
}

/// Default protected-path globs: secrets + infra/CI.
///
/// `**/`-prefixed so they match both relative and absolute paths (hook
/// adapters report absolute file paths): `**/.env` matches `.env`, `sub/.env`,
/// and `/abs/.env`. `/etc/**` is an absolute path kept verbatim.
fn default_protected_path_globs() -> Vec<String> {
    [
        "**/.env",
        "**/.env.*",
        "**/.ssh/**",
        "**/.aws/**",
        "**/*.pem",
        "**/id_rsa*",
        "**/.github/workflows/**",
        "**/Dockerfile*",
        "/etc/**",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_has_expected_untrusted_commands() {
        let config = MonitorConfig::default();
        assert!(config.shell_untrusted_commands.contains("curl"));
        assert!(config.shell_untrusted_commands.contains("wget"));
        assert_eq!(config.shell_untrusted_commands.len(), 2);
    }

    #[test]
    fn config_default_has_mcp_fetch() {
        let config = MonitorConfig::default();
        assert!(config.tool_untrusted_names.contains("mcp_fetch"));
        assert_eq!(config.tool_untrusted_names.len(), 1);
    }

    #[test]
    fn config_default_globs_match_env() {
        let set = MonitorConfig::default().build_glob_set().unwrap();
        assert!(set.is_match(".env"));
        assert!(set.is_match("id_rsa"));
        assert!(set.is_match("Dockerfile.prod"));
        // Subdirectory / absolute .env variants match via the `**/` patterns.
        assert!(set.is_match("deploy/.env.production"));
        assert!(set.is_match("/Users/dev/project/.env"));
    }

    #[test]
    fn config_default_globs_no_false_positives() {
        let set = MonitorConfig::default().build_glob_set().unwrap();
        assert!(!set.is_match("src/main.rs"));
        assert!(!set.is_match("README.md"));
    }

    #[test]
    fn config_globset_err_on_invalid_pattern() {
        let config = MonitorConfig {
            protected_path_globs: vec!["[invalid".to_string()],
            ..Default::default()
        };
        assert!(config.build_glob_set().is_err());
    }

    #[test]
    fn config_serde_empty_applies_defaults() {
        let config: MonitorConfig = serde_json::from_str("{}").unwrap();
        assert!(config.shell_untrusted_commands.contains("curl"));
        assert!(config.tool_untrusted_names.contains("mcp_fetch"));
        assert_eq!(config.protected_path_globs.len(), 9);
    }

    #[test]
    fn toml_full_document_returns_configured_values() {
        let content = r#"
            shell_untrusted_commands = ["nc"]
            tool_untrusted_names = ["browser_fetch"]
            protected_path_globs = ["secrets/**"]
            resume_approved_by = ["reviewer"]
        "#;
        let config = MonitorConfig::load_from_toml(content).unwrap();
        assert_eq!(config.shell_untrusted_commands.len(), 1);
        assert!(config.shell_untrusted_commands.contains("nc"));
        assert_eq!(config.tool_untrusted_names.len(), 1);
        assert!(config.tool_untrusted_names.contains("browser_fetch"));
        assert_eq!(config.protected_path_globs, vec!["secrets/**".to_string()]);
        assert_eq!(config.resume_approved_by.len(), 1);
        assert!(config.resume_approved_by.contains("reviewer"));
    }

    #[test]
    fn toml_partial_document_fills_defaults() {
        // Absent fields take the built-in defaults.
        let content = r#"resume_approved_by = ["user", "reviewer"]"#;
        let config = MonitorConfig::load_from_toml(content).unwrap();
        assert_eq!(config.resume_approved_by.len(), 2);
        assert!(config.resume_approved_by.contains("user"));
        assert!(config.resume_approved_by.contains("reviewer"));
        assert_eq!(
            config.shell_untrusted_commands,
            default_shell_untrusted_commands()
        );
        assert_eq!(config.tool_untrusted_names, default_tool_untrusted_names());
        assert_eq!(config.protected_path_globs, default_protected_path_globs());
    }

    #[test]
    fn toml_empty_document_equals_default() {
        let config = MonitorConfig::load_from_toml("").unwrap();
        let default = MonitorConfig::default();
        assert_eq!(
            config.shell_untrusted_commands,
            default.shell_untrusted_commands
        );
        assert_eq!(config.tool_untrusted_names, default.tool_untrusted_names);
        assert_eq!(config.protected_path_globs, default.protected_path_globs);
        assert_eq!(config.resume_approved_by, default.resume_approved_by);
    }

    #[test]
    fn toml_shipped_monitor_toml_roundtrips_to_default() {
        // The shipped policies/monitor.toml documents the built-in defaults
        // verbatim, so parsing it must equal MonitorConfig::default().
        let shipped = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../policies/monitor.toml"
        ));
        let config = MonitorConfig::load_from_toml(shipped).unwrap();
        let default = MonitorConfig::default();
        assert_eq!(
            config.shell_untrusted_commands,
            default.shell_untrusted_commands
        );
        assert_eq!(config.tool_untrusted_names, default.tool_untrusted_names);
        assert_eq!(config.protected_path_globs, default.protected_path_globs);
        assert_eq!(config.resume_approved_by, default.resume_approved_by);
    }

    #[test]
    fn toml_malformed_document_is_err() {
        // A present-but-malformed document must Err (fatal at startup).
        for malformed in [
            r#"resume_approved_by = "user""#, // wrong type: string, not array
            r#"resume_approved_by = ["user"#, // unterminated string
        ] {
            let err = MonitorConfig::load_from_toml(malformed).unwrap_err();
            assert!(
                format!("{err:#}").contains("malformed monitor.toml"),
                "error chain must carry the D-21 fatal signal, got: {err:#}"
            );
        }
    }
}
