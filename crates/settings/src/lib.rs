//! Unified `.sondera` configuration directory.
//!
//! Everything the harness loads — settings and policy assets alike — lives in a
//! `.sondera` directory. Two scopes are searched, nearest first:
//!
//! 1. **Project** — the nearest `.sondera/`, located by walking up from the
//!    working directory (like `.git`), so any subdirectory of a checkout picks
//!    up the same one.
//! 2. **User** — `~/.sondera/`, alongside the `~/.sondera/env` the hooks
//!    already read.
//!
//! Each directory holds the same known layout, every entry optional:
//!
//! ```text
//! .sondera/
//! ├── sondera.toml          # these settings
//! ├── ifc.toml              # data-sensitivity label templates
//! ├── policies.toml         # policy-category classifier templates
//! └── policies/cedar/       # Cedar rules + schema (walked recursively)
//! ```
//!
//! `sondera.toml` merges key by key, project winning. The three policy assets
//! resolve *independently* and nearest-wins ([`PolicyAssets::resolve`]): a
//! project that ships only `ifc.toml` still inherits `policies/cedar/` from
//! `~/.sondera`.
//!
//! Every settings field is optional in every scope; anything neither file sets
//! falls back to built-in values. The two in-loop model guardrails — the
//! data-sensitivity classifier over `ifc.toml` and the policy-category
//! classifier over `policies.toml` — are both disabled unless
//! `[guardrails] enabled = true`, and their configured provider defaults to a
//! local Ollama server. A *missing* file is not an error — an
//! *unparseable* one is, including unknown keys, so a mistyped setting in a
//! governance config is reported rather than silently ignored.
//!
//! This crate is deliberately free of engine vocabulary: it resolves paths and
//! model configuration and nothing else, so the Cedar engine, the trajectory
//! scanner, and the CLI can each read the same file without depending on one
//! another.
//!
//! # Example
//!
//! Pointing both guardrails at a local vLLM server, which serves the OpenAI API:
//!
//! ```toml
//! [harness]
//! addr = "127.0.0.1:50051"
//!
//! [guardrails]
//! enabled = true
//! provider = "openai"
//! base_url = "http://localhost:8000/v1"
//! model = "openai/gpt-oss-safeguard-20b"
//! temperature = 0.0
//!
//! # Optional: override a single guardrail. A key set on the specific table
//! # wins over the shared one even if the shared value came from the nearer
//! # file — specificity beats proximity.
//! [guardrails.policy]
//! model = "openai/gpt-oss-safeguard-120b"
//! ```
//!
//! `enabled` gates both classifiers together; the per-guardrail tables are how
//! they get sized separately. That matters most for the policy classifier, which
//! spends one call per template in `policies.toml`, so its cost on an
//! adjudication the agent is blocked on grows as templates are added.
//!
//! The credential is better supplied out of band, since a project file is
//! usually checked in: [`API_KEY_ENV`] overrides `api_key` from either file.
//!
//! # Trajectory scanner
//!
//! The scanner is post-hoc log analysis, not enforcement: it runs off the
//! adjudication path and costs one model call per scanned event. It is
//! therefore opt-in, and its `[scanner]` table stands on its own rather than
//! inheriting from `[guardrails]` — enforcement and analysis are sized and
//! priced differently, and silently pointing an every-event scanner at the
//! guardrail model is not a default anyone should get by accident:
//!
//! ```toml
//! [scanner]
//! enabled = true
//! provider = "vertexai"
//! location = "global"
//! model = "gemini-3.5-flash-lite"
//! ```
//!
//! # Google Cloud Vertex AI
//!
//! Vertex AI is the one provider addressed by project and location rather than
//! by URL and key, so it reads `project`/`location` and ignores `base_url` and
//! `api_key` entirely. It authenticates with Application Default Credentials
//! (`gcloud auth application-default login`, or a service account on GCP), which
//! means no secret belongs in this file at all:
//!
//! ```toml
//! [guardrails]
//! enabled = true
//! provider = "vertexai"
//! project = "my-gcp-project"
//! location = "us-central1"       # optional; defaults to `global`
//! model = "gemini-2.5-flash"
//! temperature = 0.0
//! ```
//!
//! Both keys fall back to the `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION`
//! environment variables when unset, so a deployment that already exports them
//! need only name the provider and model. The project has no default beyond
//! that: with neither the key nor the variable set, the harness fails at startup
//! rather than silently picking one.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sondera_information_flow_control::DataModelConfig;
use sondera_policy::PolicyModelConfig;
use sondera_provider::Provider;
use sondera_trajectory::ScannerConfig;

/// Directory holding Sondera configuration, in both the project and user scope.
pub const CONFIG_DIR: &str = ".sondera";

/// File name of the unified configuration within [`CONFIG_DIR`].
pub const CONFIG_FILE: &str = "sondera.toml";

/// Data-sensitivity label templates, within a [`CONFIG_DIR`].
pub const IFC_TEMPLATE_FILE: &str = "ifc.toml";

/// Policy-guardrail templates, within a [`CONFIG_DIR`].
pub const POLICY_TEMPLATE_FILE: &str = "policies.toml";

/// Directory of Cedar rules and schema, within a [`CONFIG_DIR`].
///
/// Two components rather than a `"policies/cedar"` literal so the separator is
/// the host's.
pub const CEDAR_DIR: [&str; 2] = ["policies", "cedar"];

/// Environment variable overriding the guardrail provider credential.
///
/// Takes precedence over `api_key` in either file, so the secret need not live
/// in a checked-in project config.
pub const API_KEY_ENV: &str = "SONDERA_GUARDRAIL_API_KEY";

/// Environment variable overriding the trajectory scanner credential.
///
/// Separate from [`API_KEY_ENV`] because the scanner is routinely pointed at a
/// different provider than the guardrails; a deployment that shares one
/// credential can export both to the same value.
pub const SCANNER_API_KEY_ENV: &str = "SONDERA_SCANNER_API_KEY";

/// Failure to load or interpret a `sondera.toml`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SettingsError {
    /// The file exists but could not be read.
    #[error("failed to read {}: {source}", path.display())]
    Read {
        /// The file being read.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid TOML, or carries a key this version does not know.
    #[error("failed to parse {}: {source}", path.display())]
    Parse {
        /// The file being parsed.
        path: PathBuf,
        /// The underlying TOML failure.
        #[source]
        source: Box<toml::de::Error>,
    },
    /// A `provider` value does not name a known provider.
    #[error("{}: unknown provider {value:?}; expected one of: {expected}", path.display())]
    Provider {
        /// The file the value came from.
        path: PathBuf,
        /// The unrecognized value.
        value: String,
        /// Comma-separated list of accepted provider names.
        expected: String,
    },
    /// A `harness.addr` value is not a socket address.
    #[error("{}: invalid harness.addr {value:?}: {source}", path.display())]
    Addr {
        /// The file the value came from.
        path: PathBuf,
        /// The unrecognized value.
        value: String,
        /// The underlying parse failure.
        #[source]
        source: std::net::AddrParseError,
    },
    /// An explicitly requested config directory does not exist.
    ///
    /// Only an *explicit* directory is an error; discovery finding none is
    /// reported as [`SettingsError::NoConfigDir`] when an asset is needed.
    #[error("config directory does not exist: {}", path.display())]
    MissingConfigDir {
        /// The directory that was asked for.
        path: PathBuf,
    },
    /// No `.sondera` directory was found in either scope.
    #[error(
        "no {CONFIG_DIR} directory found: looked for {CONFIG_DIR}/ at or above the working \
         directory, then ~/{CONFIG_DIR}/"
    )]
    NoConfigDir,
    /// A required policy asset is absent from every config directory.
    #[error(
        "no {asset} found in any config directory (searched: {})",
        searched.iter().map(|path| path.display().to_string()).collect::<Vec<_>>().join(", ")
    )]
    MissingAsset {
        /// The asset's path relative to a config directory, e.g. `ifc.toml`.
        asset: String,
        /// Every candidate that was checked, nearest first.
        searched: Vec<PathBuf>,
    },
}

// ============================================================================
// Resolved settings
// ============================================================================

/// Fully resolved settings, with defaults applied.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Harness server settings.
    pub harness: HarnessSettings,
    /// Whether optional in-loop model guardrails are enabled.
    pub guardrails_enabled: bool,
    /// Provider configuration for the data-sensitivity (IFC) guardrail.
    pub data_model: DataModelConfig,
    /// Provider configuration for the policy-category guardrail, which fills
    /// `context.policy` from the templates in `policies.toml`.
    pub policy_model: PolicyModelConfig,
    /// Trajectory scanner configuration. Disabled unless `[scanner] enabled`
    /// says otherwise.
    pub scanner: ScannerSettings,
    /// `sondera.toml` files that contributed, nearest first. Empty when none
    /// were found.
    pub sources: Vec<PathBuf>,
    /// Config directories that exist, nearest first: the project `.sondera`
    /// before `~/.sondera`. Policy assets are resolved against these in order,
    /// so the first match wins. Empty when neither scope has one.
    pub config_dirs: Vec<PathBuf>,
}

/// Harness server settings.
///
/// Stays `None` when unset so the caller can apply its own precedence — a CLI
/// flag should beat the file, which should beat the built-in default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HarnessSettings {
    /// Address the gRPC server binds to.
    pub addr: Option<SocketAddr>,
}

/// Trajectory scanner settings.
///
/// The scanner is background enrichment, so [`ScannerSettings::enabled`] gates
/// the whole thing: a deployment that never writes a `[scanner]` table gets no
/// scanner and pays for no model calls. The model configuration itself is the
/// scanner crate's own [`ScannerConfig`], resolved here the same way the two
/// guardrail configs are.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScannerSettings {
    /// Whether to run the trajectory scanner at all.
    pub enabled: bool,
    /// Provider, endpoint, and model for every scan granularity.
    pub model: ScannerConfig,
}

impl Settings {
    /// Load and merge the project and user configuration for this process.
    ///
    /// The project directory is located by walking up from the current working
    /// directory. Both scopes are optional.
    ///
    /// # Errors
    ///
    /// Returns [`SettingsError`] if a file that exists cannot be read, parsed,
    /// or interpreted. A missing file is not an error.
    pub fn load() -> Result<Self, SettingsError> {
        Self::load_with_config_dir(None)
    }

    /// [`Settings::load`], with the project scope pinned to `config_dir`
    /// instead of discovered from the working directory.
    ///
    /// `~/.sondera` still applies underneath, so an explicit directory that
    /// carries only some of the policy assets inherits the rest. Backs
    /// `sondera serve --config-dir`.
    ///
    /// # Errors
    ///
    /// As [`Settings::load`], plus [`SettingsError::MissingConfigDir`] if
    /// `config_dir` is given and is not a directory — an operator who names a
    /// directory explicitly should hear that it is absent rather than silently
    /// get the user scope.
    pub fn load_with_config_dir(config_dir: Option<&Path>) -> Result<Self, SettingsError> {
        let project = match config_dir {
            Some(dir) if !dir.is_dir() => {
                return Err(SettingsError::MissingConfigDir {
                    path: dir.to_path_buf(),
                });
            }
            Some(dir) => Some(dir.to_path_buf()),
            None => std::env::current_dir()
                .ok()
                .as_deref()
                .and_then(find_project_config_dir),
        };
        Self::load_dirs(dirs::home_dir().map(user_config_dir), project)
    }

    /// [`Settings::load`] against explicit search roots.
    ///
    /// Exposed so tests — and embedders that manage their own layout — can drive
    /// discovery without depending on the ambient home directory or working
    /// directory. `home` is a home *directory*, not a `.sondera` inside one.
    ///
    /// # Errors
    ///
    /// As [`Settings::load`].
    pub fn load_from(
        home: Option<&Path>,
        project_start: Option<&Path>,
    ) -> Result<Self, SettingsError> {
        Self::load_dirs(
            home.map(user_config_dir),
            project_start.and_then(find_project_config_dir),
        )
    }

    /// Merge the two scopes, given each one's `.sondera` directory.
    fn load_dirs(user: Option<PathBuf>, project: Option<PathBuf>) -> Result<Self, SettingsError> {
        // A directory that does not exist contributes nothing; an explicit one
        // was already rejected by the caller.
        let user = user.filter(|dir| dir.is_dir());
        let project = project.filter(|dir| dir.is_dir());

        let settings_file = |dir: &PathBuf| Some(dir.join(CONFIG_FILE)).filter(|p| p.is_file());
        let user_path = user.as_ref().and_then(settings_file);
        let project_path = project.as_ref().and_then(settings_file);

        // Each file is validated against its own path, so an error names the
        // file that actually set the offending value.
        let user_layer = load_layer(user_path.as_deref())?;
        let project_layer = load_layer(project_path.as_deref())?;

        let sources = [project_path, user_path].into_iter().flatten().collect();
        let config_dirs = [project, user].into_iter().flatten().collect();
        Ok(Self::from_layer(
            project_layer.or(user_layer),
            sources,
            config_dirs,
        ))
    }

    /// Resolve the policy assets against [`Settings::config_dirs`].
    ///
    /// # Errors
    ///
    /// As [`PolicyAssets::resolve`].
    pub fn policy_assets(&self) -> Result<PolicyAssets, SettingsError> {
        PolicyAssets::resolve(&self.config_dirs)
    }

    /// Apply the built-in defaults to a fully merged layer.
    fn from_layer(layer: Layer, sources: Vec<PathBuf>, config_dirs: Vec<PathBuf>) -> Self {
        // A key on a specific guardrail table wins over the shared one.
        let data = layer.data.or(layer.shared.clone());
        let policy = layer.policy.or(layer.shared);
        let api_key = env_override(API_KEY_ENV);

        // The two guardrail crates carry structurally identical configs;
        // resolve each against its own crate's defaults so neither is pinned to
        // the other's.
        let data_defaults = DataModelConfig::default();
        let data_provider = data.provider.unwrap_or(data_defaults.provider);
        let data_base_url = resolve_base_url(
            data.base_url,
            data_provider,
            data_defaults.provider,
            data_defaults.base_url,
        );
        let policy_defaults = PolicyModelConfig::default();
        let policy_provider = policy.provider.unwrap_or(policy_defaults.provider);
        let policy_base_url = resolve_base_url(
            policy.base_url,
            policy_provider,
            policy_defaults.provider,
            policy_defaults.base_url,
        );

        Self {
            harness: HarnessSettings { addr: layer.addr },
            guardrails_enabled: layer.guardrails_enabled.unwrap_or_default(),
            data_model: DataModelConfig {
                provider: data_provider,
                api_key: api_key
                    .clone()
                    .or(data.api_key)
                    .map_or(data_defaults.api_key, Into::into),
                base_url: data_base_url,
                project: data.project.or(data_defaults.project),
                location: data.location.or(data_defaults.location),
                model: data.model.unwrap_or(data_defaults.model),
                temperature: data.temperature.unwrap_or(data_defaults.temperature),
            },
            policy_model: PolicyModelConfig {
                provider: policy_provider,
                api_key: api_key
                    .or(policy.api_key)
                    .map_or(policy_defaults.api_key, Into::into),
                base_url: policy_base_url,
                project: policy.project.or(policy_defaults.project),
                location: policy.location.or(policy_defaults.location),
                model: policy.model.unwrap_or(policy_defaults.model),
                temperature: policy.temperature.unwrap_or(policy_defaults.temperature),
            },
            scanner: scanner_settings(layer.scanner_enabled, layer.scanner),
            sources,
            config_dirs,
        }
    }
}

/// Apply the scanner defaults to its merged layer.
///
/// A free function rather than a method so the guardrail and scanner
/// resolutions read the same way despite landing in different config types.
fn scanner_settings(enabled: Option<bool>, layer: ModelLayer) -> ScannerSettings {
    let defaults = ScannerConfig::default();
    let provider = layer.provider.unwrap_or(defaults.provider);
    ScannerSettings {
        enabled: enabled.unwrap_or_default(),
        model: ScannerConfig {
            provider,
            api_key: env_override(SCANNER_API_KEY_ENV)
                .or(layer.api_key)
                .map_or(defaults.api_key, Into::into),
            base_url: resolve_base_url(
                layer.base_url,
                provider,
                defaults.provider,
                defaults.base_url,
            ),
            project: layer.project.or(defaults.project),
            location: layer.location.or(defaults.location),
            model: layer.model.unwrap_or(defaults.model),
            temperature: layer.temperature.unwrap_or(defaults.temperature),
            timeout: defaults.timeout,
        },
    }
}

// ============================================================================
// Policy assets
// ============================================================================

/// The policy assets a harness loads, each resolved to a concrete path.
///
/// Built by [`PolicyAssets::resolve`] from a list of config directories. The
/// three resolve independently, so a project directory need only carry what it
/// overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAssets {
    /// Directory of Cedar rules and schema, walked recursively.
    pub cedar_dir: PathBuf,
    /// Data-sensitivity label templates.
    pub ifc_template: PathBuf,
    /// Policy-guardrail templates.
    pub policy_template: PathBuf,
}

impl PolicyAssets {
    /// Resolve every asset against `config_dirs`, nearest first.
    ///
    /// # Errors
    ///
    /// [`SettingsError::NoConfigDir`] if `config_dirs` is empty, or
    /// [`SettingsError::MissingAsset`] naming every candidate checked for the
    /// first asset that no directory provides.
    pub fn resolve(config_dirs: &[PathBuf]) -> Result<Self, SettingsError> {
        if config_dirs.is_empty() {
            return Err(SettingsError::NoConfigDir);
        }
        Ok(Self {
            cedar_dir: pick(config_dirs, &CEDAR_DIR, Path::is_dir)?,
            ifc_template: pick(config_dirs, &[IFC_TEMPLATE_FILE], Path::is_file)?,
            policy_template: pick(config_dirs, &[POLICY_TEMPLATE_FILE], Path::is_file)?,
        })
    }

    /// Resolve against a single config directory, with no user-scope fallback.
    ///
    /// For callers that manage their own layout — chiefly tests, which must not
    /// read the developer's `~/.sondera`.
    ///
    /// # Errors
    ///
    /// As [`PolicyAssets::resolve`].
    pub fn in_config_dir(dir: impl Into<PathBuf>) -> Result<Self, SettingsError> {
        Self::resolve(&[dir.into()])
    }
}

/// The first `<dir>/<relative>` satisfying `exists`, searching `dirs` in order.
fn pick(
    dirs: &[PathBuf],
    relative: &[&str],
    exists: fn(&Path) -> bool,
) -> Result<PathBuf, SettingsError> {
    let candidates = dirs.iter().map(|dir| {
        relative
            .iter()
            .fold(dir.clone(), |path, component| path.join(component))
    });
    let mut searched = Vec::new();
    for candidate in candidates {
        if exists(&candidate) {
            return Ok(candidate);
        }
        searched.push(candidate);
    }
    Err(SettingsError::MissingAsset {
        asset: relative.join("/"),
        searched,
    })
}

fn resolve_base_url(
    configured: Option<String>,
    provider: Provider,
    default_provider: Provider,
    default: Option<String>,
) -> Option<String> {
    match configured {
        Some(url) => Some(url),
        None if provider == default_provider => default,
        None => None,
    }
}

/// The credential from `variable`, if set to a non-empty value.
fn env_override(variable: &str) -> Option<String> {
    std::env::var(variable).ok().filter(|key| !key.is_empty())
}

/// The user-scope config directory inside a home directory.
fn user_config_dir(home: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join(CONFIG_DIR)
}

/// Find the nearest `.sondera` directory at or above `start`.
///
/// Keys on the directory, not on `sondera.toml` inside it: a project may ship
/// policy assets without overriding any setting.
fn find_project_config_dir(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|ancestor| ancestor.join(CONFIG_DIR))
        .find(|candidate| candidate.is_dir())
}

/// Read, parse, and validate one optional config file.
///
/// Returns an empty layer when `path` is `None`.
fn load_layer(path: Option<&Path>) -> Result<Layer, SettingsError> {
    let Some(path) = path else {
        return Ok(Layer::default());
    };
    let text = std::fs::read_to_string(path).map_err(|source| SettingsError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let raw: RawSettings = toml::from_str(&text).map_err(|source| SettingsError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    raw.validate(path)
}

// ============================================================================
// Merged layer — validated, still fully optional
// ============================================================================

/// One scope's settings after validation, before defaults are applied.
#[derive(Debug, Default, Clone)]
struct Layer {
    addr: Option<SocketAddr>,
    shared: ModelLayer,
    data: ModelLayer,
    policy: ModelLayer,
    scanner: ModelLayer,
    guardrails_enabled: Option<bool>,
    scanner_enabled: Option<bool>,
}

/// One guardrail's validated model settings.
#[derive(Debug, Default, Clone)]
struct ModelLayer {
    provider: Option<Provider>,
    base_url: Option<String>,
    project: Option<String>,
    location: Option<String>,
    model: Option<String>,
    temperature: Option<f32>,
    api_key: Option<String>,
}

impl Layer {
    /// Fields set on `self` win; anything unset falls back to `lower`.
    fn or(self, lower: Self) -> Self {
        Self {
            addr: self.addr.or(lower.addr),
            shared: self.shared.or(lower.shared),
            data: self.data.or(lower.data),
            policy: self.policy.or(lower.policy),
            scanner: self.scanner.or(lower.scanner),
            guardrails_enabled: self.guardrails_enabled.or(lower.guardrails_enabled),
            scanner_enabled: self.scanner_enabled.or(lower.scanner_enabled),
        }
    }
}

impl ModelLayer {
    /// Fields set on `self` win; anything unset falls back to `lower`.
    fn or(self, lower: Self) -> Self {
        Self {
            provider: self.provider.or(lower.provider),
            base_url: self.base_url.or(lower.base_url),
            project: self.project.or(lower.project),
            location: self.location.or(lower.location),
            model: self.model.or(lower.model),
            temperature: self.temperature.or(lower.temperature),
            api_key: self.api_key.or(lower.api_key),
        }
    }
}

// ============================================================================
// File representation
// ============================================================================

/// The on-disk document. Every field is optional in every scope.
///
/// `deny_unknown_fields` is deliberate: a mistyped key in a governance config
/// would otherwise be ignored in silence, leaving the operator believing a
/// setting took effect.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSettings {
    #[serde(default)]
    harness: RawHarness,
    #[serde(default)]
    guardrails: RawGuardrails,
    #[serde(default)]
    scanner: RawScanner,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHarness {
    addr: Option<String>,
}

/// Shared guardrail model settings, plus optional per-guardrail overrides.
///
/// The shared keys are spelled out rather than `#[serde(flatten)]`ed from a
/// [`RawModel`]: serde cannot combine `flatten` with `deny_unknown_fields`, and
/// catching a mistyped key matters more here than avoiding the repetition.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGuardrails {
    enabled: Option<bool>,
    provider: Option<String>,
    base_url: Option<String>,
    project: Option<String>,
    location: Option<String>,
    model: Option<String>,
    temperature: Option<f32>,
    api_key: Option<String>,
    #[serde(default)]
    data: RawModel,
    #[serde(default)]
    policy: RawModel,
}

impl RawGuardrails {
    /// The shared keys as a model layer for the per-guardrail tables to fall
    /// back onto.
    fn shared(&self) -> RawModel {
        RawModel {
            provider: self.provider.clone(),
            base_url: self.base_url.clone(),
            project: self.project.clone(),
            location: self.location.clone(),
            model: self.model.clone(),
            temperature: self.temperature,
            api_key: self.api_key.clone(),
        }
    }
}

/// The trajectory scanner's model settings as written in the file.
///
/// Spelled out separately from [`RawModel`] for the same `deny_unknown_fields`
/// reason as [`RawGuardrails`]: `enabled` is the one key it adds.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScanner {
    enabled: Option<bool>,
    provider: Option<String>,
    base_url: Option<String>,
    project: Option<String>,
    location: Option<String>,
    model: Option<String>,
    temperature: Option<f32>,
    api_key: Option<String>,
}

impl RawScanner {
    /// The model keys, leaving `enabled` to the caller.
    fn model_keys(&self) -> RawModel {
        RawModel {
            provider: self.provider.clone(),
            base_url: self.base_url.clone(),
            project: self.project.clone(),
            location: self.location.clone(),
            model: self.model.clone(),
            temperature: self.temperature,
            api_key: self.api_key.clone(),
        }
    }
}

/// One guardrail's model settings as written in the file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModel {
    provider: Option<String>,
    base_url: Option<String>,
    project: Option<String>,
    location: Option<String>,
    model: Option<String>,
    temperature: Option<f32>,
    api_key: Option<String>,
}

impl RawSettings {
    /// Validate against `path`, which names the file in any error.
    fn validate(self, path: &Path) -> Result<Layer, SettingsError> {
        Ok(Layer {
            addr: self
                .harness
                .addr
                .map(|value| {
                    value.parse().map_err(|source| SettingsError::Addr {
                        path: path.to_path_buf(),
                        value,
                        source,
                    })
                })
                .transpose()?,
            shared: self.guardrails.shared().validate(path)?,
            data: self.guardrails.data.validate(path)?,
            policy: self.guardrails.policy.validate(path)?,
            scanner: self.scanner.model_keys().validate(path)?,
            guardrails_enabled: self.guardrails.enabled,
            scanner_enabled: self.scanner.enabled,
        })
    }
}

impl RawModel {
    /// Validate against `path`, which names the file in any error.
    fn validate(self, path: &Path) -> Result<ModelLayer, SettingsError> {
        let provider = self
            .provider
            .map(|value| {
                value
                    .parse::<Provider>()
                    .map_err(|_| SettingsError::Provider {
                        path: path.to_path_buf(),
                        value,
                        expected: Provider::ALL
                            .iter()
                            .map(|provider| provider.name())
                            .collect::<Vec<_>>()
                            .join(", "),
                    })
            })
            .transpose()?;

        Ok(ModelLayer {
            provider,
            base_url: self.base_url,
            project: self.project,
            location: self.location,
            model: self.model,
            temperature: self.temperature,
            api_key: self.api_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `contents` to `<root>/.sondera/sondera.toml`.
    fn write_config(root: &Path, contents: &str) {
        let dir = root.join(CONFIG_DIR);
        std::fs::create_dir_all(&dir).expect("config dir should be creatable");
        std::fs::write(dir.join(CONFIG_FILE), contents).expect("config should be writable");
    }

    /// Load with no user scope, so only the project file applies.
    fn load_project(project: &Path) -> Result<Settings, SettingsError> {
        Settings::load_from(None, Some(project))
    }

    /// The committed project config is what every contributor and every demo
    /// starts from, and unknown keys are rejected rather than ignored — so a
    /// mistyped table there is a hard startup failure. Parse the real file so
    /// that lands in CI instead of in someone's first `sondera serve`.
    #[test]
    fn the_committed_project_config_parses() {
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));

        let settings = load_project(root).expect("the committed sondera.toml should parse");

        assert!(
            !settings.sources.is_empty(),
            "the committed config should have been found at {}",
            root.display()
        );
    }

    #[test]
    fn missing_files_yield_the_built_in_defaults() {
        let dir = tempfile::tempdir().expect("temp dir");

        let settings = load_project(dir.path()).expect("absent config is not an error");

        assert!(!settings.guardrails_enabled);
        assert_eq!(settings.data_model.provider, Provider::Ollama);
        assert_eq!(settings.data_model.model, DataModelConfig::default().model);
        assert!(settings.sources.is_empty());
        assert_eq!(settings.harness, HarnessSettings::default());
    }

    #[test]
    fn guardrails_require_explicit_enablement() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(dir.path(), "[guardrails]\nenabled = true\n");

        let settings = load_project(dir.path()).expect("config should load");

        assert!(settings.guardrails_enabled);
    }

    #[test]
    fn shared_guardrail_settings_apply_to_both_models() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(
            dir.path(),
            r#"
            [guardrails]
            provider = "openai"
            base_url = "http://localhost:8000/v1"
            model = "openai/gpt-oss-safeguard-20b"
            "#,
        );

        let settings = load_project(dir.path()).expect("config should load");

        assert_eq!(settings.data_model.provider, Provider::OpenAI);
        assert_eq!(settings.policy_model.provider, Provider::OpenAI);
        assert_eq!(
            settings.policy_model.base_url.as_deref(),
            Some("http://localhost:8000/v1")
        );
        assert_eq!(settings.data_model.model, "openai/gpt-oss-safeguard-20b");
    }

    #[test]
    fn a_non_default_provider_uses_its_builtin_endpoint() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(dir.path(), "[guardrails]\nprovider = \"openai\"\n");

        let settings = load_project(dir.path()).expect("config should load");

        assert_eq!(settings.data_model.provider, Provider::OpenAI);
        assert_eq!(settings.policy_model.provider, Provider::OpenAI);
        assert_eq!(settings.data_model.base_url, None);
        assert_eq!(settings.policy_model.base_url, None);
    }

    #[test]
    fn a_per_guardrail_table_overrides_the_shared_value() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(
            dir.path(),
            r#"
            [guardrails]
            provider = "openai"
            model = "shared-model"

            [guardrails.policy]
            model = "policy-model"
            "#,
        );

        let settings = load_project(dir.path()).expect("config should load");

        assert_eq!(settings.policy_model.model, "policy-model");
        assert_eq!(settings.data_model.model, "shared-model");
        // The unset key still inherits the shared value.
        assert_eq!(settings.policy_model.provider, Provider::OpenAI);
    }

    #[test]
    fn the_project_file_wins_over_the_user_file() {
        let home = tempfile::tempdir().expect("home dir");
        let project = tempfile::tempdir().expect("project dir");
        write_config(
            home.path(),
            "[guardrails]\nmodel = \"user-model\"\ntemperature = 0.5\n",
        );
        write_config(project.path(), "[guardrails]\nmodel = \"project-model\"\n");

        let settings = Settings::load_from(Some(home.path()), Some(project.path()))
            .expect("config should load");

        assert_eq!(settings.data_model.model, "project-model");
        // A key the project file leaves unset still comes from the user file.
        assert_eq!(settings.data_model.temperature, 0.5);
        assert_eq!(settings.sources.len(), 2, "both files should be recorded");
    }

    #[test]
    fn the_project_file_is_found_from_a_subdirectory() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(dir.path(), "[guardrails]\nmodel = \"from-root\"\n");
        let nested = dir.path().join("crates").join("deep");
        std::fs::create_dir_all(&nested).expect("nested dir");

        let settings = load_project(&nested).expect("config should load");

        assert_eq!(settings.data_model.model, "from-root");
    }

    #[test]
    fn vertex_ai_is_configured_by_project_and_location() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(
            dir.path(),
            r#"
            [guardrails]
            provider = "vertexai"
            project = "my-gcp-project"
            location = "us-central1"
            model = "gemini-2.5-flash"
            "#,
        );

        let settings = load_project(dir.path()).expect("config should load");

        assert_eq!(settings.data_model.provider, Provider::VertexAi);
        assert_eq!(
            settings.policy_model.project.as_deref(),
            Some("my-gcp-project")
        );
        assert_eq!(settings.data_model.location.as_deref(), Some("us-central1"));
        assert_eq!(settings.data_model.model, "gemini-2.5-flash");
    }

    #[test]
    fn the_vertex_ai_alias_is_accepted() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(dir.path(), "[guardrails]\nprovider = \"vertex\"\n");

        let settings = load_project(dir.path()).expect("config should load");

        assert_eq!(settings.data_model.provider, Provider::VertexAi);
    }

    #[test]
    fn a_per_guardrail_table_can_override_the_vertex_location() {
        // The realistic split: one project, but the heavier policy guardrail
        // pinned to a region with the quota for it.
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(
            dir.path(),
            r#"
            [guardrails]
            provider = "vertexai"
            project = "my-gcp-project"
            location = "global"

            [guardrails.policy]
            location = "us-central1"
            "#,
        );

        let settings = load_project(dir.path()).expect("config should load");

        assert_eq!(settings.data_model.location.as_deref(), Some("global"));
        assert_eq!(
            settings.policy_model.location.as_deref(),
            Some("us-central1")
        );
        // The project is unset on the specific table, so it still inherits.
        assert_eq!(
            settings.policy_model.project.as_deref(),
            Some("my-gcp-project")
        );
    }

    #[test]
    fn an_unknown_provider_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(dir.path(), "[guardrails]\nprovider = \"vllm\"\n");

        let err = load_project(dir.path()).expect_err("unknown provider should be rejected");

        assert!(matches!(err, SettingsError::Provider { .. }), "{err}");
        // The message must list what is accepted — vLLM is reached via `openai`.
        assert!(err.to_string().contains("openai"), "{err}");
    }

    #[test]
    fn an_unknown_key_is_rejected_rather_than_ignored() {
        let dir = tempfile::tempdir().expect("temp dir");
        // A silently ignored typo would leave the operator believing the
        // setting took effect.
        write_config(dir.path(), "[guardrails]\nbaseurl = \"http://x\"\n");

        let err = load_project(dir.path()).expect_err("unknown key should be rejected");

        assert!(matches!(err, SettingsError::Parse { .. }), "{err}");
    }

    #[test]
    fn an_invalid_harness_addr_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(dir.path(), "[harness]\naddr = \"not-an-address\"\n");

        let err = load_project(dir.path()).expect_err("bad addr should be rejected");

        assert!(matches!(err, SettingsError::Addr { .. }), "{err}");
    }

    #[test]
    fn harness_settings_are_parsed() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(dir.path(), "[harness]\naddr = \"0.0.0.0:9999\"\n");

        let settings = load_project(dir.path()).expect("config should load");

        assert_eq!(
            settings.harness.addr,
            Some("0.0.0.0:9999".parse().expect("valid addr"))
        );
    }

    #[test]
    fn the_scanner_is_off_unless_a_config_turns_it_on() {
        let dir = tempfile::tempdir().expect("temp dir");

        let settings = load_project(dir.path()).expect("config should load");

        assert!(
            !settings.scanner.enabled,
            "an absent [scanner] table must not start spending model calls"
        );
    }

    #[test]
    fn a_scanner_table_alone_does_not_enable_the_scanner() {
        // Naming a model is not the same as asking for it to run: `enabled` is
        // the one switch, so a half-written config stays inert.
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(dir.path(), "[scanner]\nmodel = \"gemini-2.5-flash\"\n");

        let settings = load_project(dir.path()).expect("config should load");

        assert!(!settings.scanner.enabled);
        assert_eq!(settings.scanner.model.model, "gemini-2.5-flash");
    }

    #[test]
    fn scanner_settings_are_independent_of_the_guardrails() {
        // Enforcement and post-hoc analysis are sized differently; a guardrail
        // provider must not silently become the every-event scanner.
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(
            dir.path(),
            r#"
            [guardrails]
            provider = "openai"
            model = "guardrail-model"

            [scanner]
            enabled = true
            provider = "vertexai"
            location = "global"
            model = "gemini-3.5-flash-lite"
            "#,
        );

        let settings = load_project(dir.path()).expect("config should load");

        assert!(settings.scanner.enabled);
        assert_eq!(settings.scanner.model.provider, Provider::VertexAi);
        assert_eq!(settings.scanner.model.location.as_deref(), Some("global"));
        assert_eq!(settings.scanner.model.model, "gemini-3.5-flash-lite");
        // The guardrail keys did not leak in, and the scanner's did not leak out.
        assert_eq!(settings.policy_model.provider, Provider::OpenAI);
        assert_eq!(settings.policy_model.model, "guardrail-model");
    }

    #[test]
    fn a_non_default_scanner_provider_drops_the_ollama_endpoint() {
        // The built-in base URL belongs to the default provider only; carrying
        // it onto Vertex AI would point the client at localhost.
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(
            dir.path(),
            "[scanner]\nenabled = true\nprovider = \"vertexai\"\n",
        );

        let settings = load_project(dir.path()).expect("config should load");

        assert_eq!(settings.scanner.model.base_url, None);
    }

    #[test]
    fn an_unknown_scanner_key_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_config(dir.path(), "[scanner]\nenable = true\n");

        let err = load_project(dir.path()).expect_err("unknown key should be rejected");

        assert!(matches!(err, SettingsError::Parse { .. }), "{err}");
    }

    /// Create the named policy assets inside `<root>/.sondera`. A trailing `/`
    /// makes the entry a directory; anything else is an empty file.
    fn write_assets(root: &Path, assets: &[&str]) {
        for asset in assets {
            let path = root.join(CONFIG_DIR).join(asset);
            if asset.ends_with('/') {
                std::fs::create_dir_all(&path).expect("asset dir should be creatable");
                continue;
            }
            std::fs::create_dir_all(path.parent().expect("asset has a parent"))
                .expect("asset dir should be creatable");
            std::fs::write(&path, "").expect("asset should be writable");
        }
    }

    #[test]
    fn a_config_dir_without_settings_is_still_discovered() {
        // A project may ship policy assets and override no setting at all.
        let dir = tempfile::tempdir().expect("temp dir");
        write_assets(dir.path(), &["ifc.toml"]);

        let settings = load_project(dir.path()).expect("config should load");

        assert!(settings.sources.is_empty(), "no sondera.toml was written");
        assert_eq!(settings.config_dirs, vec![dir.path().join(CONFIG_DIR)]);
    }

    #[test]
    fn config_dirs_are_ordered_project_before_user() {
        let home = tempfile::tempdir().expect("home dir");
        let project = tempfile::tempdir().expect("project dir");
        write_assets(home.path(), &["ifc.toml"]);
        write_assets(project.path(), &["ifc.toml"]);

        let settings = Settings::load_from(Some(home.path()), Some(project.path()))
            .expect("config should load");

        assert_eq!(
            settings.config_dirs,
            vec![
                project.path().join(CONFIG_DIR),
                home.path().join(CONFIG_DIR)
            ],
            "the nearer directory must be searched first"
        );
    }

    #[test]
    fn each_policy_asset_resolves_independently() {
        let home = tempfile::tempdir().expect("home dir");
        let project = tempfile::tempdir().expect("project dir");
        // The user scope carries everything; the project overrides one file.
        write_assets(
            home.path(),
            &["ifc.toml", "policies.toml", "policies/cedar/"],
        );
        write_assets(project.path(), &["ifc.toml"]);

        let settings = Settings::load_from(Some(home.path()), Some(project.path()))
            .expect("config should load");
        let assets = settings.policy_assets().expect("assets should resolve");

        let project_dir = project.path().join(CONFIG_DIR);
        let home_dir = home.path().join(CONFIG_DIR);
        assert_eq!(assets.ifc_template, project_dir.join("ifc.toml"));
        assert_eq!(
            assets.policy_template,
            home_dir.join("policies.toml"),
            "an asset the project omits must fall back to the user scope"
        );
        assert_eq!(
            assets.cedar_dir,
            home_dir.join("policies").join("cedar"),
            "the cedar corpus is inherited whole when the project ships none"
        );
    }

    #[test]
    fn a_missing_asset_names_every_candidate_searched() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_assets(dir.path(), &["ifc.toml", "policies/cedar/"]);

        let settings = load_project(dir.path()).expect("config should load");
        let err = settings
            .policy_assets()
            .expect_err("policies.toml is absent");

        let rendered = err.to_string();
        assert!(matches!(err, SettingsError::MissingAsset { .. }), "{err}");
        assert!(rendered.contains("policies.toml"), "{rendered}");
        assert!(
            rendered.contains(&dir.path().join(CONFIG_DIR).display().to_string()),
            "the message must name where it looked: {rendered}"
        );
    }

    #[test]
    fn no_config_dir_is_distinguished_from_a_missing_asset() {
        let dir = tempfile::tempdir().expect("temp dir");

        let settings = load_project(dir.path()).expect("absent config is not an error");
        let err = settings.policy_assets().expect_err("nothing to resolve");

        assert!(matches!(err, SettingsError::NoConfigDir), "{err}");
    }

    #[test]
    fn an_explicit_config_dir_that_is_absent_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let absent = dir.path().join("nonesuch");

        let err = Settings::load_with_config_dir(Some(&absent))
            .expect_err("an explicit directory must exist");

        assert!(
            matches!(err, SettingsError::MissingConfigDir { .. }),
            "{err}"
        );
    }

    #[test]
    fn an_error_names_the_file_that_set_the_bad_value() {
        let home = tempfile::tempdir().expect("home dir");
        let project = tempfile::tempdir().expect("project dir");
        write_config(home.path(), "[guardrails]\nprovider = \"nonesuch\"\n");
        write_config(project.path(), "[guardrails]\nmodel = \"fine\"\n");

        let err = Settings::load_from(Some(home.path()), Some(project.path()))
            .expect_err("bad provider should be rejected");

        let rendered = err.to_string();
        assert!(
            rendered.contains(&home.path().display().to_string()),
            "error should name the user file that set it: {rendered}"
        );
    }
}
