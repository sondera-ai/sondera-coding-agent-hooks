//! Policy-related types for adjudication, decisions, and policy loading.
//!
//! Consumers reach Cedar through the [`PolicyStore`] trait rather than reading
//! files themselves, so there is one seam to swap when policies stop coming
//! from disk. [`StaticPolicyStore`] is the only implementation: it walks a
//! directory tree once at startup and serves the result unchanged.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub use crate::guardrails::*;

// ============================================================================
// Adjudication
// ============================================================================
#[must_use]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Decision {
    /// Allow the operation
    Allow,
    /// Deny the operation
    Deny,
    /// Escalate for oversight review
    Escalate,
}

impl Decision {
    /// Stable, low-cardinality string label suitable as an OTel
    /// metric attribute value.
    #[must_use]
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Escalate => "escalate",
        }
    }
}

/// Policy evaluation mode controlling how adjudication decisions are applied.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Mode {
    /// Evaluate policies but always allow. Emit adjudication events for observability.
    #[default]
    Monitor,
    /// Enforce policy decisions (Allow/Deny/Escalate). Current default behavior.
    Govern,
    /// Evaluate policies, allow, and generate LLM-based remediation instructions on deny.
    Steer,
}

impl Mode {
    /// Returns a numeric restrictiveness rank (higher = more restrictive).
    const fn restrictiveness(self) -> u8 {
        match self {
            Self::Monitor => 0,
            Self::Steer => 1,
            Self::Govern => 2,
        }
    }

    /// Stable, low-cardinality string label suitable as an OTel
    /// metric attribute value. Held separate from `Display` so a
    /// future `Display` change cannot shift the metric label shape.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Monitor => "monitor",
            Self::Govern => "govern",
            Self::Steer => "steer",
        }
    }
}

impl PartialOrd for Mode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Mode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.restrictiveness().cmp(&other.restrictiveness())
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monitor => write!(f, "monitor"),
            Self::Govern => write!(f, "govern"),
            Self::Steer => write!(f, "steer"),
        }
    }
}

/// A string did not name a variant of one of this module's configuration enums.
///
/// Parsed from operator-authored configuration (CLI flags, stored policy
/// metadata) where a typo must be reported rather than silently resolved to a
/// default — defaulting `mode` picks the permissive one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown {kind} {value:?}; expected one of: {expected}")]
pub struct ParseEnumError {
    /// What was being parsed, e.g. `"mode"`.
    kind: &'static str,
    /// The unrecognized input.
    value: String,
    /// Comma-separated list of accepted values.
    expected: &'static str,
}

impl ParseEnumError {
    fn new(kind: &'static str, value: &str, expected: &'static str) -> Self {
        Self {
            kind,
            value: value.to_owned(),
            expected,
        }
    }
}

impl std::str::FromStr for Mode {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "monitor" => Ok(Self::Monitor),
            "govern" => Ok(Self::Govern),
            "steer" => Ok(Self::Steer),
            other => Err(ParseEnumError::new("mode", other, "monitor, govern, steer")),
        }
    }
}

/// Cedar policy metadata extracted from matching policies
#[must_use]
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyMetadata {
    /// Policy ID from @id annotation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// Description from @description annotation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether this policy requires escalation to a human or other oracle to decide the final verdict.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub escalate: bool,
    /// The argument passed to @escalate, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalate_arg: Option<String>,
    /// Custom metadata (key-value pairs) including finra_rule, business_impact, etc.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub metadata: HashMap<String, String>,
}

impl PolicyMetadata {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_id(mut self, id: String) -> Self {
        self.policy_id = Some(id);
        self
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn with_escalate(mut self, escalate_arg: Option<String>) -> Self {
        self.escalate = true;
        self.escalate_arg = escalate_arg;
        self
    }

    pub fn with(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

// ============================================================================
// PolicyStore
// ============================================================================

/// Query parameters for fetching policies from a [`PolicyStore`].
#[must_use]
#[derive(Debug, Clone, Default)]
pub struct PolicyStoreQuery {
    /// Agent the policies are being compiled for.
    pub agent_id: String,
}

impl PolicyStoreQuery {
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
        }
    }
}

/// Error type for policy store operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyStoreError {
    /// The requested policy set was not found.
    #[error("policy not found: {0}")]
    NotFound(String),

    /// The storage backend is unreachable or returned a transport error.
    #[error("storage unavailable: {0}")]
    Unavailable(String),

    /// The policy content is malformed (invalid Cedar, bad encoding, etc.).
    #[error("invalid policy content: {0}")]
    InvalidContent(String),

    /// Configuration error (bad path, missing credentials, etc.).
    #[error("configuration error: {0}")]
    Config(String),
}

/// The compiled Cedar artifacts an authorizer needs, plus the mode to apply them in.
#[must_use]
#[derive(Debug, Clone)]
pub struct CompiledPolicySet {
    /// Every policy in the set, keyed by its `@id` annotation.
    pub policy_set: cedar_policy::PolicySet,
    /// The merged schema the policies typecheck against.
    pub schema: cedar_policy::Schema,
    /// How decisions from this set should be applied.
    pub mode: Mode,
}

/// The core abstraction for loading Cedar policies.
///
/// Implementations fetch policies from a backing store, parse and validate
/// them, and return a [`CompiledPolicySet`] ready for authorization.
///
/// The trait is dyn-compatible (`#[async_trait]`) so a consumer can hold
/// `Arc<dyn PolicyStore>` and swap implementations at runtime.
#[async_trait::async_trait]
pub trait PolicyStore: Send + Sync {
    /// Compile the effective Cedar policies and mode for the given query context.
    async fn compile_policy_set(
        &self,
        query: &PolicyStoreQuery,
    ) -> Result<CompiledPolicySet, PolicyStoreError>;
}

#[async_trait::async_trait]
impl<T> PolicyStore for std::sync::Arc<T>
where
    T: PolicyStore + ?Sized,
{
    async fn compile_policy_set(
        &self,
        query: &PolicyStoreQuery,
    ) -> Result<CompiledPolicySet, PolicyStoreError> {
        (**self).compile_policy_set(query).await
    }
}

// ============================================================================
// StaticPolicyStore
// ============================================================================

/// A [`PolicyStore`] backed by a directory tree read once at construction.
///
/// Walks the root and every subdirectory, compiling all `.cedar` and
/// `.cedarschema` files into a single [`CompiledPolicySet`] that every query
/// receives — the set is not agent-scoped, so [`PolicyStoreQuery`] is ignored.
///
/// Reading eagerly in [`Self::load`] rather than per query is what makes a
/// malformed policy a startup failure instead of a first-request failure: an
/// engine that only discovers unparseable Cedar on the request path has already
/// begun adjudicating, and the natural error handling there is to fail open.
#[derive(Debug)]
pub struct StaticPolicyStore {
    compiled: CompiledPolicySet,
}

impl StaticPolicyStore {
    /// Load and compile every Cedar file under `root`, recursively.
    ///
    /// Errors if `root` is not a directory, if any file fails to parse, if two
    /// policies claim the same `@id`, or if no schema is found — an empty schema
    /// would let every request fail context validation at adjudication time.
    pub fn load(root: impl AsRef<Path>) -> Result<Self, PolicyStoreError> {
        Self::load_with_mode(root, Mode::default())
    }

    /// As [`Self::load`], with an explicit evaluation [`Mode`].
    pub fn load_with_mode(root: impl AsRef<Path>, mode: Mode) -> Result<Self, PolicyStoreError> {
        let root = root.as_ref();
        if !root.is_dir() {
            return Err(PolicyStoreError::Config(format!(
                "policy directory does not exist: {}",
                root.display()
            )));
        }

        let mut files = Vec::new();
        collect_cedar_files(root, &mut files)?;
        // Directory iteration order is filesystem-defined; sorting makes the
        // compiled set — and any duplicate-id error naming two files — identical
        // across machines.
        files.sort();

        let mut policy_set = cedar_policy::PolicySet::new();
        let mut fragments = Vec::new();

        for path in &files {
            let content = std::fs::read_to_string(path).map_err(|e| {
                PolicyStoreError::Unavailable(format!("failed to read {}: {e}", path.display()))
            })?;

            match path.extension().and_then(|e| e.to_str()) {
                Some("cedarschema") => {
                    let (fragment, warnings) = cedar_policy::SchemaFragment::from_cedarschema_str(
                        &content,
                    )
                    .map_err(|e| {
                        PolicyStoreError::InvalidContent(format!(
                            "failed to parse schema {}: {e}",
                            path.display()
                        ))
                    })?;
                    for warning in warnings {
                        tracing::warn!("Cedar schema warning in {}: {warning}", path.display());
                    }
                    fragments.push(fragment);
                }
                Some("cedar") => {
                    let parsed: cedar_policy::PolicySet = content.parse().map_err(|e| {
                        PolicyStoreError::InvalidContent(format!(
                            "failed to parse policies {}: {e}",
                            path.display()
                        ))
                    })?;
                    for policy in parsed.policies() {
                        // Key each policy by its `@id` so a decision's diagnostics
                        // name the authored rule, not Cedar's positional id.
                        let id = policy
                            .annotation("id")
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| policy.id().as_ref());
                        let named = policy.new_id(cedar_policy::PolicyId::new(id));
                        policy_set.add(named).map_err(|e| {
                            PolicyStoreError::InvalidContent(format!(
                                "duplicate policy id {id:?} in {}: {e}",
                                path.display()
                            ))
                        })?;
                    }
                }
                _ => {}
            }
        }

        if fragments.is_empty() {
            return Err(PolicyStoreError::NotFound(format!(
                "no .cedarschema files found under {}",
                root.display()
            )));
        }

        let schema = cedar_policy::Schema::from_schema_fragments(fragments).map_err(|e| {
            PolicyStoreError::InvalidContent(format!("failed to merge schema fragments: {e}"))
        })?;

        Ok(Self {
            compiled: CompiledPolicySet {
                policy_set,
                schema,
                mode,
            },
        })
    }

    /// The compiled set, without going through the async trait.
    pub fn compiled(&self) -> &CompiledPolicySet {
        &self.compiled
    }
}

#[async_trait::async_trait]
impl PolicyStore for StaticPolicyStore {
    async fn compile_policy_set(
        &self,
        _query: &PolicyStoreQuery,
    ) -> Result<CompiledPolicySet, PolicyStoreError> {
        Ok(self.compiled.clone())
    }
}

/// Recursively collect `.cedar` and `.cedarschema` paths under `dir`.
///
/// Symlinked directories are followed by `is_dir()`, so a cycle would not
/// terminate; policy trees are checked-in source rather than arbitrary input,
/// and tracking visited inodes buys nothing here.
fn collect_cedar_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), PolicyStoreError> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        PolicyStoreError::Unavailable(format!("failed to read {}: {e}", dir.display()))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            PolicyStoreError::Unavailable(format!("failed to read entry in {}: {e}", dir.display()))
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_cedar_files(&path, out)?;
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("cedar" | "cedarschema")
        ) {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const SCHEMA: &str = r#"
        namespace Test {
            entity Agent;
            entity Resource;
            action "Act" appliesTo {
                principal: [Agent],
                resource: [Resource],
            };
        }
    "#;

    fn rule(id: &str) -> String {
        format!(
            "@id(\"{id}\")\n@description(\"d\")\nforbid (principal, action, resource) when {{ true }};\n"
        )
    }

    fn write(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn mode_parses_and_rejects_an_unknown_value() {
        for mode in [Mode::Monitor, Mode::Govern, Mode::Steer] {
            assert_eq!(Mode::from_str(mode.as_label()), Ok(mode));
        }
        // Defaulting a typo would silently pick the permissive mode.
        assert!(Mode::from_str("goverm").is_err());
    }

    #[test]
    fn mode_orders_by_restrictiveness_not_declaration_order() {
        assert!(Mode::Govern > Mode::Steer);
        assert!(Mode::Steer > Mode::Monitor);
    }

    /// The point of the recursive walk: rules nested below the root must load,
    /// or a reorganized tree silently adjudicates against fewer rules.
    #[test]
    fn load_walks_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "base.cedarschema", SCHEMA);
        write(dir.path(), "top.cedar", &rule("top"));
        write(dir.path(), "nested/deep/inner.cedar", &rule("inner"));

        let store = StaticPolicyStore::load(dir.path()).unwrap();
        let ids: Vec<String> = store
            .compiled()
            .policy_set
            .policies()
            .map(|p| p.id().to_string())
            .collect();

        assert_eq!(ids.len(), 2, "got {ids:?}");
        assert!(ids.contains(&"top".to_string()), "got {ids:?}");
        assert!(ids.contains(&"inner".to_string()), "got {ids:?}");
    }

    /// Policies are keyed by `@id`, not Cedar's positional id, so decision
    /// diagnostics name the authored rule.
    #[test]
    fn load_keys_policies_by_their_id_annotation() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "s.cedarschema", SCHEMA);
        write(dir.path(), "r.cedar", &rule("named-rule"));

        let store = StaticPolicyStore::load(dir.path()).unwrap();
        assert!(
            store
                .compiled()
                .policy_set
                .policy(&"named-rule".parse().unwrap())
                .is_some()
        );
    }

    /// Two rules claiming one id would silently drop a policy from the set.
    #[test]
    fn load_rejects_a_duplicate_policy_id() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "s.cedarschema", SCHEMA);
        write(dir.path(), "a.cedar", &rule("same"));
        write(dir.path(), "sub/b.cedar", &rule("same"));

        let err = StaticPolicyStore::load(dir.path()).unwrap_err();
        assert!(
            matches!(err, PolicyStoreError::InvalidContent(ref m) if m.contains("duplicate policy id")),
            "got {err:?}"
        );
    }

    /// Without a schema every request would fail context validation, so an
    /// absent one is a load error rather than an empty-schema success.
    #[test]
    fn load_requires_a_schema() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "r.cedar", &rule("only"));

        let err = StaticPolicyStore::load(dir.path()).unwrap_err();
        assert!(matches!(err, PolicyStoreError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn load_rejects_unparseable_cedar() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "s.cedarschema", SCHEMA);
        write(dir.path(), "bad.cedar", "this is not cedar");

        let err = StaticPolicyStore::load(dir.path()).unwrap_err();
        assert!(
            matches!(err, PolicyStoreError::InvalidContent(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn load_rejects_a_missing_directory() {
        let err = StaticPolicyStore::load("/nonexistent/policy/dir").unwrap_err();
        assert!(matches!(err, PolicyStoreError::Config(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn compile_policy_set_serves_the_same_set_for_any_query() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "s.cedarschema", SCHEMA);
        write(dir.path(), "r.cedar", &rule("r"));

        let store = StaticPolicyStore::load_with_mode(dir.path(), Mode::Govern).unwrap();
        let a = store
            .compile_policy_set(&PolicyStoreQuery::new("agent-a"))
            .await
            .unwrap();
        let b = store
            .compile_policy_set(&PolicyStoreQuery::new("agent-b"))
            .await
            .unwrap();

        assert_eq!(a.mode, Mode::Govern);
        assert_eq!(a.policy_set.policies().count(), 1);
        assert_eq!(
            a.policy_set.policies().count(),
            b.policy_set.policies().count()
        );
    }
}
