//! Policy model for evaluating content against customizable policy rules
//! using [gpt-oss-safeguard](https://ollama.com/library/gpt-oss-safeguard).
//!
//! The evaluating LLM's provider is selected at runtime (see
//! [`sondera_provider::Provider`]; the default is a local Ollama
//! server). The gpt-oss-safeguard reasoning model classifies content against
//! policy templates following the Harmony prompt format with multi-category
//! severity tiers. Structured output is obtained with the provider client's
//! extractor, which constrains the model to the [`PolicyModelResult`] schema:
//! `{ "violation": 0|1, "policy_category": "<code>" }`.

mod policy;

use schemars::JsonSchema as JsonSchemaDerive;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sondera_provider::{AgentClientExt, Client, ClientConfig};
use std::path::Path;
use std::time::Duration;
use strum_macros::{Display, EnumString};
use thiserror::Error;
use tracing::instrument;

pub use policy::{PolicyClassification, PolicyTemplate, PolicyViolation};
pub use sondera_provider::{Provider, Secret};

// ---------------------------------------------------------------------------
// Structured output from gpt-oss-safeguard
// ---------------------------------------------------------------------------

/// Policy-referencing structured output returned by gpt-oss-safeguard.
///
/// Category labels encourage gpt-oss-safeguard to reason about which section of
/// the policy applies, keeping outputs concise.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchemaDerive)]
pub struct PolicyModelResult {
    /// `1` if the content violates the policy, `0` if compliant.
    pub violation: u8,
    /// The policy category code that applies (e.g. "SC2" for injection).
    pub policy_category: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during policy evaluation.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Failed to build model provider client: {0}")]
    ClientBuild(#[from] sondera_provider::ProviderError),
    #[error("Model inference error: {0}")]
    Inference(String),
    #[error("Policy model not available: {0}")]
    ModelNotAvailable(String),
    #[error("No policy templates configured")]
    NoPolicies,
    #[error("Invalid content: {0}")]
    InvalidContent(String),
    #[error("Policy evaluation timeout")]
    Timeout,
    #[error("Failed to read policy file: {0}")]
    IoError(String),
    #[error("Failed to parse TOML: {0}")]
    TomlError(String),
}

// ---------------------------------------------------------------------------
// Conversation types
// ---------------------------------------------------------------------------

/// A message in the conversation history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    /// Role of the message sender
    pub role: ConversationRole,
    /// Content of the message
    pub content: String,
}

/// Role in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "lowercase")]
pub enum ConversationRole {
    /// User message
    User,
    /// Assistant/model response
    Assistant,
    /// System message
    System,
    /// Tool invocation or response
    Tool,
}

impl ConversationMessage {
    /// Create a new user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ConversationRole::User,
            content: content.into(),
        }
    }

    /// Create a new assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: ConversationRole::Assistant,
            content: content.into(),
        }
    }

    /// Create a new system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ConversationRole::System,
            content: content.into(),
        }
    }

    /// Create a new tool message.
    pub fn tool(content: impl Into<String>) -> Self {
        Self {
            role: ConversationRole::Tool,
            content: content.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Model configuration
// ---------------------------------------------------------------------------

/// Configuration for the policy model.
///
/// The provider and endpoint are chosen at runtime; the defaults target a local
/// Ollama server at `http://localhost:11434`.
#[derive(Debug, Clone)]
pub struct PolicyModelConfig {
    /// LLM provider to use (default: [`Provider::Ollama`]).
    pub provider: Provider,
    /// Provider API key. Ignored for providers that need none, such as Ollama.
    pub api_key: Secret,
    /// Base URL override for the provider endpoint (default: the local Ollama
    /// server). `None` uses the provider's built-in default endpoint.
    pub base_url: Option<String>,
    /// Google Cloud project, used only by [`Provider::VertexAi`] — which is
    /// addressed by project and location rather than by URL and key. Falls back
    /// to `GOOGLE_CLOUD_PROJECT` when `None`; Vertex AI has no default project,
    /// so with neither set the client fails to build.
    pub project: Option<String>,
    /// Google Cloud location, used only by [`Provider::VertexAi`] (e.g.
    /// `us-central1`). Falls back to `GOOGLE_CLOUD_LOCATION` when `None`, then
    /// to `global`.
    pub location: Option<String>,
    /// Model name (default: gpt-oss-safeguard:20b)
    pub model: String,
    /// Temperature for model inference (default: 0.0 for deterministic output)
    pub temperature: f32,
}

impl Default for PolicyModelConfig {
    fn default() -> Self {
        Self {
            provider: Provider::Ollama,
            api_key: Secret::default(),
            base_url: Some("http://localhost:11434".to_string()),
            project: None,
            location: None,
            model: "gpt-oss-safeguard:20b".to_string(),
            temperature: 0.0,
        }
    }
}

impl PolicyModelConfig {
    pub fn with_model(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            ..Default::default()
        }
    }

    pub fn provider(mut self, provider: Provider) -> Self {
        self.provider = provider;
        self
    }

    pub fn api_key(mut self, api_key: impl Into<Secret>) -> Self {
        self.api_key = api_key.into();
        self
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Set the Google Cloud project ([`Provider::VertexAi`] only).
    pub fn project(mut self, project: impl Into<String>) -> Self {
        self.project = Some(project.into());
        self
    }

    /// Set the Google Cloud location ([`Provider::VertexAi`] only).
    pub fn location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    pub fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = temperature;
        self
    }
}

// ---------------------------------------------------------------------------
// PolicyModel
// ---------------------------------------------------------------------------

/// Policy model using gpt-oss-safeguard for evaluating content against policy
/// templates with multi-category severity tiers.
///
/// Each [`PolicyTemplate`] is evaluated independently. The model returns a
/// policy-referencing structured output (`violation` + `policy_category`)
/// which is mapped to a [`PolicyViolation`] when the content violates the policy.
///
/// # Example
///
/// ```no_run
/// use sondera_policy::{PolicyModel, PolicyTemplate};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let policy = PolicyTemplate::new("SECURE_CODE", "SC")
///     .description("Security vulnerabilities in AI-generated code.")
///     .category("SC0", "Compliant", "Code follows secure coding practices.")
///     .category("SC2", "Injection", "Unsanitized user input in queries or commands.")
///     .example(r#"cursor.execute(f"SELECT * FROM users WHERE id = {id}")"#, true, "SC2")
///     .example(r#"cursor.execute("SELECT * FROM users WHERE id = %s", (id,))"#, false, "SC0");
///
/// let model = PolicyModel::new(vec![policy])?;
/// let result = model.evaluate_content("os.system(f\"ping {host}\")").await?;
///
/// if !result.compliant {
///     for v in &result.violations {
///         println!("{v}");
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct PolicyModel {
    client: Client,
    config: PolicyModelConfig,
    policies: Vec<PolicyTemplate>,
}

impl PolicyModel {
    /// Build a model with the default (local Ollama) provider configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::ClientBuild`] if the provider client cannot be
    /// constructed from the configuration.
    pub fn new(policies: Vec<PolicyTemplate>) -> Result<Self, PolicyError> {
        Self::with_config(policies, PolicyModelConfig::default())
    }

    pub fn from_toml(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let policies = PolicyTemplate::load_from_toml(path)?;
        Self::new(policies)
    }

    /// Build a model with an explicit runtime provider configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::ClientBuild`] if the provider client cannot be
    /// constructed from `config`.
    pub fn with_config(
        policies: Vec<PolicyTemplate>,
        config: PolicyModelConfig,
    ) -> Result<Self, PolicyError> {
        let client = config.provider.client(
            &ClientConfig::new(config.api_key.expose())
                .maybe_base_url(config.base_url.as_deref())
                .maybe_project(config.project.as_deref())
                .maybe_location(config.location.as_deref()),
        )?;
        Ok(Self {
            client,
            config,
            policies,
        })
    }

    /// Evaluate raw content against all configured policy templates.
    ///
    /// Each policy is evaluated independently. A violation is recorded when
    /// `violation == 1` in the model's response.
    #[instrument(skip(self, content), fields(content_len = content.len()))]
    pub async fn evaluate_content(
        &self,
        content: &str,
    ) -> Result<PolicyClassification, PolicyError> {
        if self.policies.is_empty() {
            return Err(PolicyError::NoPolicies);
        }
        if content.is_empty() {
            return Err(PolicyError::InvalidContent(
                "Content cannot be empty".into(),
            ));
        }

        let mut violations = Vec::new();

        for policy in &self.policies {
            let result = self
                .evaluate_single(policy, content, Duration::from_secs(30))
                .await?;

            if result.violation == 1 {
                let code = &result.policy_category;
                let category_name = policy.category_name(code).unwrap_or_else(|| code.clone());
                let description = policy
                    .category_definition(code)
                    .unwrap_or_else(|| code.clone());

                violations.push(PolicyViolation {
                    category: category_name,
                    rule: code.clone(),
                    description,
                });
            }
        }

        Ok(PolicyClassification {
            compliant: violations.is_empty(),
            violations,
        })
    }

    /// Evaluate a conversation history against all configured policy templates.
    pub async fn evaluate(
        &self,
        history: &[ConversationMessage],
    ) -> Result<PolicyClassification, PolicyError> {
        if history.is_empty() {
            return Err(PolicyError::InvalidContent(
                "Conversation history cannot be empty".into(),
            ));
        }

        let content = Self::format_conversation(history);
        self.evaluate_content(&content).await
    }

    /// Get the configured policy templates.
    pub fn policies(&self) -> &[PolicyTemplate] {
        &self.policies
    }

    /// Get the current model name.
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// Get the current configuration.
    pub fn config(&self) -> &PolicyModelConfig {
        &self.config
    }

    /// Health check to verify the provider is responsive.
    ///
    /// Returns Ok(()) if the provider responds within 5 seconds, Err otherwise.
    /// Use this at startup to fail fast if the provider is unavailable.
    pub async fn health_check(&self) -> Result<(), PolicyError> {
        if let Some(policy) = self.policies.first() {
            self.evaluate_single(policy, "health check", Duration::from_secs(5))
                .await?;
            Ok(())
        } else {
            Err(PolicyError::NoPolicies)
        }
    }

    // -- private helpers ---------------------------------------------------

    async fn evaluate_single(
        &self,
        policy: &PolicyTemplate,
        content: &str,
        timeout: Duration,
    ) -> Result<PolicyModelResult, PolicyError> {
        let system_prompt = policy.render();
        let user_prompt = policy.render_user_message(content);

        // The provider client's Extractor drives the model through a `submit`
        // tool constrained by the `PolicyModelResult` JSON schema, returning the
        // typed value directly. The Harmony system prompt becomes the extractor
        // preamble and temperature is forwarded as a request parameter.
        let extractor = self
            .client
            .extractor::<PolicyModelResult>(&self.config.model)
            .preamble(&system_prompt)
            .additional_params(json!({ "temperature": self.config.temperature }))
            .build();

        tokio::time::timeout(timeout, extractor.extract(user_prompt))
            .await
            .map_err(|_| PolicyError::Timeout)?
            .map_err(|e| PolicyError::Inference(e.to_string()))
    }

    fn format_conversation(history: &[ConversationMessage]) -> String {
        let mut out = String::new();
        for (i, msg) in history.iter().enumerate() {
            out.push_str(&format!("[{}] {}:\n{}\n\n", i + 1, msg.role, msg.content));
        }
        out
    }
}

/// Builder for constructing a [`PolicyModel`] with custom configuration.
#[derive(Debug, Clone)]
pub struct PolicyModelBuilder {
    policies: Vec<PolicyTemplate>,
    config: PolicyModelConfig,
}

impl PolicyModelBuilder {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            config: PolicyModelConfig::default(),
        }
    }

    pub fn policy(mut self, policy: PolicyTemplate) -> Self {
        self.policies.push(policy);
        self
    }

    pub fn provider(mut self, provider: Provider) -> Self {
        self.config.provider = provider;
        self
    }

    pub fn api_key(mut self, api_key: impl Into<Secret>) -> Self {
        self.config.api_key = api_key.into();
        self
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.config.base_url = Some(base_url.into());
        self
    }

    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.config.model = model.into();
        self
    }

    pub fn temperature(mut self, temperature: f32) -> Self {
        self.config.temperature = temperature;
        self
    }

    /// Construct the [`PolicyModel`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::ClientBuild`] if the provider client cannot be
    /// constructed from the configured provider.
    pub fn build(self) -> Result<PolicyModel, PolicyError> {
        PolicyModel::with_config(self.policies, self.config)
    }
}

impl Default for PolicyModelBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn violations_by_category_case_insensitive() {
        let classification = PolicyClassification {
            compliant: false,
            violations: vec![
                PolicyViolation {
                    category: "Injection".to_string(),
                    rule: "SC2".to_string(),
                    description: "V1".to_string(),
                },
                PolicyViolation {
                    category: "injection".to_string(),
                    rule: "SC2".to_string(),
                    description: "V2".to_string(),
                },
                PolicyViolation {
                    category: "Secrets Exposure".to_string(),
                    rule: "SC3".to_string(),
                    description: "V3".to_string(),
                },
            ],
        };

        assert_eq!(classification.violations_by_category("injection").len(), 2);
        let display = format!("{}", classification);
        assert!(display.contains("NON-COMPLIANT"));
    }

    /// Two findings under one code are one code, so a policy matching it does
    /// not depend on how many times the classifier said it.
    #[test]
    fn codes_are_deduplicated() {
        let classification = PolicyClassification {
            compliant: false,
            violations: vec![
                PolicyViolation {
                    category: "Injection".to_string(),
                    rule: "SC2".to_string(),
                    description: "V1".to_string(),
                },
                PolicyViolation {
                    category: "injection".to_string(),
                    rule: "SC2".to_string(),
                    description: "V2".to_string(),
                },
            ],
        };

        assert_eq!(
            classification.codes(),
            BTreeSet::from(["SC2".to_string()]),
            "codes must be the deduplicated `rule` values, not the category names"
        );
    }

    #[test]
    fn policy_model_result_serde() {
        let json = r#"{"violation": 1, "policy_category": "SC2"}"#;
        let result: PolicyModelResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.violation, 1);
        assert_eq!(result.policy_category, "SC2");
    }

    #[test]
    fn policy_template_render_full() {
        let policy = PolicyTemplate::new("SECURE_CODE", "SC")
            .description("Security vulnerabilities in code.")
            .instructions("Evaluate code for vulnerabilities. Return JSON.")
            .category("SC0", "Compliant", "Secure code.")
            .category("SC2", "Injection", "Unsanitized input in queries.")
            .example(
                r#"cursor.execute(f"SELECT * FROM users WHERE id = {id}")"#,
                true,
                "SC2",
            )
            .example(
                r#"cursor.execute("SELECT * FROM users WHERE id = %s", (id,))"#,
                false,
                "SC0",
            );

        let rendered = policy.render();
        assert!(rendered.contains("# SECURE_CODE"));
        assert!(rendered.contains("Evaluate code for vulnerabilities."));
        assert!(rendered.contains("- SC0 (Compliant): Secure code."));
        assert!(rendered.contains(r#""violation": 1, "policy_category": "SC2""#));
    }

    #[test]
    fn policy_template_default_instructions() {
        let policy = PolicyTemplate::new("MINIMAL", "M").category("M0", "Safe", "Safe content.");
        let rendered = policy.render();
        assert!(rendered.contains(r#""violation": 0, "policy_category": "M0""#));
        assert!(!rendered.contains("## EXAMPLES"));
    }

    #[test]
    fn safe_category_uses_prefix() {
        assert_eq!(PolicyTemplate::new("T", "SC").safe_category(), "SC0");
        assert_eq!(PolicyTemplate::new("T", "SP").safe_category(), "SP0");
    }

    #[test]
    fn category_lookups_case_insensitive() {
        let policy = PolicyTemplate::new("TEST", "SC")
            .category("SC0", "Compliant", "Safe code.")
            .category("SC2", "Injection", "Bad input handling.");

        assert_eq!(policy.category_name("SC2"), Some("Injection".to_string()));
        assert_eq!(policy.category_name("sc2"), Some("Injection".to_string()));
        assert_eq!(policy.category_name("SC9"), None);
        assert_eq!(
            policy.category_definition("SC2"),
            Some("Bad input handling.".to_string())
        );
    }

    #[test]
    fn policy_model_builder() {
        let model = PolicyModelBuilder::new()
            .provider(Provider::OpenAI)
            .api_key("sk-test")
            .base_url("https://proxy.internal/v1")
            .model("gpt-oss-safeguard:120b")
            .temperature(0.1)
            .policy(PolicyTemplate::new("P1", "A").category("A0", "Safe", "Safe."))
            .policy(PolicyTemplate::new("P2", "B").category("B0", "Safe", "Safe."))
            .build()
            .expect("client should build");

        assert_eq!(model.model(), "gpt-oss-safeguard:120b");
        assert_eq!(model.config().provider, Provider::OpenAI);
        assert_eq!(
            model.config().base_url.as_deref(),
            Some("https://proxy.internal/v1")
        );
        assert_eq!(model.policies().len(), 2);
    }

    #[test]
    fn format_conversation() {
        let history = vec![
            ConversationMessage::user("Hello"),
            ConversationMessage::assistant("Hi there"),
        ];

        let formatted = PolicyModel::format_conversation(&history);
        assert!(formatted.contains("[1] User:"));
        assert!(formatted.contains("[2] Assistant:"));
    }

    #[test]
    fn parse_toml_full_roundtrip() {
        let toml = r#"
[[policies]]
name = "SECURE_CODE"
prefix = "SC"
description = "Security vulnerabilities."

[[policies.categories]]
code = "SC0"
name = "Compliant"
definition = "Secure code."

[[policies.categories]]
code = "SC2"
name = "Injection"
definition = "Unsanitized input."

[[policies.examples]]
content = "cursor.execute(f\"SELECT * FROM users WHERE id = {id}\")"
violation = true
category = "SC2"

[[policies.examples]]
content = "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (id,))"
violation = false
category = "SC0"
"#;
        let policies = PolicyTemplate::parse_toml(toml).unwrap();
        let p = &policies[0];
        assert_eq!(p.prefix, "SC");
        assert_eq!(p.categories.len(), 2);
        assert!(p.examples[0].violation);

        let rendered = p.render();
        assert!(rendered.contains("# SECURE_CODE"));
    }

    #[test]
    fn parse_toml_invalid() {
        let result = PolicyTemplate::parse_toml("not valid toml [[[");
        assert!(matches!(result.unwrap_err(), PolicyError::TomlError(_)));
    }

    #[test]
    fn load_baseline_toml() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../.sondera/policies.toml"
        );
        let policies = PolicyTemplate::load_from_toml(path).unwrap();
        let p = &policies[0];
        assert_eq!(p.prefix, "SC");
        let codes: Vec<&str> = p.categories.iter().map(|c| c.code.as_str()).collect();
        assert!(codes.contains(&"SC0"));
        assert!(codes.contains(&"SC2"));
        assert!(codes.contains(&"SC7"));
        let _ = p.render();
    }

    #[test]
    fn load_toml_file_not_found() {
        let result = PolicyTemplate::load_from_toml("/nonexistent/path/policy.toml");
        assert!(matches!(result.unwrap_err(), PolicyError::IoError(_)));
    }

    #[test]
    fn policy_model_from_toml() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../.sondera/policies.toml"
        );
        let model = PolicyModel::from_toml(path).unwrap();
        assert_eq!(model.policies().len(), 1);
        assert_eq!(model.model(), "gpt-oss-safeguard:20b");
    }
}
