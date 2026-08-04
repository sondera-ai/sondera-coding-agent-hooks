//! Scanner configuration for trajectory analysis.

use std::time::Duration;

use sondera_provider::{Provider, Secret};

/// Default per-scan wall-clock budget.
///
/// Transcript-level scans send a whole run's events, so they are minutes-scale
/// work on a slow local model. The budget exists to bound a *stuck* call, not to
/// race a working one: a scan that trips it produces nothing, and the trajectory
/// simply ships without that enrichment.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);

/// Configuration for the trajectory scanner.
///
/// Structurally the same shape as the guardrail model configs
/// (`sondera_policy::PolicyModelConfig`,
/// `sondera_information_flow_control::DataModelConfig`), because it answers the
/// same question: which provider, which endpoint, which model. It is a separate
/// type rather than a shared one so a deployment can size post-hoc analysis
/// independently of enforcement — the scanner runs on every event and the
/// guardrails run on every *adjudication*, which are different budgets.
///
/// `sondera_settings::Settings` resolves one of these from `[scanner]` in
/// `sondera.toml`.
#[derive(Debug, Clone, PartialEq)]
pub struct ScannerConfig {
    /// LLM provider the scanner extracts with.
    pub provider: Provider,
    /// Provider credential. Ignored by providers that need none, such as Ollama
    /// and Vertex AI.
    pub api_key: Secret,
    /// Endpoint override. `None` uses the provider's built-in default.
    pub base_url: Option<String>,
    /// Google Cloud project, used only by [`Provider::VertexAi`]. Falls back to
    /// `GOOGLE_CLOUD_PROJECT` when `None`.
    pub project: Option<String>,
    /// Google Cloud location, used only by [`Provider::VertexAi`]. Falls back to
    /// `GOOGLE_CLOUD_LOCATION` when `None`, then to `global`.
    pub location: Option<String>,
    /// Completion model used at every scan granularity.
    pub model: String,
    /// Sampling temperature. Log analysis wants the same verdict twice, so this
    /// defaults to zero.
    pub temperature: f32,
    /// Wall-clock budget for a single scan.
    pub timeout: Duration,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            provider: Provider::Ollama,
            api_key: Secret::default(),
            base_url: Some("http://localhost:11434".to_string()),
            project: None,
            location: None,
            model: "gpt-oss:20b".to_string(),
            temperature: 0.0,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl ScannerConfig {
    /// The default configuration with `model` replaced.
    #[must_use]
    pub fn with_model(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn provider(mut self, provider: Provider) -> Self {
        self.provider = provider;
        self
    }

    #[must_use]
    pub fn api_key(mut self, api_key: impl Into<Secret>) -> Self {
        self.api_key = api_key.into();
        self
    }

    #[must_use]
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Set the Google Cloud project ([`Provider::VertexAi`] only).
    #[must_use]
    pub fn project(mut self, project: impl Into<String>) -> Self {
        self.project = Some(project.into());
        self
    }

    /// Set the Google Cloud location ([`Provider::VertexAi`] only).
    #[must_use]
    pub fn location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    #[must_use]
    pub fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = temperature;
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_targets_a_local_provider_that_needs_no_credential() {
        let config = ScannerConfig::default();
        assert_eq!(config.provider, Provider::Ollama);
        assert!(config.api_key.is_empty());
        assert_eq!(config.temperature, 0.0);
    }

    #[test]
    fn the_builder_threads_every_field() {
        let config = ScannerConfig::with_model("gemini-2.5-flash")
            .provider(Provider::VertexAi)
            .project("my-gcp-project")
            .location("us-central1")
            .timeout(Duration::from_secs(5));

        assert_eq!(config.model, "gemini-2.5-flash");
        assert_eq!(config.provider, Provider::VertexAi);
        assert_eq!(config.project.as_deref(), Some("my-gcp-project"));
        assert_eq!(config.location.as_deref(), Some("us-central1"));
        assert_eq!(config.timeout, Duration::from_secs(5));
    }
}
