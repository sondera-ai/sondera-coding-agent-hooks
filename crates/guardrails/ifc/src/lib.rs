//! Data classification model for categorizing content sensitivity levels.
//!
//! This module provides data classification capabilities using local LLMs via Ollama.
//! It classifies content into sensitivity levels aligned with Microsoft Purview
//! sensitivity labels: Public, General, Confidential, and Highly Confidential.
//!
//! The crate uses the gpt-oss-safeguard reasoning model via Ollama to classify
//! content against sensitivity label templates following the Harmony prompt format
//! with multi-category sensitivity tiers.
//!
//! The model returns structured output with `sensitivity_category` as a [`Label`]
//! enum value (`public`, `internal`, `confidential`, `highly_confidential`),
//! enabling type-safe classification without string-based lookups.
//!
//! See: <https://learn.microsoft.com/en-us/purview/sensitivity-labels>

mod label;

use sondera_llm_backend::{LlmBackend, LlmBackendError};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tracing::instrument;

pub use label::{
    Label, LabelCategory, LabelExample, LabelTemplate, SensitivityClassification,
    SensitivityFinding, SensitivityModelResult,
};
pub use sondera_llm_backend::{self, BackendConfig};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during data classification.
#[derive(Debug, Error)]
pub enum DataClassificationError {
    #[error("LLM backend error: {0}")]
    BackendError(String),
    #[error("Failed to parse classification response: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("No label templates configured")]
    NoLabels,
    #[error("Failed to read label file: {0}")]
    IoError(String),
    #[error("Failed to parse TOML: {0}")]
    TomlError(String),
}

impl From<LlmBackendError> for DataClassificationError {
    fn from(e: LlmBackendError) -> Self {
        Self::BackendError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Model configuration
// ---------------------------------------------------------------------------

/// Configuration for the data classification model.
#[derive(Debug, Clone)]
pub struct DataModelConfig {
    /// Backend connection configuration.
    pub backend: BackendConfig,
    /// Model name (default: gpt-oss-safeguard:20b)
    pub model: String,
    /// Temperature for model inference (default: 0.0 for deterministic output)
    pub temperature: f32,
}

impl Default for DataModelConfig {
    fn default() -> Self {
        Self {
            backend: BackendConfig::default(),
            model: "gpt-oss-safeguard:20b".to_string(),
            temperature: 0.0,
        }
    }
}

impl DataModelConfig {
    pub fn with_model(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            ..Default::default()
        }
    }

    pub fn backend(mut self, backend: BackendConfig) -> Self {
        self.backend = backend;
        self
    }

    pub fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = temperature;
        self
    }
}

// ---------------------------------------------------------------------------
// DataModel
// ---------------------------------------------------------------------------

/// Data classification model using gpt-oss-safeguard for evaluating content
/// against sensitivity label templates with multi-category tiers.
///
/// Each [`LabelTemplate`] is evaluated independently. The model returns a
/// structured output with `sensitivity_category` as a [`Label`] enum value,
/// which is mapped to a [`SensitivityFinding`] when the content is sensitive.
///
/// # Example
///
/// ```no_run
/// use sondera_information_flow_control::{DataModel, Label, LabelTemplate};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let label = LabelTemplate::new("DATA_SENSITIVITY")
///     .description("Data sensitivity classification aligned with Microsoft Purview.")
///     .category(Label::Public, "Information that can be freely shared externally.")
///     .category(Label::HighlyConfidential, "Most sensitive data with strict access restrictions.")
///     .example("Our company was founded in 2010.", false, Label::Public)
///     .example("Employee SSN: 123-45-6789", true, Label::HighlyConfidential);
///
/// let model = DataModel::new(vec![label]);
/// let result = model.classify("Employee SSN: 123-45-6789").await?;
///
/// if result.is_sensitive() {
///     for f in &result.findings {
///         println!("{}: {}", f.label.display_name(), f.description);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct DataModel {
    backend: LlmBackend,
    config: DataModelConfig,
    labels: Vec<LabelTemplate>,
}

impl DataModel {
    pub fn new(labels: Vec<LabelTemplate>) -> Self {
        Self::with_config(labels, DataModelConfig::default())
    }

    pub fn from_toml(path: impl AsRef<Path>) -> Result<Self, DataClassificationError> {
        let labels = LabelTemplate::load_from_toml(path)?;
        Ok(Self::new(labels))
    }

    /// Load label templates from TOML with an explicit backend and optional model override.
    pub fn from_toml_with_backend(
        path: impl AsRef<Path>,
        backend: LlmBackend,
        model: Option<&str>,
    ) -> Result<Self, DataClassificationError> {
        let labels = LabelTemplate::load_from_toml(path)?;
        let mut config = DataModelConfig::default();
        if let Some(m) = model {
            config.model = m.to_string();
        }
        Ok(Self {
            backend,
            config,
            labels,
        })
    }

    pub fn with_config(labels: Vec<LabelTemplate>, config: DataModelConfig) -> Self {
        let backend = LlmBackend::from_config(&config.backend);
        Self {
            backend,
            config,
            labels,
        }
    }

    /// Classify content against all configured label templates.
    ///
    /// Each label is evaluated independently. A finding is recorded when
    /// `sensitive == 1` in the model's response.
    #[instrument(skip(self, content), fields(content_len = content.len()))]
    pub async fn classify(
        &self,
        content: &str,
    ) -> Result<SensitivityClassification, DataClassificationError> {
        if self.labels.is_empty() {
            return Err(DataClassificationError::NoLabels);
        }

        let mut findings = Vec::new();

        let timeout_secs = std::env::var("SONDERA_TIMEOUT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);

        for label in &self.labels {
            let result = self
                .classify_single(label, content, Duration::from_secs(timeout_secs))
                .await?;

            if result.sensitive == 1 {
                let sensitivity_label = result.sensitivity_category;
                let description = label
                    .category_definition(sensitivity_label)
                    .unwrap_or_else(|| sensitivity_label.display_name().to_string());

                findings.push(SensitivityFinding {
                    label: sensitivity_label,
                    description,
                });
            }
        }

        Ok(SensitivityClassification {
            is_public: findings.is_empty(),
            findings,
        })
    }

    /// Get the configured label templates.
    pub fn labels(&self) -> &[LabelTemplate] {
        &self.labels
    }

    /// Get the current model name.
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// Get the current configuration.
    pub fn config(&self) -> &DataModelConfig {
        &self.config
    }

    /// Health check to verify Ollama is responsive.
    ///
    /// Returns Ok(()) if Ollama responds within 5 seconds, Err otherwise.
    /// Use this at startup to fail fast if Ollama is unavailable.
    pub async fn health_check(&self) -> Result<(), DataClassificationError> {
        if let Some(label) = self.labels.first() {
            self.classify_single(label, "health check", Duration::from_secs(5))
                .await?;
            Ok(())
        } else {
            Err(DataClassificationError::NoLabels)
        }
    }

    // -- private helpers ---------------------------------------------------

    async fn classify_single(
        &self,
        label: &LabelTemplate,
        content: &str,
        timeout: Duration,
    ) -> Result<SensitivityModelResult, DataClassificationError> {
        let system_prompt = label.render();
        let user_prompt = label.render_user_message(content);

        let json_schema = serde_json::to_value(schemars::schema_for!(SensitivityModelResult))
            .map_err(|e| DataClassificationError::BackendError(format!("Schema error: {e}")))?;

        let response = self
            .backend
            .chat_completion(
                &self.config.model,
                &system_prompt,
                &user_prompt,
                json_schema,
                self.config.temperature,
                timeout,
            )
            .await?;

        let result: SensitivityModelResult = serde_json::from_str(&response)?;

        Ok(result)
    }
}

/// Builder for constructing a [`DataModel`] with custom configuration.
#[derive(Debug, Clone)]
pub struct DataModelBuilder {
    labels: Vec<LabelTemplate>,
    config: DataModelConfig,
}

impl DataModelBuilder {
    pub fn new() -> Self {
        Self {
            labels: Vec::new(),
            config: DataModelConfig::default(),
        }
    }

    pub fn label(mut self, label: LabelTemplate) -> Self {
        self.labels.push(label);
        self
    }

    pub fn backend(mut self, backend: BackendConfig) -> Self {
        self.config.backend = backend;
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

    pub fn build(self) -> DataModel {
        DataModel::with_config(self.labels, self.config)
    }
}

impl Default for DataModelBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_model_builder_custom_config() {
        let model = DataModelBuilder::new()
            .backend(BackendConfig::Ollama {
                host: "http://192.168.1.100".to_string(),
                port: 11435,
            })
            .model("gpt-oss-safeguard:120b")
            .temperature(0.1)
            .label(LabelTemplate::new("L1").category(Label::Public, "Public."))
            .label(LabelTemplate::new("L2").category(Label::Public, "Public."))
            .build();

        assert_eq!(model.model(), "gpt-oss-safeguard:120b");
        assert_eq!(model.labels().len(), 2);
    }

    #[test]
    fn data_model_from_toml() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../policies/ifc.toml");
        let model = DataModel::from_toml(path).unwrap();
        assert_eq!(model.labels().len(), 1);
        assert_eq!(model.model(), "gpt-oss-safeguard:20b");
    }
}
