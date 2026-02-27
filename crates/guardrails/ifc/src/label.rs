//! Sensitivity label templates for data classification.
//!
//! This module defines sensitivity label templates following the gpt-oss-safeguard
//! model format, analogous to the policy template system. Labels define categories
//! for classifying data sensitivity based on Microsoft Purview sensitivity labels.

use crate::DataClassificationError;
use schemars::JsonSchema as JsonSchemaDerive;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use strum_macros::{Display, EnumString};

/// Data sensitivity classification levels aligned with Microsoft Purview sensitivity labels.
///
/// These labels follow the Microsoft Purview Information Protection standard:
/// - **Public**: Information that can be freely shared externally
/// - **General**: Internal information not intended for public sharing
/// - **Confidential**: Sensitive business data requiring access control
/// - **Highly Confidential**: Most sensitive data with strict access restrictions
///
/// The enum serializes to snake_case (`"public"`, `"internal"`, `"confidential"`,
/// `"highly_confidential"`) for use in structured model output and TOML configuration.
///
/// See: <https://learn.microsoft.com/en-us/purview/sensitivity-labels>
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    JsonSchemaDerive,
    EnumString,
    Display,
    Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    /// Public data - can be freely shared externally without restrictions.
    /// Examples: Marketing materials, public announcements, published content.
    #[default]
    Public,
    /// General (internal) data - not intended for public sharing but not highly sensitive.
    /// Examples: Internal communications, general business documents, policies.
    Internal,
    /// Confidential data - sensitive business information requiring protection.
    /// Examples: Business strategies, customer lists, internal reports.
    /// Sublabels: Anyone (unrestricted), All Employees, Trusted People.
    Confidential,
    /// Highly Confidential data - most sensitive, requires strict access control.
    /// Examples: Trade secrets, PII, financial records, credentials, M&A data.
    /// Requires encryption, audit logging, and DLP policies.
    HighlyConfidential,
}

impl Label {
    /// Human-readable display name with proper spacing.
    pub fn display_name(&self) -> &'static str {
        match self {
            Label::Public => "Public",
            Label::Internal => "Internal",
            Label::Confidential => "Confidential",
            Label::HighlyConfidential => "Highly Confidential",
        }
    }

    /// The snake_case name used in serde serialization and model output.
    pub fn serde_name(&self) -> &'static str {
        match self {
            Label::Public => "public",
            Label::Internal => "internal",
            Label::Confidential => "confidential",
            Label::HighlyConfidential => "highly_confidential",
        }
    }

    /// Numeric sensitivity level (0=Public, 1=Internal, 2=Confidential, 3=HighlyConfidential).
    pub fn level(&self) -> u8 {
        match self {
            Label::Public => 0,
            Label::Internal => 1,
            Label::Confidential => 2,
            Label::HighlyConfidential => 3,
        }
    }
}

/// A sensitivity category within a label template.
///
/// Each category maps to a [`Label`] enum value and provides a definition
/// describing what content belongs in that sensitivity tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelCategory {
    /// The sensitivity label for this category.
    pub label: Label,
    /// Definition of what content belongs in this category.
    pub definition: String,
}

/// A labeled example used for sensitivity classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelExample {
    /// The example content.
    pub content: String,
    /// Whether this is sensitive data (true) or not (false).
    pub sensitive: bool,
    /// The sensitivity label for this example.
    pub label: Label,
}

/// A sensitivity label template following the gpt-oss-safeguard Harmony prompt format
/// with multi-category sensitivity tiers.
///
/// Each template defines a set of [`LabelCategory`] tiers mapping to [`Label`] values.
/// The model evaluates content and returns a structured output with `sensitive` (0 or 1)
/// and `sensitivity_category` as a [`Label`] enum value.
///
/// # Example
///
/// ```
/// use sondera_information_flow_control::{Label, LabelTemplate};
///
/// let label = LabelTemplate::new("DATA_SENSITIVITY")
///     .description("Data sensitivity classification aligned with Microsoft Purview.")
///     .category(Label::Public, "Information that can be freely shared externally.")
///     .category(Label::Internal, "Internal information not intended for public sharing.")
///     .category(Label::Confidential, "Sensitive business data requiring access control.")
///     .category(Label::HighlyConfidential, "Most sensitive data with strict access restrictions.")
///     .example("Our company was founded in 2010.", false, Label::Public)
///     .example("Employee SSN: 123-45-6789", true, Label::HighlyConfidential);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelTemplate {
    /// Unique identifier for this label (e.g. "DATA_SENSITIVITY").
    pub name: String,
    /// One-line description of the label scope.
    #[serde(default)]
    pub description: String,
    /// What the model must do and the expected response format.
    #[serde(default)]
    pub instructions: String,
    /// Sensitivity categories from public to most sensitive.
    #[serde(default)]
    pub categories: Vec<LabelCategory>,
    /// Labeled examples for classification boundaries.
    #[serde(default)]
    pub examples: Vec<LabelExample>,
}

/// TOML file structure containing an array of sensitivity labels.
#[derive(Deserialize)]
struct LabelFile {
    labels: Vec<LabelTemplate>,
}

impl LabelTemplate {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            instructions: String::new(),
            categories: Vec::new(),
            examples: Vec::new(),
        }
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = instructions.into();
        self
    }

    pub fn category(mut self, label: Label, definition: impl Into<String>) -> Self {
        self.categories.push(LabelCategory {
            label,
            definition: definition.into(),
        });
        self
    }

    pub fn example(mut self, content: impl Into<String>, sensitive: bool, label: Label) -> Self {
        self.examples.push(LabelExample {
            content: content.into(),
            sensitive,
            label,
        });
        self
    }

    /// Look up a category definition by its label.
    pub fn category_definition(&self, label: Label) -> Option<String> {
        self.categories
            .iter()
            .find(|c| c.label == label)
            .map(|c| c.definition.clone())
    }

    pub fn load_from_toml(
        path: impl AsRef<Path>,
    ) -> Result<Vec<LabelTemplate>, DataClassificationError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| DataClassificationError::IoError(e.to_string()))?;
        Self::parse_toml(&content)
    }

    pub fn parse_toml(content: &str) -> Result<Vec<LabelTemplate>, DataClassificationError> {
        let file: LabelFile = toml::from_str(content)
            .map_err(|e| DataClassificationError::TomlError(e.to_string()))?;
        Ok(file.labels)
    }

    /// Render this label template into a system prompt following the Harmony format
    /// with sensitivity categories and structured output.
    pub fn render(&self) -> String {
        let mut prompt = format!("# {}\n", self.name);

        if !self.description.is_empty() {
            prompt.push('\n');
            prompt.push_str(&self.description);
            prompt.push('\n');
        }

        prompt.push_str("\n## INSTRUCTIONS\n");
        if self.instructions.is_empty() {
            prompt.push_str(
                "Evaluate the following content for data sensitivity.\n\
                 If the content is sensitive, return:\n\
                 {\"sensitive\": 1, \"sensitivity_category\": \"<label>\"}\n\
                 If the content is public/non-sensitive, return:\n\
                 {\"sensitive\": 0, \"sensitivity_category\": \"public\"}\n",
            );
        } else {
            prompt.push_str(&self.instructions);
            prompt.push('\n');
        }

        if !self.categories.is_empty() {
            prompt.push_str("\n## CATEGORIES\n");
            for cat in &self.categories {
                prompt.push_str(&format!(
                    "- {} ({}): {}\n",
                    cat.label.serde_name(),
                    cat.label.display_name(),
                    cat.definition
                ));
            }
        }

        if !self.examples.is_empty() {
            prompt.push_str("\n## EXAMPLES\n");
            for ex in &self.examples {
                prompt.push_str(&format!(
                    "Content: {}\nAnswer: {{\"sensitive\": {}, \"sensitivity_category\": \"{}\"}}\n\n",
                    ex.content,
                    if ex.sensitive { 1 } else { 0 },
                    ex.label.serde_name()
                ));
            }
        }

        prompt
    }

    /// Render the user message for evaluation.
    pub fn render_user_message(&self, content: &str) -> String {
        format!("Content: {content}\nAnswer:")
    }
}

/// Structured output from sensitivity classification model.
///
/// The `sensitivity_category` field uses the [`Label`] enum directly, constraining
/// the model's structured JSON output to valid sensitivity levels.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchemaDerive)]
pub struct SensitivityModelResult {
    /// `1` if the content is sensitive, `0` if public/non-sensitive.
    pub sensitive: u8,
    /// The sensitivity label that applies.
    pub sensitivity_category: Label,
}

/// A single sensitivity finding detected in the content.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchemaDerive)]
pub struct SensitivityFinding {
    /// The sensitivity label classification.
    pub label: Label,
    /// Description of the sensitivity finding (category definition from the template).
    pub description: String,
}

impl fmt::Display for SensitivityFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) - {}",
            self.label.display_name(),
            self.label.serde_name(),
            self.description
        )
    }
}

/// Aggregated result of evaluating content against all sensitivity labels.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchemaDerive)]
pub struct SensitivityClassification {
    /// Whether the content is public (not sensitive).
    pub is_public: bool,
    /// List of sensitivity findings detected.
    #[serde(default)]
    pub findings: Vec<SensitivityFinding>,
}

impl Default for SensitivityClassification {
    fn default() -> Self {
        Self {
            is_public: true,
            findings: Vec::new(),
        }
    }
}

impl SensitivityClassification {
    /// Check if the content is public (no sensitive data).
    pub fn is_public(&self) -> bool {
        self.is_public
    }

    /// Check if the content is sensitive.
    pub fn is_sensitive(&self) -> bool {
        !self.is_public
    }

    /// Get findings matching a specific label.
    pub fn findings_by_label(&self, label: Label) -> Vec<&SensitivityFinding> {
        self.findings.iter().filter(|f| f.label == label).collect()
    }

    /// The highest sensitivity label found, or [`Label::Public`] if no findings.
    pub fn max_label(&self) -> Label {
        self.findings
            .iter()
            .map(|f| f.label)
            .max_by_key(|l| l.level())
            .unwrap_or(Label::Public)
    }
}

impl fmt::Display for SensitivityClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} finding(s)",
            if self.is_public {
                "PUBLIC"
            } else {
                "SENSITIVE"
            },
            self.findings.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_serde_roundtrip() {
        let json = serde_json::to_string(&Label::HighlyConfidential).unwrap();
        assert_eq!(json, r#""highly_confidential""#);
        let parsed: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Label::HighlyConfidential);
    }

    #[test]
    fn label_level_ordering() {
        assert!(Label::Public.level() < Label::Internal.level());
        assert!(Label::Internal.level() < Label::Confidential.level());
        assert!(Label::Confidential.level() < Label::HighlyConfidential.level());
    }

    #[test]
    fn label_template_builder_and_render() {
        let label = LabelTemplate::new("DATA_SENSITIVITY")
            .description("Sensitivity classification.")
            .category(Label::Public, "Public data.")
            .category(Label::HighlyConfidential, "Restricted data.")
            .example("Press release content", false, Label::Public)
            .example("SSN: 123-45-6789", true, Label::HighlyConfidential);

        assert_eq!(label.categories.len(), 2);
        assert_eq!(label.examples.len(), 2);
        assert_eq!(
            label.category_definition(Label::Public),
            Some("Public data.".to_string())
        );
        assert_eq!(label.category_definition(Label::Internal), None);

        let prompt = label.render();
        assert!(prompt.contains("# DATA_SENSITIVITY"));
        assert!(prompt.contains("Sensitivity classification."));
        assert!(prompt.contains("public (Public): Public data."));
        assert!(prompt.contains(r#""sensitivity_category": "highly_confidential""#));
    }

    #[test]
    fn render_default_instructions() {
        let label = LabelTemplate::new("TEST").category(Label::Public, "Public data.");
        let prompt = label.render();
        assert!(prompt.contains("## INSTRUCTIONS"));
        assert!(prompt.contains(r#""sensitivity_category": "public""#));
    }

    #[test]
    fn render_user_message() {
        let label = LabelTemplate::new("TEST");
        assert_eq!(
            label.render_user_message("Hello world"),
            "Content: Hello world\nAnswer:"
        );
    }

    #[test]
    fn model_result_serde() {
        let json = r#"{"sensitive": 1, "sensitivity_category": "highly_confidential"}"#;
        let result: SensitivityModelResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.sensitive, 1);
        assert_eq!(result.sensitivity_category, Label::HighlyConfidential);

        let roundtrip = serde_json::to_string(&result).unwrap();
        let result2: SensitivityModelResult = serde_json::from_str(&roundtrip).unwrap();
        assert_eq!(result2.sensitivity_category, Label::HighlyConfidential);
    }

    #[test]
    fn model_result_json_schema() {
        use schemars::schema_for;
        let schema = schema_for!(SensitivityModelResult);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("sensitive"));
        assert!(json.contains("sensitivity_category"));
        assert!(json.contains("highly_confidential"));
    }

    #[test]
    fn parse_toml_full_roundtrip() {
        let toml = r#"
[[labels]]
name = "DATA_SENSITIVITY"
description = "Data sensitivity classification."

[[labels.categories]]
label = "public"
definition = "Public data."

[[labels.categories]]
label = "highly_confidential"
definition = "Restricted data."

[[labels.examples]]
content = "Company press release"
sensitive = false
label = "public"

[[labels.examples]]
content = "SSN: 123-45-6789"
sensitive = true
label = "highly_confidential"
"#;
        let labels = LabelTemplate::parse_toml(toml).unwrap();
        assert_eq!(labels.len(), 1);

        let l = &labels[0];
        assert_eq!(l.categories[0].label, Label::Public);
        assert_eq!(l.categories[1].label, Label::HighlyConfidential);
        assert!(!l.examples[0].sensitive);
        assert!(l.examples[1].sensitive);

        let rendered = l.render();
        assert!(rendered.contains("# DATA_SENSITIVITY"));
        assert!(rendered.contains("public (Public): Public data."));
    }

    #[test]
    fn parse_toml_invalid() {
        let result = LabelTemplate::parse_toml("not valid toml [[[");
        assert!(matches!(
            result.unwrap_err(),
            DataClassificationError::TomlError(_)
        ));
    }

    #[test]
    fn load_baseline_toml() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../policies/ifc.toml");
        let labels = LabelTemplate::load_from_toml(path).unwrap();
        assert_eq!(labels.len(), 1);

        let l = &labels[0];
        let label_values: Vec<Label> = l.categories.iter().map(|c| c.label).collect();
        assert!(label_values.contains(&Label::Public));
        assert!(label_values.contains(&Label::HighlyConfidential));
        let _ = l.render();
    }

    #[test]
    fn load_toml_file_not_found() {
        let result = LabelTemplate::load_from_toml("/nonexistent/path/label.toml");
        assert!(matches!(
            result.unwrap_err(),
            DataClassificationError::IoError(_)
        ));
    }

    #[test]
    fn classification_lifecycle() {
        // Default is public
        let default = SensitivityClassification::default();
        assert!(default.is_public());
        assert!(!default.is_sensitive());
        assert_eq!(default.max_label(), Label::Public);

        // With findings
        let classification = SensitivityClassification {
            is_public: false,
            findings: vec![
                SensitivityFinding {
                    label: Label::Internal,
                    description: "Internal data".to_string(),
                },
                SensitivityFinding {
                    label: Label::HighlyConfidential,
                    description: "Contains PII".to_string(),
                },
            ],
        };
        assert_eq!(classification.max_label(), Label::HighlyConfidential);
        assert_eq!(classification.findings_by_label(Label::Internal).len(), 1);
        assert_eq!(classification.findings_by_label(Label::Public).len(), 0);

        let display = format!("{}", classification);
        assert!(display.contains("SENSITIVE"));
    }
}
