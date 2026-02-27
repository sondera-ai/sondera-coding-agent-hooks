use crate::PolicyError;
use schemars::JsonSchema as JsonSchemaDerive;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::path::Path;

/// A severity category within a policy template.
///
/// Categories follow a tiered scheme where the `{prefix}0` code is always the
/// safe / compliant tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCategory {
    /// Short code, e.g. "SC0", "SC2".
    pub code: String,
    /// Human-readable name, e.g. "Compliant", "Injection".
    pub name: String,
    /// Definition of what content belongs in this category.
    pub definition: String,
}

/// A labeled example used near decision boundaries in a policy template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExample {
    /// The example content.
    pub content: String,
    /// Whether the example violates the policy.
    pub violation: bool,
    /// The category code for this example (e.g. "SC0", "SC2").
    pub category: String,
}

/// A policy template following the gpt-oss-safeguard Harmony prompt format
/// with multi-category severity tiers.
///
/// Each template defines a set of [`PolicyCategory`] tiers. The model evaluates
/// content and returns a policy-referencing output with `violation` (0 or 1)
/// and `policy_category` indicating which tier applies.
/// The `{prefix}0` category is always the safe / compliant tier.
///
/// See: <https://developers.openai.com/cookbook/articles/gpt-oss-safeguard-guide>
///
/// # Example
///
/// ```
/// use sondera_policy::PolicyTemplate;
///
/// let policy = PolicyTemplate::new("SECURE_CODE", "SC")
///     .description("Security vulnerabilities in AI-generated code.")
///     .category("SC0", "Compliant", "Code follows secure coding practices.")
///     .category("SC2", "Injection", "CWE-78/89/79: unsanitized user input in interpreters.")
///     .example(r#"cursor.execute(f"SELECT * FROM users WHERE id = {id}")"#, true, "SC2")
///     .example(r#"cursor.execute("SELECT * FROM users WHERE id = %s", (id,))"#, false, "SC0");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplate {
    /// Unique identifier for this policy (e.g. "SECURE_CODE_GENERATION").
    pub name: String,
    /// Short prefix for category codes (e.g. "SC").
    pub prefix: String,
    /// One-line description of the policy scope.
    #[serde(default)]
    pub description: String,
    /// What the model must do and the expected response format.
    #[serde(default)]
    pub instructions: String,
    /// Severity categories from safe (X0) to most severe.
    #[serde(default)]
    pub categories: Vec<PolicyCategory>,
    /// Labeled examples near decision boundaries.
    #[serde(default)]
    pub examples: Vec<PolicyExample>,
}

/// TOML file structure containing an array of policy templates.
#[derive(Deserialize)]
struct PolicyFile {
    policies: Vec<PolicyTemplate>,
}

impl PolicyTemplate {
    pub fn new(name: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            prefix: prefix.into(),
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

    pub fn category(
        mut self,
        code: impl Into<String>,
        name: impl Into<String>,
        definition: impl Into<String>,
    ) -> Self {
        self.categories.push(PolicyCategory {
            code: code.into(),
            name: name.into(),
            definition: definition.into(),
        });
        self
    }

    pub fn example(
        mut self,
        content: impl Into<String>,
        violation: bool,
        category: impl Into<String>,
    ) -> Self {
        self.examples.push(PolicyExample {
            content: content.into(),
            violation,
            category: category.into(),
        });
        self
    }

    /// The safe / compliant category code (always `{prefix}0`).
    pub fn safe_category(&self) -> String {
        format!("{}0", self.prefix)
    }

    /// Look up a category name by its code.
    pub fn category_name(&self, code: &str) -> Option<String> {
        self.categories
            .iter()
            .find(|c| c.code.eq_ignore_ascii_case(code))
            .map(|c| c.name.clone())
    }

    /// Look up a category definition by its code.
    pub fn category_definition(&self, code: &str) -> Option<String> {
        self.categories
            .iter()
            .find(|c| c.code.eq_ignore_ascii_case(code))
            .map(|c| c.definition.clone())
    }

    pub fn load_from_toml(path: impl AsRef<Path>) -> Result<Vec<PolicyTemplate>, PolicyError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| PolicyError::IoError(e.to_string()))?;
        Self::parse_toml(&content)
    }

    pub fn parse_toml(content: &str) -> Result<Vec<PolicyTemplate>, PolicyError> {
        let file: PolicyFile =
            toml::from_str(content).map_err(|e| PolicyError::TomlError(e.to_string()))?;
        Ok(file.policies)
    }

    /// Render this template into a system prompt following the Harmony format
    /// with severity categories and policy-referencing structured output.
    pub fn render(&self) -> String {
        let mut prompt = format!("# {}\n", self.name);

        if !self.description.is_empty() {
            prompt.push('\n');
            prompt.push_str(&self.description);
            prompt.push('\n');
        }

        prompt.push_str("\n## INSTRUCTIONS\n");
        if self.instructions.is_empty() {
            prompt.push_str(&format!(
                "Evaluate the following content against this policy.\n\
                 If the content violates this policy, return:\n\
                 {{\"violation\": 1, \"policy_category\": \"<category_code>\"}}\n\
                 If the content is compliant, return:\n\
                 {{\"violation\": 0, \"policy_category\": \"{safe}\"}}\n",
                safe = self.safe_category()
            ));
        } else {
            prompt.push_str(&self.instructions);
            prompt.push('\n');
        }

        if !self.categories.is_empty() {
            prompt.push_str("\n## CATEGORIES\n");
            for cat in &self.categories {
                prompt.push_str(&format!(
                    "- {} ({}): {}\n",
                    cat.code, cat.name, cat.definition
                ));
            }
        }

        if !self.examples.is_empty() {
            prompt.push_str("\n## EXAMPLES\n");
            for ex in &self.examples {
                prompt.push_str(&format!(
                    "Content: {}\nAnswer: {{\"violation\": {}, \"policy_category\": \"{}\"}}\n\n",
                    ex.content,
                    if ex.violation { 1 } else { 0 },
                    ex.category
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

/// A single policy violation detected in the content.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchemaDerive)]
pub struct PolicyViolation {
    /// Human-readable category name (e.g. "Injection").
    pub category: String,
    /// Category code (e.g. "SC2").
    pub rule: String,
    /// Description of the violation (category definition from the template).
    pub description: String,
}

impl fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} - {}", self.category, self.rule, self.description)
    }
}

/// Aggregated result of evaluating content against all policy templates.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchemaDerive)]
pub struct PolicyClassification {
    /// Overall compliance status.
    pub compliant: bool,
    /// List of policy violations detected.
    #[serde(default)]
    pub violations: Vec<PolicyViolation>,
}

impl Default for PolicyClassification {
    fn default() -> Self {
        Self {
            compliant: true,
            violations: Vec::new(),
        }
    }
}

impl PolicyClassification {
    /// Get policy violation categories as a set.
    pub fn categories(&self) -> HashSet<String> {
        self.violations.iter().map(|v| v.category.clone()).collect()
    }

    /// Get violations of a specific category (case-insensitive).
    pub fn violations_by_category(&self, category: &str) -> Vec<&PolicyViolation> {
        self.violations
            .iter()
            .filter(|v| v.category.eq_ignore_ascii_case(category))
            .collect()
    }
}

impl fmt::Display for PolicyClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} violation(s)",
            if self.compliant {
                "COMPLIANT"
            } else {
                "NON-COMPLIANT"
            },
            self.violations.len(),
        )
    }
}
