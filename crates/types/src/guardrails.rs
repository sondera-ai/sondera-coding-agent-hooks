//! Guardrail result types for content scanning and signature matching.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Structured guardrail results attached to an adjudication.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use sondera_types::GuardrailResults;
///
/// GuardrailResults::default();
/// ```
#[must_use]
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct GuardrailResults {
    /// Signature/YARA-based content scanning results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureGuardrailResult>,
    /// IFC/data-sensitivity classification result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifc: Option<IfcGuardrailResult>,
}

impl GuardrailResults {
    pub fn with_signature(mut self, signature: SignatureGuardrailResult) -> Self {
        self.signature = Some(signature);
        self
    }

    pub fn with_ifc(mut self, ifc: IfcGuardrailResult) -> Self {
        self.ifc = Some(ifc);
        self
    }
}

/// Structured result from IFC/data-sensitivity classification.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct IfcGuardrailResult {
    /// Highest sensitivity label returned by classification.
    pub label: String,
    /// Public-default fallback reason, when classification did not produce a
    /// real label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
}

/// Structured results from signature-based guardrail scanning.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureGuardrailResult {
    /// Whether any guardrail rules matched.
    pub triggered: bool,
    /// Highest matched severity, when any signature matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Distinct categories covered by the matched signatures.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub categories: Vec<String>,
    /// Detailed match metadata for matched signatures.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub matches: Vec<SignatureGuardrailMatch>,
}

/// One matched signature rule.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureGuardrailMatch {
    /// Stable rule identifier.
    pub rule: String,
    /// Optional namespace for the matched rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Rule metadata copied from the YARA rule definition.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub metadata: HashMap<String, String>,
}
