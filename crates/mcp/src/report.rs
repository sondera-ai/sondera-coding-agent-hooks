//! The structured result every validation tool returns.
//!
//! Two properties matter more than the shape itself.
//!
//! **Findings carry a stable code.** `lint/raw-url-glob` is something a caller
//! can branch on; a prose string is not. The codes are public
//! ([`crate::lint::LINT_CODES`], [`CODE_POLICY_VALIDATION`],
//! [`CODE_SCHEMA_VALIDATION`]) and are served to agents as data, so what will
//! be checked is knowable before drafting rather than only after a failure.
//!
//! **[`Provenance::checks_run`] reports which stages actually ran.** A report
//! that omits a stage is not a report that the stage passed: parsing failures
//! stop the pipeline, and a caller that cannot tell "clean" from "never got
//! that far" will read the second as the first.

use serde::{Deserialize, Serialize};

/// Finding code for Cedar parse failures, missing or empty required
/// annotations, and duplicate `@id`s within one candidate.
pub const CODE_POLICY_VALIDATION: &str = "cedar/policy-validation";

/// Finding code for schema parse failures and for a candidate that does not
/// validate against the schema.
pub const CODE_SCHEMA_VALIDATION: &str = "cedar/schema-validation";

/// Finding code for entity failures: a malformed UID, an entity type absent
/// from the schema, or entities JSON that does not match it.
pub const CODE_ENTITY_VALIDATION: &str = "cedar/entity-validation";

/// How much a finding matters. Only [`Severity::Error`] makes a report invalid.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The candidate is not usable as written.
    Error,
    /// The candidate is valid Cedar but likely does not do what was intended.
    Warning,
}

/// One structured problem with a candidate.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Finding {
    /// Stable machine-readable code, e.g. `cedar/policy-validation`.
    pub code: String,
    /// Whether this invalidates the candidate.
    pub severity: Severity,
    /// Human-readable explanation, including how to fix it where that is known.
    pub message: String,
    /// `@id` of the policy the finding is about, when it is attributable to
    /// one. Absent for whole-candidate failures such as a parse error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

impl Finding {
    /// An error-severity finding, not attributed to a single policy.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Error,
            message: message.into(),
            policy_id: None,
        }
    }

    /// A warning-severity finding, not attributed to a single policy.
    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Warning,
            message: message.into(),
            policy_id: None,
        }
    }

    /// Attribute this finding to the policy with the given `@id`.
    #[must_use]
    pub fn in_policy(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }
}

/// What the validator did, so a caller can tell a passed check from a check
/// that never ran.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Provenance {
    /// Stage names that executed, in order. A stage absent here did not run.
    pub checks_run: Vec<String>,
    /// Name and version of the validator that produced this report.
    pub validator: String,
}

/// The outcome of validating one candidate.
///
/// Verify-only for policy text: `candidate` is the input echoed back
/// byte-for-byte. The validator never reformats, rewrites, or
/// namespace-qualifies a policy on the caller's behalf — a caller that receives
/// one back can trust it is the one they sent.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidationReport {
    /// True when no error-severity findings were produced. Warnings do not
    /// invalidate a candidate.
    pub valid: bool,
    /// What this report is about. For policy and schema text it is the input
    /// echoed back unchanged; for a single entity, which is supplied as a type
    /// and an id rather than as text, it is the UID those compose to.
    pub candidate: String,
    /// Findings that make the candidate unusable.
    pub errors: Vec<Finding>,
    /// Findings worth review that do not block use.
    pub warnings: Vec<Finding>,
    /// Which checks ran, and what ran them.
    pub provenance: Provenance,
}

impl ValidationReport {
    /// Build a report, deriving `valid` from whether any errors were recorded.
    pub fn new(candidate: &str, findings: Vec<Finding>, checks_run: Vec<String>) -> Self {
        let (errors, warnings): (Vec<_>, Vec<_>) = findings
            .into_iter()
            .partition(|f| f.severity == Severity::Error);

        Self {
            valid: errors.is_empty(),
            candidate: candidate.to_string(),
            errors,
            warnings,
            provenance: Provenance {
                checks_run,
                validator: validator_id(),
            },
        }
    }
}

/// The validator's name and version, recorded on every report.
pub fn validator_id() -> String {
    format!("sondera-mcp {}", env!("CARGO_PKG_VERSION"))
}
