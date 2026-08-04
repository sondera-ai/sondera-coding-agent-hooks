//! The enumerations a policy author has to get exactly right.
//!
//! Signature categories, policy violation codes, and sensitivity labels are
//! closed sets matched exactly. A literal outside the set is not a weaker
//! policy — it is a condition that can never be true, and Cedar cannot catch it
//! because every one of them is a well-typed `String`. So the values come from
//! the same Rust definitions the engine matches on, computed at call time: there
//! is no second copy to fall out of date.
//!
//! What this module adds over returning all of that is *bounding*. The full rule
//! set is far larger than an MCP client will accept inline, and a client that
//! truncates does not say so — the caller sees a short list and reasonably
//! concludes it is the whole list. So the unfiltered response carries only the
//! enumerations (small, and complete by construction), rules are served against
//! a filter, and anything dropped for size is named in `omitted_rule_ids`.

use std::collections::{BTreeMap, BTreeSet};

use rmcp::ErrorData as McpError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::lint::LINT_CODES;

/// Maximum serialized size of the `rules` array in one response.
const MAX_RULES_BYTES: usize = 8 * 1024;

/// Which slice of the context feature surface to return.
#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct ContextFeaturesArgs {
    /// Signature category to list rules for, e.g. `credential_access`. Values
    /// come from the `signatures.categories` enumeration this tool returns.
    pub category: Option<String>,
    /// Case-insensitive substring match over a rule's identifier and metadata.
    /// Combines with `category` — both must match.
    pub query: Option<String>,
    /// Include the classifier definitions for policy categories and sensitivity
    /// labels. These are long prose; the codes alone are what a policy matches
    /// on, so they are omitted by default.
    pub include_definitions: Option<bool>,
}

/// One signature category and how many rules carry it.
#[derive(Serialize, Debug)]
pub struct CategoryCount {
    /// The value to match in `context.signature.categories`.
    pub category: String,
    /// Number of signature rules in this category.
    pub rule_count: usize,
}

/// One signature rule, metadata only.
#[derive(Serialize, Debug)]
pub struct RuleSummary {
    /// Rule identifier.
    pub identifier: String,
    /// Namespace the rule is declared in.
    pub namespace: String,
    /// Rule metadata, including its category and severity.
    pub metadata: BTreeMap<String, String>,
}

/// A policy-model category: the codes `context.policy.violations` carries.
#[derive(Serialize, Debug)]
pub struct PolicyCategory {
    /// The value to match in `context.policy.violations`.
    pub code: String,
    /// Short human name.
    pub name: String,
    /// Classifier definition, when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition: Option<String>,
}

/// A policy model and its categories.
#[derive(Serialize, Debug)]
pub struct PolicyModel {
    /// Model name.
    pub name: String,
    /// Code prefix shared by this model's categories.
    pub prefix: String,
    /// What the model evaluates.
    pub description: String,
    /// The closed set of codes it can report.
    pub categories: Vec<PolicyCategory>,
}

/// One sensitivity label.
#[derive(Serialize, Debug)]
pub struct LabelCategory {
    /// The `Sondera::Label::"…"` entity id.
    pub label: String,
    /// Human-readable name.
    pub display_name: String,
    /// Position in the lattice; higher is more sensitive.
    pub level: u8,
    /// Classifier definition, when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition: Option<String>,
}

/// A label model and its categories.
#[derive(Serialize, Debug)]
pub struct LabelModel {
    /// Model name.
    pub name: String,
    /// What the model classifies.
    pub description: String,
    /// The lattice, least to most sensitive.
    pub categories: Vec<LabelCategory>,
}

/// The signature enumeration plus, when asked for, matching rules.
#[derive(Serialize, Debug)]
pub struct Signatures {
    /// Total rules in the embedded set.
    pub rule_count: usize,
    /// Every category, with its rule count. Always complete.
    pub categories: Vec<CategoryCount>,
    /// Rules matching the filter. Absent when no filter was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<RuleSummary>>,
    /// How many rules matched the filter, including any omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_match_count: Option<usize>,
    /// Identifiers of matching rules that did not fit the response budget.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub omitted_rule_ids: Vec<String>,
    /// Set when `category` named a category no rule carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_category: Option<String>,
    /// How to get rules, present only when none were requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_hint: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ClosedVocabularies {
    pub signature_categories: BTreeSet<String>,
    pub policy_violations: BTreeSet<String>,
    pub sensitivity_labels: BTreeSet<String>,
}

pub(crate) fn closed_vocabularies() -> Option<ClosedVocabularies> {
    let signature_categories = sondera_signature::list_rules()
        .into_iter()
        .map(|rule| category_of(&rule.metadata))
        .collect();
    let policy_violations =
        sondera_policy::PolicyTemplate::parse_toml(include_str!("../../../.sondera/policies.toml"))
            .ok()?
            .into_iter()
            .flat_map(|template| {
                template
                    .categories
                    .into_iter()
                    .map(|category| category.code)
            })
            .collect();
    let sensitivity_labels = sondera_information_flow_control::LabelTemplate::parse_toml(
        include_str!("../../../.sondera/ifc.toml"),
    )
    .ok()?
    .into_iter()
    .flat_map(|template| {
        template
            .categories
            .into_iter()
            .map(|category| category.label.serde_name().to_string())
    })
    .collect();

    Some(ClosedVocabularies {
        signature_categories,
        policy_violations,
        sensitivity_labels,
    })
}

/// Everything an author needs to write a literal the engine can match.
#[derive(Serialize, Debug)]
pub struct ContextFeatures {
    /// YARA signature categories behind `context.signature.categories` and
    /// `context.file_signature.categories`.
    pub signatures: Signatures,
    /// Policy models behind `context.policy.violations`.
    pub policy_violations: Vec<PolicyModel>,
    /// Sensitivity labels behind `context.label` and `resource.label`.
    pub sensitivity_labels: Vec<LabelModel>,
    /// The semantic lints a candidate is checked against, so what will be
    /// verified is knowable before drafting.
    pub lints: &'static [crate::lint::LintCode],
}

/// Build the context feature surface for one request.
///
/// # Errors
/// Returns an error if the embedded policy or label templates cannot be parsed,
/// which is a build-time defect rather than a caller error.
pub fn context_features(args: &ContextFeaturesArgs) -> Result<ContextFeatures, McpError> {
    Ok(ContextFeatures {
        signatures: signatures(args),
        policy_violations: policy_models(args.include_definitions.unwrap_or(false))?,
        sensitivity_labels: label_models(args.include_definitions.unwrap_or(false))?,
        lints: LINT_CODES,
    })
}

/// The category enumeration, plus rules when a filter selects them.
fn signatures(args: &ContextFeaturesArgs) -> Signatures {
    let rules = sondera_signature::list_rules();

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for rule in &rules {
        *counts.entry(category_of(&rule.metadata)).or_default() += 1;
    }

    let total_rules = rules.len();
    let filtering = args.category.is_some() || args.query.is_some();
    let unknown_category = args
        .category
        .as_ref()
        .filter(|requested| !counts.contains_key(*requested))
        .cloned();

    let categories = counts
        .into_iter()
        .map(|(category, rule_count)| CategoryCount {
            category,
            rule_count,
        })
        .collect();

    if !filtering {
        return Signatures {
            rule_count: total_rules,
            categories,
            rules: None,
            rule_match_count: None,
            omitted_rule_ids: Vec::new(),
            unknown_category: None,
            rules_hint: Some(
                "Rules are not listed by default because the full set exceeds what clients \
                 accept inline. Pass `category` (from `signatures.categories`) or `query` to \
                 list them."
                    .to_string(),
            ),
        };
    }

    let query = args.query.as_ref().map(|q| q.to_lowercase());
    let matched: Vec<RuleSummary> = rules
        .into_iter()
        .filter(|rule| match &args.category {
            Some(category) => &category_of(&rule.metadata) == category,
            None => true,
        })
        .filter(|rule| match &query {
            Some(query) => {
                let haystack = format!(
                    "{} {}",
                    rule.identifier,
                    rule.metadata
                        .values()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ")
                )
                .to_lowercase();
                query.split_whitespace().all(|term| haystack.contains(term))
            }
            None => true,
        })
        .map(|rule| RuleSummary {
            identifier: rule.identifier,
            namespace: rule.namespace,
            metadata: rule.metadata.into_iter().collect(),
        })
        .collect();

    let match_count = matched.len();
    let mut kept = Vec::new();
    let mut omitted_rule_ids = Vec::new();
    let mut used = 0;
    for rule in matched {
        let size = serde_json::to_string(&rule).map(|s| s.len()).unwrap_or(0);
        if !omitted_rule_ids.is_empty() || used + size > MAX_RULES_BYTES {
            omitted_rule_ids.push(rule.identifier);
        } else {
            used += size;
            kept.push(rule);
        }
    }

    Signatures {
        // The total, not the match count: a caller comparing the two is how a
        // filter that matched almost nothing becomes visible as such.
        rule_count: total_rules,
        categories,
        rules: Some(kept),
        rule_match_count: Some(match_count),
        omitted_rule_ids,
        unknown_category,
        rules_hint: None,
    }
}

/// A rule's declared category, or the bucket for rules that declare none.
fn category_of(metadata: &std::collections::HashMap<String, String>) -> String {
    metadata
        .get("category")
        .cloned()
        .unwrap_or_else(|| "uncategorized".to_string())
}

/// The policy models the engine ships with.
fn policy_models(include_definitions: bool) -> Result<Vec<PolicyModel>, McpError> {
    let templates =
        sondera_policy::PolicyTemplate::parse_toml(include_str!("../../../.sondera/policies.toml"))
            .map_err(|e| {
                McpError::internal_error(format!("Failed to parse policy baseline: {e}"), None)
            })?;

    Ok(templates
        .iter()
        .map(|template| PolicyModel {
            name: template.name.clone(),
            prefix: template.prefix.clone(),
            description: template.description.clone(),
            categories: template
                .categories
                .iter()
                .map(|category| PolicyCategory {
                    code: category.code.clone(),
                    name: category.name.clone(),
                    definition: include_definitions.then(|| category.definition.clone()),
                })
                .collect(),
        })
        .collect())
}

/// The sensitivity lattice the engine ships with.
fn label_models(include_definitions: bool) -> Result<Vec<LabelModel>, McpError> {
    let templates = sondera_information_flow_control::LabelTemplate::parse_toml(include_str!(
        "../../../.sondera/ifc.toml"
    ))
    .map_err(|e| McpError::internal_error(format!("Failed to parse IFC baseline: {e}"), None))?;

    Ok(templates
        .iter()
        .map(|template| LabelModel {
            name: template.name.clone(),
            description: template.description.clone(),
            categories: template
                .categories
                .iter()
                .map(|category| LabelCategory {
                    label: category.label.serde_name().to_string(),
                    display_name: category.label.display_name().to_string(),
                    level: category.label.level(),
                    definition: include_definitions.then(|| category.definition.clone()),
                })
                .collect(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features(args: ContextFeaturesArgs) -> ContextFeatures {
        context_features(&args).expect("embedded baselines should parse")
    }

    fn size_of(features: &ContextFeatures) -> usize {
        serde_json::to_string(features).unwrap().len()
    }

    #[test]
    fn the_unfiltered_response_omits_rules() {
        let features = features(ContextFeaturesArgs::default());

        assert!(features.signatures.rules.is_none());
        assert!(features.signatures.rules_hint.is_some());
    }

    /// The regression this bounding exists for: the unfiltered response used to
    /// carry every rule's metadata and ran well past what clients accept inline,
    /// where the overflow is dropped without any indication it happened.
    #[test]
    fn the_unfiltered_response_stays_inline() {
        let size = size_of(&features(ContextFeaturesArgs::default()));

        assert!(
            size <= 9 * 1024,
            "unfiltered response is {size} bytes, too large to return inline"
        );
    }

    #[test]
    fn the_category_enumeration_is_always_complete() {
        let unfiltered = features(ContextFeaturesArgs::default());
        let filtered = features(ContextFeaturesArgs {
            category: Some("credential_access".to_string()),
            ..Default::default()
        });

        assert_eq!(
            unfiltered.signatures.categories.len(),
            filtered.signatures.categories.len(),
            "filtering rules must not narrow the category enumeration"
        );
    }

    #[test]
    fn every_category_carries_at_least_one_rule() {
        for category in &features(ContextFeaturesArgs::default())
            .signatures
            .categories
        {
            assert!(
                category.rule_count > 0,
                "{} is listed with no rules",
                category.category
            );
        }
    }

    #[test]
    fn filtering_by_category_returns_only_that_category() {
        let categories = features(ContextFeaturesArgs::default())
            .signatures
            .categories;
        let target = categories
            .first()
            .expect("the embedded rule set should declare categories")
            .category
            .clone();

        let filtered = features(ContextFeaturesArgs {
            category: Some(target.clone()),
            ..Default::default()
        });

        for rule in filtered.signatures.rules.as_ref().unwrap() {
            assert_eq!(rule.metadata.get("category"), Some(&target));
        }
    }

    #[test]
    fn an_unknown_category_is_reported_rather_than_returning_an_empty_list() {
        let filtered = features(ContextFeaturesArgs {
            category: Some("no_such_category".to_string()),
            ..Default::default()
        });

        assert_eq!(
            filtered.signatures.unknown_category.as_deref(),
            Some("no_such_category")
        );
    }

    #[test]
    fn a_query_matches_all_terms() {
        let filtered = features(ContextFeaturesArgs {
            query: Some("zzzz-no-such-rule".to_string()),
            ..Default::default()
        });

        assert_eq!(filtered.signatures.rules.as_ref().unwrap().len(), 0);
    }

    #[test]
    fn a_broad_filter_names_what_it_omitted() {
        // An empty query matches every rule, which is deliberately more than
        // fits: the point is that the overflow is reported, not silent.
        let filtered = features(ContextFeaturesArgs {
            query: Some(String::new()),
            ..Default::default()
        });
        let signatures = filtered.signatures;

        assert_eq!(
            signatures.rules.as_ref().unwrap().len() + signatures.omitted_rule_ids.len(),
            signatures.rule_match_count.unwrap(),
            "every matching rule must be either returned or named as omitted"
        );
    }

    #[test]
    fn definitions_are_excluded_by_default() {
        let features = features(ContextFeaturesArgs::default());

        assert!(
            features.sensitivity_labels[0].categories[0]
                .definition
                .is_none()
        );
    }

    #[test]
    fn definitions_are_included_on_request() {
        let features = features(ContextFeaturesArgs {
            include_definitions: Some(true),
            ..Default::default()
        });

        assert!(
            features.sensitivity_labels[0].categories[0]
                .definition
                .is_some()
        );
    }

    /// `rule_count` is the size of the embedded set, so it does not move when a
    /// filter narrows the result; `rule_match_count` is what moves.
    #[test]
    fn the_total_rule_count_is_stable_across_filters() {
        let unfiltered = features(ContextFeaturesArgs::default());
        let filtered = features(ContextFeaturesArgs {
            query: Some("zzzz-no-such-rule".to_string()),
            ..Default::default()
        });

        assert_eq!(
            unfiltered.signatures.rule_count,
            filtered.signatures.rule_count
        );
        assert_eq!(filtered.signatures.rule_match_count, Some(0));
    }

    #[test]
    fn the_lint_contract_is_served_with_the_enumerations() {
        let features = features(ContextFeaturesArgs::default());

        assert_eq!(features.lints.len(), LINT_CODES.len());
    }

    #[test]
    fn the_lattice_is_ordered_least_to_most_sensitive() {
        let labels = features(ContextFeaturesArgs::default());
        let levels: Vec<u8> = labels.sensitivity_labels[0]
            .categories
            .iter()
            .map(|c| c.level)
            .collect();

        assert!(
            levels.windows(2).all(|w| w[0] <= w[1]),
            "labels are served out of lattice order: {levels:?}"
        );
    }
}
