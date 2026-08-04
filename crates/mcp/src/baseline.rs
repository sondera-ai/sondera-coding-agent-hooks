//! A queryable view over the Cedar baseline the harness ships with.
//!
//! The baseline is the largest body of worked, deployed policy in the project,
//! and an agent drafting a new rule needs two things from it that a raw dump
//! cannot give: *does a policy for this already exist*, and *is the `@id` I am
//! about to assign already taken*. Both are lookups, so this serves rows rather
//! than text — the corpus is far past what any client will accept inline, and a
//! truncated dump is worse than no dump: the facts that fall off the end read as
//! facts that do not exist, which is what turns a missing example into an
//! invented one.
//!
//! This is the baseline **as shipped**, embedded at build time. A deployment
//! adjudicates against whatever `.sondera/policies/cedar/` the harness resolves
//! at run time, which may add to or replace it; the served rows are a drafting
//! reference, not an inventory of a running system.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use cedar_policy::{ActionConstraint, Effect, Policy, PolicySet};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

include!(concat!(env!("OUT_DIR"), "/baseline_generated.rs"));

/// Maximum serialized size of the rows in one coverage response.
///
/// Sized to sit under the inline tool-output limits MCP clients impose, with
/// headroom. Rows past the budget are named in
/// [`CoverageResult::omitted_ids`], never dropped silently: a caller that can
/// see what it did not receive can re-query for it, and one that cannot will
/// reasonably assume it received everything.
const MAX_RESPONSE_BYTES: usize = 8 * 1024;

/// One baseline policy, summarized for discovery.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BaselineRow {
    /// The policy's `@id` annotation, or its position-derived id when it
    /// carries none.
    pub id: String,
    /// Source file, relative to the baseline directory.
    pub file: String,
    /// `permit` or `forbid`.
    pub effect: String,
    /// Actions the policy's scope constrains it to. Empty means the scope is
    /// unconstrained, so the policy applies to every surface.
    pub actions: Vec<String>,
    /// The policy's `@description` annotation.
    pub description: String,
    /// Signature categories the policy's conditions match against.
    pub signature_categories: Vec<String>,
    /// Sensitivity labels the policy's conditions reference.
    pub labels: Vec<String>,
}

/// What to return from the baseline. Every field narrows the result; an empty
/// filter returns the whole set, subject to the response budget.
#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct CoverageFilter {
    /// Action surface to match, qualified (`Sondera::Action::"ShellCommand"`)
    /// or bare (`ShellCommand`). Policies with an unconstrained scope match
    /// every action and are always included.
    pub action: Option<String>,
    /// Signature category to match, e.g. `secrets`. Exact match against the
    /// categories a policy's conditions test.
    pub signature_category: Option<String>,
    /// Exact `@id` to look up. An empty result means the id is unused — this is
    /// the only way to check an id is free, since ids cannot be discovered by
    /// guessing.
    pub policy_id: Option<String>,
    /// Case-insensitive substring match over id, description, and file.
    pub query: Option<String>,
}

/// The result of a coverage query.
#[derive(Serialize, Debug)]
pub struct CoverageResult {
    /// Matching rows that fit the response budget.
    pub policies: Vec<BaselineRow>,
    /// How many rows matched in total, including any omitted.
    pub match_count: usize,
    /// Ids of matching rows that did not fit the budget. Narrow the filter and
    /// re-query to see them.
    pub omitted_ids: Vec<String>,
    /// Set when the filter named an action the baseline schema does not
    /// declare, which is almost always a typo rather than an empty result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_action: Option<String>,
}

/// The parsed baseline, built once per process.
fn index() -> &'static [BaselineRow] {
    static INDEX: OnceLock<Vec<BaselineRow>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut rows: Vec<BaselineRow> = BASELINE_SOURCES
            .iter()
            .flat_map(|(file, source)| rows_in_file(file, source))
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.file.cmp(&b.file)));
        rows
    })
}

/// Summarize every policy in one baseline file.
///
/// A file that does not parse contributes nothing rather than failing the
/// process: the authoring surface is a reference, and refusing to serve 133
/// usable files because one is malformed would be the worse failure. The
/// harness, which must actually enforce the baseline, is where a parse error is
/// fatal.
fn rows_in_file(file: &str, source: &str) -> Vec<BaselineRow> {
    let Ok(set) = source.parse::<PolicySet>() else {
        return Vec::new();
    };
    set.policies().map(|policy| row(file, policy)).collect()
}

fn row(file: &str, policy: &Policy) -> BaselineRow {
    let json = policy.to_json().ok();
    let annotation = |key: &str| policy.annotation(key).unwrap_or_default().to_string();

    let mut signature_categories = BTreeSet::new();
    let mut labels = BTreeSet::new();
    if let Some(json) = json.as_ref() {
        collect_signature_categories(json, &mut signature_categories);
        collect_labels(json, &mut labels);
    }

    BaselineRow {
        id: match policy.annotation("id") {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => policy.id().to_string(),
        },
        file: file.to_string(),
        effect: match policy.effect() {
            Effect::Permit => "permit".to_string(),
            Effect::Forbid => "forbid".to_string(),
        },
        actions: match policy.action_constraint() {
            ActionConstraint::Any => Vec::new(),
            ActionConstraint::Eq(uid) => vec![uid.to_string()],
            ActionConstraint::In(uids) => uids.iter().map(ToString::to_string).collect(),
        },
        description: annotation("description"),
        signature_categories: signature_categories.into_iter().collect(),
        labels: labels.into_iter().collect(),
    }
}

/// Collect literals tested against a signature `categories` set.
fn collect_signature_categories(expr: &Value, out: &mut BTreeSet<String>) {
    // All three set operators, not just `contains`: a policy testing categories
    // with `containsAny`/`containsAll` is exactly as much coverage of that
    // category, and missing it makes the policy undiscoverable by the filter
    // that exists to prevent duplicates.
    if let Some(operands) = ["contains", "containsAny", "containsAll"]
        .iter()
        .find_map(|op| expr.get(op))
        && let Some(left) = operands.get("left")
        && crate::lint::dotted_path(left).is_some_and(|path| path.ends_with(".categories"))
        && let Some(right) = operands.get("right")
    {
        out.extend(crate::lint::string_literals(right));
    }
    walk_values(expr, &mut |value| collect_signature_categories(value, out));
}

/// Collect the ids of every `Label` entity an expression references.
fn collect_labels(expr: &Value, out: &mut BTreeSet<String>) {
    if let Some(entity) = expr.get("__entity")
        && entity.get("type").and_then(Value::as_str) == Some("Sondera::Label")
        && let Some(id) = entity.get("id").and_then(Value::as_str)
    {
        out.insert(id.to_string());
    }
    walk_values(expr, &mut |value| collect_labels(value, out));
}

/// Apply `visit` to every child of a JSON node.
fn walk_values(expr: &Value, visit: &mut impl FnMut(&Value)) {
    match expr {
        Value::Object(object) => object.values().for_each(visit),
        Value::Array(items) => items.iter().for_each(visit),
        _ => {}
    }
}

/// Query the baseline.
///
/// `declared_actions` is the action set of the schema the server has loaded,
/// used only to tell an unknown action from a genuine miss.
pub fn query(filter: &CoverageFilter, declared_actions: &[String]) -> CoverageResult {
    let action = filter.action.as_deref().map(bare_action_name);
    let unknown_action = action.as_ref().and_then(|name| {
        (!declared_actions.is_empty() && !declared_actions.iter().any(|declared| declared == name))
            .then(|| name.clone())
    });

    let matched: Vec<&BaselineRow> = index()
        .iter()
        .filter(|row| matches(row, filter, action.as_deref()))
        .collect();

    // Fill up to the budget, then name the rest. Rows are appended whole; a
    // partially serialized row would be indistinguishable from a policy that
    // genuinely constrains nothing.
    let mut policies = Vec::new();
    let mut omitted_ids = Vec::new();
    let mut used = 0;
    for row in &matched {
        let size = serde_json::to_string(row).map(|s| s.len()).unwrap_or(0);
        if !omitted_ids.is_empty() || used + size > MAX_RESPONSE_BYTES {
            omitted_ids.push(row.id.clone());
        } else {
            used += size;
            policies.push((*row).clone());
        }
    }

    CoverageResult {
        match_count: matched.len(),
        policies,
        omitted_ids,
        unknown_action,
    }
}

/// Whether one row satisfies every populated field of the filter.
fn matches(row: &BaselineRow, filter: &CoverageFilter, action: Option<&str>) -> bool {
    if let Some(action) = action {
        // An unconstrained scope applies to every surface, so it is coverage for
        // whatever action was asked about.
        let applies = row.actions.is_empty()
            || row
                .actions
                .iter()
                .any(|declared| bare_action_name(declared) == action);
        if !applies {
            return false;
        }
    }

    if let Some(category) = &filter.signature_category
        && !row.signature_categories.contains(category)
    {
        return false;
    }

    if let Some(id) = &filter.policy_id
        && &row.id != id
    {
        return false;
    }

    if let Some(query) = &filter.query {
        let query = query.to_lowercase();
        let haystack = format!("{} {} {}", row.id, row.description, row.file).to_lowercase();
        if !haystack.contains(&query) {
            return false;
        }
    }

    true
}

/// The action id from either spelling: `Sondera::Action::"ShellCommand"` and
/// `ShellCommand` both reduce to `ShellCommand`.
fn bare_action_name(action: &str) -> String {
    action
        .rsplit("::")
        .next()
        .unwrap_or(action)
        .trim_matches('"')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> CoverageResult {
        query(&CoverageFilter::default(), &[])
    }

    #[test]
    fn the_shipped_baseline_is_indexed() {
        // A guard against the build-time walk silently finding nothing; the
        // exact count is expected to grow, so this only asserts a floor.
        assert!(
            all().match_count > 100,
            "expected the shipped baseline, got {} rows",
            all().match_count
        );
    }

    #[test]
    fn every_row_carries_an_id_and_a_source_file() {
        for row in index() {
            assert!(!row.id.is_empty(), "row from {} has no id", row.file);
            assert!(!row.file.is_empty(), "row {} has no file", row.id);
        }
    }

    #[test]
    fn the_default_permit_is_present_with_its_effect() {
        let result = query(
            &CoverageFilter {
                policy_id: Some("default-permit".to_string()),
                ..Default::default()
            },
            &[],
        );

        assert_eq!(result.match_count, 1);
        assert_eq!(result.policies[0].effect, "permit");
    }

    #[test]
    fn an_unused_id_returns_no_matches() {
        let result = query(
            &CoverageFilter {
                policy_id: Some("no-policy-has-this-id".to_string()),
                ..Default::default()
            },
            &[],
        );

        assert_eq!(result.match_count, 0);
        assert!(result.unknown_action.is_none());
    }

    #[test]
    fn filtering_by_action_accepts_either_spelling() {
        let bare = query(
            &CoverageFilter {
                action: Some("ShellCommand".to_string()),
                ..Default::default()
            },
            &[],
        );
        let qualified = query(
            &CoverageFilter {
                action: Some("Sondera::Action::\"ShellCommand\"".to_string()),
                ..Default::default()
            },
            &[],
        );

        assert_eq!(bare.match_count, qualified.match_count);
        assert!(bare.match_count > 0);
    }

    #[test]
    fn filtering_by_action_excludes_other_surfaces() {
        let result = query(
            &CoverageFilter {
                action: Some("WebFetch".to_string()),
                ..Default::default()
            },
            &[],
        );

        for row in &result.policies {
            assert!(
                row.actions.is_empty() || row.actions.iter().any(|a| a.contains("WebFetch")),
                "{} is not a WebFetch policy: {:?}",
                row.id,
                row.actions
            );
        }
    }

    #[test]
    fn an_undeclared_action_is_reported_rather_than_returning_an_empty_result() {
        let result = query(
            &CoverageFilter {
                action: Some("NoSuchSurface".to_string()),
                ..Default::default()
            },
            &["ShellCommand".to_string()],
        );

        assert_eq!(result.unknown_action.as_deref(), Some("NoSuchSurface"));
    }

    #[test]
    fn signature_categories_are_extracted_from_conditions() {
        let categorized: Vec<&BaselineRow> = index()
            .iter()
            .filter(|row| !row.signature_categories.is_empty())
            .collect();

        assert!(
            !categorized.is_empty(),
            "no baseline policy was found to test a signature category"
        );
    }

    #[test]
    fn labels_are_extracted_from_conditions() {
        let labelled: Vec<&BaselineRow> = index()
            .iter()
            .filter(|row| !row.labels.is_empty())
            .collect();

        assert!(
            !labelled.is_empty(),
            "no baseline policy was found to reference a sensitivity label"
        );
    }

    #[test]
    fn an_unfiltered_query_reports_what_it_omitted() {
        let result = all();

        assert_eq!(
            result.policies.len() + result.omitted_ids.len(),
            result.match_count,
            "every matching row must be either returned or named as omitted"
        );
    }

    #[test]
    fn the_returned_rows_fit_the_response_budget() {
        let serialized = serde_json::to_string(&all().policies).unwrap();

        assert!(
            serialized.len() <= MAX_RESPONSE_BYTES,
            "returned rows are {} bytes, over the {MAX_RESPONSE_BYTES} budget",
            serialized.len()
        );
    }

    /// Every lint finding the shipped baseline produces, paired with the file
    /// it came from.
    fn baseline_lint_findings() -> Vec<(&'static str, crate::report::Finding)> {
        BASELINE_SOURCES
            .iter()
            .filter_map(|(file, source)| Some((*file, source.parse::<PolicySet>().ok()?)))
            .flat_map(|(file, set)| {
                set.policies()
                    .flat_map(crate::lint::run_lints)
                    .map(|finding| (file, finding))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Render findings for an assertion message.
    fn describe(findings: &[(&str, crate::report::Finding)]) -> String {
        findings
            .iter()
            .map(|(file, finding)| format!("{file}: {} — {}", finding.code, finding.message))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The lints and the baseline share one notion of what the engine can
    /// produce, so the shipped corpus is the broadest available check that the
    /// lints do not fire on correct policy.
    #[test]
    fn the_shipped_baseline_is_free_of_lint_errors() {
        let offenders: Vec<(&str, crate::report::Finding)> = baseline_lint_findings()
            .into_iter()
            .filter(|(_, finding)| finding.severity == crate::report::Severity::Error)
            .collect();

        assert!(
            offenders.is_empty(),
            "the shipped baseline has lint errors:\n{}",
            describe(&offenders)
        );
    }

    /// Calibration, not correctness: ~180 hand-written policies that the engine
    /// actually enforces are the only false-positive corpus available. A lint
    /// that starts firing here is far more likely to be miscalibrated than to
    /// have found 180 latent bugs, so the whole baseline is held clean of
    /// warnings too — a noisy lint is one an author learns to skip past.
    #[test]
    fn the_shipped_baseline_produces_no_lint_findings_at_all() {
        let findings = baseline_lint_findings();

        assert!(
            findings.is_empty(),
            "{} lint findings on the shipped baseline; suspect the lint before the policies:\n{}",
            findings.len(),
            describe(&findings)
        );
    }

    #[test]
    fn every_baseline_file_parses() {
        let unparseable: Vec<&str> = BASELINE_SOURCES
            .iter()
            .filter(|(_, source)| source.parse::<PolicySet>().is_err())
            .map(|(file, _)| *file)
            .collect();

        assert!(
            unparseable.is_empty(),
            "baseline files do not parse: {unparseable:?}"
        );
    }
}
