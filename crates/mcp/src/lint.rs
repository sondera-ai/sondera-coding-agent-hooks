//! Semantic lints over a parsed candidate policy.
//!
//! The Cedar parser and schema validator answer "is this well-formed and
//! well-typed". They cannot answer "can this condition ever be true", and that
//! is where the expensive authoring mistakes live: a policy that typechecks,
//! validates, deploys, and then silently never fires because the literal it
//! matches against is not a value the engine's normalization can produce. A
//! forbid that never fires reads exactly like a forbid that is working.
//!
//! Each lint here encodes a normalization the engine documents in
//! `base.cedarschema` — lowercasing, separator folding, the `program:token`
//! encoding — and reports literals that contradict it. They are a backstop over
//! specific known-unsafe constructs, not a completeness check: a candidate with
//! no findings has not been proven to express its author's intent.
//!
//! Lints run over Cedar's own structured policy representation
//! ([`Policy::to_json`]), never over the source text, so comments and
//! formatting cannot affect a result.

use cedar_policy::Policy;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::features::closed_vocabularies;
use crate::report::{Finding, Severity};

/// A literal matched against `context.path_normalized` that the engine's path
/// normalization can never produce.
pub const CODE_PATH_NORMALIZED_LITERAL: &str = "lint/path-normalized-literal";

/// A literal matched against a normalized shell parse field that the engine's
/// shell normalization can never produce.
pub const CODE_SHELL_NORMALIZED_LITERAL: &str = "lint/shell-normalized-literal";

/// A shell parse literal missing the `program:` scope prefix the engine encodes
/// those sets with.
pub const CODE_PROGRAM_TOKEN_UNSCOPED: &str = "lint/program-token-unscoped";

/// A host matched with a glob over the raw URL instead of the parsed host.
pub const CODE_RAW_URL_GLOB: &str = "lint/raw-url-glob";

/// `action` constrained in a condition instead of in the policy scope.
pub const CODE_ACTION_IN_CONDITION: &str = "lint/action-in-condition";

/// A literal outside a closed vocabulary emitted by the engine.
pub const CODE_UNKNOWN_CONTEXT_VALUE: &str = "lint/unknown-context-value";

/// A condition that depends on a context field fixed by the transform.
pub const CODE_STUBBED_CONTEXT_FIELD: &str = "lint/stubbed-context-field";

/// One lint's public contract: what it is called, how much it matters, and what
/// it catches.
///
/// Served to agents as data so a policy author can know what will be checked
/// before drafting, rather than discovering it from a failure. This is the same
/// value the lints themselves are keyed on, so the served list cannot drift
/// from the checks that run.
#[derive(Serialize, Debug, Clone)]
pub struct LintCode {
    /// The stable code reported on a [`Finding`].
    pub code: &'static str,
    /// Severity every finding from this lint carries.
    pub severity: Severity,
    /// One line on what the lint catches.
    pub summary: &'static str,
}

/// Every lint this validator runs.
pub const LINT_CODES: &[LintCode] = &[
    LintCode {
        code: CODE_PATH_NORMALIZED_LITERAL,
        severity: Severity::Error,
        summary: "matching `context.path_normalized` against a literal containing uppercase or \
                  backslashes, which the engine's lowercased slash-folded path view never contains",
    },
    LintCode {
        code: CODE_SHELL_NORMALIZED_LITERAL,
        severity: Severity::Error,
        summary: "matching a normalized shell parse field against a literal containing uppercase, \
                  backslashes, or (for `programs`) a path separator, none of which the engine's \
                  normalized shell view ever contains",
    },
    LintCode {
        code: CODE_PROGRAM_TOKEN_UNSCOPED,
        severity: Severity::Error,
        summary: "matching a per-program shell parse set against a literal with no `program:` \
                  prefix; those sets are exact-match `program:token` entries, so a bare token \
                  never matches",
    },
    LintCode {
        code: CODE_RAW_URL_GLOB,
        severity: Severity::Warning,
        summary: "matching a host with a `like` glob over the raw `context.url` instead of the \
                  parsed `context.url_parse.host`",
    },
    LintCode {
        code: CODE_ACTION_IN_CONDITION,
        severity: Severity::Warning,
        summary: "constraining `action` inside a `when`/`unless` condition instead of in the \
                  policy scope",
    },
    LintCode {
        code: CODE_UNKNOWN_CONTEXT_VALUE,
        severity: Severity::Error,
        summary: "matching a signature category, policy violation code, or sensitivity label \
                  outside the closed vocabulary the engine emits",
    },
    LintCode {
        code: CODE_STUBBED_CONTEXT_FIELD,
        severity: Severity::Error,
        summary: "depending on `context.file_signature`, which the only action declaring it always \
                  emits empty",
    },
];

/// Shell parse fields the engine lowercases and folds separators in.
const NORMALIZED_SHELL_FIELDS: &[&str] = &[
    "program_flags_normalized",
    "program_args_normalized",
    "program_arg_path_components_normalized",
];

/// Shell parse fields encoded as exact-match `program:token` entries.
const PROGRAM_SCOPED_FIELDS: &[&str] = &[
    "program_flags",
    "program_flags_normalized",
    "program_args",
    "program_args_normalized",
    "program_arg_path_components_normalized",
];

/// Run every lint over one policy.
///
/// A policy whose structured form cannot be produced is skipped rather than
/// reported: the parser and validator own well-formedness, and a lint pass is
/// not the place to surface a Cedar-internal serialization failure.
pub fn run_lints(policy: &Policy) -> Vec<Finding> {
    let Ok(json) = policy.to_json() else {
        return Vec::new();
    };
    let policy_id = json
        .get("annotations")
        .and_then(|a| a.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| policy.id().as_ref())
        .to_string();

    let Some(conditions) = json.get("conditions").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for condition in conditions {
        let Some(body) = condition.get("body") else {
            continue;
        };
        walk(body, &policy_id, &mut findings);
    }

    if conditions
        .iter()
        .filter_map(|c| c.get("body"))
        .any(references_action)
    {
        findings.push(
            Finding::warning(
                CODE_ACTION_IN_CONDITION,
                "`action` is constrained inside a condition. Constrain it in the policy scope \
                 instead (`forbid (principal, action == Sondera::Action::\"…\", resource)`): the \
                 scope is what the engine indexes policies by and what a reviewer reads to see \
                 which surface a rule covers.",
            )
            .in_policy(&policy_id),
        );
    }

    findings
}

/// Walk one condition expression, reporting on every comparison it contains.
fn walk(expr: &Value, policy_id: &str, findings: &mut Vec<Finding>) {
    check_stubbed_field(expr, policy_id, findings);
    if let Some(object) = expr.as_object() {
        for (op, operands) in object {
            check_comparison(op, operands, policy_id, findings);
        }
    }

    // Recurse structurally rather than matching every Cedar operator: a lint
    // that only understood `&&` would miss the same mistake written under `||`,
    // `if`, or a negation.
    match expr {
        Value::Object(object) => {
            for value in object.values() {
                walk(value, policy_id, findings);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, policy_id, findings);
            }
        }
        _ => {}
    }
}

/// Report on a single comparison node, if this operator is one that compares a
/// context field against literals.
fn check_comparison(op: &str, operands: &Value, policy_id: &str, findings: &mut Vec<Finding>) {
    match op {
        "contains" | "containsAll" | "containsAny" => {
            let (Some(left), Some(right)) = (operands.get("left"), operands.get("right")) else {
                return;
            };
            let Some(path) = attr_path(left) else { return };
            for literal in string_literals(right) {
                check_field_literal(&path, &literal, false, policy_id, findings);
            }
        }
        "==" => {
            let (Some(left), Some(right)) = (operands.get("left"), operands.get("right")) else {
                return;
            };
            // Either operand may be the field; Cedar does not require an order.
            for (field, value) in [(left, right), (right, left)] {
                let Some(path) = attr_path(field) else {
                    continue;
                };
                for literal in string_literals(value) {
                    check_field_literal(&path, &literal, false, policy_id, findings);
                }
                if path == ["context", "label"]
                    && let Some(label) = entity_literal(value, "Sondera::Label")
                {
                    check_known_value(
                        "context.label",
                        &label,
                        closed_vocabularies().map(|v| v.sensitivity_labels),
                        policy_id,
                        findings,
                    );
                }
            }
        }
        "like" => {
            let (Some(left), Some(pattern)) = (operands.get("left"), operands.get("pattern"))
            else {
                return;
            };
            let Some(path) = attr_path(left) else { return };
            let pattern = LikePattern::from_est(pattern);
            check_field_literal(&path, &pattern.literals, true, policy_id, findings);
            check_raw_url_glob(&path, &pattern, policy_id, findings);
        }
        _ => {}
    }
}

/// Report a literal that the field it is matched against can never hold.
///
/// `from_pattern` distinguishes a `like` pattern's literal characters from a
/// whole string literal: a pattern is a partial match by construction, so the
/// checks that depend on the value being complete (the `program:` prefix) do
/// not apply to it.
fn check_field_literal(
    path: &[String],
    literal: &str,
    from_pattern: bool,
    policy_id: &str,
    findings: &mut Vec<Finding>,
) {
    let Some(field) = path.last() else { return };
    let rooted_at_context = path.first().is_some_and(|root| root == "context");
    if !rooted_at_context {
        return;
    }

    match path {
        [root, signature, categories]
            if root == "context"
                && (signature == "signature" || signature == "file_signature")
                && categories == "categories" =>
        {
            check_known_value(
                &path.join("."),
                literal,
                closed_vocabularies().map(|v| v.signature_categories),
                policy_id,
                findings,
            );
        }
        [root, policy, violations]
            if root == "context" && policy == "policy" && violations == "violations" =>
        {
            check_known_value(
                "context.policy.violations",
                literal,
                closed_vocabularies().map(|v| v.policy_violations),
                policy_id,
                findings,
            );
        }
        _ => {}
    }

    if field == "path_normalized" {
        if let Some(reason) = never_normalized(literal) {
            findings.push(
                Finding::error(
                    CODE_PATH_NORMALIZED_LITERAL,
                    format!(
                        "`context.path_normalized` is lowercased with backslashes folded to `/`, \
                         so the literal {literal:?} ({reason}) can never match and this condition \
                         is dead. Write the literal lowercased with forward slashes, or match \
                         `context.path` if the raw spelling is what you mean."
                    ),
                )
                .in_policy(policy_id),
            );
        }
        return;
    }

    // Everything below is a shell parse field; they only exist under
    // `context.parse`.
    let under_parse = path.len() >= 2 && path[path.len() - 2] == "parse";
    if !under_parse {
        return;
    }

    if NORMALIZED_SHELL_FIELDS.contains(&field.as_str())
        && let Some(reason) = never_normalized(literal)
    {
        findings.push(
            Finding::error(
                CODE_SHELL_NORMALIZED_LITERAL,
                format!(
                    "`context.parse.{field}` is lowercased with backslashes folded to `/`, so the \
                     literal {literal:?} ({reason}) can never match and this condition is dead. \
                     Lowercase the literal, or match the unnormalized companion field if the raw \
                     spelling is what you mean."
                ),
            )
            .in_policy(policy_id),
        );
    }

    if field == "programs" {
        if let Some(reason) = never_normalized(literal) {
            findings.push(
                Finding::error(
                    CODE_SHELL_NORMALIZED_LITERAL,
                    format!(
                        "`context.parse.programs` holds lowercased command basenames, so the \
                         literal {literal:?} ({reason}) can never match and this condition is \
                         dead."
                    ),
                )
                .in_policy(policy_id),
            );
        } else if literal.contains('/') {
            findings.push(
                Finding::error(
                    CODE_SHELL_NORMALIZED_LITERAL,
                    format!(
                        "`context.parse.programs` holds command basenames, not paths, so the \
                         path-qualified literal {literal:?} can never match. Match the basename \
                         alone — it already covers absolute-path invocations."
                    ),
                )
                .in_policy(policy_id),
            );
        }
        return;
    }

    if !from_pattern && PROGRAM_SCOPED_FIELDS.contains(&field.as_str()) && !literal.contains(':') {
        findings.push(
            Finding::error(
                CODE_PROGRAM_TOKEN_UNSCOPED,
                format!(
                    "`context.parse.{field}` holds `program:token` entries matched exactly, so \
                     the unscoped literal {literal:?} can never match. Scope it to the program \
                     that carries it, e.g. \"rm:{literal}\"."
                ),
            )
            .in_policy(policy_id),
        );
    }
}

fn check_known_value(
    field: &str,
    value: &str,
    known: Option<BTreeSet<String>>,
    policy_id: &str,
    findings: &mut Vec<Finding>,
) {
    let Some(known) = known else { return };
    if known.contains(value) {
        return;
    }
    findings.push(
        Finding::error(
            CODE_UNKNOWN_CONTEXT_VALUE,
            format!(
                "`{value}` is not emitted by `{field}`, so this condition can never match. \
                 Nearest known values: {}.",
                nearest_known(value, &known)
            ),
        )
        .in_policy(policy_id),
    );
}

fn nearest_known(unknown: &str, known: &BTreeSet<String>) -> String {
    let mut ranked: Vec<(usize, &str)> = known
        .iter()
        .map(|candidate| (edit_distance(unknown, candidate), candidate.as_str()))
        .collect();
    ranked.sort();
    ranked
        .into_iter()
        .take(3)
        .map(|(_, candidate)| format!("`{candidate}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    for (row, left_char) in left.chars().enumerate() {
        let mut current = vec![row + 1];
        for (column, right_char) in right.iter().enumerate() {
            let substitution = previous[column] + usize::from(left_char != *right_char);
            current.push(
                substitution
                    .min(previous[column + 1] + 1)
                    .min(current[column] + 1),
            );
        }
        previous = current;
    }
    previous[right.len()]
}

fn entity_literal(expr: &Value, entity_type: &str) -> Option<String> {
    let entity = expr.get("Value")?.get("__entity")?;
    if entity.get("type")?.as_str()? != entity_type {
        return None;
    }
    entity.get("id")?.as_str().map(str::to_string)
}

fn check_stubbed_field(expr: &Value, policy_id: &str, findings: &mut Vec<Finding>) {
    let Some(path) = attr_path(expr) else { return };
    let explanation = match path.join(".").as_str() {
        "context.file_signature.matches"
        | "context.file_signature.categories"
        | "context.file_signature.severity" => Some(
            "`context.file_signature` is empty for ShellCommand; file content enters policy \
             through explicit file-operation events.",
        ),
        _ => None,
    };
    if let Some(explanation) = explanation {
        findings.push(Finding::error(CODE_STUBBED_CONTEXT_FIELD, explanation).in_policy(policy_id));
    }
}

/// Why the engine's normalization can never produce `literal`, or `None` when
/// it could.
fn never_normalized(literal: &str) -> Option<&'static str> {
    if literal.chars().any(|c| c.is_ascii_uppercase()) {
        Some("it contains uppercase characters")
    } else if literal.contains('\\') {
        Some("it contains a backslash")
    } else {
        None
    }
}

/// Warn when a host is matched by globbing the raw URL.
fn check_raw_url_glob(
    path: &[String],
    pattern: &LikePattern,
    policy_id: &str,
    findings: &mut Vec<Finding>,
) {
    if path != ["context", "url"] {
        return;
    }
    // A dot is the signal that the pattern is reaching for a hostname rather
    // than a path segment. Matching a path with a raw glob is ordinary; matching
    // a host that way is what userinfo, case, port, and percent-encoding tricks
    // evade.
    if !pattern.literals.contains('.') {
        return;
    }
    findings.push(
        Finding::warning(
            CODE_RAW_URL_GLOB,
            format!(
                "the pattern {:?} matches a host by globbing the raw `context.url`. That match is \
                 lexical: `https://evil.com/?x=good.com`, userinfo (`https://good.com@evil.com`), \
                 case, and percent-encoding all defeat it. Match \
                 `context.url_parse.host` instead, gated on `context.url_parse.ok`.",
                pattern.display
            ),
        )
        .in_policy(policy_id),
    );
}

/// A `like` pattern recovered from its structured form.
struct LikePattern {
    /// The pattern as written, for error messages.
    display: String,
    /// Only the literal characters, for checks about what a value can hold. An
    /// escaped `\*` is a literal star here; an unescaped one is not, and the
    /// distinction is lost in `display`.
    literals: String,
}

impl LikePattern {
    fn from_est(pattern: &Value) -> Self {
        let mut display = String::new();
        let mut literals = String::new();
        for element in pattern.as_array().into_iter().flatten() {
            match element {
                Value::String(wildcard) if wildcard == "Wildcard" => display.push('*'),
                Value::Object(object) => {
                    if let Some(literal) = object.get("Literal").and_then(Value::as_str) {
                        display.push_str(literal);
                        literals.push_str(literal);
                    }
                }
                _ => {}
            }
        }
        Self { display, literals }
    }
}

/// [`attr_path`] joined with `.`, for callers that only need to recognize a
/// known field rather than inspect the path.
pub(crate) fn dotted_path(expr: &Value) -> Option<String> {
    attr_path(expr).map(|path| path.join("."))
}

/// Resolve an attribute-access chain to its dotted path, e.g.
/// `context.parse.programs` — or `None` when the expression is not a chain of
/// attribute accesses rooted at a variable.
fn attr_path(expr: &Value) -> Option<Vec<String>> {
    if let Some(var) = expr.get("Var").and_then(Value::as_str) {
        return Some(vec![var.to_string()]);
    }
    let access = expr.get(".")?;
    let mut path = attr_path(access.get("left")?)?;
    path.push(access.get("attr")?.as_str()?.to_string());
    Some(path)
}

/// Every string literal an expression denotes: one for a value, many for a set.
pub(crate) fn string_literals(expr: &Value) -> Vec<String> {
    if let Some(value) = expr.get("Value") {
        return match value {
            Value::String(literal) => vec![literal.clone()],
            _ => Vec::new(),
        };
    }
    if let Some(items) = expr.get("Set").and_then(Value::as_array) {
        return items.iter().flat_map(string_literals).collect();
    }
    Vec::new()
}

/// Whether an expression mentions the `action` variable anywhere.
fn references_action(expr: &Value) -> bool {
    match expr {
        Value::Object(object) => {
            if object.get("Var").and_then(Value::as_str) == Some("action") {
                return true;
            }
            object.values().any(references_action)
        }
        Value::Array(items) => items.iter().any(references_action),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::PolicySet;

    /// Lint one policy written as source.
    fn lint(source: &str) -> Vec<Finding> {
        let set: PolicySet = source.parse().expect("test policy should parse");
        set.policies().flat_map(run_lints).collect()
    }

    fn codes(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.code.as_str()).collect()
    }

    fn shell(condition: &str) -> String {
        format!(
            "@id(\"p\") @description(\"d\")
             forbid (principal, action == Sondera::Action::\"ShellCommand\", resource)
             when {{ {condition} }};"
        )
    }

    #[test]
    fn uppercase_path_literal_is_reported_as_dead() {
        let findings = lint(&shell("context.path_normalized like \"*/Users/*\""));

        assert_eq!(codes(&findings), vec![CODE_PATH_NORMALIZED_LITERAL]);
    }

    #[test]
    fn backslash_path_literal_is_reported_as_dead() {
        let findings = lint(&shell("context.path_normalized like \"*c:\\\\windows*\""));

        assert_eq!(codes(&findings), vec![CODE_PATH_NORMALIZED_LITERAL]);
    }

    #[test]
    fn lowercased_path_literal_is_accepted() {
        let findings = lint(&shell("context.path_normalized like \"*/users/*\""));

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn uppercase_literal_on_the_unnormalized_flag_set_is_accepted() {
        // `program_flags` deliberately preserves case, so `rm:-R` is exactly
        // what the engine produces for `rm -R`.
        let findings = lint(&shell("context.parse.program_flags.contains(\"rm:-R\")"));

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn uppercase_literal_on_the_normalized_flag_set_is_reported() {
        let findings = lint(&shell(
            "context.parse.program_flags_normalized.contains(\"rm:-R\")",
        ));

        assert_eq!(codes(&findings), vec![CODE_SHELL_NORMALIZED_LITERAL]);
    }

    #[test]
    fn unscoped_program_token_is_reported() {
        let findings = lint(&shell("context.parse.program_flags.contains(\"-rf\")"));

        assert_eq!(codes(&findings), vec![CODE_PROGRAM_TOKEN_UNSCOPED]);
    }

    #[test]
    fn unscoped_program_token_message_suggests_a_scoped_form() {
        let findings = lint(&shell("context.parse.program_flags.contains(\"-rf\")"));

        assert!(
            findings[0].message.contains("\"rm:-rf\""),
            "message should show the fix: {}",
            findings[0].message
        );
    }

    #[test]
    fn path_qualified_program_is_reported() {
        let findings = lint(&shell("context.parse.programs.contains(\"/bin/rm\")"));

        assert_eq!(codes(&findings), vec![CODE_SHELL_NORMALIZED_LITERAL]);
    }

    #[test]
    fn bare_program_basename_is_accepted() {
        let findings = lint(&shell("context.parse.programs.contains(\"rm\")"));

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn every_literal_in_a_set_is_checked() {
        let findings = lint(&shell(
            "context.parse.program_flags_normalized.containsAny([\"rm:-r\", \"rm:-F\"])",
        ));

        assert_eq!(codes(&findings), vec![CODE_SHELL_NORMALIZED_LITERAL]);
    }

    #[test]
    fn host_shaped_raw_url_glob_is_warned() {
        let source = "@id(\"p\") @description(\"d\")
             forbid (principal, action == Sondera::Action::\"WebFetch\", resource)
             when { context.url like \"*evil.com*\" };";

        assert_eq!(codes(&lint(source)), vec![CODE_RAW_URL_GLOB]);
    }

    #[test]
    fn path_shaped_raw_url_glob_is_not_warned() {
        let source = "@id(\"p\") @description(\"d\")
             forbid (principal, action == Sondera::Action::\"WebFetch\", resource)
             when { context.url like \"*/admin/*\" };";

        assert!(lint(source).is_empty());
    }

    #[test]
    fn parsed_host_match_is_not_warned() {
        let source = "@id(\"p\") @description(\"d\")
             forbid (principal, action == Sondera::Action::\"WebFetch\", resource)
             when { context.url_parse.ok && context.url_parse.host like \"*.evil.com\" };";

        assert!(lint(source).is_empty());
    }

    #[test]
    fn action_in_a_condition_is_warned() {
        let source = "@id(\"p\") @description(\"d\")
             forbid (principal, action, resource)
             when { action == Sondera::Action::\"ShellCommand\" };";

        assert_eq!(codes(&lint(source)), vec![CODE_ACTION_IN_CONDITION]);
    }

    #[test]
    fn action_in_the_scope_is_not_warned() {
        let findings = lint(&shell("context.command like \"*rm*\""));

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn findings_are_attributed_to_the_policy_id() {
        let findings = lint(&shell("context.path_normalized like \"*/Users/*\""));

        assert_eq!(findings[0].policy_id.as_deref(), Some("p"));
    }

    /// Lints must see through the boolean structure, not just the top-level
    /// conjunction — the same mistake under a disjunction is the same mistake.
    #[test]
    fn lints_reach_into_nested_boolean_structure() {
        let findings = lint(&shell(
            "context.parse.ok && (context.command like \"*x*\" || \
             !(context.path_normalized like \"*/Users/*\"))",
        ));

        assert_eq!(codes(&findings), vec![CODE_PATH_NORMALIZED_LITERAL]);
    }

    #[test]
    fn unless_conditions_are_linted() {
        let source = "@id(\"p\") @description(\"d\")
             forbid (principal, action == Sondera::Action::\"FileRead\", resource)
             unless { context.path_normalized like \"*/Users/*\" };";

        assert_eq!(codes(&lint(source)), vec![CODE_PATH_NORMALIZED_LITERAL]);
    }

    #[test]
    fn unknown_signature_category_suggests_a_known_value() {
        let findings = lint(&shell(
            "context.signature.categories.contains(\"prompt_injecton\")",
        ));

        assert!(codes(&findings).contains(&CODE_UNKNOWN_CONTEXT_VALUE));
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("`prompt_injection`"))
        );
    }

    #[test]
    fn known_signature_category_is_accepted() {
        let findings = lint(&shell(
            "context.signature.categories.contains(\"prompt_injection\")",
        ));

        assert!(!codes(&findings).contains(&CODE_UNKNOWN_CONTEXT_VALUE));
    }

    #[test]
    fn unknown_policy_violation_code_is_reported() {
        let findings = lint(&shell("context.policy.violations.contains(\"SC22\")"));

        assert_eq!(codes(&findings), vec![CODE_UNKNOWN_CONTEXT_VALUE]);
    }

    /// The codes are the closed set, and a declared one is a live condition —
    /// the classifier that fills this field is wired into the transform.
    #[test]
    fn known_policy_violation_code_is_accepted() {
        let findings = lint(&shell("context.policy.violations.contains(\"SC2\")"));

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn unknown_sensitivity_label_is_reported() {
        let findings = lint(&shell(
            "context.label == Sondera::Label::\"HighlyConfidental\"",
        ));

        assert!(codes(&findings).contains(&CODE_UNKNOWN_CONTEXT_VALUE));
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("`HighlyConfidential`"))
        );
    }

    #[test]
    fn policy_compliance_field_is_accepted() {
        let findings = lint(&shell("!context.policy.compliant"));

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn fixed_file_signature_field_is_reported() {
        let findings = lint(&shell("context.file_signature.matches > 0"));

        assert_eq!(codes(&findings), vec![CODE_STUBBED_CONTEXT_FIELD]);
    }

    #[test]
    fn every_lint_code_is_documented() {
        for code in LINT_CODES {
            assert!(!code.summary.is_empty(), "{} has no summary", code.code);
        }
    }
}
