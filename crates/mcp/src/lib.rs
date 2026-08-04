//! MCP server for Cedar policy authoring and local console queries.
//!
//! Exposes Cedar policy operations plus the unary agent and trajectory console
//! endpoints as MCP tools. Streaming RPCs and trajectory sparkline batches stay
//! on gRPC.
//!
//! The console tools are a gRPC client of `sondera serve` ([`console`]), not a
//! second opener of its database — the store takes an exclusive per-process
//! lock, so reading it directly would mean this server could not start while
//! the harness was running. The Cedar tools need no console and stay available
//! whether or not one is reachable.
//!
//! Built on the official Model Context Protocol Rust SDK (`rmcp`): tools are
//! declared with [`macro@rmcp::tool`], prompts with [`macro@rmcp::prompt`], and
//! resources are served through the [`ServerHandler`] trait.
//!
//! [`serve_stdio`] carries it: `sondera mcp` runs as the subprocess an MCP
//! client launches itself, speaking JSON-RPC over stdio.
//!
//! Everything is grounded in the open-source harness engine (`crates/harness`):
//! the real harness Cedar schema, the shipped baseline, and the authoring guide
//! are served as resources, `get_cedar_policy_context_features` surfaces the
//! live YARA signature categories / policy templates / IFC labels,
//! `query_baseline_coverage` answers what the engine already forbids, and the
//! `autoformalize` prompt turns a natural-language policy intent into Cedar for
//! that engine.
//!
//! # What validation covers
//!
//! `validate_policy` is the only tool whose approval means anything, and it is
//! deliberately more than a Cedar parse:
//!
//! 1. Cedar parse, required `@id`/`@description` annotations, and duplicate-id
//!    detection within the candidate.
//! 2. Schema validation, against the caller's schema or the embedded harness
//!    schema when none is given.
//! 3. Semantic lints ([`lint`]) over conditions that typecheck but can never be
//!    true.
//!
//! It is verify-only: the candidate comes back byte-for-byte, never rewritten.
//! Findings carry stable codes, and
//! [`Provenance::checks_run`](report::Provenance::checks_run) reports which
//! stages ran — a stage that is absent did not pass, it did not happen.

pub mod baseline;
pub mod console;
pub mod doctrine;
pub mod features;
pub mod lint;
pub mod report;

use cedar_policy::{
    AuthorizationError, Authorizer, Context as CedarContext, Entities, Entity, EntityId,
    EntityTypeName, EntityUid, Policy, PolicyId, PolicySet, Request, Response, Schema,
    ValidationMode, Validator,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    AnnotateAble, GetPromptRequestParams, GetPromptResult, Implementation, ListPromptsResult,
    ListResourcesResult, PaginatedRequestParams, PromptMessage, PromptMessageRole, RawResource,
    ReadResourceRequestParams, ReadResourceResult, ResourceContents, ServerCapabilities,
    ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt, prompt, prompt_handler,
    prompt_router, tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;

use crate::baseline::CoverageFilter;
use crate::console::{ConsoleClient, ConsoleError};
use crate::features::ContextFeaturesArgs;
use crate::report::{
    CODE_ENTITY_VALIDATION, CODE_POLICY_VALIDATION, CODE_SCHEMA_VALIDATION, Finding,
    ValidationReport,
};

/// The OSS harness Cedar schema, embedded so validation has something
/// authoritative to check against even when the caller supplies nothing.
const HARNESS_SCHEMA: &str = include_str!("../../../.sondera/policies/cedar/base.cedarschema");

/// The exposure contract: every model-facing tool this server serves, sorted.
///
/// Each name here is a deliberate decision to spend a caller's context on it.
/// The list is asserted against the live registry by
/// `the_server_exposes_exactly_the_declared_tools`, so a tool cannot reach
/// callers without appearing here, and one removed from the server cannot
/// linger here.
pub const TOOL_NAMES: &[&str] = &[
    "add_entity",
    "analyze_agents",
    "analyze_policies",
    "analyze_schema",
    "clear_state",
    "create_action_schema",
    "create_entity_schema",
    "delete_agent",
    "format_policy",
    "get_agent",
    "get_cedar_policy_context_features",
    "get_schema_status",
    "get_trajectory",
    "is_authorized",
    "list_agents",
    "list_entities",
    "list_trajectories",
    "list_trajectory_events",
    "load_policies",
    "load_schema",
    "merge_schema_fragments",
    "query_baseline_coverage",
    "remove_entity",
    "update_agent",
    "validate_entities_against_schema",
    "validate_entity",
    "validate_policy",
    "validate_policy_against_schema",
    "validate_schema",
];

/// Every resource URI this server serves, sorted. Same contract as
/// [`TOOL_NAMES`].
pub const RESOURCE_URIS: &[&str] = &[
    "cedar://harness/authoring-guide",
    "cedar://harness/base-policies",
    "cedar://harness/schema",
];

/// The embedded harness schema, parsed once.
///
/// Validation falls back to this when a caller supplies no schema. A candidate
/// checked against no schema at all is barely checked — every context field
/// reference goes unverified — and reporting that as `valid` is the failure this
/// avoids.
///
/// Named for where it comes from rather than what it is, so it does not read as
/// interchangeable with the test helper of the same shape.
fn embedded_schema() -> Option<&'static Schema> {
    static SCHEMA: OnceLock<Option<Schema>> = OnceLock::new();
    SCHEMA
        .get_or_init(|| {
            Schema::from_cedarschema_str(HARNESS_SCHEMA)
                .ok()
                .map(|s| s.0)
        })
        .as_ref()
}

/// Bare action ids the harness schema declares, for telling a caller's typo
/// from a genuinely empty coverage result.
fn declared_action_names() -> &'static [String] {
    static ACTIONS: OnceLock<Vec<String>> = OnceLock::new();
    ACTIONS.get_or_init(|| match embedded_schema() {
        Some(schema) => schema
            .actions()
            .map(|uid| uid.id().unescaped().to_string())
            .collect(),
        None => Vec::new(),
    })
}

/// Build an MCP error for a server-side failure the client cannot fix.
fn tool_error(message: impl Into<String>) -> McpError {
    McpError::internal_error(message.into(), None)
}

/// Build an MCP error for bad client input (JSON-RPC `invalid_params`).
///
/// An unparseable UID, an entity type absent from the schema, or a malformed
/// context is the caller's to correct; reporting it as `internal_error` tells
/// the client the server broke and the request is not worth reformulating.
fn input_error(message: impl Into<String>) -> McpError {
    McpError::invalid_params(message.into(), None)
}

/// Classify a console read failure for the client.
///
/// A rejected request is the caller's to reformulate, so the console's own
/// message is passed through as `invalid_params`. Everything else — an
/// unreachable server, an undecodable response — is reported as an internal
/// error with its text intact: "is `sondera serve` running?" is the actionable
/// part, and swallowing it would leave the caller with a bare "internal error"
/// for a condition they can actually fix.
fn console_error(error: ConsoleError) -> McpError {
    match error {
        ConsoleError::Rpc {
            code:
                tonic::Code::NotFound
                | tonic::Code::AlreadyExists
                | tonic::Code::InvalidArgument
                | tonic::Code::FailedPrecondition,
            message,
        } => input_error(message),
        other => {
            tracing::error!(error = %other, "console read failed");
            tool_error(other.to_string())
        }
    }
}

fn json_result(value: &impl Serialize) -> Result<String, McpError> {
    serde_json::to_string_pretty(value).map_err(|error| tool_error(error.to_string()))
}

/// Resolve an action the caller named into the [`EntityUid`] the loaded schema
/// actually declares.
///
/// The Sondera schema puts everything under `namespace Sondera`, so its actions
/// are `Sondera::Action::"ShellCommand"`. Naively wrapping a bare name as
/// `Action::"ShellCommand"` names an undeclared type in the empty namespace:
/// against a schema the request is rejected, and *without* one it builds a
/// request no namespaced policy can match, so a `forbid` under test reports
/// `Allow`. A silent false pass is the worst answer this tool can give, hence
/// the resolution here.
///
/// Accepts either spelling:
/// - a qualified UID (`Sondera::Action::"ShellCommand"`), parsed as written;
/// - a bare name (`ShellCommand`), matched against the schema's declared
///   actions so the caller need not know the namespace.
///
/// # Errors
/// Returns an error if a qualified UID does not parse, if a bare name matches
/// no declared action, or if it is ambiguous across namespaces — the last two
/// list the candidates so the caller can correct the call.
fn resolve_action_uid(action: &str, schema: Option<&Schema>) -> Result<EntityUid, McpError> {
    let action = action.trim();
    if action.is_empty() {
        return Err(input_error("Action must not be empty"));
    }

    // Let Cedar's own parser decide the shape. A bare name has no `Type::"id"`
    // form and simply fails to parse, which is the signal to resolve it — no
    // string sniffing, and anything Cedar accepts as a UID is honoured as
    // written once it carries a namespace.
    //
    // Note actions are *not* entity types in Cedar's schema API: they live in
    // `Schema::actions()`, not `Schema::entity_types()`. Both spellings
    // therefore resolve by matching the action **id** against the declared set.
    let id = match action.parse::<EntityUid>() {
        Ok(uid) if !uid.type_name().namespace().is_empty() => return Ok(uid),
        Ok(uid) => uid.id().unescaped().to_string(),
        Err(_) => action.to_string(),
    };

    let Some(schema) = schema else {
        // No schema loaded means no namespace to resolve against. Cedar skips
        // validation for such a request, so the unqualified UID is the only
        // thing we can build — and it will only match equally unqualified
        // policies. `is_authorized` warns about that in its result.
        return Ok(EntityUid::from_type_name_and_id(
            unqualified_action_type()?,
            EntityId::new(&id),
        ));
    };

    let matches: Vec<&EntityUid> = schema
        .actions()
        .filter(|declared| declared.id().unescaped() == id)
        .collect();

    match matches.as_slice() {
        [uid] => Ok((*uid).clone()),
        [] => Err(input_error(format!(
            "Action '{}' is not declared in the loaded schema. Declared actions: {}",
            id,
            describe(schema.actions().map(|uid| uid.id().unescaped().to_string()))
        ))),
        ambiguous => Err(input_error(format!(
            "Action '{}' is ambiguous across namespaces; pass a qualified UID. Candidates: {}",
            id,
            describe(ambiguous.iter().map(ToString::to_string))
        ))),
    }
}

/// The `Action` type in the empty namespace, used only when no schema is loaded.
fn unqualified_action_type() -> Result<EntityTypeName, McpError> {
    "Action"
        .parse()
        .map_err(|e| tool_error(format!("Failed to build the Action type name: {}", e)))
}

/// Render candidate names for an error message: sorted, deduplicated, and
/// explicit about the empty case rather than trailing off after a colon.
fn describe(names: impl Iterator<Item = String>) -> String {
    let mut names: Vec<String> = names.collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        "(none)".to_string()
    } else {
        names.join(", ")
    }
}

/// Resolve an entity UID the caller named against the loaded schema, applying
/// the same bare-name convenience as [`resolve_action_uid`].
///
/// Principals and resources parse as written when qualified. A bare
/// `Agent::"claude"` would otherwise land in the empty namespace and match no
/// `Sondera::Agent` policy or entity, producing the same false pass this
/// resolution exists to prevent.
///
/// # Errors
/// Returns an error if the UID is malformed, or if its type is bare and matches
/// no declared entity type or several across namespaces.
fn resolve_entity_uid(
    uid: &str,
    schema: Option<&Schema>,
    role: &str,
) -> Result<EntityUid, McpError> {
    let parsed: EntityUid = uid
        .trim()
        .parse()
        .map_err(|e| input_error(format!("Invalid {} UID '{}': {}", role, uid, e)))?;

    // `namespace()` is empty exactly when the type was written bare — Cedar's
    // own notion of qualification, so multi-level namespaces work without any
    // string handling here.
    if !parsed.type_name().namespace().is_empty() {
        return Ok(parsed);
    }

    let Some(schema) = schema else {
        return Ok(parsed);
    };

    let qualified = resolve_entity_type(parsed.type_name().basename(), schema, role)?;
    Ok(EntityUid::from_type_name_and_id(
        qualified,
        parsed.id().clone(),
    ))
}

/// Resolve a bare entity type name to the one the schema declares.
///
/// # Errors
/// Returns an error if no declared type has this name, or if several
/// namespaces declare it.
fn resolve_entity_type(
    type_name: &str,
    schema: &Schema,
    role: &str,
) -> Result<EntityTypeName, McpError> {
    let matches: Vec<&EntityTypeName> = schema
        .entity_types()
        .filter(|declared| declared.basename() == type_name)
        .collect();

    match matches.as_slice() {
        [found] => Ok((*found).clone()),
        [] => Err(input_error(format!(
            "{} type '{}' is not declared in the loaded schema. Declared types: {}",
            role,
            type_name,
            describe(schema.entity_types().map(ToString::to_string))
        ))),
        ambiguous => Err(input_error(format!(
            "{} type '{}' is ambiguous across namespaces; qualify it. Candidates: {}",
            role,
            type_name,
            describe(ambiguous.iter().map(ToString::to_string))
        ))),
    }
}

/// Parse a candidate and enforce the annotation rules the engine requires.
///
/// Returns the parsed set, or every structural problem found. Annotation and
/// duplicate-id checks run over all policies rather than stopping at the first,
/// so a caller fixing a multi-policy candidate sees the whole list at once.
fn parse_and_check_annotations(policy_text: &str) -> Result<PolicySet, Vec<Finding>> {
    let policy_set: PolicySet = match policy_text.parse() {
        Ok(set) => set,
        Err(e) => {
            return Err(vec![Finding::error(
                CODE_POLICY_VALIDATION,
                format!("Policy parse error: {e}"),
            )]);
        }
    };

    let mut findings = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();

    for policy in policy_set.policies() {
        let position = policy.id().to_string();
        let declared_id = annotation(policy, "id");

        match &declared_id {
            Some(id) => *seen.entry(id.clone()).or_default() += 1,
            None => findings.push(Finding::error(
                CODE_POLICY_VALIDATION,
                format!(
                    "Policy `{position}` has no non-empty `@id` annotation. Every policy needs a \
                     unique kebab-case `@id`; the engine and its operators identify policies by \
                     it."
                ),
            )),
        }

        if annotation(policy, "description").is_none() {
            let name = declared_id.clone().unwrap_or(position);
            findings.push(Finding::error(
                CODE_POLICY_VALIDATION,
                format!(
                    "Policy `{name}` has no non-empty `@description` annotation. The description \
                     is the rationale shown to an operator at adjudication time."
                ),
            ));
        }
    }

    let mut duplicates: Vec<(&String, &usize)> =
        seen.iter().filter(|(_, count)| **count > 1).collect();
    duplicates.sort();
    for (id, count) in duplicates {
        findings.push(Finding::error(
            CODE_POLICY_VALIDATION,
            format!(
                "`@id(\"{id}\")` is used by {count} policies in this candidate. Ids must be \
                 unique: two policies sharing one id cannot be told apart in an adjudication \
                 record."
            ),
        ));
    }

    if findings.is_empty() {
        Ok(policy_set)
    } else {
        Err(findings)
    }
}

/// A policy's annotation, or `None` when it is absent or empty. An empty
/// annotation satisfies Cedar and satisfies nothing else.
fn annotation(policy: &Policy, key: &str) -> Option<String> {
    policy
        .annotation(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Run the full candidate pipeline: parse and annotations, then schema
/// validation, then lints.
///
/// `schema_source` is the caller's schema when they supplied one. With none,
/// validation falls back to the embedded harness schema, because the engine
/// this server exists to author for has exactly one schema and checking against
/// nothing is not a check.
fn validate_candidate(policy_text: &str, schema_source: Option<&str>) -> ValidationReport {
    let mut checks_run = vec!["cedar-parse-and-annotations".to_string()];

    let policy_set = match parse_and_check_annotations(policy_text) {
        Ok(set) => set,
        // Schema validation and lints both need a parsed policy, so a parse or
        // annotation failure ends the run. `checks_run` is what tells the caller
        // the later stages did not pass — they did not execute.
        Err(findings) => return ValidationReport::new(policy_text, findings, checks_run),
    };

    let mut findings = Vec::new();

    let schema = match schema_source {
        Some(source) => match Schema::from_cedarschema_str(source) {
            Ok((schema, warnings)) => {
                checks_run.push("schema-validation (caller-supplied schema)".to_string());
                for warning in warnings {
                    findings.push(Finding::warning(
                        CODE_SCHEMA_VALIDATION,
                        format!("Schema warning: {warning}"),
                    ));
                }
                Some(schema)
            }
            Err(e) => {
                findings.push(Finding::error(
                    CODE_SCHEMA_VALIDATION,
                    format!("Schema parse error: {e}"),
                ));
                None
            }
        },
        None => match embedded_schema() {
            Some(schema) => {
                checks_run.push("schema-validation (embedded harness schema)".to_string());
                Some(schema.clone())
            }
            None => None,
        },
    };

    if let Some(schema) = schema {
        let validation = Validator::new(schema).validate(&policy_set, ValidationMode::default());
        for error in validation.validation_errors() {
            findings.push(Finding::error(
                CODE_SCHEMA_VALIDATION,
                format!("Validation error: {error}"),
            ));
        }
        for warning in validation.validation_warnings() {
            findings.push(Finding::warning(
                CODE_SCHEMA_VALIDATION,
                format!("Validation warning: {warning}"),
            ));
        }
    }

    checks_run.push("semantic-lints".to_string());
    for policy in policy_set.policies() {
        findings.extend(lint::run_lints(policy));
    }

    ValidationReport::new(policy_text, findings, checks_run)
}

/// The outcome of an `is_authorized` query.
///
/// `request` echoes the fully-qualified UIDs the query actually evaluated. A
/// bare name the caller passed is resolved against the loaded schema, and an
/// `ALLOW` means something quite different depending on which namespace it
/// landed in — so the resolution is reported rather than left implicit.
#[derive(Serialize, Deserialize, Debug)]
struct AuthorizationResult {
    decision: String,
    /// The policies that determined the decision.
    ///
    /// Empty on a `DENY` means Cedar's default-deny, not a `forbid` firing;
    /// [`AuthorizationResult::warnings`] says so explicitly.
    reasons: Vec<PolicyRef>,
    /// Policies that errored during evaluation and so contributed nothing.
    errors: Vec<PolicyEvaluationFailure>,
    request: EvaluatedRequest,
    /// Conditions that make the decision prove less than it appears to. Empty
    /// when the run is trustworthy on its face.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// A policy named in a decision, under both of its identities.
///
/// Cedar assigns positional ids (`policy0`, `policy1`, …) in load order, which
/// say nothing about which rule fired. The `@id` annotation is the identity the
/// author wrote and the harness reports at adjudication time, so it leads;
/// `policy_id` is kept because it is what Cedar's own error text cites.
#[derive(Serialize, Deserialize, Debug)]
struct PolicyRef {
    /// The `@id` annotation, absent only on a policy that omits one.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    policy_id: String,
}

/// A policy that failed to evaluate, and why.
#[derive(Serialize, Deserialize, Debug)]
struct PolicyEvaluationFailure {
    #[serde(flatten)]
    policy: PolicyRef,
    message: String,
}

/// `error` followed by its source chain.
///
/// Cedar's entity errors report only that something did not conform; the
/// attribute actually at fault is one or more levels down, and without it the
/// caller cannot tell a missing attribute from a mistyped one.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// `uid` in Cedar's entity JSON form, `{"type": …, "id": …}`.
fn uid_json(uid: &EntityUid) -> serde_json::Value {
    serde_json::json!({
        "type": uid.type_name().to_string(),
        "id": uid.id().unescaped(),
    })
}

/// Name `policy_id` under both of its identities, reading the `@id` annotation
/// out of the set the decision came from.
fn policy_ref(policy_set: &PolicySet, policy_id: &PolicyId) -> PolicyRef {
    PolicyRef {
        id: policy_set.annotation(policy_id, "id").map(str::to_string),
        policy_id: policy_id.to_string(),
    }
}

/// The principal/action/resource actually submitted to the authorizer.
#[derive(Serialize, Deserialize, Debug)]
struct EvaluatedRequest {
    principal: String,
    action: String,
    resource: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PolicyAnalysis {
    policy_count: usize,
    policies: Vec<PolicyRef>,
}

// ---------------------------------------------------------------------------
// Tool / prompt argument schemas
//
// rmcp's `#[tool]` and `#[prompt]` macros take a single `Parameters<T>` value
// and derive the JSON input schema from `T`. Doc comments become field
// descriptions in that schema.
// ---------------------------------------------------------------------------

/// A single Cedar policy source string.
#[derive(Debug, Deserialize, JsonSchema)]
struct PolicyArg {
    /// Cedar policy source code.
    policy: String,
}

/// A single Cedar schema source string.
#[derive(Debug, Deserialize, JsonSchema)]
struct SchemaArg {
    /// Cedar schema source (`.cedarschema` syntax).
    schema: String,
}

/// A Cedar policy set source string.
#[derive(Debug, Deserialize, JsonSchema)]
struct PoliciesArg {
    /// One or more Cedar policies concatenated as source.
    policies: String,
}

/// A Cedar policy plus an optional schema to validate against.
#[derive(Debug, Deserialize, JsonSchema)]
struct ValidatePolicyArgs {
    /// Cedar policy source code.
    policy: String,
    /// Optional Cedar schema to validate the policy against.
    schema: Option<String>,
}

/// A Cedar policy and the schema to validate it against.
#[derive(Debug, Deserialize, JsonSchema)]
struct PolicyAndSchemaArgs {
    /// Cedar policy source code.
    policy: String,
    /// Cedar schema source to validate against.
    schema: String,
}

/// Entities JSON and the schema to validate them against.
#[derive(Debug, Deserialize, JsonSchema)]
struct EntitiesAndSchemaArgs {
    /// Cedar entities as a JSON array.
    entities_json: String,
    /// Cedar schema source to validate against.
    schema: String,
}

/// A new entity to add to the in-memory store.
#[derive(Debug, Deserialize, JsonSchema)]
struct AddEntityArgs {
    /// Entity type, qualified (`Sondera::Agent`) or bare (`Agent`). A bare name
    /// is resolved against the loaded schema's namespace.
    entity_type: String,
    /// Entity identifier.
    entity_id: String,
    /// Optional parent entity UIDs (e.g. `Sondera::Label::"Confidential"`).
    /// Bare type names are resolved the same way.
    parents: Option<Vec<String>>,
    /// Optional attributes as a JSON object string, in the same form as
    /// `is_authorized`'s `context_json`: entity references use Cedar's escape
    /// form, e.g.
    /// `{"provider": "claude", "label": {"__entity": {"type": "Sondera::Label", "id": "Public"}}}`.
    /// Required for any entity type whose schema declares attributes.
    attributes: Option<String>,
}

/// A principal/action/resource authorization query.
#[derive(Debug, Deserialize, JsonSchema)]
struct IsAuthorizedArgs {
    /// Principal entity UID, qualified (`Sondera::Agent::"claude"`) or bare
    /// (`Agent::"claude"`). A bare type is resolved against the loaded schema.
    principal: String,
    /// Action, qualified (`Sondera::Action::"ShellCommand"`) or bare
    /// (`ShellCommand`). A bare name is resolved against the loaded schema.
    action: String,
    /// Resource entity UID, qualified (`Sondera::Trajectory::"t1"`) or bare
    /// (`Trajectory::"t1"`). A bare type is resolved against the loaded schema.
    resource: String,
    /// Optional request context as a JSON object string.
    context_json: Option<String>,
}

/// Cedar schema fragments to merge.
#[derive(Debug, Deserialize, JsonSchema)]
struct MergeFragmentsArgs {
    /// Schema fragments to concatenate and validate.
    fragments: Vec<String>,
}

/// Parameters for generating an entity schema fragment.
#[derive(Debug, Deserialize, JsonSchema)]
struct CreateEntitySchemaArgs {
    /// Entity type name to declare.
    entity_name: String,
    /// Optional parent entity types (membership list).
    parents: Option<Vec<String>>,
    /// Optional attributes as a JSON object of `name -> cedar-type`.
    attributes: Option<String>,
}

/// Parameters for generating an action schema fragment.
#[derive(Debug, Deserialize, JsonSchema)]
struct CreateActionSchemaArgs {
    /// Action name to declare.
    action_name: String,
    /// Principal entity types the action applies to.
    principal_types: Vec<String>,
    /// Resource entity types the action applies to.
    resource_types: Vec<String>,
}

/// An entity type/id pair to validate.
#[derive(Debug, Deserialize, JsonSchema)]
struct ValidateEntityArgs {
    /// Entity type name.
    entity_type: String,
    /// Entity identifier.
    entity_id: String,
}

/// An entity UID to remove.
#[derive(Debug, Deserialize, JsonSchema)]
struct RemoveEntityArgs {
    /// Entity UID to remove (e.g. `Agent::"claude"`).
    entity_uid: String,
}

/// Agent list request parameters.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
struct ListAgentsArgs {
    page_size: i32,
    page_token: String,
    filter: String,
    order_by: String,
}

/// Agent filter parameters.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
struct AnalyzeAgentsArgs {
    filter: String,
}

/// One agent resource name.
#[derive(Debug, Deserialize, JsonSchema)]
struct AgentNameArgs {
    /// AIP resource name (`agents/{agent}`).
    name: String,
}

/// Trajectory list request parameters.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
struct ListTrajectoriesArgs {
    page_size: i32,
    page_token: String,
    filter: String,
    order_by: String,
}

/// One trajectory resource name.
#[derive(Debug, Deserialize, JsonSchema)]
struct TrajectoryNameArgs {
    /// AIP resource name (`trajectories/{trajectory}`).
    name: String,
}

/// Trajectory event list request parameters.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
struct ListTrajectoryEventsArgs {
    /// AIP resource name (`trajectories/{trajectory}`).
    trajectory: String,
    page_size: i32,
    page_token: String,
}

#[derive(Debug, Serialize)]
struct DeleteAgentResult {
    deleted: String,
}

/// The natural-language intent for the `autoformalize` prompt.
#[derive(Debug, Deserialize, JsonSchema)]
struct AutoformalizeArgs {
    /// Natural-language description of the governance intent to formalize
    /// into Cedar for the Sondera open-source harness engine.
    intent: String,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// MCP server for Cedar authoring and the local console read surface.
pub struct CedarMcpServer {
    state: Arc<CedarState>,
    console: ConsoleClient,
}

struct CedarState {
    schema: RwLock<Option<Schema>>,
    policy_set: RwLock<PolicySet>,
    entities: RwLock<Entities>,
    authorizer: Authorizer,
}

impl CedarMcpServer {
    /// Create a server with an empty Cedar working set, reading the console at
    /// `console`.
    pub fn new(console: ConsoleClient) -> Self {
        Self {
            state: Arc::new(CedarState {
                schema: RwLock::new(None),
                policy_set: RwLock::new(PolicySet::new()),
                entities: RwLock::new(Entities::empty()),
                authorizer: Authorizer::new(),
            }),
            console,
        }
    }
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[tool_router]
impl CedarMcpServer {
    #[tool(
        description = "List local coding agents with activity rollups and latest-run sparklines"
    )]
    async fn list_agents(
        &self,
        Parameters(args): Parameters<ListAgentsArgs>,
    ) -> Result<String, McpError> {
        // The request grammar is validated by the console, not here: an
        // unrecognized filter key is its INVALID_ARGUMENT to raise, and parsing
        // it twice would let the two sides disagree about what a clause means.
        let result = self
            .console
            .list_agents(
                args.page_size,
                &args.page_token,
                &args.filter,
                &args.order_by,
            )
            .await
            .map_err(console_error)?;
        json_result(&result)
    }

    #[tool(description = "Get one local coding agent by its agents/{agent} resource name")]
    async fn get_agent(
        &self,
        Parameters(args): Parameters<AgentNameArgs>,
    ) -> Result<String, McpError> {
        let agent = self
            .console
            .get_agent(&args.name)
            .await
            .map_err(console_error)?;
        json_result(&agent)
    }

    #[tool(description = "Return one agent's fresh computed projection; no fields are writable")]
    async fn update_agent(
        &self,
        Parameters(args): Parameters<AgentNameArgs>,
    ) -> Result<String, McpError> {
        let agent = self
            .console
            .update_agent(&args.name)
            .await
            .map_err(console_error)?;
        json_result(&agent)
    }

    #[tool(description = "Compute aggregate status counts over filtered local coding agents")]
    async fn analyze_agents(
        &self,
        Parameters(args): Parameters<AnalyzeAgentsArgs>,
    ) -> Result<String, McpError> {
        let stats = self
            .console
            .analyze_agents(&args.filter)
            .await
            .map_err(console_error)?;
        json_result(&stats)
    }

    #[tool(description = "Delete one local agent and its trajectory events")]
    async fn delete_agent(
        &self,
        Parameters(args): Parameters<AgentNameArgs>,
    ) -> Result<String, McpError> {
        self.console
            .delete_agent(&args.name)
            .await
            .map_err(console_error)?;
        json_result(&DeleteAgentResult { deleted: args.name })
    }

    #[tool(description = "Get one local trajectory summary by its trajectories/{trajectory} name")]
    async fn get_trajectory(
        &self,
        Parameters(args): Parameters<TrajectoryNameArgs>,
    ) -> Result<String, McpError> {
        let trajectory = self
            .console
            .get_trajectory(&args.name)
            .await
            .map_err(console_error)?;
        json_result(&trajectory)
    }

    #[tool(description = "List paginated folded events for one local trajectory")]
    async fn list_trajectory_events(
        &self,
        Parameters(args): Parameters<ListTrajectoryEventsArgs>,
    ) -> Result<String, McpError> {
        let result = self
            .console
            .list_trajectory_events(&args.trajectory, args.page_size, &args.page_token)
            .await
            .map_err(console_error)?;
        json_result(&result)
    }

    #[tool(
        description = "List local trajectory summaries with agent, decision, and status filters"
    )]
    async fn list_trajectories(
        &self,
        Parameters(args): Parameters<ListTrajectoriesArgs>,
    ) -> Result<String, McpError> {
        let result = self
            .console
            .list_trajectories(
                args.page_size,
                &args.page_token,
                &args.filter,
                &args.order_by,
            )
            .await
            .map_err(console_error)?;
        json_result(&result)
    }

    #[tool(
        description = "Enumerate the closed sets a Cedar condition must match exactly: YARA \
                       signature categories behind context.signature.categories, policy violation \
                       codes behind context.policy.violations, the sensitivity label lattice, and \
                       the semantic lints validate_policy will run. Consult this before writing \
                       any category, code, or label literal — an undeclared value is a condition \
                       that can never be true, and Cedar cannot catch it because all of them are \
                       well-typed strings. Individual signature rules are NOT returned by default \
                       (the full set is larger than clients accept inline): pass `category` or \
                       `query` to list them. Anything dropped for size is named in \
                       omitted_rule_ids, never silently truncated."
    )]
    async fn get_cedar_policy_context_features(
        &self,
        Parameters(args): Parameters<ContextFeaturesArgs>,
    ) -> Result<String, McpError> {
        let features = features::context_features(&args)?;
        serde_json::to_string_pretty(&features).map_err(|e| tool_error(e.to_string()))
    }

    #[tool(
        description = "Query the Cedar baseline the harness ships with — what the engine already \
                       forbids. Filter by `action` surface or `signature_category` to find an \
                       existing policy covering an intent, or a worked example of the shape to \
                       follow, before drafting a duplicate. Filter by `policy_id` for the inverse \
                       check: an empty result means that @id is free, and ids cannot be \
                       discovered by guessing. An empty filter returns as much of the baseline as \
                       fits, naming the rest in omitted_ids. This is the shipped baseline; a \
                       deployment may load a different policy directory, so treat it as a \
                       drafting reference rather than an inventory of a running system."
    )]
    async fn query_baseline_coverage(
        &self,
        Parameters(filter): Parameters<CoverageFilter>,
    ) -> Result<String, McpError> {
        let result = baseline::query(&filter, declared_action_names());
        serde_json::to_string_pretty(&result).map_err(|e| tool_error(e.to_string()))
    }

    #[tool(
        description = "Validate a candidate Cedar policy for the harness engine: Cedar parse, \
                       required @id/@description annotations, duplicate-id detection, schema \
                       validation, and semantic lints for conditions that typecheck but can never \
                       be true. Verify-only — the candidate is returned unchanged, never \
                       rewritten. `schema` is optional; with none, the candidate is validated \
                       against the embedded harness schema. Findings carry stable codes, and \
                       provenance.checks_run reports which stages actually ran — a stage absent \
                       from that list did not pass, it did not execute. Do not present Cedar that \
                       has not returned valid=true."
    )]
    async fn validate_policy(
        &self,
        Parameters(ValidatePolicyArgs { policy, schema }): Parameters<ValidatePolicyArgs>,
    ) -> Result<String, McpError> {
        let report = validate_candidate(&policy, schema.as_deref());
        serde_json::to_string_pretty(&report).map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Validate Cedar schema syntax and report errors")]
    async fn validate_schema(
        &self,
        Parameters(SchemaArg { schema }): Parameters<SchemaArg>,
    ) -> Result<String, McpError> {
        let findings = match Schema::from_cedarschema_str(&schema) {
            Ok((_, warnings)) => warnings
                .into_iter()
                .map(|warning| {
                    Finding::warning(CODE_SCHEMA_VALIDATION, format!("Schema warning: {warning}"))
                })
                .collect(),
            Err(e) => vec![Finding::error(
                CODE_SCHEMA_VALIDATION,
                format!("Schema parse error: {e}"),
            )],
        };

        let report = ValidationReport::new(&schema, findings, vec!["schema-parse".to_string()]);
        serde_json::to_string_pretty(&report).map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Load a Cedar schema for subsequent operations")]
    async fn load_schema(
        &self,
        Parameters(SchemaArg { schema }): Parameters<SchemaArg>,
    ) -> Result<String, McpError> {
        match Schema::from_cedarschema_str(&schema) {
            Ok((parsed_schema, warnings)) => {
                *self.state.schema.write().await = Some(parsed_schema);

                let warning_msgs: Vec<String> =
                    warnings.into_iter().map(|w| w.to_string()).collect();
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "warnings": warning_msgs
                }))
                .map_err(|e| tool_error(e.to_string()))
            }
            Err(e) => Err(tool_error(format!("Failed to parse schema: {}", e))),
        }
    }

    #[tool(description = "Load Cedar policies for authorization checks")]
    async fn load_policies(
        &self,
        Parameters(PoliciesArg { policies }): Parameters<PoliciesArg>,
    ) -> Result<String, McpError> {
        let policy_set: PolicySet = policies
            .parse()
            .map_err(|e| tool_error(format!("Failed to parse policies: {}", e)))?;

        {
            let schema_lock = self.state.schema.read().await;
            if let Some(ref schema) = *schema_lock {
                let validator = Validator::new(schema.clone());
                let validation = validator.validate(&policy_set, ValidationMode::default());
                if !validation.validation_passed() {
                    let errors: Vec<String> = validation
                        .validation_errors()
                        .map(|e| e.to_string())
                        .collect();
                    return Err(tool_error(format!(
                        "Policy validation failed: {}",
                        errors.join("; ")
                    )));
                }
            }
        }

        let policy_count = policy_set.policies().count();
        *self.state.policy_set.write().await = policy_set;

        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "policy_count": policy_count
        }))
        .map_err(|e| tool_error(e.to_string()))
    }

    #[tool(
        description = "Add an entity to the store. Pass `attributes` for any type whose schema \
                       declares them — Agent, File, Trajectory, and Message all require \
                       attributes, and an entity added without them is rejected as \
                       non-conforming. A policy reading an attribute of an entity that is not in \
                       the store errors during evaluation and contributes nothing to the \
                       decision, so the rule reads as untested rather than as failing."
    )]
    async fn add_entity(
        &self,
        Parameters(AddEntityArgs {
            entity_type,
            entity_id,
            parents,
            attributes,
        }): Parameters<AddEntityArgs>,
    ) -> Result<String, McpError> {
        // Clone the schema so the read guard is released before the entities
        // write lock is taken — holding it across the write needlessly stalls a
        // pending `load_schema` on this write-preferring lock.
        let schema = self.state.schema.read().await.clone();

        // Resolve the same way `is_authorized` does. An entity added as
        // `Agent::"claude"` while policies name `Sondera::Agent` is a different
        // entity that no rule can reach, which surfaces later as a puzzling
        // ALLOW rather than as an error here.
        let parsed: EntityTypeName = entity_type
            .trim()
            .parse()
            .map_err(|e| input_error(format!("Invalid entity type '{}': {}", entity_type, e)))?;

        let entity_type_name = match schema.as_ref() {
            Some(schema) if parsed.namespace().is_empty() => {
                resolve_entity_type(parsed.basename(), schema, "Entity")?
            }
            _ => parsed,
        };

        let uid = EntityUid::from_type_name_and_id(entity_type_name, EntityId::new(&entity_id));

        let parent_set: HashSet<EntityUid> = match parents {
            Some(parent_strs) => {
                let mut set = HashSet::new();
                for p in parent_strs {
                    set.insert(resolve_entity_uid(&p, schema.as_ref(), "Parent")?);
                }
                set
            }
            None => HashSet::new(),
        };

        let attrs: serde_json::Value = match attributes {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| input_error(format!("Invalid attributes JSON: {}", e)))?,
            None => serde_json::json!({}),
        };
        if !attrs.is_object() {
            return Err(input_error(
                "`attributes` must be a JSON object of attribute name to value".to_string(),
            ));
        }

        // Built through the entity JSON parser rather than `Entity::new`, so
        // attribute values use the same escape form as `context_json` — one
        // convention for entity references across the two tools that take
        // Cedar data as JSON.
        let entity = Entity::from_json_value(
            serde_json::json!({
                "uid": uid_json(&uid),
                "attrs": attrs,
                "parents": parent_set.iter().map(uid_json).collect::<Vec<_>>(),
            }),
            schema.as_ref(),
        )
        .map_err(|e| input_error(format!("Failed to build entity: {}", error_chain(&e))))?;

        let mut entities_lock = self.state.entities.write().await;
        // Build the new set from a clone rather than `mem::take`ing the shared
        // store: `add_entities` consumes its receiver, so on a recoverable error
        // (entity type not in schema, duplicate UID) the `?` would return with
        // the store left permanently empty.
        let updated = entities_lock
            .clone()
            .add_entities([entity], schema.as_ref())
            .map_err(|e| input_error(format!("Failed to add entity: {}", error_chain(&e))))?;
        *entities_lock = updated;

        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "entity": uid.to_string()
        }))
        .map_err(|e| tool_error(e.to_string()))
    }

    #[tool(
        description = "Check authorization for principal/action/resource. Load the schema first: \
                       bare names are resolved against its namespace, and without it the request \
                       cannot match namespaced policies. The result echoes the qualified UIDs \
                       that were evaluated. `reasons` names the deciding policies by their @id; \
                       an empty `reasons` on a DENY is Cedar's default-deny, not a forbid firing. \
                       `errors` names policies that failed to evaluate and so decided nothing. \
                       Read `warnings` before trusting a decision — it is present exactly when \
                       the result proves less than it appears to."
    )]
    async fn is_authorized(
        &self,
        Parameters(IsAuthorizedArgs {
            principal,
            action,
            resource,
            context_json,
        }): Parameters<IsAuthorizedArgs>,
    ) -> Result<String, McpError> {
        // Clone the schema so every resolution below sees one consistent view
        // and the read guard is not held across them.
        let schema = self.state.schema.read().await.clone();

        let principal_uid = resolve_entity_uid(&principal, schema.as_ref(), "Principal")?;
        let action_uid = resolve_action_uid(&action, schema.as_ref())?;
        let resource_uid = resolve_entity_uid(&resource, schema.as_ref(), "Resource")?;

        let ctx_cedar = match context_json {
            Some(json) => CedarContext::from_json_str(&json, None)
                .map_err(|e| input_error(format!("Invalid context JSON: {}", e)))?,
            None => CedarContext::empty(),
        };

        let evaluated = EvaluatedRequest {
            principal: principal_uid.to_string(),
            action: action_uid.to_string(),
            resource: resource_uid.to_string(),
        };

        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            ctx_cedar,
            schema.as_ref(),
        )
        .map_err(|e| input_error(format!("Failed to create request: {}", e)))?;

        // Resolve both diagnostics to `@id`s while the policy set is still
        // locked: the annotation lives in the set, not in the response.
        let (response, reasons, errors): (Response, Vec<PolicyRef>, Vec<PolicyEvaluationFailure>) = {
            let policy_lock = self.state.policy_set.read().await;
            let entities_lock = self.state.entities.read().await;
            let response =
                self.state
                    .authorizer
                    .is_authorized(&request, &policy_lock, &entities_lock);

            let reasons = response
                .diagnostics()
                .reason()
                .map(|id| policy_ref(&policy_lock, id))
                .collect();
            let errors = response
                .diagnostics()
                .errors()
                .map(|error| {
                    let AuthorizationError::PolicyEvaluationError(failure) = error;
                    PolicyEvaluationFailure {
                        policy: policy_ref(&policy_lock, failure.policy_id()),
                        message: failure.inner().to_string(),
                    }
                })
                .collect();

            (response, reasons, errors)
        };

        let denied = response.decision() == cedar_policy::Decision::Deny;

        // Every condition below produces a result that looks like a verdict and
        // is not one. They are reported together because they compound: an
        // unqualified request against an erroring policy set denies for two
        // unrelated non-reasons.
        let mut warnings = Vec::new();
        if schema.is_none() {
            warnings.push(
                "No schema is loaded, so the request was not validated and bare names could \
                 not be namespace-qualified. Call load_schema first; otherwise a policy \
                 written against a namespaced action cannot match, and the decision reflects \
                 only Cedar's defaults."
                    .to_string(),
            );
        }
        if !errors.is_empty() {
            warnings.push(format!(
                "{} polic{} errored and contributed nothing to this decision. A policy that \
                 reads an attribute of an entity absent from the store errors rather than \
                 matching — add the entity with its attributes, or the rule is untested.",
                errors.len(),
                if errors.len() == 1 { "y" } else { "ies" }
            ));
        }
        if denied && reasons.is_empty() {
            warnings.push(
                "No policy matched, so this DENY is Cedar's default-deny rather than a forbid \
                 firing. Load the baseline default-permit alongside the candidate to tell the \
                 two apart."
                    .to_string(),
            );
        }

        let result = AuthorizationResult {
            decision: if denied {
                "DENY".to_string()
            } else {
                "ALLOW".to_string()
            },
            reasons,
            errors,
            request: evaluated,
            warnings,
        };

        serde_json::to_string_pretty(&result).map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Analyze loaded Cedar policies and return metadata")]
    async fn analyze_policies(&self) -> Result<String, McpError> {
        let policy_lock = self.state.policy_set.read().await;
        let policies: Vec<PolicyRef> = policy_lock
            .policies()
            .map(|p| policy_ref(&policy_lock, p.id()))
            .collect();
        let policy_count = policies.len();
        drop(policy_lock);

        let analysis = PolicyAnalysis {
            policy_count,
            policies,
        };

        serde_json::to_string_pretty(&analysis).map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Format Cedar policy source code")]
    async fn format_policy(
        &self,
        Parameters(PolicyArg { policy }): Parameters<PolicyArg>,
    ) -> Result<String, McpError> {
        let policy_set: PolicySet = policy
            .parse()
            .map_err(|e| tool_error(format!("Failed to parse policy: {}", e)))?;

        Ok(policy_set.to_string())
    }

    #[tool(description = "Clear all loaded state")]
    async fn clear_state(&self) -> Result<String, McpError> {
        *self.state.schema.write().await = None;
        *self.state.policy_set.write().await = PolicySet::new();
        *self.state.entities.write().await = Entities::empty();

        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "message": "All state cleared"
        }))
        .map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Parse and analyze a Cedar schema returning actions")]
    async fn analyze_schema(
        &self,
        Parameters(SchemaArg { schema }): Parameters<SchemaArg>,
    ) -> Result<String, McpError> {
        let (parsed_schema, warnings) = Schema::from_cedarschema_str(&schema)
            .map_err(|e| tool_error(format!("Failed to parse schema: {}", e)))?;

        let action_entities = parsed_schema
            .action_entities()
            .map_err(|e| tool_error(format!("Failed to get action entities: {}", e)))?;

        let actions: Vec<String> = action_entities
            .iter()
            .map(|e| e.uid().to_string())
            .collect();
        let warning_msgs: Vec<String> = warnings.into_iter().map(|w| w.to_string()).collect();

        serde_json::to_string_pretty(&serde_json::json!({
            "actions": actions,
            "action_count": actions.len(),
            "warnings": warning_msgs
        }))
        .map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Merge multiple Cedar schema fragments into one")]
    async fn merge_schema_fragments(
        &self,
        Parameters(MergeFragmentsArgs { fragments }): Parameters<MergeFragmentsArgs>,
    ) -> Result<String, McpError> {
        if fragments.is_empty() {
            return Err(tool_error("No schema fragments provided"));
        }

        let combined = fragments.join("\n\n");

        match Schema::from_cedarschema_str(&combined) {
            Ok((_, warnings)) => {
                let warning_msgs: Vec<String> =
                    warnings.into_iter().map(|w| w.to_string()).collect();
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "merged_schema": combined,
                    "warnings": warning_msgs
                }))
                .map_err(|e| tool_error(e.to_string()))
            }
            Err(e) => Err(tool_error(format!(
                "Failed to merge schema fragments: {}",
                e
            ))),
        }
    }

    #[tool(description = "Create Cedar schema fragment for entity type")]
    async fn create_entity_schema(
        &self,
        Parameters(CreateEntitySchemaArgs {
            entity_name,
            parents,
            attributes,
        }): Parameters<CreateEntitySchemaArgs>,
    ) -> Result<String, McpError> {
        let mut schema_fragment = String::new();

        match parents {
            Some(ref parent_types) if !parent_types.is_empty() => {
                schema_fragment.push_str(&format!(
                    "entity {} in [{}]",
                    entity_name,
                    parent_types.join(", ")
                ));
            }
            _ => schema_fragment.push_str(&format!("entity {}", entity_name)),
        }

        if let Some(attrs_json) = attributes {
            let attrs: serde_json::Value = serde_json::from_str(&attrs_json)
                .map_err(|e| tool_error(format!("Invalid attributes JSON: {}", e)))?;
            match attrs {
                serde_json::Value::Object(map) if !map.is_empty() => {
                    schema_fragment.push_str(" = {\n");
                    for (name, type_val) in map {
                        let type_str = type_val.as_str().unwrap_or("String");
                        schema_fragment.push_str(&format!("    {}: {},\n", name, type_str));
                    }
                    schema_fragment.push('}');
                }
                _ => schema_fragment.push(';'),
            }
        } else {
            schema_fragment.push(';');
        }

        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "fragment": schema_fragment
        }))
        .map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Create Cedar schema fragment for action")]
    async fn create_action_schema(
        &self,
        Parameters(CreateActionSchemaArgs {
            action_name,
            principal_types,
            resource_types,
        }): Parameters<CreateActionSchemaArgs>,
    ) -> Result<String, McpError> {
        if principal_types.is_empty() {
            return Err(tool_error("At least one principal type required"));
        }
        if resource_types.is_empty() {
            return Err(tool_error("At least one resource type required"));
        }

        let schema_fragment = format!(
            "action \"{}\" appliesTo {{\n    principal: [{}],\n    resource: [{}]\n}};",
            action_name,
            principal_types.join(", "),
            resource_types.join(", ")
        );

        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "fragment": schema_fragment
        }))
        .map_err(|e| tool_error(e.to_string()))
    }

    #[tool(
        description = "Validate a candidate Cedar policy against an explicitly supplied schema. \
                       Identical to validate_policy with `schema` set; prefer validate_policy, \
                       which falls back to the harness schema when none is given."
    )]
    async fn validate_policy_against_schema(
        &self,
        Parameters(PolicyAndSchemaArgs { policy, schema }): Parameters<PolicyAndSchemaArgs>,
    ) -> Result<String, McpError> {
        let report = validate_candidate(&policy, Some(&schema));
        serde_json::to_string_pretty(&report).map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Validate entities JSON against a Cedar schema")]
    async fn validate_entities_against_schema(
        &self,
        Parameters(EntitiesAndSchemaArgs {
            entities_json,
            schema,
        }): Parameters<EntitiesAndSchemaArgs>,
    ) -> Result<String, McpError> {
        let mut findings = Vec::new();
        let mut checks_run = vec!["schema-parse".to_string()];
        let mut entity_count = None;

        match Schema::from_cedarschema_str(&schema) {
            Ok((parsed_schema, warnings)) => {
                for warning in warnings {
                    findings.push(Finding::warning(
                        CODE_SCHEMA_VALIDATION,
                        format!("Schema warning: {warning}"),
                    ));
                }
                checks_run.push("entity-validation".to_string());
                match Entities::from_json_str(&entities_json, Some(&parsed_schema)) {
                    Ok(entities) => entity_count = Some(entities.iter().count()),
                    Err(e) => findings.push(Finding::error(
                        CODE_ENTITY_VALIDATION,
                        format!("Entity validation error: {e}"),
                    )),
                }
            }
            Err(e) => findings.push(Finding::error(
                CODE_SCHEMA_VALIDATION,
                format!("Schema parse error: {e}"),
            )),
        }

        let report = ValidationReport::new(&entities_json, findings, checks_run);
        serde_json::to_string_pretty(&serde_json::json!({
            "report": report,
            "entity_count": entity_count,
        }))
        .map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Validate single entity against loaded schema")]
    async fn validate_entity(
        &self,
        Parameters(ValidateEntityArgs {
            entity_type,
            entity_id,
        }): Parameters<ValidateEntityArgs>,
    ) -> Result<String, McpError> {
        let candidate = format!("{entity_type}::\"{entity_id}\"");
        let mut checks_run = Vec::new();

        let entity_type_name: EntityTypeName = match entity_type.parse() {
            Ok(name) => name,
            Err(e) => {
                let report = ValidationReport::new(
                    &candidate,
                    vec![Finding::error(
                        CODE_ENTITY_VALIDATION,
                        format!("Invalid entity type: {e}"),
                    )],
                    checks_run,
                );
                return serde_json::to_string_pretty(&report)
                    .map_err(|e| tool_error(e.to_string()));
            }
        };
        checks_run.push("entity-type-parse".to_string());

        let uid = EntityUid::from_type_name_and_id(entity_type_name, EntityId::new(&entity_id));
        let entity = Entity::new_no_attrs(uid, HashSet::new());

        // Cedar performs no validation against a `None` schema, so reporting a
        // valid entity here would claim a check that never ran.
        let findings = match self.state.schema.read().await.clone() {
            None => vec![Finding::error(
                CODE_ENTITY_VALIDATION,
                "No schema loaded: entities cannot be validated. Call load_schema first."
                    .to_string(),
            )],
            Some(schema) => {
                checks_run.push("entity-validation".to_string());
                match Entities::empty().add_entities([entity], Some(&schema)) {
                    Ok(_) => Vec::new(),
                    Err(e) => vec![Finding::error(
                        CODE_ENTITY_VALIDATION,
                        format!("Entity validation failed: {e}"),
                    )],
                }
            }
        };

        let report = ValidationReport::new(&candidate, findings, checks_run);
        serde_json::to_string_pretty(&report).map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "List all entities in the entity store")]
    async fn list_entities(&self) -> Result<String, McpError> {
        let entities_lock = self.state.entities.read().await;
        let entity_list: Vec<serde_json::Value> = entities_lock
            .iter()
            .map(|e| {
                serde_json::json!({
                    "uid": e.uid().to_string(),
                    "type": e.uid().type_name().to_string(),
                })
            })
            .collect();
        let count = entity_list.len();
        drop(entities_lock);

        serde_json::to_string_pretty(&serde_json::json!({
            "entity_count": count,
            "entities": entity_list
        }))
        .map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Remove an entity by UID from the store")]
    async fn remove_entity(
        &self,
        Parameters(RemoveEntityArgs { entity_uid }): Parameters<RemoveEntityArgs>,
    ) -> Result<String, McpError> {
        let uid: EntityUid = entity_uid
            .parse()
            .map_err(|e| input_error(format!("Invalid entity UID: {}", e)))?;

        let mut entities_lock = self.state.entities.write().await;
        // Same as `add_entity`: work on a clone so a failing remove cannot leave
        // the shared store emptied by `mem::take`.
        let updated = entities_lock
            .clone()
            .remove_entities([uid.clone()])
            .map_err(|e| input_error(format!("Failed to remove entity: {}", e)))?;
        *entities_lock = updated;

        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "removed": uid.to_string()
        }))
        .map_err(|e| tool_error(e.to_string()))
    }

    #[tool(description = "Get schema loading status")]
    async fn get_schema_status(&self) -> Result<String, McpError> {
        let schema_lock = self.state.schema.read().await;
        let status = match schema_lock.as_ref() {
            Some(schema) => {
                let action_count = schema
                    .action_entities()
                    .map(|e| e.iter().count())
                    .unwrap_or(0);
                serde_json::json!({ "loaded": true, "action_count": action_count })
            }
            None => serde_json::json!({ "loaded": false }),
        };
        drop(schema_lock);

        serde_json::to_string_pretty(&status).map_err(|e| tool_error(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

#[prompt_router]
impl CedarMcpServer {
    /// Formalize a natural-language governance intent into Cedar for the
    /// open-source harness engine.
    #[prompt(
        name = "autoformalize",
        description = "Formalize a natural-language coding-agent governance intent into a Cedar forbid policy for the Sondera open-source harness engine (crates/harness)"
    )]
    async fn autoformalize(
        &self,
        Parameters(AutoformalizeArgs { intent }): Parameters<AutoformalizeArgs>,
    ) -> Result<GetPromptResult, McpError> {
        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            PromptMessageRole::User,
            autoformalize_prompt(&intent),
        )])
        .with_description("Autoformalization guidance for the Sondera OSS harness Cedar engine"))
    }
}

/// Build the autoformalization message for the OSS harness engine.
///
/// Deliberately short. The doctrine is served as
/// [`AUTHORING_GUIDE`](doctrine::AUTHORING_GUIDE) and the schema as a resource,
/// so this carries the intent and the entry points rather than a copy of both —
/// the schema alone ran to several hundred lines on every invocation, and a
/// prompt that restates what the tools enforce is a second copy of the rules
/// free to drift from the first.
fn autoformalize_prompt(intent: &str) -> String {
    format!(
        r#"Formalize a natural-language governance intent into Cedar for the Sondera
coding-agent harness. Output only Cedar policy text that has passed validation.

Before drafting, read these — they are the authority, and drafting from memory
of the schema is how dead policies get written:

1. `cedar://harness/authoring-guide` — how to draft for this engine: the
   default-permit/forbid-override model, required annotations, the
   normalizations your literals have to match, and when to refuse.
2. `cedar://harness/schema` — the authoritative action and context surface.
   Fields not declared there do not exist.
3. `query_baseline_coverage` — what the engine already forbids on the surface
   you are about to write for, and a free `@id`.
4. `get_cedar_policy_context_features` — the exact signature categories, policy
   violation codes, and label names to use as literals.

Then draft, and validate the exact text with `validate_policy`. Fix errors and
re-validate. Present nothing that has not returned `valid: true`, and refuse —
naming the missing capability — where the engine cannot express the intent.

## Intent to formalize
{intent}
"#
    )
}

// ---------------------------------------------------------------------------
// Server handler: tools + prompts (via macros) plus manual resources
// ---------------------------------------------------------------------------

/// The default-permit policy the whole baseline sits on top of, plus the
/// per-action context map documented alongside it.
///
/// This is the *root* of the baseline, not a sample of it: it declares the
/// default permit and nothing else. The worked `forbid` examples are the other
/// 109 rules of the shipped corpus, which are far too large to serve as one
/// document and are queried through
/// [`query_baseline_coverage`](CedarMcpServer::query_baseline_coverage)
/// instead.
const HARNESS_BASE_POLICIES: &str = include_str!("../../../.sondera/policies/cedar/base.cedar");

const HARNESS_SCHEMA_URI: &str = "cedar://harness/schema";
const HARNESS_BASE_POLICIES_URI: &str = "cedar://harness/base-policies";
const AUTHORING_GUIDE_URI: &str = "cedar://harness/authoring-guide";

/// The document served at `uri`, or `None` when nothing is served there.
///
/// Split out from the handler so the served set can be checked against
/// [`RESOURCE_URIS`] without standing up a request context.
fn resource_body(uri: &str) -> Option<&'static str> {
    match uri {
        AUTHORING_GUIDE_URI => Some(doctrine::AUTHORING_GUIDE),
        HARNESS_SCHEMA_URI => Some(HARNESS_SCHEMA),
        HARNESS_BASE_POLICIES_URI => Some(HARNESS_BASE_POLICIES),
        _ => None,
    }
}

#[tool_handler]
#[prompt_handler]
impl ServerHandler for CedarMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new(
            "sondera-mcp",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions(
            // A router, not a summary: it names the surfaces and defers the
            // procedure to the served guide, so this text cannot drift from the
            // doctrine it would otherwise paraphrase.
            "Cedar policy authoring server for the Sondera coding-agent harness. \
             Start at the `cedar://harness/authoring-guide` resource — it is how to \
             draft for this engine — with `cedar://harness/schema` for the \
             authoritative field surface. `query_baseline_coverage` shows what the \
             baseline already forbids and whether an @id is free; \
             `get_cedar_policy_context_features` gives the closed sets that \
             category, code, and label literals must come from. Only \
             `validate_policy` approves a candidate: it checks annotations, the \
             schema, and semantic lints for conditions that typecheck but can never \
             fire. The `autoformalize` prompt runs this loop for one intent. The \
             remaining tools are a Cedar scratchpad (load a schema and policies, \
             manage entities, run is_authorized) for trying a policy out by hand. \
             Agent and trajectory tools read a running `sondera serve` over its \
             console API and report what it projects; they are unavailable when \
             none is running, which does not affect the Cedar tools. Live \
             streams and trajectory sparkline batches remain gRPC-only.",
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::with_all_items(vec![
            RawResource::new(
                AUTHORING_GUIDE_URI,
                "How to author Cedar for the Sondera harness (read this first)",
            )
            .no_annotation(),
            RawResource::new(HARNESS_SCHEMA_URI, "Sondera harness Cedar schema").no_annotation(),
            RawResource::new(
                HARNESS_BASE_POLICIES_URI,
                "Sondera harness default-permit root (query_baseline_coverage has the forbids)",
            )
            .no_annotation(),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let Some(body) = resource_body(request.uri.as_str()) else {
            return Err(McpError::resource_not_found(
                format!("Unknown resource: {}", request.uri),
                None,
            ));
        };
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            body,
            &request.uri,
        )]))
    }
}

// ============================================================================
// stdio transport
// ============================================================================

/// Failure to run the MCP server over stdio.
///
/// The underlying `rmcp` errors are flattened to strings deliberately, so the
/// transport crate does not leak into this crate's public signature.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// The client never completed the MCP initialization handshake.
    #[error("MCP initialization failed: {0}")]
    Initialize(String),
    /// The server task ended abnormally rather than on a clean client quit.
    #[error("MCP server terminated abnormally: {0}")]
    Terminated(String),
}

/// Serve the Cedar MCP server over stdio until the client disconnects.
///
/// stdio is the transport MCP clients launch a server process with, and the
/// JSON-RPC stream owns **stdout**. Callers must therefore keep their logging
/// on stderr — anything else written to stdout corrupts the protocol.
///
/// # Errors
///
/// Returns [`ServeError`] if the initialization handshake fails or the server
/// task ends abnormally. A clean client disconnect returns `Ok`.
pub async fn serve_stdio(console: ConsoleClient) -> Result<(), ServeError> {
    let service = CedarMcpServer::new(console)
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|err| ServeError::Initialize(err.to_string()))?;

    service
        .waiting()
        .await
        .map_err(|err| ServeError::Terminated(err.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real harness schema, so these tests fail if the namespace or the
    /// action set ever moves.
    fn harness_schema() -> Schema {
        Schema::from_cedarschema_str(HARNESS_SCHEMA)
            .expect("embedded harness schema should parse")
            .0
    }

    /// A well-formed shell policy with `{}` substituted into the condition.
    fn shell_policy(id: &str, condition: &str) -> String {
        format!(
            "@id(\"{id}\")\n@description(\"d\")\n\
             forbid (principal, action == Sondera::Action::\"ShellCommand\", resource)\n\
             when {{ {condition} }};\n"
        )
    }

    fn codes(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.code.as_str()).collect()
    }

    // ---- Exposure contract -------------------------------------------------

    #[test]
    fn the_server_exposes_exactly_the_declared_tools() {
        let mut exposed: Vec<String> = CedarMcpServer::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        exposed.sort();

        assert_eq!(
            exposed,
            TOOL_NAMES
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "the served tools and the declared exposure contract disagree; adding a tool is a \
             decision to spend caller context on it, so update TOOL_NAMES deliberately"
        );
    }

    #[test]
    fn the_declared_tool_names_are_sorted_and_unique() {
        let mut sorted = TOOL_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        assert_eq!(sorted, TOOL_NAMES);
    }

    /// A client bound to an endpoint with nothing behind it. Nothing is dialed
    /// until a console tool actually runs.
    fn offline_console() -> ConsoleClient {
        ConsoleClient::new("http://127.0.0.1:1").expect("a well-formed endpoint binds")
    }

    #[tokio::test]
    async fn an_unreachable_console_names_the_server_to_start() {
        let server = CedarMcpServer::new(offline_console());

        let error = server
            .list_trajectories(Parameters(ListTrajectoriesArgs::default()))
            .await
            .expect_err("a console read cannot succeed with nothing listening");

        // The remedy has to survive the trip to the caller: a bare "internal
        // error" would leave a fixable condition looking like a server bug.
        assert!(
            error.message.contains("sondera serve"),
            "the failure should name the server to start, got: {}",
            error.message
        );
    }

    // ---- The scratchpad reports what it actually proved ---------------------

    /// A `Prompt` context that conforms to the harness schema, so the request
    /// itself is never what fails in these tests.
    const PROMPT_CONTEXT: &str = r#"{
        "workspace": {"cwd": "/tmp"},
        "signature": {"matches": 1, "categories": ["prompt_injection"], "severity": 4},
        "label": {"__entity": {"type": "Sondera::Label", "id": "Public"}}
    }"#;

    /// A server with the harness schema and `policies` loaded.
    async fn scratchpad(policies: &str) -> CedarMcpServer {
        let server = CedarMcpServer::new(offline_console());
        server
            .load_schema(Parameters(SchemaArg {
                schema: HARNESS_SCHEMA.to_string(),
            }))
            .await
            .expect("the embedded harness schema loads");
        server
            .load_policies(Parameters(PoliciesArg {
                policies: policies.to_string(),
            }))
            .await
            .expect("test policies parse");
        server
    }

    async fn prompt_decision(server: &CedarMcpServer) -> serde_json::Value {
        let raw = server
            .is_authorized(Parameters(IsAuthorizedArgs {
                principal: r#"Sondera::Agent::"claude""#.to_string(),
                action: "Prompt".to_string(),
                resource: r#"Sondera::Message::"m1""#.to_string(),
                context_json: Some(PROMPT_CONTEXT.to_string()),
            }))
            .await
            .expect("the query runs");
        serde_json::from_str(&raw).expect("the result is JSON")
    }

    /// Cedar names policies positionally (`policy0`), which says nothing about
    /// which rule fired. The `@id` is the identity the author wrote.
    #[tokio::test]
    async fn a_decision_names_the_policy_by_its_at_id() {
        let server = scratchpad(
            r#"@id("default-permit")
               @description("d")
               permit (principal, action, resource);
               @id("forbid-critical-prompt")
               @description("d")
               forbid (principal, action == Sondera::Action::"Prompt", resource)
               when { context.signature.severity >= 4 };"#,
        )
        .await;

        let result = prompt_decision(&server).await;

        assert_eq!(result["decision"], "DENY");
        assert_eq!(result["reasons"][0]["id"], "forbid-critical-prompt");
        assert_eq!(result["reasons"][0]["policy_id"], "policy1");
        assert!(
            result["warnings"].is_null(),
            "a clean decision carries no warnings, got: {result}"
        );
    }

    /// The false pass this fixes: with nothing matching, Cedar's default-deny
    /// is reported as `DENY` and reads exactly like a `forbid` firing.
    #[tokio::test]
    async fn a_default_deny_is_not_left_looking_like_a_forbid_firing() {
        let server = scratchpad(
            r#"@id("forbid-shell")
               @description("d")
               forbid (principal, action == Sondera::Action::"ShellCommand", resource);"#,
        )
        .await;

        let result = prompt_decision(&server).await;

        assert_eq!(result["decision"], "DENY");
        assert_eq!(
            result["reasons"].as_array().map(Vec::len),
            Some(0),
            "no policy matched this request"
        );
        let warnings = result["warnings"].to_string();
        assert!(
            warnings.contains("default-deny"),
            "the DENY should be attributed to Cedar's default, got: {warnings}"
        );
    }

    /// A policy reading an attribute of an absent entity errors and contributes
    /// nothing — the rule is untested, not passing.
    #[tokio::test]
    async fn an_erroring_policy_is_named_and_warned_about() {
        let server = scratchpad(
            r#"@id("default-permit")
               @description("d")
               permit (principal, action, resource);
               @id("forbid-message-content")
               @description("d")
               forbid (principal, action == Sondera::Action::"Prompt", resource)
               when { resource.content like "*secret*" };"#,
        )
        .await;

        let result = prompt_decision(&server).await;

        assert_eq!(result["errors"][0]["id"], "forbid-message-content");
        let warnings = result["warnings"].to_string();
        assert!(
            warnings.contains("errored"),
            "an erroring policy should be called out, got: {warnings}"
        );
    }

    /// The same policy, once its resource exists with the attributes the schema
    /// requires. Without attribute support on `add_entity` this case was
    /// unreachable: `Message` cannot be added without `content` and `role`.
    #[tokio::test]
    async fn an_entity_with_required_attributes_can_be_added_and_matched() {
        let server = scratchpad(
            r#"@id("default-permit")
               @description("d")
               permit (principal, action, resource);
               @id("forbid-message-content")
               @description("d")
               forbid (principal, action == Sondera::Action::"Prompt", resource)
               when { resource.content like "*secret*" };"#,
        )
        .await;

        server
            .add_entity(Parameters(AddEntityArgs {
                entity_type: "Sondera::Message".to_string(),
                entity_id: "m1".to_string(),
                parents: None,
                attributes: Some(
                    r#"{"content": "the secret is out",
                        "role": {"__entity": {"type": "Sondera::Role", "id": "user"}}}"#
                        .to_string(),
                ),
            }))
            .await
            .expect("a Message with its required attributes conforms to the schema");

        let result = prompt_decision(&server).await;

        assert_eq!(result["decision"], "DENY");
        assert_eq!(result["reasons"][0]["id"], "forbid-message-content");
        assert_eq!(
            result["errors"].as_array().map(Vec::len),
            Some(0),
            "the attribute read now resolves, got: {result}"
        );
    }

    /// Parents now travel through the entity JSON parser rather than
    /// `Entity::new_no_attrs`, and the label lattice is the reason they exist:
    /// drop them and every `in` test silently reports no match.
    #[tokio::test]
    async fn parents_still_build_the_label_hierarchy() {
        let server = scratchpad(
            r#"@id("default-permit")
               @description("d")
               permit (principal, action, resource);
               @id("forbid-confidential-or-less")
               @description("d")
               forbid (principal, action == Sondera::Action::"Prompt", resource)
               when { context.label in Sondera::Label::"Confidential" };"#,
        )
        .await;

        // Each level is a child of the next more sensitive one, matching
        // `crates/policy/cedar/src/lib.rs`.
        for (id, parent) in [
            ("HighlyConfidential", None),
            (
                "Confidential",
                Some(r#"Sondera::Label::"HighlyConfidential""#),
            ),
            ("Internal", Some(r#"Sondera::Label::"Confidential""#)),
            ("Public", Some(r#"Sondera::Label::"Internal""#)),
        ] {
            server
                .add_entity(Parameters(AddEntityArgs {
                    entity_type: "Sondera::Label".to_string(),
                    entity_id: id.to_string(),
                    parents: parent.map(|p| vec![p.to_string()]),
                    attributes: None,
                }))
                .await
                .expect("a Label has no attributes to supply");
        }

        // PROMPT_CONTEXT carries `Public`, which is *below* Confidential and so
        // `in` it — the direction that trips authors up.
        let result = prompt_decision(&server).await;

        assert_eq!(result["decision"], "DENY");
        assert_eq!(result["reasons"][0]["id"], "forbid-confidential-or-less");
    }

    /// `add_entity` was infallible before it started parsing attributes. The
    /// no-schema path is the one with no conformance check to lean on.
    #[tokio::test]
    async fn an_entity_can_be_added_before_any_schema_is_loaded() {
        let server = CedarMcpServer::new(offline_console());

        let result = server
            .add_entity(Parameters(AddEntityArgs {
                entity_type: "Agent".to_string(),
                entity_id: "claude".to_string(),
                parents: None,
                attributes: Some(r#"{"provider": "claude"}"#.to_string()),
            }))
            .await
            .expect("an entity can be staged before the schema arrives");

        assert!(result.contains(r#"Agent::\"claude\""#), "got: {result}");
    }

    /// Attributes the schema does not declare are rejected here rather than
    /// surfacing later as an evaluation error.
    #[tokio::test]
    async fn attributes_are_checked_against_the_schema() {
        let server = scratchpad("").await;

        let error = server
            .add_entity(Parameters(AddEntityArgs {
                entity_type: "Sondera::Message".to_string(),
                entity_id: "m1".to_string(),
                parents: None,
                attributes: Some(r#"{"content": "hi"}"#.to_string()),
            }))
            .await
            .expect_err("`role` is required and missing");

        assert!(
            error.message.contains("role"),
            "the failure should name the missing attribute, got: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn cedar_authoring_works_without_a_console() {
        // The regression this whole client exists for: policy authoring never
        // needed the trajectory store, so it must not need a reachable console
        // either. Opening the store directly used to couple the two.
        let server = CedarMcpServer::new(offline_console());

        let result = server
            .validate_policy(Parameters(ValidatePolicyArgs {
                policy: shell_policy("p1", "true"),
                schema: None,
            }))
            .await
            .expect("Cedar validation does not read the console");

        assert!(result.contains("\"valid\": true"), "got: {result}");
    }

    #[test]
    fn every_declared_resource_is_served() {
        for uri in RESOURCE_URIS {
            assert!(
                resource_body(uri).is_some_and(|body| !body.is_empty()),
                "{uri} is declared but serves nothing"
            );
        }
    }

    #[test]
    fn an_undeclared_resource_is_not_served() {
        assert!(resource_body("cedar://harness/nope").is_none());
    }

    // ---- Required annotations ----------------------------------------------

    #[test]
    fn a_policy_without_an_id_is_rejected() {
        let report = validate_candidate(
            "@description(\"d\")\nforbid (principal, action, resource);",
            None,
        );

        assert!(!report.valid);
        assert_eq!(codes(&report.errors), vec![CODE_POLICY_VALIDATION]);
    }

    #[test]
    fn a_policy_without_a_description_is_rejected() {
        let report = validate_candidate("@id(\"x\")\nforbid (principal, action, resource);", None);

        assert!(!report.valid);
        assert_eq!(codes(&report.errors), vec![CODE_POLICY_VALIDATION]);
    }

    /// An empty annotation parses and carries no rationale; treating it as
    /// present would let a policy satisfy the rule while defeating its point.
    #[test]
    fn an_empty_annotation_does_not_count_as_present() {
        let report = validate_candidate(
            "@id(\"x\")\n@description(\"  \")\nforbid (principal, action, resource);",
            None,
        );

        assert!(!report.valid);
    }

    #[test]
    fn duplicate_ids_within_one_candidate_are_rejected() {
        let candidate = format!(
            "{}{}",
            shell_policy("same-id", "context.command like \"*a*\""),
            shell_policy("same-id", "context.command like \"*b*\"")
        );

        let report = validate_candidate(&candidate, None);

        assert!(!report.valid);
        assert!(
            report.errors.iter().any(|f| f.message.contains("unique")),
            "expected a duplicate-id error, got {:?}",
            report.errors
        );
    }

    #[test]
    fn distinct_ids_within_one_candidate_are_accepted() {
        let candidate = format!(
            "{}{}",
            shell_policy("first", "context.command like \"*a*\""),
            shell_policy("second", "context.command like \"*b*\"")
        );

        assert!(validate_candidate(&candidate, None).valid);
    }

    // ---- Provenance --------------------------------------------------------

    #[test]
    fn a_parse_failure_reports_only_the_stage_that_ran() {
        let report = validate_candidate("this is not cedar", None);

        assert_eq!(
            report.provenance.checks_run,
            ["cedar-parse-and-annotations"]
        );
    }

    #[test]
    fn a_full_run_reports_every_stage() {
        let report = validate_candidate(&shell_policy("x", "context.command like \"*a*\""), None);

        assert_eq!(report.provenance.checks_run.len(), 3, "{report:?}");
        assert!(report.provenance.checks_run.last().unwrap() == "semantic-lints");
    }

    #[test]
    fn the_schema_source_is_recorded_in_provenance() {
        let candidate = shell_policy("x", "context.command like \"*a*\"");

        let implied = validate_candidate(&candidate, None);
        let explicit = validate_candidate(&candidate, Some(HARNESS_SCHEMA));

        assert!(implied.provenance.checks_run[1].contains("embedded"));
        assert!(explicit.provenance.checks_run[1].contains("caller-supplied"));
    }

    // ---- Schema validation --------------------------------------------------

    /// Without the fallback, omitting the schema meant every context field
    /// reference went unchecked and the report still said `valid`.
    #[test]
    fn an_undeclared_context_field_is_caught_without_a_supplied_schema() {
        let report = validate_candidate(&shell_policy("x", "context.no_such_field == \"a\""), None);

        assert!(!report.valid);
        assert_eq!(codes(&report.errors), vec![CODE_SCHEMA_VALIDATION]);
    }

    /// The mistake the namespace resolution elsewhere in this server exists
    /// for, caught at authoring time rather than at adjudication time.
    #[test]
    fn an_unqualified_action_is_caught() {
        let report = validate_candidate(
            "@id(\"x\")\n@description(\"d\")\n\
             forbid (principal, action == Action::\"ShellCommand\", resource);",
            None,
        );

        assert!(!report.valid);
    }

    // ---- Verify-only --------------------------------------------------------

    #[test]
    fn the_candidate_is_echoed_byte_for_byte() {
        let candidate = "@id(\"x\")   @description(\"d\")\n\n\nforbid (principal,action,resource);";

        assert_eq!(validate_candidate(candidate, None).candidate, candidate);
    }

    #[test]
    fn an_invalid_candidate_is_echoed_too() {
        let candidate = "not cedar";

        assert_eq!(validate_candidate(candidate, None).candidate, candidate);
    }

    // ---- Lints reach the report ---------------------------------------------

    #[test]
    fn a_lint_error_invalidates_the_candidate() {
        let report = validate_candidate(
            &shell_policy("x", "context.parse.programs.contains(\"/bin/rm\")"),
            None,
        );

        assert!(!report.valid);
        assert_eq!(
            codes(&report.errors),
            vec![lint::CODE_SHELL_NORMALIZED_LITERAL]
        );
    }

    #[test]
    fn an_unknown_context_vocabulary_value_invalidates_the_candidate() {
        let report = validate_candidate(
            &shell_policy(
                "x",
                "context.signature.categories.contains(\"prompt_injecton\")",
            ),
            None,
        );

        assert!(!report.valid);
        assert_eq!(
            codes(&report.errors),
            vec![lint::CODE_UNKNOWN_CONTEXT_VALUE]
        );
        assert!(report.errors[0].message.contains("`prompt_injection`"));
    }

    #[test]
    fn a_lint_warning_does_not_invalidate_the_candidate() {
        let report = validate_candidate(
            "@id(\"x\")\n@description(\"d\")\n\
             forbid (principal, action == Sondera::Action::\"WebFetch\", resource)\n\
             when { context.url like \"*evil.com*\" };",
            None,
        );

        assert!(report.valid);
        assert_eq!(codes(&report.warnings), vec![lint::CODE_RAW_URL_GLOB]);
    }

    // ---- The prompt ---------------------------------------------------------

    /// The schema used to be inlined into every invocation. It is a resource;
    /// the prompt points at it.
    #[test]
    fn the_prompt_does_not_inline_the_schema() {
        let prompt = autoformalize_prompt("block rm -rf");

        assert!(
            prompt.len() < 2_000,
            "the prompt is {} bytes; it should carry entry points, not doctrine",
            prompt.len()
        );
        assert!(!prompt.contains("type ShellParseContext"));
    }

    #[test]
    fn the_prompt_carries_the_intent_and_points_at_the_guide() {
        let prompt = autoformalize_prompt("block rm -rf");

        assert!(prompt.contains("block rm -rf"));
        assert!(prompt.contains(AUTHORING_GUIDE_URI));
    }

    // ---- The label lattice the guide documents ------------------------------

    /// The label entities exactly as the harness builds them: each label is a
    /// child of the next more sensitive one.
    fn label_entities() -> Entities {
        let label = |id: &str| {
            EntityUid::from_type_name_and_id(
                "Sondera::Label".parse().expect("label type parses"),
                EntityId::new(id),
            )
        };
        let entity = |id: &str, parent: Option<EntityUid>| {
            Entity::new_no_attrs(label(id), parent.into_iter().collect())
        };

        Entities::empty()
            .add_entities(
                [
                    entity("HighlyConfidential", None),
                    entity("Confidential", Some(label("HighlyConfidential"))),
                    entity("Internal", Some(label("Confidential"))),
                    entity("Public", Some(label("Internal"))),
                ],
                None,
            )
            .expect("the label lattice should build")
    }

    /// Evaluate `<subject> in Sondera::Label::"<ancestor>"` the way a policy
    /// condition would.
    fn label_is_in(subject: &str, ancestor: &str) -> bool {
        let policies: PolicySet = format!(
            "@id(\"t\")@description(\"d\")
             permit (principal, action, resource)
             when {{ resource.label in Sondera::Label::\"{ancestor}\" }};"
        )
        .parse()
        .expect("test policy parses");

        let resource_type: EntityTypeName = "Sondera::Trajectory".parse().unwrap();
        let resource_uid = EntityUid::from_type_name_and_id(resource_type, EntityId::new("t1"));
        let resource = Entity::new(
            resource_uid.clone(),
            [(
                "label".to_string(),
                cedar_policy::RestrictedExpression::new_entity_uid(
                    format!("Sondera::Label::\"{subject}\"")
                        .parse::<EntityUid>()
                        .unwrap(),
                ),
            )]
            .into_iter()
            .collect(),
            HashSet::new(),
        )
        .expect("resource entity builds");

        let entities = label_entities()
            .add_entities([resource], None)
            .expect("entities merge");

        let request = Request::new(
            resolve_entity_uid(r#"Agent::"a""#, Some(&harness_schema()), "Principal").unwrap(),
            resolve_action_uid("ShellCommand", Some(&harness_schema())).unwrap(),
            resource_uid,
            CedarContext::empty(),
            None,
        )
        .expect("request builds");

        Authorizer::new()
            .is_authorized(&request, &policies, &entities)
            .decision()
            == cedar_policy::Decision::Allow
    }

    /// The authoring guide tells authors that `in` reads *down* the lattice.
    /// Getting this backwards inverts an exfiltration gate — it would fire on
    /// public data and pass highly confidential data — so the claim is pinned
    /// to the engine's actual hierarchy rather than left to prose.
    #[test]
    fn label_in_matches_that_level_or_less_sensitive() {
        assert!(label_is_in("Public", "Confidential"));
        assert!(label_is_in("Internal", "Confidential"));
        assert!(label_is_in("Confidential", "Confidential"));
    }

    #[test]
    fn label_in_does_not_match_more_sensitive_levels() {
        assert!(!label_is_in("HighlyConfidential", "Confidential"));
        assert!(!label_is_in("Confidential", "Internal"));
    }

    /// The corollary that makes `in` useless as a sensitivity gate: everything
    /// is at or below the top of the lattice.
    #[test]
    fn every_label_is_in_the_most_sensitive_one() {
        for label in ["Public", "Internal", "Confidential", "HighlyConfidential"] {
            assert!(label_is_in(label, "HighlyConfidential"));
        }
    }

    #[test]
    fn bare_action_name_resolves_into_the_schema_namespace() {
        let uid = resolve_action_uid("ShellCommand", Some(&harness_schema())).unwrap();

        assert_eq!(uid.to_string(), r#"Sondera::Action::"ShellCommand""#);
    }

    #[test]
    fn unqualified_action_uid_resolves_into_the_schema_namespace() {
        let uid = resolve_action_uid(r#"Action::"ShellCommand""#, Some(&harness_schema())).unwrap();

        assert_eq!(uid.to_string(), r#"Sondera::Action::"ShellCommand""#);
    }

    #[test]
    fn qualified_action_uid_is_used_as_written() {
        let uid =
            resolve_action_uid(r#"Sondera::Action::"WebFetch""#, Some(&harness_schema())).unwrap();

        assert_eq!(uid.to_string(), r#"Sondera::Action::"WebFetch""#);
    }

    #[test]
    fn undeclared_action_is_rejected_rather_than_silently_evaluated() {
        let error = resolve_action_uid("NoSuchAction", Some(&harness_schema())).unwrap_err();

        assert!(
            error.message.contains("not declared"),
            "expected a not-declared error, got: {}",
            error.message
        );
    }

    #[test]
    fn undeclared_action_error_lists_the_declared_actions() {
        let error = resolve_action_uid("NoSuchAction", Some(&harness_schema())).unwrap_err();

        assert!(
            error.message.contains("ShellCommand"),
            "error should list candidates, got: {}",
            error.message
        );
    }

    #[test]
    fn empty_action_is_rejected() {
        let error = resolve_action_uid("   ", Some(&harness_schema())).unwrap_err();

        assert!(
            error.message.contains("must not be empty"),
            "got: {}",
            error.message
        );
    }

    #[test]
    fn action_without_a_schema_falls_back_to_the_empty_namespace() {
        let uid = resolve_action_uid("ShellCommand", None).unwrap();

        assert_eq!(uid.to_string(), r#"Action::"ShellCommand""#);
    }

    #[test]
    fn bare_principal_type_resolves_into_the_schema_namespace() {
        let uid =
            resolve_entity_uid(r#"Agent::"claude""#, Some(&harness_schema()), "Principal").unwrap();

        assert_eq!(uid.to_string(), r#"Sondera::Agent::"claude""#);
    }

    #[test]
    fn qualified_principal_is_used_as_written() {
        let uid = resolve_entity_uid(
            r#"Sondera::Agent::"claude""#,
            Some(&harness_schema()),
            "Principal",
        )
        .unwrap();

        assert_eq!(uid.to_string(), r#"Sondera::Agent::"claude""#);
    }

    #[test]
    fn undeclared_entity_type_is_rejected() {
        let error =
            resolve_entity_uid(r#"Wombat::"w1""#, Some(&harness_schema()), "Resource").unwrap_err();

        assert!(
            error.message.contains("not declared"),
            "got: {}",
            error.message
        );
    }

    #[test]
    fn malformed_entity_uid_is_reported_as_bad_input() {
        let error =
            resolve_entity_uid("not a uid", Some(&harness_schema()), "Principal").unwrap_err();

        assert!(
            error.message.contains("Invalid Principal UID"),
            "got: {}",
            error.message
        );
    }

    /// The regression this resolution exists for: before it, a bare action name
    /// was wrapped as `Action::"ShellCommand"`, which no `Sondera::`-namespaced
    /// forbid could match — so a policy that denies reported ALLOW.
    #[test]
    fn a_namespaced_forbid_denies_when_the_action_is_named_bare() {
        let schema = harness_schema();
        let policies: PolicySet = r#"
            @id("forbid-all-shell")
            forbid (principal, action == Sondera::Action::"ShellCommand", resource);
            @id("default-permit")
            permit (principal, action, resource);
        "#
        .parse()
        .expect("test policies should parse");

        let request = Request::new(
            resolve_entity_uid(r#"Agent::"claude""#, Some(&schema), "Principal").unwrap(),
            resolve_action_uid("ShellCommand", Some(&schema)).unwrap(),
            resolve_entity_uid(r#"Trajectory::"t1""#, Some(&schema), "Resource").unwrap(),
            CedarContext::empty(),
            None,
        )
        .expect("request should build");

        let decision = Authorizer::new()
            .is_authorized(&request, &policies, &Entities::empty())
            .decision();

        assert_eq!(decision, cedar_policy::Decision::Deny);
    }
}
