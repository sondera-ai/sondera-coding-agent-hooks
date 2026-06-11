//! Dashboard-owned read-only DTOs — the single projection rulebook.
//!
//! Structural rules, all enforced by construction:
//!
//! - No DTO struct contains an untyped JSON value sourced from `Event.raw`
//!   or the `raw_json` column. If a field cannot be named, it cannot cross
//!   the boundary.
//! - Harness serde types are deserialize-only inputs imported privately —
//!   never re-exported from this crate.
//! - [`AdjudicationDto::project`] is the ONLY raw-touching path in the crate:
//!   it parses `Event.raw` through a private deserialization target that
//!   declares exactly the three known keys (`monitor` / `request` /
//!   `response`); every other raw key is dropped by construction.
//! - All DTOs serialize camelCase (the hook-adapter wire convention), `None`
//!   optionals are absent from the JSON, and [`MonitorDto::taints`]
//!   serializes even when empty.
//! - DTOs carry the full typed event content with no truncation.
//! - The three guardrail signals cross as the field-by-field
//!   [`GuardrailSignalsDto`] projection of `context.signature` /
//!   `context.policy` / `context.label` — scalar, nameable fields that
//!   satisfy the structural rule. This is a narrow extension of the
//!   rulebook, not a general reopening; every other context key (`command`,
//!   `working_dir`, `workspace`, `stdout`, `stderr`, `content`, `url`,
//!   `prompt`, `path`, `result`, ...) stays undeclared in the private
//!   target and is dropped by construction.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sondera_harness::{
    Annotation, Control, Event, Label, MonitorSnapshot, TrajectoryEvent, Verdict,
};
use std::collections::HashMap;

// ============================================================================
// Trajectory summary
// ============================================================================

/// Input struct for the aggregate SELECT shape (GROUP BY `trajectory_id`
/// with per-category and per-decision counts). Mirrors the harness
/// `TrajectoryStats` columns plus computed `deny_count` / `escalate_count`.
#[derive(Debug, Clone)]
pub struct TrajectoryAggregateRow {
    pub trajectory_id: String,
    pub event_count: u64,
    pub first_event_at: Option<DateTime<Utc>>,
    pub last_event_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<i64>,
    pub agent_id: Option<String>,
    pub agent_provider: Option<String>,
    pub action_count: u64,
    pub observation_count: u64,
    pub control_count: u64,
    pub state_count: u64,
    pub deny_count: u64,
    pub escalate_count: u64,
}

/// Per-trajectory summary for list views.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrajectorySummaryDto {
    pub trajectory_id: String,
    pub event_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_event_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_provider: Option<String>,
    pub action_count: u64,
    pub observation_count: u64,
    pub control_count: u64,
    pub state_count: u64,
    pub deny_count: u64,
    pub escalate_count: u64,
}

impl From<TrajectoryAggregateRow> for TrajectorySummaryDto {
    fn from(row: TrajectoryAggregateRow) -> Self {
        Self {
            trajectory_id: row.trajectory_id,
            event_count: row.event_count,
            first_event_at: row.first_event_at,
            last_event_at: row.last_event_at,
            duration_seconds: row.duration_seconds,
            agent_id: row.agent_id,
            agent_provider: row.agent_provider,
            action_count: row.action_count,
            observation_count: row.observation_count,
            control_count: row.control_count,
            state_count: row.state_count,
            deny_count: row.deny_count,
            escalate_count: row.escalate_count,
        }
    }
}

// ============================================================================
// Event
// ============================================================================

/// A single trajectory event with its full typed payload.
///
/// `Event.raw` is never read — it is dropped by construction, not filtered.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventDto {
    pub event_id: String,
    pub trajectory_id: String,
    pub agent_id: String,
    pub agent_provider: String,
    pub timestamp: DateTime<Utc>,
    pub actor_id: String,
    /// Debug rendering of the actor type, matching the stored column.
    pub actor_type: String,
    pub correlation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub causation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Full typed event payload — no truncation. Reusing the harness serde
    /// type here is allowed because it is typed, not raw.
    pub event: TrajectoryEvent,
}

impl From<&Event> for EventDto {
    fn from(event: &Event) -> Self {
        // Event.raw is simply never read here — exclusion by construction.
        Self {
            event_id: event.event_id.clone(),
            trajectory_id: event.trajectory_id.clone(),
            agent_id: event.agent.id.clone(),
            agent_provider: event.agent.provider_id.clone(),
            timestamp: event.timestamp,
            actor_id: event.actor.id.clone(),
            actor_type: format!("{:?}", event.actor.actor_type),
            correlation_id: event.causality.correlation_id.clone(),
            causation_id: event.causality.causation_id.clone(),
            parent_id: event.causality.parent_id.clone(),
            event: event.event.clone(),
        }
    }
}

// ============================================================================
// Adjudication
// ============================================================================

/// One Cedar policy annotation (typed passthrough of the harness shape).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnnotationDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

/// Typed monitor state projected from `raw_json["monitor"]` only.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorDto {
    /// snake_case serde rendering of the monitor `Verdict`.
    pub verdict: String,
    /// FSM state name (`"clean"` / `"armed"` / `"violated"`).
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub armed_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleared_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tripped_event_id: Option<String>,
    pub untrusted_pending: bool,
    /// Serializes even when empty — uniform shape, no absent-field special
    /// cases.
    pub taints: Vec<String>,
    /// snake_case serde rendering of the sensitivity label.
    pub label: String,
}

impl From<MonitorSnapshot> for MonitorDto {
    fn from(snapshot: MonitorSnapshot) -> Self {
        Self {
            verdict: verdict_wire(snapshot.verdict).to_string(),
            state: snapshot.state,
            armed_event_id: snapshot.attributes.armed_event_id,
            cleared_event_id: snapshot.attributes.cleared_event_id,
            tripped_event_id: snapshot.attributes.tripped_event_id,
            untrusted_pending: snapshot.untrusted_pending,
            taints: snapshot.taints,
            label: snapshot.label.serde_name().to_string(),
        }
    }
}

/// The snake_case serde rendering of [`Verdict`] as `&'static str`.
///
/// Mirrors `#[serde(rename_all = "snake_case")]` on the harness enum; a new
/// variant breaks compilation here, which is the desired loud failure.
fn verdict_wire(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Satisfied => "satisfied",
        Verdict::Violated => "violated",
        Verdict::Pending => "pending",
    }
}

/// Cedar request identity triple. The request `context` object is never
/// projected: it cannot be named field by field, so per the structural rule
/// it cannot cross the boundary. Only the named guardrail sub-blocks cross,
/// via [`GuardrailSignalsDto`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CedarRequestDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// Cedar response block as the harness wrote it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CedarResponseDto {
    pub decision: String,
    pub reason_policy_ids: Vec<String>,
    pub errors: Vec<String>,
}

/// YARA-X signature scan result projected from `context.signature`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureSignalDto {
    pub matches: i64,
    pub categories: Vec<String>,
    pub severity: i64,
}

/// Secure-code policy verdict projected from `context.policy`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySignalDto {
    pub compliant: bool,
    pub violations: Vec<String>,
}

/// The three guardrail signals: signature scan, secure-code policy verdict,
/// and the per-event IFC label — projected field by field from
/// `raw_json.request.context` through the single raw-touching gate.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardrailSignalsDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureSignalDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicySignalDto>,
    /// snake_case serde rendering of the per-event IFC label (matches
    /// [`MonitorDto::label`]'s convention).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// An adjudication record: the typed `Adjudicated` payload plus the typed
/// blocks projected from `raw_json` (monitor / cedar request / response).
///
/// `actor_id` is surfaced top-level so callers can discriminate cedar vs
/// monitor records — and the backstop pair (`monitor-backstop-` policy-id
/// prefix AND a `source=monitor` annotation entry) — without re-parsing
/// anything.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdjudicationDto {
    pub event_id: String,
    pub trajectory_id: String,
    pub timestamp: DateTime<Utc>,
    /// `"cedar"` | `"monitor"` — the record discriminator.
    pub actor_id: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub annotations: Vec<AnnotationDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitor: Option<MonitorDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<CedarRequestDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<CedarResponseDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardrails: Option<GuardrailSignalsDto>,
}

impl AdjudicationDto {
    /// Project an Adjudicated control event into its DTO.
    ///
    /// Returns `None` unless the event is `Control::Adjudicated`. This is
    /// the ONLY function in the crate that touches `Event.raw` — and only
    /// for Adjudicated records; raw on every other event is never read.
    pub fn project(event: &Event) -> Option<Self> {
        let TrajectoryEvent::Control(Control::Adjudicated(adjudicated)) = &event.event else {
            return None;
        };

        // The single raw-touching path: deserialize through the private
        // typed target. Parse failures drop the projection blocks loudly
        // (warn), never the record itself.
        let raw = event.raw.as_ref().and_then(|value| {
            match RawAdjudicated::deserialize(value) {
                Ok(parsed) => Some(parsed),
                Err(err) => {
                    tracing::warn!(
                        event_id = %event.event_id,
                        %err,
                        "raw_json on Adjudicated record failed typed parse; dropping projection blocks"
                    );
                    None
                }
            }
        });
        let (monitor, request, response, guardrails) = match raw {
            Some(parsed) => {
                // Extract the guardrail sub-blocks from the request context
                // before mapping the identity triple.
                let mut request = parsed.request;
                let context = request.as_mut().and_then(|r| r.context.take());
                let guardrails = context.and_then(|c| project_guardrails(c, &event.event_id));
                (
                    parsed.monitor.map(MonitorDto::from),
                    request.map(|request| CedarRequestDto {
                        principal: request.principal,
                        action: request.action,
                        resource: request.resource,
                    }),
                    parsed.response.map(|response| CedarResponseDto {
                        decision: response.decision,
                        reason_policy_ids: response.reason,
                        errors: response.errors,
                    }),
                    guardrails,
                )
            }
            None => (None, None, None, None),
        };

        Some(Self {
            event_id: event.event_id.clone(),
            trajectory_id: event.trajectory_id.clone(),
            timestamp: event.timestamp,
            actor_id: event.actor.id.clone(),
            decision: format!("{:?}", adjudicated.decision),
            reason: adjudicated.reason.clone(),
            annotations: adjudicated
                .annotations
                .iter()
                .map(AnnotationDto::from)
                .collect(),
            monitor,
            request,
            response,
            guardrails,
        })
    }
}

impl From<&Annotation> for AnnotationDto {
    fn from(annotation: &Annotation) -> Self {
        Self {
            policy_id: annotation.policy_id.clone(),
            description: annotation.description.clone(),
            annotations: annotation.annotations.clone(),
        }
    }
}

/// Map an already-parsed [`RawContext`] to the wire-facing guardrail
/// signals. Takes the typed context, never `Event.raw` —
/// [`AdjudicationDto::project`] remains the crate's only raw-touching path.
///
/// Returns `None` when all three signals are absent so an empty context
/// (the ToolCall shape) never puts an empty `guardrails` object on the
/// wire.
fn project_guardrails(context: RawContext, event_id: &str) -> Option<GuardrailSignalsDto> {
    let signature = context.signature.map(|signature| SignatureSignalDto {
        matches: signature.matches,
        categories: signature.categories,
        severity: signature.severity,
    });
    let policy = context.policy.map(|policy| PolicySignalDto {
        compliant: policy.compliant,
        violations: policy.violations,
    });
    // The label crosses ONLY as Label::from_str-validated serde_name()
    // output — arbitrary raw strings cannot ride the label field.
    let label = context
        .label
        .and_then(|label_ref| label_ref.entity)
        .and_then(
            |entity| match <Label as std::str::FromStr>::from_str(&entity.id) {
                Ok(label) => Some(label.serde_name().to_string()),
                Err(_) => {
                    tracing::warn!(
                        event_id,
                        label_id = %entity.id,
                        "context label failed typed parse; dropping label signal"
                    );
                    None
                }
            },
        );

    if signature.is_none() && policy.is_none() && label.is_none() {
        return None;
    }
    Some(GuardrailSignalsDto {
        signature,
        policy,
        label,
    })
}

// ============================================================================
// Private raw_json deserialization target (the raw-touching gate)
// ============================================================================

/// Private deserialization target for `Event.raw` on Adjudicated records.
///
/// Declares ONLY the three keys the harness writes (`monitor`, `request`,
/// `response`); any other key in the raw payload is dropped silently by
/// construction — serde never even looks at it.
#[derive(Deserialize)]
struct RawAdjudicated {
    monitor: Option<MonitorSnapshot>,
    request: Option<RawRequest>,
    response: Option<RawResponse>,
}

/// The cedar request block. Of the `context` object, ONLY the three
/// guardrail sub-blocks are declared; everything else in the context is
/// dropped by construction.
#[derive(Deserialize)]
struct RawRequest {
    principal: Option<String>,
    action: Option<String>,
    resource: Option<String>,
    context: Option<RawContext>,
}

/// The cedar request context — the gate side of the guardrail projection.
///
/// Declares ONLY the three guardrail sub-blocks. Every content-bearing
/// context key (`command`, `working_dir`, `workspace`, `stdout`, `stderr`,
/// `content`, `url`, `prompt`, `path`, `result`, `protected_path`,
/// `untrusted_pending`, `exit_code`, `code`, `operation`) stays undeclared
/// — serde drops them by construction. No `serde_json::Value` field exists
/// anywhere in this target (untyped values cannot cross), and
/// `deny_unknown_fields` is deliberately absent (unknown keys are ignored,
/// not errored).
///
/// A typed sub-parse failure (schema drift, e.g. `severity` becoming a
/// string) fails the whole [`RawAdjudicated`] parse and takes the existing
/// warn-and-drop-all-blocks path — schema drift must surface loudly, so do
/// not add leniency here.
#[derive(Deserialize)]
struct RawContext {
    signature: Option<RawSignature>,
    policy: Option<RawPolicy>,
    label: Option<RawLabelRef>,
}

/// `context.signature` as transform.rs writes it on every guarded shape.
#[derive(Deserialize)]
struct RawSignature {
    matches: i64,
    categories: Vec<String>,
    severity: i64,
}

/// `context.policy` as transform.rs writes it.
#[derive(Deserialize)]
struct RawPolicy {
    compliant: bool,
    violations: Vec<String>,
}

/// `context.label` in Cedar's `__entity` escape form
/// (`{"__entity": {"type": "Label", "id": "<variant>"}}`).
#[derive(Deserialize)]
struct RawLabelRef {
    #[serde(rename = "__entity")]
    entity: Option<RawLabelEntity>,
}

/// The entity ref payload; the `type` key is undeclared and dropped.
#[derive(Deserialize)]
struct RawLabelEntity {
    id: String,
}

/// The cedar response block as written by the harness.
#[derive(Deserialize)]
struct RawResponse {
    decision: String,
    #[serde(default)]
    reason: Vec<String>,
    #[serde(default)]
    errors: Vec<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_harness::{
        Action, Actor, Adjudicated, Agent, Annotation, Control, Label, MonitorAttributes,
        ShellCommand, ToolCall, Verdict,
    };

    fn test_agent() -> Agent {
        Agent {
            id: "test-agent".to_string(),
            provider_id: "test-provider".to_string(),
        }
    }

    fn snapshot_fixture() -> MonitorSnapshot {
        MonitorSnapshot {
            verdict: Verdict::Pending,
            state: "armed".to_string(),
            attributes: MonitorAttributes {
                armed_event_id: Some("evt-armed-1".to_string()),
                cleared_event_id: None,
                tripped_event_id: None,
            },
            untrusted_pending: true,
            taints: vec!["untrusted_read".to_string()],
            label: Label::Confidential,
        }
    }

    /// The canonical production ShellCommand context shape with SENTINEL
    /// values on every content-bearing key — reused so the guardrails tests
    /// and the fixture stay in sync.
    fn shell_command_context() -> serde_json::Value {
        serde_json::json!({
            "workspace": "SENTINEL-context-workspace",
            "command": "cat /etc/SENTINEL-context-command",
            "working_dir": "/tmp/SENTINEL-context-wd",
            "protected_path": true,
            "label": {"__entity": {"type": "Label", "id": "Confidential"}},
            "policy": {
                "compliant": false,
                "violations": ["SC2: OS Command Injection"],
            },
            "signature": {
                "matches": 2,
                "categories": ["credential_access"],
                "severity": 3,
            },
        })
    }

    /// Cedar-path Adjudicated event with the given request context inside
    /// the full `{request, response, monitor}` raw sibling structure.
    fn cedar_event_with_context(context: serde_json::Value) -> Event {
        let raw = serde_json::json!({
            "request": {
                "principal": "Agent::\"test-agent\"",
                "action": "Action::\"ShellCommand\"",
                "resource": "Trajectory::\"traj-guardrails\"",
                "context": context,
            },
            "response": {
                "decision": "Deny",
                "reason": [],
                "errors": [],
            },
            "monitor": serde_json::to_value(snapshot_fixture()).unwrap(),
        });
        Event::new(
            test_agent(),
            "traj-guardrails",
            TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::deny())),
        )
        .with_actor(Actor::policy("cedar"))
        .with_raw(raw)
    }

    /// Cedar-path record: monitor + request + response projected, planted
    /// extra raw key provably dropped at the serialization level.
    #[test]
    fn cedar_path_projection() {
        let snap = snapshot_fixture();
        let adj = Adjudicated::deny()
            .with_reason("multi-hop forbid")
            .with_annotation(Annotation::new().with_id("multi-hop-001".to_string()));
        let raw = serde_json::json!({
            "request": {
                "principal": "Agent::\"test-agent\"",
                "action": "Action::\"FileWrite\"",
                "resource": "File::\"/repo/.github/workflows/ci.yml\"",
                "context": shell_command_context(),
            },
            "response": {
                "decision": "Deny",
                "reason": ["multi-hop-001"],
                "errors": [],
            },
            "monitor": serde_json::to_value(&snap).unwrap(),
            "agent_secret_payload": "SENTINEL-raw-must-not-cross",
        });
        let event = Event::new(
            test_agent(),
            "traj-cedar",
            TrajectoryEvent::Control(Control::Adjudicated(adj)),
        )
        .with_actor(Actor::policy("cedar"))
        .with_raw(raw);

        let dto = AdjudicationDto::project(&event).expect("Adjudicated event must project");
        assert_eq!(dto.actor_id, "cedar");
        assert_eq!(dto.decision, "Deny");
        assert_eq!(dto.reason.as_deref(), Some("multi-hop forbid"));
        assert_eq!(
            dto.annotations[0].policy_id.as_deref(),
            Some("multi-hop-001")
        );

        let monitor = dto.monitor.as_ref().expect("monitor block populated");
        // Verdict must match the fixture's snake_case serde rendering — the
        // assertion is pinned to serde itself so the DTO cannot drift.
        let expected_verdict = serde_json::to_value(snap.verdict).unwrap();
        assert_eq!(monitor.verdict, expected_verdict.as_str().unwrap());
        assert_eq!(monitor.state, snap.state);
        assert_eq!(monitor.armed_event_id, snap.attributes.armed_event_id);
        assert_eq!(monitor.cleared_event_id, None);
        assert_eq!(monitor.tripped_event_id, None);
        assert_eq!(monitor.untrusted_pending, snap.untrusted_pending);
        assert_eq!(monitor.taints, snap.taints);
        assert_eq!(monitor.label, snap.label.serde_name());

        let request = dto.request.as_ref().expect("cedar request populated");
        assert_eq!(request.principal.as_deref(), Some("Agent::\"test-agent\""));
        assert_eq!(request.action.as_deref(), Some("Action::\"FileWrite\""));
        let response = dto.response.as_ref().expect("cedar response populated");
        assert_eq!(response.decision, "Deny");
        assert_eq!(response.reason_policy_ids, vec!["multi-hop-001"]);
        assert!(response.errors.is_empty());

        let serialized = serde_json::to_string(&dto).unwrap();
        assert!(
            !serialized.contains("SENTINEL-raw-must-not-cross"),
            "extra raw keys must be dropped by construction (D-44)"
        );
        // The cedar request "context" object is never projected: unnameable
        // fields cannot cross. Only the named guardrail sub-blocks ride
        // GuardrailSignalsDto.
        assert!(!serialized.contains("protected_path"));
        assert!(!serialized.contains("SENTINEL-context-workspace"));
        assert!(!serialized.contains("SENTINEL-context-command"));
        assert!(!serialized.contains("SENTINEL-context-wd"));

        let guardrails = dto.guardrails.as_ref().expect("guardrails projected");
        let signature = guardrails.signature.as_ref().expect("signature signal");
        assert_eq!(signature.matches, 2);
        assert_eq!(signature.categories, vec!["credential_access"]);
        assert_eq!(signature.severity, 3);
        let policy = guardrails.policy.as_ref().expect("policy signal");
        assert!(!policy.compliant);
        assert_eq!(policy.violations, vec!["SC2: OS Command Injection"]);
        assert_eq!(guardrails.label.as_deref(), Some("confidential"));
    }

    /// The production ShellCommand context projects all three guardrail
    /// signals — and ONLY them; every content-bearing sentinel stays behind
    /// the boundary.
    #[test]
    fn guardrails_projected_from_context() {
        let event = cedar_event_with_context(shell_command_context());
        let dto = AdjudicationDto::project(&event).expect("Adjudicated event must project");

        let guardrails = dto.guardrails.as_ref().expect("guardrails projected");
        let signature = guardrails.signature.as_ref().expect("signature signal");
        assert_eq!(signature.matches, 2);
        assert_eq!(signature.categories, vec!["credential_access"]);
        assert_eq!(signature.severity, 3);

        let policy = guardrails.policy.as_ref().expect("policy signal");
        assert!(!policy.compliant);
        assert_eq!(policy.violations, vec!["SC2: OS Command Injection"]);

        // snake_case via Label::serde_name — matches MonitorDto.label.
        assert_eq!(guardrails.label.as_deref(), Some("confidential"));

        let serialized = serde_json::to_string(&dto).unwrap();
        assert!(!serialized.contains("SENTINEL-context-workspace"));
        assert!(!serialized.contains("SENTINEL-context-command"));
        assert!(!serialized.contains("SENTINEL-context-wd"));
        assert!(!serialized.contains("protected_path"));
    }

    /// The ToolCall shape (empty context) projects NO guardrails block —
    /// no empty-object noise on the wire.
    #[test]
    fn guardrails_absent_for_empty_context() {
        let event = cedar_event_with_context(serde_json::json!({}));
        let dto = AdjudicationDto::project(&event).expect("Adjudicated event must project");
        assert!(dto.guardrails.is_none());

        let value = serde_json::to_value(&dto).unwrap();
        assert!(
            value.get("guardrails").is_none(),
            "no guardrails key on an empty context"
        );
    }

    /// The Prompt shape (signature + label, no policy key) projects
    /// signature and label with policy absent inside guardrails.
    #[test]
    fn guardrails_partial_prompt_shape() {
        let event = cedar_event_with_context(serde_json::json!({
            "workspace": "SENTINEL-context-workspace",
            "label": {"__entity": {"type": "Label", "id": "Confidential"}},
            "signature": {
                "matches": 2,
                "categories": ["credential_access"],
                "severity": 3,
            },
        }));
        let dto = AdjudicationDto::project(&event).expect("Adjudicated event must project");

        let guardrails = dto.guardrails.as_ref().expect("guardrails projected");
        assert!(guardrails.signature.is_some());
        assert_eq!(guardrails.label.as_deref(), Some("confidential"));
        assert!(guardrails.policy.is_none());

        let value = serde_json::to_value(&dto).unwrap();
        assert!(
            value["guardrails"].get("policy").is_none(),
            "no policy key inside guardrails for the Prompt shape"
        );
        assert!(!value.to_string().contains("SENTINEL-context-workspace"));
    }

    /// An unparseable label id drops ONLY the label signal (warn logged) —
    /// the signature signal still projects.
    #[test]
    fn guardrails_unparseable_label_drops_label_only() {
        let event = cedar_event_with_context(serde_json::json!({
            "label": {"__entity": {"type": "Label", "id": "NotALabel"}},
            "signature": {
                "matches": 2,
                "categories": ["credential_access"],
                "severity": 3,
            },
        }));
        let dto = AdjudicationDto::project(&event).expect("Adjudicated event must project");

        let guardrails = dto.guardrails.as_ref().expect("guardrails projected");
        assert!(
            guardrails.label.is_none(),
            "arbitrary raw strings cannot ride the label field (T-06-18)"
        );
        assert!(guardrails.signature.is_some(), "signature still projects");
    }

    /// Synthetic Started/Resumed snapshot record (raw = monitor block only):
    /// monitor populated, cedar blocks None, discriminator surfaced.
    #[test]
    fn monitor_actor_projection() {
        let snap = snapshot_fixture();
        let event = Event::new(
            test_agent(),
            "traj-monitor",
            TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
        )
        .with_actor(Actor::policy("monitor"))
        .with_raw(serde_json::json!({
            "monitor": serde_json::to_value(&snap).unwrap(),
        }));

        let dto = AdjudicationDto::project(&event).expect("synthetic snapshot record must project");
        assert_eq!(
            dto.actor_id, "monitor",
            "Phase 6 discriminator surfaced top-level, not buried"
        );
        assert!(dto.monitor.is_some());
        assert!(dto.request.is_none());
        assert!(dto.response.is_none());
        assert!(
            dto.guardrails.is_none(),
            "monitor-actor records (raw = monitor only) carry no guardrails"
        );
        assert_eq!(dto.decision, "Allow");
    }

    /// Non-Adjudicated events never project — their raw is never read.
    #[test]
    fn non_adjudicated_returns_none() {
        let event = Event::new(
            test_agent(),
            "traj-action",
            TrajectoryEvent::Action(Action::ToolCall(ToolCall::new(
                "Read",
                serde_json::json!({ "path": "/tmp/input.txt" }),
            ))),
        )
        .with_raw(serde_json::json!({ "tool_input": "SENTINEL-never-read" }));

        assert!(AdjudicationDto::project(&event).is_none());
    }

    /// EventDto drops raw by construction while carrying the full typed
    /// payload with no truncation.
    #[test]
    fn event_dto_drops_raw() {
        let event = Event::new(
            test_agent(),
            "traj-shell",
            TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("cat /etc/hosts"))),
        )
        .with_raw(serde_json::json!({
            "agent_native": "SENTINEL-raw-must-not-cross",
        }));

        let dto = EventDto::from(&event);
        let serialized = serde_json::to_string(&dto).unwrap();
        assert!(
            !serialized.contains("SENTINEL-raw-must-not-cross"),
            "EventDto serialization must never contain Event.raw content"
        );
        // Full typed payload IS present.
        assert!(serialized.contains("cat /etc/hosts"));
        assert_eq!(dto.trajectory_id, "traj-shell");
        assert_eq!(dto.agent_id, "test-agent");
        assert_eq!(dto.actor_type, "Agent");
    }

    /// Wire shape: camelCase keys, None optionals absent, empty taints
    /// serialized.
    #[test]
    fn summary_wire_shape() {
        let row = TrajectoryAggregateRow {
            trajectory_id: "traj-summary".to_string(),
            event_count: 7,
            first_event_at: Some(chrono::Utc::now()),
            last_event_at: None,
            duration_seconds: None,
            agent_id: Some("test-agent".to_string()),
            agent_provider: None,
            action_count: 2,
            observation_count: 3,
            control_count: 1,
            state_count: 1,
            deny_count: 1,
            escalate_count: 0,
        };
        let dto = TrajectorySummaryDto::from(row);
        let value = serde_json::to_value(&dto).unwrap();
        let obj = value.as_object().unwrap();
        assert!(obj.contains_key("trajectoryId"));
        assert!(obj.contains_key("eventCount"));
        assert!(obj.contains_key("denyCount"));
        assert!(obj.contains_key("escalateCount"));
        assert!(obj.contains_key("firstEventAt"));
        assert!(obj.contains_key("agentId"));
        // None optionals are absent from the JSON (skip_serializing_if).
        assert!(!obj.contains_key("lastEventAt"));
        assert!(!obj.contains_key("durationSeconds"));
        assert!(!obj.contains_key("agentProvider"));

        // taints on MonitorDto serializes even when empty.
        let mut snap = snapshot_fixture();
        snap.taints = Vec::new();
        let monitor_value = serde_json::to_value(MonitorDto::from(snap)).unwrap();
        assert_eq!(
            monitor_value.get("taints"),
            Some(&serde_json::json!([])),
            "empty taints must still serialize"
        );
    }
}
