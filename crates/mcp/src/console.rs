//! The console read surface, reached over gRPC.
//!
//! `sondera serve` owns the trajectory database. Turso takes an exclusive
//! per-process lock on the file, so a second process that opens it directly
//! cannot start at all while the server is running. This client therefore reads
//! the console the way `sondera tui` does — over
//! `sondera.console.v1.ConsoleService` — and opens no database of its own.
//!
//! # What these tools answer with
//!
//! The console wire messages are *projections*, not the domain types. An event's
//! `agent` arrives as a bare `agents/{id}` name carrying neither provider nor
//! platform, and `TrajectorySummary.score` cannot tell "unscored" from zero.
//! Rebuilding a [`sondera_types::Trajectory`] out of one would have to invent
//! the difference, so nothing here does: each projection is rendered
//! field-for-field as the console reported it.
//!
//! The deep payloads are the exception, and they are exact. `payload`,
//! `adjudication`, `summary`, `digest`, and `scan` are `sondera.harness.v1`
//! messages — the harness's own event model rather than a projection of it — so
//! they decode through the same converters the hook ingest path uses and render
//! through the domain types' serde. Enum fields decode to their domain enum for
//! the same reason: a model reads `"Deny"`, not `2`.

use serde_json::{Value, json};
use sondera_console::sparkline::{SparklineCell, SparklineEventKind, TrajectorySparkline};
use sondera_schema::console_v1 as pb;
use sondera_schema::console_v1::console_service_client::ConsoleServiceClient;
use sondera_schema::harness_v1 as hb;
use sondera_schema::names::trajectory_id_from_name;
use sondera_schema::wire::format_timestamp;
use sondera_types::{
    Adjudicated, AgentStatus, Decision, EventScanResult, TrajectoryEvent, TranscriptDigest,
    TranscriptScanResult, ValidationError,
};
use tonic::transport::Channel;

/// The console endpoint `sondera serve` binds by default.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:50051";

/// Why a console read could not be answered.
#[derive(Debug, thiserror::Error)]
pub enum ConsoleError {
    /// The configured endpoint is not a URI tonic can dial.
    #[error("invalid console endpoint '{endpoint}': {reason}")]
    Endpoint { endpoint: String, reason: String },

    /// Nothing is listening — nearly always a `sondera serve` that is not
    /// running.
    #[error("could not reach the console at {endpoint} — is `sondera serve` running? ({reason})")]
    Unavailable { endpoint: String, reason: String },

    /// The console refused the call.
    #[error("console returned {code:?}: {message}")]
    Rpc { code: tonic::Code, message: String },

    /// The console answered with a payload this build cannot read.
    #[error("could not decode the console's response: {0}")]
    Decode(#[from] ValidationError),

    /// A field the response contract marks `REQUIRED` was absent.
    #[error("the console omitted the required field '{0}'")]
    Missing(&'static str),
}

/// A client for the console's unary read surface.
///
/// Cheap to clone — tonic channels are reference-counted and multiplex over one
/// HTTP/2 connection.
#[derive(Clone)]
pub struct ConsoleClient {
    inner: ConsoleServiceClient<Channel>,
    endpoint: String,
}

impl ConsoleClient {
    /// Bind a client to `endpoint` (`http://host:port`) without dialing it.
    ///
    /// The channel connects lazily, on the first RPC, rather than here. That is
    /// deliberate: the Cedar authoring tools read no console at all and are why
    /// most clients launch this server, so a console that is down must not keep
    /// the process from starting. Unreachability is reported per call, on the
    /// tools that actually need it.
    ///
    /// # Errors
    ///
    /// Returns [`ConsoleError::Endpoint`] if `endpoint` is not a dialable URI.
    /// A well-formed endpoint with nothing behind it is not an error here.
    pub fn new(endpoint: &str) -> Result<Self, ConsoleError> {
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|error| ConsoleError::Endpoint {
                endpoint: endpoint.to_string(),
                reason: error.to_string(),
            })?
            .connect_lazy();
        Ok(Self {
            inner: ConsoleServiceClient::new(channel),
            endpoint: endpoint.to_string(),
        })
    }

    /// An owned handle for one call. The generated methods take `&mut self`,
    /// and cloning the channel is a refcount bump — the whole client is not
    /// cloned, so the endpoint string is not copied per RPC.
    fn client(&self) -> ConsoleServiceClient<Channel> {
        self.inner.clone()
    }

    /// Classify a transport failure, naming the endpoint when nothing answered.
    fn failed(&self, status: tonic::Status) -> ConsoleError {
        if status.code() == tonic::Code::Unavailable {
            return ConsoleError::Unavailable {
                endpoint: self.endpoint.clone(),
                reason: status.message().to_string(),
            };
        }
        ConsoleError::Rpc {
            code: status.code(),
            message: status.message().to_string(),
        }
    }

    /// List agent rollups. `filter` and `order_by` are the console's AIP clause
    /// grammar, passed through untouched — an unrecognized key is the console's
    /// `INVALID_ARGUMENT` to report, not something to silently drop here.
    pub async fn list_agents(
        &self,
        page_size: i32,
        page_token: &str,
        filter: &str,
        order_by: &str,
    ) -> Result<Value, ConsoleError> {
        let response = self
            .client()
            .list_agents(pb::ListAgentsRequest {
                page_size,
                page_token: page_token.to_string(),
                filter: filter.to_string(),
                order_by: order_by.to_string(),
            })
            .await
            .map_err(|status| self.failed(status))?
            .into_inner();
        Ok(json!({
            "agents": response.agents.iter().map(agent_summary).collect::<Vec<_>>(),
            "next_page_token": response.next_page_token,
            "total_size": response.total_size,
        }))
    }

    /// Get one agent rollup by its `agents/{agent}` resource name.
    pub async fn get_agent(&self, name: &str) -> Result<Value, ConsoleError> {
        let agent = self
            .client()
            .get_agent(pb::GetAgentRequest {
                name: name.to_string(),
            })
            .await
            .map_err(|status| self.failed(status))?
            .into_inner();
        // The wrapper adds only the resource name, which the summary already
        // carries, so the summary alone is the answer.
        let summary = agent.summary.ok_or(ConsoleError::Missing("summary"))?;
        Ok(agent_summary(&summary))
    }

    /// Re-read one agent's computed projection. No field is console-writable,
    /// so this sends identity only and persists nothing.
    pub async fn update_agent(&self, name: &str) -> Result<Value, ConsoleError> {
        let summary = self
            .client()
            .update_agent(pb::UpdateAgentRequest {
                agent: Some(pb::AgentSummary {
                    name: name.to_string(),
                    ..pb::AgentSummary::default()
                }),
                update_mask: None,
            })
            .await
            .map_err(|status| self.failed(status))?
            .into_inner();
        Ok(agent_summary(&summary))
    }

    /// Aggregate status counts over the filtered agent set.
    pub async fn analyze_agents(&self, filter: &str) -> Result<Value, ConsoleError> {
        let stats = self
            .client()
            .analyze_agents(pb::AnalyzeAgentsRequest {
                filter: filter.to_string(),
            })
            .await
            .map_err(|status| self.failed(status))?
            .into_inner();
        Ok(json!({
            "total": stats.total,
            "healthy": stats.healthy,
            "degraded": stats.degraded,
            "offline": stats.offline,
        }))
    }

    /// Delete one agent and its trajectory events.
    pub async fn delete_agent(&self, name: &str) -> Result<(), ConsoleError> {
        self.client()
            .delete_agent(pb::DeleteAgentRequest {
                name: name.to_string(),
            })
            .await
            .map_err(|status| self.failed(status))?;
        Ok(())
    }

    /// Get one run's summary by its `trajectories/{trajectory}` resource name.
    pub async fn get_trajectory(&self, name: &str) -> Result<Value, ConsoleError> {
        let summary = self
            .client()
            .get_trajectory(pb::GetTrajectoryRequest {
                name: name.to_string(),
            })
            .await
            .map_err(|status| self.failed(status))?
            .into_inner();
        trajectory_summary(&summary)
    }

    /// Page one run's folded events.
    pub async fn list_trajectory_events(
        &self,
        trajectory: &str,
        page_size: i32,
        page_token: &str,
    ) -> Result<Value, ConsoleError> {
        let response = self
            .client()
            .list_trajectory_events(pb::ListTrajectoryEventsRequest {
                trajectory: trajectory.to_string(),
                page_size,
                page_token: page_token.to_string(),
            })
            .await
            .map_err(|status| self.failed(status))?
            .into_inner();
        let details = response
            .details
            .iter()
            .map(event_detail)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({
            "details": details,
            "next_page_token": response.next_page_token,
            "total_size": response.total_size,
        }))
    }

    /// List run summaries. `filter` and `order_by` pass through as on
    /// [`Self::list_agents`].
    pub async fn list_trajectories(
        &self,
        page_size: i32,
        page_token: &str,
        filter: &str,
        order_by: &str,
    ) -> Result<Value, ConsoleError> {
        let response = self
            .client()
            .list_trajectories(pb::ListTrajectoriesRequest {
                page_size,
                page_token: page_token.to_string(),
                filter: filter.to_string(),
                order_by: order_by.to_string(),
            })
            .await
            .map_err(|status| self.failed(status))?
            .into_inner();
        let trajectories = response
            .trajectories
            .iter()
            .map(trajectory_summary)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({
            "trajectories": trajectories,
            "next_page_token": response.next_page_token,
            "total_size": response.total_size,
        }))
    }
}

// ---------------------------------------------------------------------------
// Enum decoding
//
// Each of these maps a wire enum onto the domain enum that owns its serde
// spelling, so the JSON a model reads matches the vocabulary used everywhere
// else in the workspace.
// ---------------------------------------------------------------------------

/// Decode a verdict. `UNSPECIFIED` — nothing was adjudicated — is `None`, and
/// so is a value this build does not recognize: an absent verdict must never
/// read as allow.
fn decision(value: i32) -> Option<Decision> {
    match hb::Decision::try_from(value) {
        Ok(hb::Decision::Allow) => Some(Decision::Allow),
        Ok(hb::Decision::Deny) => Some(Decision::Deny),
        Ok(hb::Decision::Escalate) => Some(Decision::Escalate),
        Ok(hb::Decision::Unspecified) | Err(_) => None,
    }
}

fn agent_status(value: i32) -> AgentStatus {
    match pb::AgentStatus::try_from(value) {
        Ok(pb::AgentStatus::Healthy) => AgentStatus::Healthy,
        Ok(pb::AgentStatus::Degraded) => AgentStatus::Degraded,
        Ok(pb::AgentStatus::Offline) => AgentStatus::Offline,
        Ok(pb::AgentStatus::Unspecified) | Err(_) => AgentStatus::Unspecified,
    }
}

/// Name the category in the *domain* event's vocabulary, not the wire enum's.
///
/// The rendered event nests its decoded payload, which tags itself with the
/// same discriminant through `TrajectoryEvent`'s serde. Two adjacent fields
/// named `category`, one inside the other, always describing the same variant,
/// must not disagree on spelling — so these follow the payload rather than
/// lower-casing the proto constant.
fn event_category(value: i32) -> &'static str {
    match pb::TrajectoryEventCategory::try_from(value) {
        Ok(pb::TrajectoryEventCategory::Action) => "Action",
        Ok(pb::TrajectoryEventCategory::Observation) => "Observation",
        Ok(pb::TrajectoryEventCategory::Control) => "Control",
        Ok(pb::TrajectoryEventCategory::State) => "State",
        Ok(pb::TrajectoryEventCategory::Unspecified) | Err(_) => "Unspecified",
    }
}

fn sparkline_kind(value: i32) -> SparklineEventKind {
    match pb::SparklineEventKind::try_from(value) {
        Ok(pb::SparklineEventKind::PromptUser) => SparklineEventKind::PromptUser,
        Ok(pb::SparklineEventKind::PromptModel) => SparklineEventKind::PromptModel,
        Ok(pb::SparklineEventKind::Thought) => SparklineEventKind::Thought,
        Ok(pb::SparklineEventKind::Tool) => SparklineEventKind::Tool,
        Ok(pb::SparklineEventKind::Shell) => SparklineEventKind::Shell,
        Ok(pb::SparklineEventKind::Web) => SparklineEventKind::Web,
        Ok(pb::SparklineEventKind::File) => SparklineEventKind::File,
        Ok(pb::SparklineEventKind::Control) => SparklineEventKind::Control,
        Ok(pb::SparklineEventKind::State) => SparklineEventKind::State,
        Ok(pb::SparklineEventKind::Unspecified) | Err(_) => SparklineEventKind::Unspecified,
    }
}

// ---------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------

/// An empty proto string means "unset" for every optional identifier on this
/// surface, and `null` says that far more clearly than `""` to a model.
fn optional(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

/// Render an agent rollup exactly as the console projected it.
fn agent_summary(wire: &pb::AgentSummary) -> Value {
    json!({
        "name": wire.name,
        "display_name": wire.display_name,
        "provider": wire.provider,
        "platform": wire.platform,
        "status": agent_status(wire.status),
        "health_score": wire.health_score,
        "last_seen": wire.last_seen.as_ref().map(format_timestamp),
        "runs_today": wire.runs_today,
        "deny_rate": wire.deny_rate,
        "sparkline": wire.sparkline.as_ref().map(sparkline),
    })
}

/// Rebuild the activity strip.
///
/// Unlike the summaries around it this one is an exact round trip — every field
/// of the console's own composite survives the wire — so it is rendered through
/// the composite's serde rather than hand-built.
fn sparkline(wire: &pb::TrajectorySparkline) -> TrajectorySparkline {
    TrajectorySparkline {
        // The strip identifies its run by bare id; the wire carries the
        // resource name. A name the console minted always parses, so a
        // malformed one degrades to the raw string rather than failing the read.
        trajectory_id: trajectory_id_from_name(&wire.trajectory)
            .map_or_else(|_| wire.trajectory.clone(), ToString::to_string),
        cells: wire
            .cells
            .iter()
            .map(|cell| SparklineCell {
                kind: sparkline_kind(cell.kind),
                duration_ms: cell.duration_ms,
                policy_hit: optional(&cell.policy_hit).map(ToString::to_string),
                decision: decision(cell.decision),
            })
            .collect(),
        decision: decision(wire.decision),
        truncated: wire.truncated,
    }
}

/// Render a run summary.
///
/// `score` is reported as the console reported it. The wire field is a bare
/// `double`, so an unscored run and a run that scored zero are the same bits by
/// the time they arrive here; this does not guess which one it received.
fn trajectory_summary(wire: &pb::TrajectorySummary) -> Result<Value, ConsoleError> {
    let scan = wire.scan.as_ref().map(transcript_scan).transpose()?;
    Ok(json!({
        "name": wire.name,
        "agent": wire.agent,
        "started_at": wire.started_at.as_ref().map(format_timestamp),
        "duration_ms": wire.duration_ms,
        "decision": decision(wire.decision),
        "event_count": wire.event_count,
        "policy_hits": wire.policy_hits,
        "score": wire.score,
        "summary": wire.summary,
        "status": wire.status,
        "update_time": wire.update_time.as_ref().map(format_timestamp),
        "digest": wire.digest.as_ref().map(TranscriptDigest::from),
        "scan": scan,
    }))
}

/// Decode a transcript-level scan and its triggering event id.
fn transcript_scan(wire: &hb::TranscriptScan) -> Result<Value, ConsoleError> {
    let result = wire
        .result
        .as_ref()
        .ok_or(ConsoleError::Missing("scan.result"))?;
    Ok(json!({
        "source_event_id": wire.source_event_id,
        "result": TranscriptScanResult::try_from(result)?,
    }))
}

/// Render one folded event: the console's envelope, plus the harness payloads
/// decoded in full.
fn event_detail(wire: &pb::TrajectoryEventDetail) -> Result<Value, ConsoleError> {
    let event = wire
        .event
        .as_ref()
        .ok_or(ConsoleError::Missing("detail.event"))?;
    let adjudication = wire
        .adjudication
        .as_ref()
        .map(Adjudicated::try_from)
        .transpose()?;
    let summary = wire
        .summary
        .as_ref()
        .map(EventScanResult::try_from)
        .transpose()?;
    Ok(json!({
        "event": trajectory_event(event)?,
        "adjudication": adjudication,
        "summary": summary,
    }))
}

fn trajectory_event(wire: &pb::TrajectoryEvent) -> Result<Value, ConsoleError> {
    let payload = wire
        .payload
        .as_ref()
        .ok_or(ConsoleError::Missing("event.payload"))?;
    Ok(json!({
        "name": wire.name,
        "trajectory": wire.trajectory,
        "event_id": wire.event_id,
        "agent": wire.agent,
        "timestamp": wire.timestamp.as_ref().map(format_timestamp),
        "category": event_category(wire.category),
        "actor": wire.actor,
        "correlation_id": wire.correlation_id,
        "causation_id": optional(&wire.causation_id),
        "parent_id": optional(&wire.parent_id),
        "payload": TrajectoryEvent::try_from(payload)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use sondera_types::{Actor, Agent, Causality, Control, Event, Observation, Thought};

    /// Encode a domain event exactly as the console does, so these tests decode
    /// the bytes the real server sends rather than a hand-built approximation.
    fn wire_event(payload: TrajectoryEvent) -> pb::TrajectoryEvent {
        pb::TrajectoryEvent::from(&Event {
            event_id: "e1".to_string(),
            trajectory_id: "run-1".to_string(),
            agent: Agent::new("a1", "anthropic", "claude-code"),
            timestamp: Utc.timestamp_millis_opt(0).unwrap(),
            event: payload,
            actor: Actor::agent("a1"),
            causality: Causality::default(),
        })
    }

    fn thought() -> TrajectoryEvent {
        TrajectoryEvent::Observation(Observation::Thought(Thought::new("hm")))
    }

    // ---- Enum decoding -----------------------------------------------------

    #[test]
    fn an_unadjudicated_verdict_never_reads_as_allow() {
        // The same invariant the encoder is held to in `sondera_schema`:
        // "nothing was checked" and "everything was permitted" are different
        // audit claims, and neither absence nor a value from a newer producer
        // may collapse onto the permissive one.
        assert_eq!(decision(hb::Decision::Unspecified as i32), None);
        assert_eq!(decision(9_999), None);
        assert_eq!(decision(hb::Decision::Deny as i32), Some(Decision::Deny));
        assert_eq!(
            decision(hb::Decision::Escalate as i32),
            Some(Decision::Escalate)
        );
    }

    #[test]
    fn an_unrecognized_agent_status_does_not_read_as_healthy() {
        assert_eq!(agent_status(9_999), AgentStatus::Unspecified);
        assert_eq!(
            agent_status(pb::AgentStatus::Degraded as i32),
            AgentStatus::Degraded
        );
    }

    // ---- Events ------------------------------------------------------------

    #[test]
    fn the_envelope_category_agrees_with_the_payload_it_describes() {
        // Both fields are named `category` and one is nested inside the other,
        // so a spelling mismatch reads as two different claims about one event.
        for payload in [
            thought(),
            TrajectoryEvent::Control(Control::Adjudicated(sondera_types::Adjudicated::allow())),
        ] {
            let rendered = trajectory_event(&wire_event(payload)).expect("decodes");
            assert_eq!(
                rendered["category"], rendered["payload"]["category"],
                "envelope and payload disagree: {rendered}"
            );
        }
    }

    #[test]
    fn an_event_carries_its_decoded_payload_rather_than_the_envelope_alone() {
        let rendered = trajectory_event(&wire_event(thought())).expect("decodes");

        assert_eq!(rendered["event_id"], "e1");
        assert_eq!(rendered["trajectory"], "trajectories/run-1");
        assert_eq!(rendered["agent"], "agents/a1");
        assert_eq!(rendered["payload"]["category"], "Observation");
        assert_eq!(rendered["payload"]["payload"]["type"], "Thought");
        assert_eq!(rendered["payload"]["payload"]["data"]["thought"], "hm");
    }

    #[test]
    fn absent_causality_renders_as_null_while_a_correlation_id_always_survives() {
        // `causation_id` and `parent_id` are optional in the domain and encode
        // as empty strings; `correlation_id` is not optional, so an empty one is
        // a real (if unusual) value rather than an absence to erase.
        let rendered = trajectory_event(&wire_event(thought())).expect("decodes");

        assert!(rendered["causation_id"].is_null());
        assert!(rendered["parent_id"].is_null());
        assert!(rendered["correlation_id"].is_string());
    }

    #[test]
    fn a_detail_missing_its_event_names_the_field_rather_than_rendering_a_hole() {
        let error = event_detail(&pb::TrajectoryEventDetail::default())
            .expect_err("a detail with no event cannot be rendered");

        assert!(matches!(error, ConsoleError::Missing("detail.event")));
    }

    #[test]
    fn an_event_missing_its_payload_is_rejected() {
        let mut wire = wire_event(thought());
        wire.payload = None;

        assert!(matches!(
            trajectory_event(&wire).expect_err("an envelope alone is not an event"),
            ConsoleError::Missing("event.payload")
        ));
    }

    #[test]
    fn a_folded_adjudication_decodes_onto_its_event() {
        let detail = pb::TrajectoryEventDetail {
            event: Some(wire_event(thought())),
            adjudication: Some(hb::Adjudicated::from(&sondera_types::Adjudicated::deny())),
            summary: None,
        };

        let rendered = event_detail(&detail).expect("decodes");
        assert_eq!(rendered["adjudication"]["decision"], "Deny");
        assert!(rendered["summary"].is_null());
    }

    // ---- Trajectories ------------------------------------------------------

    #[test]
    fn a_run_summary_renders_absence_as_null_rather_than_a_placeholder() {
        let rendered = trajectory_summary(&pb::TrajectorySummary {
            name: "trajectories/run-1".to_string(),
            agent: "agents/a1".to_string(),
            status: "running".to_string(),
            ..pb::TrajectorySummary::default()
        })
        .expect("decodes");

        assert_eq!(rendered["name"], "trajectories/run-1");
        assert_eq!(rendered["status"], "running");
        // Unadjudicated, unscanned, not yet started: each absent for a different
        // reason, none of them zero or false.
        assert!(rendered["decision"].is_null());
        assert!(rendered["digest"].is_null());
        assert!(rendered["scan"].is_null());
        assert!(rendered["started_at"].is_null());
    }

    #[test]
    fn a_scan_without_its_result_is_rejected() {
        let summary = pb::TrajectorySummary {
            scan: Some(hb::TranscriptScan {
                source_event_id: "e1".to_string(),
                result: None,
            }),
            ..pb::TrajectorySummary::default()
        };

        assert!(matches!(
            trajectory_summary(&summary).expect_err("a scan is nothing without its result"),
            ConsoleError::Missing("scan.result")
        ));
    }

    // ---- Sparklines --------------------------------------------------------

    #[test]
    fn a_cell_without_a_policy_fire_carries_neither_hit_nor_verdict() {
        let strip = sparkline(&pb::TrajectorySparkline {
            trajectory: "trajectories/run-1".to_string(),
            cells: vec![pb::SparklineCell {
                kind: pb::SparklineEventKind::Shell as i32,
                duration_ms: 12,
                policy_hit: String::new(),
                decision: hb::Decision::Unspecified as i32,
            }],
            decision: hb::Decision::Unspecified as i32,
            truncated: false,
        });

        assert_eq!(strip.trajectory_id, "run-1");
        assert_eq!(strip.cells[0].kind, SparklineEventKind::Shell);
        assert_eq!(strip.cells[0].policy_hit, None);
        assert_eq!(strip.cells[0].decision, None);
        assert_eq!(strip.decision, None);
    }

    #[test]
    fn a_strip_naming_a_run_it_cannot_parse_keeps_the_raw_identifier() {
        // Degrading beats failing the whole read: the strip is decoration, and
        // an unparsable name is still more informative than a dropped agent row.
        let strip = sparkline(&pb::TrajectorySparkline {
            trajectory: "not-a-resource-name".to_string(),
            ..pb::TrajectorySparkline::default()
        });

        assert_eq!(strip.trajectory_id, "not-a-resource-name");
    }
}
