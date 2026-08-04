//! Event / adjudication envelope ↔ proto conversions.
//!
//! The `AdjudicatedEvent` encoder source struct lives in `sondera-types`; the
//! leaf payload conversions live in [`crate::trajectory`], and the shape of a
//! decode rejection in [`crate::decode`]. What remains here is the `Event`
//! envelope and the adjudication response encoding.
//!
//! Conversions are borrowed in both directions — `From<&Event> for pb::Event`,
//! `TryFrom<&pb::Event> for Event` — matching the leaf conversions, so the
//! crate presents one surface rather than an owned overload at the envelope
//! only.

use crate::decode::{decode_error, require};
use crate::harness_v1 as pb;
use crate::wire::{datetime_to_timestamp, timestamp_to_datetime};
use sondera_types::{Actor, Adjudicated, AdjudicatedEvent, Event, ValidationError};

// ============================================================================
// Event envelope
// ============================================================================

impl From<&Event> for pb::Event {
    fn from(event: &Event) -> Self {
        pb::Event {
            event_id: event.event_id.clone(),
            trajectory_id: event.trajectory_id.clone(),
            agent: Some((&event.agent).into()),
            event_time: Some(datetime_to_timestamp(&event.timestamp)),
            actor: Some((&event.actor).into()),
            causality: Some((&event.causality).into()),
            event: Some((&event.event).into()),
        }
    }
}

impl TryFrom<&pb::Event> for Event {
    type Error = ValidationError;

    fn try_from(value: &pb::Event) -> Result<Self, Self::Error> {
        let event_time = require(value.event_time.as_ref(), "event_time")?;

        Ok(Event {
            event_id: value.event_id.clone(),
            trajectory_id: value.trajectory_id.clone(),
            agent: require(value.agent.as_ref(), "agent")?.into(),
            timestamp: timestamp_to_datetime(event_time).ok_or_else(|| {
                decode_error("field 'event_time' is outside the representable range.")
            })?,
            event: require(value.event.as_ref(), "event")?.try_into()?,
            actor: require(value.actor.as_ref(), "actor")?.try_into()?,
            causality: require(value.causality.as_ref(), "causality")?.into(),
        })
    }
}

// ============================================================================
// Adjudication response encoding
// ============================================================================

impl From<AdjudicatedEvent<'_>> for pb::Event {
    fn from(value: AdjudicatedEvent<'_>) -> Self {
        pb::Event {
            event_id: format!("adj-{}", value.source_event_id),
            trajectory_id: value.source_trajectory_id.to_owned(),
            agent: Some(pb::Agent {
                id: value.source_agent_id.to_owned(),
                ..Default::default()
            }),
            event_time: Some(datetime_to_timestamp(&chrono::Utc::now())),
            actor: Some((&Actor::policy("policy-engine")).into()),
            causality: Some(pb::Causality {
                correlation_id: value.source_trajectory_id.to_owned(),
                causation_id: Some(value.source_event_id.to_owned()),
                parent_id: None,
            }),
            // Built as proto directly rather than through a domain
            // `TrajectoryEvent::Control(Control::Adjudicated(..))`: the
            // adjudication is already borrowed, and routing it through the
            // domain enum would deep-clone the whole subtree just to hand the
            // borrowing conversion something to borrow.
            event: Some(pb::TrajectoryEvent {
                category: Some(pb::trajectory_event::Category::Control(pb::Control {
                    kind: Some(pb::control::Kind::Adjudicated(value.adjudicated.into())),
                })),
            }),
        }
    }
}

impl TryFrom<&pb::Event> for Adjudicated {
    type Error = ValidationError;

    fn try_from(value: &pb::Event) -> Result<Self, Self::Error> {
        let invalid = || {
            ValidationError::message(format!(
                "invalid adjudication DTO: could not decode payload for event '{}'",
                value.event_id
            ))
        };

        let Some(pb::trajectory_event::Category::Control(control)) =
            value.event.as_ref().and_then(|e| e.category.as_ref())
        else {
            return Err(invalid());
        };
        let Some(pb::control::Kind::Adjudicated(adj)) = control.kind.as_ref() else {
            return Err(invalid());
        };

        Adjudicated::try_from(adj).map_err(|e| {
            tracing::warn!(
                event_id = %value.event_id,
                error = %e,
                "Failed to decode Adjudicated from proto payload"
            );
            invalid()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::UNNORMALIZED_EVENT_MARKER;
    use sondera_types::{Agent, Control, Decision, Event, Observation, Thought, TrajectoryEvent};

    fn test_agent() -> Agent {
        Agent {
            id: "test-agent".to_string(),
            provider: "anthropic".to_string(),
            platform: "claude-code".to_string(),
        }
    }

    fn event_with(payload: TrajectoryEvent) -> Event {
        Event::new(test_agent(), "traj-1", payload)
    }

    /// Round-trip an event through the proto encoding and back.
    fn roundtrip(event: &Event) -> Event {
        let proto: pb::Event = event.into();
        Event::try_from(&proto).expect("event roundtrip must succeed")
    }

    #[test]
    fn envelope_roundtrips_intact() {
        let event = event_with(TrajectoryEvent::Observation(Observation::Thought(
            Thought::new("hello"),
        )));

        let decoded = roundtrip(&event);

        assert_eq!(decoded.event_id, event.event_id);
        assert_eq!(decoded.trajectory_id, event.trajectory_id);
        assert_eq!(decoded.agent, event.agent);
        assert_eq!(decoded.actor, event.actor);
        assert_eq!(decoded.causality, event.causality);
        // Timestamps survive to nanosecond precision through prost Timestamp.
        assert_eq!(decoded.timestamp, event.timestamp);
        assert_eq!(decoded.event, event.event);
    }

    // ------------------------------------------------------------------
    // Decode rejections
    // ------------------------------------------------------------------

    #[test]
    fn decode_rejects_a_missing_event_payload() {
        let mut proto: pb::Event = (&event_with(TrajectoryEvent::Observation(
            Observation::Thought(Thought::new("hi")),
        )))
            .into();
        proto.event = None;

        let err = Event::try_from(&proto).expect_err("missing event should be rejected");

        assert!(err.to_string().contains(UNNORMALIZED_EVENT_MARKER));
        assert!(err.to_string().contains("'event'"));
    }

    #[test]
    fn decode_rejects_a_missing_agent() {
        let mut proto: pb::Event = (&event_with(TrajectoryEvent::Observation(
            Observation::Thought(Thought::new("hi")),
        )))
            .into();
        proto.agent = None;

        let err = Event::try_from(&proto).expect_err("missing agent should be rejected");

        assert!(err.to_string().contains(UNNORMALIZED_EVENT_MARKER));
    }

    #[test]
    fn decode_rejects_negative_timestamp_nanos() {
        let mut proto: pb::Event = (&event_with(TrajectoryEvent::Observation(
            Observation::Thought(Thought::new("hi")),
        )))
            .into();
        proto
            .event_time
            .as_mut()
            .expect("timestamp should exist")
            .nanos = -1;

        let err = Event::try_from(&proto).expect_err("invalid timestamp should be rejected");

        assert!(err.to_string().contains(UNNORMALIZED_EVENT_MARKER));
        assert!(err.to_string().contains("event_time"));
    }

    #[test]
    fn decode_rejects_unspecified_enum_rather_than_defaulting() {
        // An UNSPECIFIED discriminant means the producer did not send a value.
        // Decoding must fail rather than invent one — silently defaulting a
        // Decision to Allow would forge an authorization in the audit record.
        let event = event_with(TrajectoryEvent::Control(Control::Adjudicated(
            Adjudicated::deny(),
        )));
        let mut proto: pb::Event = (&event).into();

        if let Some(pb::trajectory_event::Category::Control(c)) =
            proto.event.as_mut().and_then(|e| e.category.as_mut())
            && let Some(pb::control::Kind::Adjudicated(adj)) = c.kind.as_mut()
        {
            adj.decision = pb::Decision::Unspecified as i32;
        }

        let err = Event::try_from(&proto).expect_err("UNSPECIFIED decision must be rejected");

        assert!(err.to_string().contains(UNNORMALIZED_EVENT_MARKER));
        assert!(err.to_string().contains("decision"));
    }

    #[test]
    fn decode_rejects_an_unknown_enum_discriminant() {
        // A newer producer sending a value this build does not know must fail
        // closed rather than silently mapping to some in-range variant.
        let event = event_with(TrajectoryEvent::Control(Control::Adjudicated(
            Adjudicated::allow(),
        )));
        let mut proto: pb::Event = (&event).into();

        if let Some(pb::trajectory_event::Category::Control(c)) =
            proto.event.as_mut().and_then(|e| e.category.as_mut())
            && let Some(pb::control::Kind::Adjudicated(adj)) = c.kind.as_mut()
        {
            adj.decision = 9999;
        }

        let err = Event::try_from(&proto).expect_err("unknown decision must be rejected");

        assert!(err.to_string().contains(UNNORMALIZED_EVENT_MARKER));
    }

    #[test]
    fn decode_rejections_carry_a_stable_wire_level_error_code() {
        // Operators and dashboards pivot on this code, so it is part of the
        // wire contract even though hook classification no longer reads it.
        assert_eq!(UNNORMALIZED_EVENT_MARKER, "E_UNNORMALIZED_TRAJECTORY_EVENT");

        let err = Event::try_from(&pb::Event::default())
            .expect_err("an empty envelope should be rejected");

        // `contains`, not `starts_with`: `ValidationError` Displays as
        // "validation error: {0}", and the hook classifier substring-matches.
        assert!(err.to_string().contains(UNNORMALIZED_EVENT_MARKER));
    }

    // ------------------------------------------------------------------
    // Adjudication response encoding
    // ------------------------------------------------------------------

    #[test]
    fn adjudicated_event_roundtrips_through_the_response_envelope() {
        let adjudicated = Adjudicated::deny().with_reason("nope");
        let proto = pb::Event::from(AdjudicatedEvent {
            adjudicated: &adjudicated,
            source_event_id: "evt-1",
            source_trajectory_id: "traj-1",
            source_agent_id: "agent-1",
        });

        assert_eq!(proto.event_id, "adj-evt-1");
        assert_eq!(proto.trajectory_id, "traj-1");
        assert_eq!(
            Adjudicated::try_from(&proto).expect("adjudication roundtrip must succeed"),
            adjudicated
        );
    }

    #[test]
    fn adjudicated_response_envelope_is_itself_a_decodable_event() {
        // rpc.rs returns these to clients; they must satisfy the same envelope
        // contract as any other event, not just the Adjudicated extractor.
        let adjudicated = Adjudicated::escalate();
        let proto = pb::Event::from(AdjudicatedEvent {
            adjudicated: &adjudicated,
            source_event_id: "evt-1",
            source_trajectory_id: "traj-1",
            source_agent_id: "agent-1",
        });

        let decoded = Event::try_from(&proto).expect("response envelope must decode as an Event");

        assert_eq!(decoded.actor.actor_type, sondera_types::ActorType::Policy);
        assert_eq!(
            decoded.causality.causation_id.as_deref(),
            Some("evt-1"),
            "the response must point back at the event it adjudicated"
        );
        match decoded.event {
            TrajectoryEvent::Control(Control::Adjudicated(adj)) => {
                assert_eq!(adj.decision, Decision::Escalate);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn adjudicated_try_from_rejects_a_non_adjudication_event() {
        let proto: pb::Event = (&event_with(TrajectoryEvent::Observation(Observation::Thought(
            Thought::new("hi"),
        ))))
            .into();

        let err =
            Adjudicated::try_from(&proto).expect_err("a non-adjudication event must be rejected");

        assert!(err.to_string().contains("invalid adjudication DTO"));
    }
}
