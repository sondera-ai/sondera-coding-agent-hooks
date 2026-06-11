//! Live stream hub: the typed envelope and the global firehose.
//!
//! Every new trajectory event and adjudication is published ONCE onto a
//! single bounded `tokio::sync::broadcast` channel (a global firehose;
//! clients filter by `trajectory_id`). The wire envelope is:
//!
//! ```json
//! {"type": "event" | "adjudication" | "lagged", "trajectory_id": "...", "data": {...}}
//! ```
//!
//! where `data` is the [`dto::EventDto`] / [`dto::AdjudicationDto`] verbatim
//! — so the raw-never-crosses guarantee holds automatically and stream
//! items render with the same client code as REST responses. The `lagged`
//! variant carries `missed` instead of `trajectory_id`/`data` (slow-client
//! notice).
//!
//! Classification: each `Control::Adjudicated` record is emitted exactly
//! once, as `type:"adjudication"` — never double-emitted as `type:"event"`.
//! Timeline deltas therefore come from BOTH message types.
//!
//! Subscription semantics: `broadcast::Sender::subscribe` delivers only
//! messages sent after the call — new connections get new events only;
//! history comes from REST. REST = state, WS = deltas.
//!
//! Two feed sources publish into the hub, decided once at startup: the
//! [`tail`] notify JSONL watcher (primary) or the [`poll`] Turso id-cursor
//! loop (fallback when the watcher cannot start). Both initialize at the
//! current high-water mark (EOF offsets / `MAX(id)`) so history never
//! replays, and neither touches the adjudication hot path.

pub mod poll;
pub mod tail;

use crate::dto;
use axum::extract::ws::Utf8Bytes;
use serde::Serialize;
use sondera_harness::Event;
use tokio::sync::broadcast;

/// Bounded ring capacity for the global firehose. Memory stays bounded by
/// this regardless of slow receivers; overruns surface to lagging clients
/// as a `lagged` notice.
pub const BROADCAST_CAPACITY: usize = 256;

/// The wire envelope. Envelope keys are snake_case (`type`,
/// `trajectory_id`, `data`, `missed`); the `data` payloads keep their
/// camelCase DTO serialization.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StreamMessage {
    /// Any non-Adjudicated trajectory event, projected through
    /// [`dto::EventDto`] (raw dropped by construction).
    Event {
        trajectory_id: String,
        data: dto::EventDto,
    },
    /// A `Control::Adjudicated` record, projected through
    /// [`dto::AdjudicationDto`] — emitted once, never also as `event`.
    Adjudication {
        trajectory_id: String,
        data: dto::AdjudicationDto,
    },
    /// Slow-client overrun notice: `missed` messages were skipped; the
    /// stream continues from the repositioned cursor.
    Lagged { missed: u64 },
}

/// Classify `event`, serialize the envelope ONCE, and broadcast it.
///
/// `Control::Adjudicated` events project via [`dto::AdjudicationDto::project`]
/// into a single `adjudication` envelope; everything else projects via
/// [`dto::EventDto`] into an `event` envelope.
///
/// Send errors are ignored: `broadcast::Sender::send` errs only when zero
/// subscribers exist right now — normal between client sessions; future
/// sends succeed.
pub fn publish(tx: &broadcast::Sender<Utf8Bytes>, event: &Event) {
    let message = match dto::AdjudicationDto::project(event) {
        Some(data) => StreamMessage::Adjudication {
            trajectory_id: event.trajectory_id.clone(),
            data,
        },
        None => StreamMessage::Event {
            trajectory_id: event.trajectory_id.clone(),
            data: dto::EventDto::from(event),
        },
    };
    match serde_json::to_string(&message) {
        Ok(json) => {
            // Err means zero subscribers — normal, never fatal.
            let _ = tx.send(Utf8Bytes::from(json));
        }
        Err(err) => {
            tracing::warn!(%err, "failed to serialize stream envelope; message dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_harness::{
        Action, Actor, Adjudicated, Agent, Control, ShellCommand, TrajectoryEvent,
    };

    fn test_agent() -> Agent {
        Agent {
            id: "test-agent".to_string(),
            provider_id: "test-provider".to_string(),
        }
    }

    fn action_event(traj: &str) -> Event {
        Event::new(
            test_agent(),
            traj,
            TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("cat /etc/hosts"))),
        )
        .with_raw(serde_json::json!({
            "agent_native": "SENTINEL-raw-must-not-cross",
        }))
    }

    fn adjudicated_event(traj: &str) -> Event {
        Event::new(
            test_agent(),
            traj,
            TrajectoryEvent::Control(Control::Adjudicated(
                Adjudicated::deny().with_reason("multi-hop forbid"),
            )),
        )
        .with_actor(Actor::policy("cedar"))
        .with_raw(serde_json::json!({
            "response": { "decision": "Deny", "reason": [], "errors": [] },
            "agent_secret_payload": "SENTINEL-raw-must-not-cross",
        }))
    }

    /// Literal wire shape: `type` is exactly "event" / "adjudication" /
    /// "lagged"; siblings are `trajectory_id` + `data` (or `missed` for
    /// lagged); `data` keeps the camelCase DTO keys.
    #[test]
    fn envelope_wire_shape() {
        let event = action_event("traj-wire");
        let msg = StreamMessage::Event {
            trajectory_id: event.trajectory_id.clone(),
            data: dto::EventDto::from(&event),
        };
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(value["type"], "event");
        assert_eq!(value["trajectory_id"], "traj-wire");
        let data = value["data"].as_object().expect("data is an object");
        assert!(data.contains_key("eventId"), "DTO keys stay camelCase");
        assert!(data.contains_key("trajectoryId"));

        let adj_event = adjudicated_event("traj-wire-adj");
        let msg = StreamMessage::Adjudication {
            trajectory_id: adj_event.trajectory_id.clone(),
            data: dto::AdjudicationDto::project(&adj_event).expect("Adjudicated projects"),
        };
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(value["type"], "adjudication");
        assert_eq!(value["trajectory_id"], "traj-wire-adj");
        let data = value["data"].as_object().expect("data is an object");
        assert!(data.contains_key("actorId"), "DTO keys stay camelCase");
        assert_eq!(data["decision"], "Deny");

        let msg = StreamMessage::Lagged { missed: 42 };
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(value["type"], "lagged");
        assert_eq!(value["missed"], 42);
        let obj = value.as_object().unwrap();
        assert!(!obj.contains_key("trajectory_id"));
        assert!(!obj.contains_key("data"));
    }

    /// An Adjudicated record produces ONE `adjudication` envelope, never an
    /// additional `event` envelope; everything else is an `event` envelope;
    /// raw never crosses either way.
    #[test]
    fn publish_classifies_adjudicated_once() {
        let (tx, mut rx) = broadcast::channel::<Utf8Bytes>(16);

        publish(&tx, &adjudicated_event("traj-classify"));
        let payload = rx.try_recv().expect("one envelope published");
        let value: serde_json::Value = serde_json::from_str(payload.as_str()).unwrap();
        assert_eq!(value["type"], "adjudication");
        assert_eq!(value["trajectory_id"], "traj-classify");
        assert!(
            rx.try_recv().is_err(),
            "Adjudicated must never double-emit as an event envelope (Open Q1)"
        );

        publish(&tx, &action_event("traj-classify"));
        let payload = rx.try_recv().expect("one envelope published");
        let value: serde_json::Value = serde_json::from_str(payload.as_str()).unwrap();
        assert_eq!(value["type"], "event");
        assert!(
            !payload.as_str().contains("SENTINEL-raw-must-not-cross"),
            "Event.raw must never reach a stream envelope (D-44 via D-68)"
        );
        assert!(rx.try_recv().is_err());
    }

    /// Pins the exact `tokio::sync::broadcast` Lagged behavior the WS
    /// forward loop relies on — a capacity-2 ring with 5 sends gives the
    /// un-consuming receiver `Err(Lagged(3))` (3 skipped), then recv
    /// continues from the repositioned cursor at the oldest RETAINED value
    /// (the 4th sent). Memory is bounded by the ring; the receiver is never
    /// disconnected by lag.
    #[tokio::test]
    async fn broadcast_lagged_pin() {
        let (tx, mut rx) = broadcast::channel::<u32>(2);
        for value in 1..=5u32 {
            tx.send(value).unwrap();
        }
        match rx.recv().await {
            Err(broadcast::error::RecvError::Lagged(missed)) => {
                assert_eq!(missed, 3, "values 1-3 fell off the capacity-2 ring");
            }
            other => panic!("expected Lagged(3), got {other:?}"),
        }
        assert_eq!(
            rx.recv().await.unwrap(),
            4,
            "post-lag recv resumes at the oldest retained value"
        );
        assert_eq!(rx.recv().await.unwrap(), 5);
    }

    /// Send with zero receivers is normal between sessions — publish must
    /// not panic or error.
    #[test]
    fn publish_ignores_zero_subscribers() {
        let (tx, _) = broadcast::channel::<Utf8Bytes>(16);
        // The default receiver is dropped immediately — zero subscribers.
        publish(&tx, &action_event("traj-nobody"));
        publish(&tx, &adjudicated_event("traj-nobody"));
        // Reaching here without panic is the assertion; a later subscriber
        // still works.
        let mut rx = tx.subscribe();
        publish(&tx, &action_event("traj-late"));
        assert!(rx.try_recv().is_ok(), "sends succeed again once subscribed");
    }
}
