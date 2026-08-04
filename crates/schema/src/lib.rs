//! Generated protobuf/gRPC wire types for Sondera service APIs, plus the
//! domain ↔ proto conversions.
//!
//! This crate owns the wire DTOs generated from `proto/` and the shared
//! [`wire`] helpers. The conversions themselves are trait impls on those types,
//! so they need no public module of their own; internally they are split by
//! layer across `event` (the `Event` envelope and the adjudication response),
//! `trajectory` (every payload message beneath it), and `decode` (how an
//! inbound envelope is rejected). They depend on `sondera-types` for the domain
//! types; `sondera-types` carries no prost dependency and does not depend on
//! this crate.

pub mod harness {
    pub mod v1 {
        tonic::include_proto!("sondera.harness.v1");
    }
}

pub mod console {
    pub mod v1 {
        tonic::include_proto!("sondera.console.v1");
    }
}

pub use console::v1 as console_v1;
pub use harness::v1 as harness_v1;

mod decode;
mod event;
pub mod names;
mod trajectory;
pub mod wire;

// The console DTO conversions use `#[path]` so the file keeps its domain name
// without colliding with the `console` proto module above.
#[path = "console.rs"]
mod console_dto;

pub use console_dto::decision_to_proto;
pub use decode::UNNORMALIZED_EVENT_MARKER;
pub use wire::proto_event_to_json;
