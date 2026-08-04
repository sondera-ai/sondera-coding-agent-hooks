//! How a wire decode is rejected.
//!
//! Both conversion modules ([`crate::event`] and [`crate::trajectory`]) depend
//! on this one, so the marker below has a single home rather than living in
//! whichever module happened to need it first.
//!
//! Every rejection raised while decoding an inbound `Event` envelope is
//! prefixed with [`UNNORMALIZED_EVENT_MARKER`]. That prefix is a wire-level
//! error code, not prose, so an operator reading a log can tell a malformed
//! envelope from a transport fault. Hooks no longer match on it: they classify
//! the wrapping `InvalidArgument` status structurally, so the marker is a
//! diagnostic aid rather than load-bearing behavior.
//!
//! The one decode that deliberately does *not* carry the marker is
//! `TryFrom<&pb::Event> for Adjudicated` in [`crate::event`], which extracts an
//! adjudication from a *response* the harness sent us. That is a different
//! failure — our own client could not read the server's reply — and it is
//! classified separately.

use sondera_types::ValidationError;

/// Wire-level error code prefixed to every trajectory-event decode rejection,
/// so a malformed envelope is identifiable in a log without parsing prose.
pub const UNNORMALIZED_EVENT_MARKER: &str = "E_UNNORMALIZED_TRAJECTORY_EVENT";

/// Reject a decode, tagged with [`UNNORMALIZED_EVENT_MARKER`].
pub(crate) fn decode_error(reason: impl std::fmt::Display) -> ValidationError {
    ValidationError::message(format!("{UNNORMALIZED_EVENT_MARKER}: {reason}"))
}

/// Reject a decode because a `REQUIRED` field was not sent.
pub(crate) fn missing(field: &str) -> ValidationError {
    decode_error(format!("missing required field '{field}'."))
}

/// Unwrap a `REQUIRED` submessage, naming it when the producer omitted it.
pub(crate) fn require<'a, T>(value: Option<&'a T>, field: &str) -> Result<&'a T, ValidationError> {
    value.ok_or_else(|| missing(field))
}

/// Reject a decode because an enum field is `UNSPECIFIED`, or carries a value
/// this build does not recognize.
///
/// `field` is the wire field being decoded, not the enum's type name: one enum
/// serves several fields (`SignalSeverity` is both `Signal.severity` and
/// `TranscriptScanResult.aggregate_severity`), and the rejection has to name
/// the one that actually failed.
pub(crate) fn unrecognized_enum(field: &str) -> ValidationError {
    decode_error(format!(
        "field '{field}' is unset or carries an unrecognized enum value."
    ))
}
