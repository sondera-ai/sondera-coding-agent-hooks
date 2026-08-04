//! Shared DTO wire-format helpers.
//!
//! Pure `prost_types` <-> `serde_json` / `chrono` conversions plus the
//! proto-event JSON summary. These were moved out of `sondera-types` so the
//! domain crate stays proto-free.

use crate::harness_v1 as pb;
use prost_types::Timestamp;

pub fn datetime_to_timestamp(dt: &chrono::DateTime<chrono::Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

/// Convert a proto [`Timestamp`] back into a UTC datetime.
///
/// Returns `None` when the timestamp is out of `chrono`'s representable range.
pub fn timestamp_to_datetime(ts: &Timestamp) -> Option<chrono::DateTime<chrono::Utc>> {
    let nanos = u32::try_from(ts.nanos).ok()?;
    chrono::DateTime::from_timestamp(ts.seconds, nanos)
}

/// Format a proto [`Timestamp`] as an RFC 3339 string.
///
/// Returns an empty string if the timestamp cannot be converted.
pub fn format_timestamp(ts: &Timestamp) -> String {
    timestamp_to_datetime(ts)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

/// Render a proto harness event as JSON for display.
///
/// The typed envelope is decoded and rendered through the domain event's own
/// serde representation, so the output carries the payload rather than only the
/// envelope scalars. An envelope that does not decode still renders — as its
/// identifiers plus the rejection — so a malformed event is displayable rather
/// than dropped.
pub fn proto_event_to_json(e: &pb::Event) -> serde_json::Value {
    let rejected = |error: String| {
        serde_json::json!({
            "event_id": e.event_id,
            "trajectory_id": e.trajectory_id,
            "event_time": e.event_time.as_ref().map(format_timestamp),
            "error": error,
        })
    };

    match sondera_types::Event::try_from(e) {
        Ok(event) => serde_json::to_value(event).unwrap_or_else(|err| rejected(err.to_string())),
        Err(err) => rejected(err.to_string()),
    }
}

// ============================================================================
// serde_json <-> google.protobuf.Struct / Value
//
// Used only by the three irreducibly free-form fields in the trajectory model:
// `ToolCall.arguments`, `ToolOutput.output`, and `Snapshot.variables`.
//
// `google.protobuf.Value` stores every number as an IEEE-754 double, so
// integers beyond 2^53 that pass through these fields are rounded and cannot be
// recovered. That limit is inherent to the proto type and is documented on the
// fields in `trajectory.proto`; producers needing exact large integers must
// encode them as strings. Whole numbers within the exactly-representable range
// are re-narrowed to JSON integers on decode so ordinary values (`200`, not
// `200.0`) survive a round trip unchanged.
// ============================================================================

/// Largest magnitude an `f64` represents exactly for consecutive integers.
const MAX_EXACT_INT: i64 = 1 << 53;

pub fn json_value_to_proto_struct(value: &serde_json::Value) -> Option<prost_types::Struct> {
    if let serde_json::Value::Object(map) = value {
        Some(prost_types::Struct {
            fields: map
                .iter()
                .map(|(k, v)| (k.clone(), json_to_proto_value(v)))
                .collect(),
        })
    } else {
        None
    }
}

pub fn json_to_proto_value(value: &serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(*b),
        // serde_json's default number model always yields an `f64` here; keep the
        // digits as a string rather than defaulting to `0.0` if that changes.
        serde_json::Value::Number(n) => match n.as_f64() {
            Some(f) => Kind::NumberValue(f),
            None => Kind::StringValue(n.to_string()),
        },
        serde_json::Value::String(s) => Kind::StringValue(s.clone()),
        serde_json::Value::Array(arr) => Kind::ListValue(prost_types::ListValue {
            values: arr.iter().map(json_to_proto_value).collect(),
        }),
        serde_json::Value::Object(map) => Kind::StructValue(prost_types::Struct {
            fields: map
                .iter()
                .map(|(k, v)| (k.clone(), json_to_proto_value(v)))
                .collect(),
        }),
    };
    prost_types::Value { kind: Some(kind) }
}

pub fn proto_struct_to_json_value(s: &prost_types::Struct) -> serde_json::Value {
    serde_json::Value::Object(
        s.fields
            .iter()
            .map(|(k, v)| (k.clone(), proto_value_to_json(v)))
            .collect(),
    )
}

pub fn proto_value_to_json(value: &prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    match &value.kind {
        Some(Kind::NullValue(_)) | None => serde_json::Value::Null,
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::NumberValue(n)) => {
            // Re-narrow within the range where f64 and integer agree exactly, so
            // `200` does not come back as `200.0`. Anything larger came from a
            // genuine float, or from an integer this type cannot represent.
            let n = *n;
            if n.fract() == 0.0 && n.abs() <= MAX_EXACT_INT as f64 {
                serde_json::Value::Number((n as i64).into())
            } else {
                serde_json::Number::from_f64(n)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            }
        }
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::ListValue(l)) => {
            serde_json::Value::Array(l.values.iter().map(proto_value_to_json).collect())
        }
        Some(Kind::StructValue(s)) => proto_struct_to_json_value(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a JSON value through the proto `Value` encoding.
    fn roundtrip(value: serde_json::Value) -> serde_json::Value {
        proto_value_to_json(&json_to_proto_value(&value))
    }

    #[test]
    fn format_timestamp_rejects_negative_nanos() {
        let ts = Timestamp {
            seconds: 0,
            nanos: -1,
        };

        assert!(timestamp_to_datetime(&ts).is_none());
        assert_eq!(format_timestamp(&ts), "");
    }

    #[test]
    fn roundtrip_preserves_small_integers_as_integers() {
        assert_eq!(roundtrip(serde_json::json!(200)), serde_json::json!(200));
    }

    #[test]
    fn roundtrip_preserves_fractional_numbers() {
        assert_eq!(roundtrip(serde_json::json!(1.5)), serde_json::json!(1.5));
    }

    #[test]
    fn roundtrip_preserves_nested_containers() {
        let payload = serde_json::json!({
            "tool": "fetch",
            "input": { "ids": [1, 2, 3], "page": 2, "flag": true, "none": null },
        });
        assert_eq!(roundtrip(payload.clone()), payload);
    }

    #[test]
    fn integers_beyond_f64_precision_are_lossy_by_construction() {
        // Documents the known limit of `google.protobuf.Value`: it holds every
        // number as a double, so this nanosecond timestamp cannot survive. The
        // field docs in trajectory.proto tell producers to send such values as
        // strings; this test pins the behaviour so the loss is never a surprise.
        let nanos = serde_json::json!(1_700_000_000_123_456_789i64);
        assert_ne!(
            roundtrip(nanos),
            serde_json::json!(1_700_000_000_123_456_789i64)
        );

        let as_string = serde_json::json!("1700000000123456789");
        assert_eq!(roundtrip(as_string.clone()), as_string);
    }
}
