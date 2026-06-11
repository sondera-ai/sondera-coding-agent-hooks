//! Typed query-filter parsing for `GET /trajectories`.
//!
//! Wire format is flat snake_case query params — `decision`, `label`,
//! `policy_id`, `from`, `to`, `limit`, `before`, `before_id` — with
//! repeated keys for OR within a dimension. Parsing is a manual
//! split-on-`&`-then-`=` pair loop (the `auth.rs` no-deps style; plain
//! `Query<T>` does not collect repeated keys).
//!
//! Percent-decoding is minimal and applied to VALUES only: `%XX` hex
//! sequences are decoded; `'+'` is deliberately NOT treated as a space —
//! clients send Z-suffixed timestamps or `%2B`-encoded offsets, and a
//! plus-to-space mapping would corrupt RFC 3339 `+00:00` cursors.
//!
//! Unrecognized values and unknown keys produce human-readable errors
//! naming the offender (the `config.rs` message style); the route maps
//! them to 400 `ErrorBody`. The `token` key is silently ignored — it is
//! auth's domain, never the filter parser's.

use chrono::{DateTime, Utc};
use serde::Deserialize;

/// The parsed, validated filter set for the list endpoint.
///
/// `decisions` hold the canonical serde wire strings (`Allow`/`Deny`/
/// `Escalate`); `labels` the canonical snake_case label strings. Both are
/// canonicalized case-insensitively on input.
#[derive(Debug, Clone, PartialEq)]
pub struct FilterSet {
    pub decisions: Vec<String>,
    pub labels: Vec<String>,
    pub policy_ids: Vec<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Already clamped to 1..=200; defaults to 50.
    pub limit: u32,
    /// Raw keyset cursor timestamp — the route re-renders it through
    /// chrono so the SQL comparison matches the stored `+00:00` form.
    pub before: Option<String>,
    pub before_id: Option<String>,
}

impl Default for FilterSet {
    fn default() -> Self {
        Self {
            decisions: Vec::new(),
            labels: Vec::new(),
            policy_ids: Vec::new(),
            from: None,
            to: None,
            limit: 50,
            before: None,
            before_id: None,
        }
    }
}

/// The four valid label wire strings (`#[serde(rename_all = "snake_case")]`
/// on the harness `Label`).
const LABELS: [&str; 4] = ["public", "internal", "confidential", "highly_confidential"];

impl FilterSet {
    /// Parse the raw query string into a validated `FilterSet`.
    ///
    /// `Err` carries a human-readable message naming the offending key or
    /// value, which the route maps to a 400 `ErrorBody`.
    pub fn parse(query: Option<&str>) -> Result<FilterSet, String> {
        let mut set = FilterSet::default();
        let mut limit_raw: Option<String> = None;
        let mut from_raw: Option<String> = None;
        let mut to_raw: Option<String> = None;

        let Some(query) = query else {
            return Ok(set);
        };

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(raw_value)?;
            match key {
                "decision" => set.decisions.push(canonical_decision(&value)?),
                "label" => set.labels.push(canonical_label(&value)?),
                "policy_id" => set.policy_ids.push(value),
                "from" => set_scalar(&mut from_raw, "from", value)?,
                "to" => set_scalar(&mut to_raw, "to", value)?,
                "limit" => set_scalar(&mut limit_raw, "limit", value)?,
                "before" => set_scalar(&mut set.before, "before", value)?,
                "before_id" => set_scalar(&mut set.before_id, "before_id", value)?,
                // Auth's domain — never the filter parser's.
                "token" => {}
                other => return Err(format!("unknown query parameter '{other}'")),
            }
        }

        if let Some(raw) = limit_raw {
            let parsed: u32 = raw
                .parse()
                .map_err(|_| format!("invalid limit '{raw}': must be an integer"))?;
            set.limit = parsed.clamp(1, 200);
        }
        set.from = from_raw
            .map(|raw| parse_rfc3339("from", &raw))
            .transpose()?;
        set.to = to_raw.map(|raw| parse_rfc3339("to", &raw)).transpose()?;
        Ok(set)
    }

    /// Whether any payload-fact dimension (decision/label/policy id) is
    /// active — these require the Adjudicated-scan + Rust post-filter phase;
    /// pure time filters use the cheaper DISTINCT-id scan.
    pub fn has_payload_filters(&self) -> bool {
        !self.decisions.is_empty() || !self.labels.is_empty() || !self.policy_ids.is_empty()
    }
}

/// Reject duplicate scalar params (two `limit=`, two `before=`, …).
fn set_scalar(slot: &mut Option<String>, key: &str, value: String) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate query parameter '{key}'"));
    }
    *slot = Some(value);
    Ok(())
}

/// Strict RFC 3339 parse for `from`/`to` (400 on failure, unlike the
/// store's lenient stored-timestamp parse).
fn parse_rfc3339(key: &str, value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| format!("invalid {key} '{value}': must be an RFC 3339 timestamp"))
}

/// Case-insensitive decision canonicalization to the harness serde wire
/// strings.
fn canonical_decision(value: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Ok("Allow".to_string()),
        "deny" => Ok("Deny".to_string()),
        "escalate" => Ok("Escalate".to_string()),
        _ => Err(format!(
            "invalid decision '{value}': expected allow, deny, or escalate"
        )),
    }
}

/// Case-insensitive label canonicalization to the four snake_case wire
/// strings.
fn canonical_label(value: &str) -> Result<String, String> {
    let lowered = value.to_ascii_lowercase();
    if LABELS.contains(&lowered.as_str()) {
        Ok(lowered)
    } else {
        Err(format!(
            "invalid label '{value}': expected public, internal, confidential, \
             or highly_confidential"
        ))
    }
}

/// Minimal percent-decoding: `%XX` hex sequences only. `'+'` is NOT
/// mapped to space (see the module doc).
fn percent_decode(value: &str) -> Result<String, String> {
    if !value.contains('%') {
        return Ok(value.to_string());
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .ok_or_else(|| format!("invalid percent-encoding in '{value}'"))?;
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|_| format!("invalid percent-encoding in '{value}'"))?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("invalid UTF-8 after percent-decoding in '{value}'"))
}

// ============================================================================
// Label matching against raw_json (the post-filter)
// ============================================================================

/// Private raw-monitor deserialize target: declares ONLY the `monitor` key
/// (the same serde type the DTOs use) — every other key in the raw payload
/// is never even looked at, and nothing here is ever serialized outward or
/// logged (the match result is a boolean).
#[derive(Deserialize)]
struct RawMonitorOnly {
    monitor: Option<sondera_harness::MonitorSnapshot>,
}

/// Whether the row's raw monitor block carries any of the requested
/// (canonical snake_case) labels. Unparseable or monitor-less raw payloads
/// simply do not match — never an error, never logged content.
pub(crate) fn raw_label_matches(raw_json: &str, labels: &[String]) -> bool {
    match serde_json::from_str::<RawMonitorOnly>(raw_json) {
        Ok(RawMonitorOnly {
            monitor: Some(snapshot),
        }) => {
            let wire = snapshot.label.serde_name();
            labels.iter().any(|label| label == wire)
        }
        _ => false,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_query_yields_defaults() {
        for query in [None, Some("")] {
            let set = FilterSet::parse(query).unwrap();
            assert_eq!(set.limit, 50);
            assert!(set.decisions.is_empty());
            assert!(set.labels.is_empty());
            assert!(set.policy_ids.is_empty());
            assert!(set.from.is_none());
            assert!(set.to.is_none());
            assert!(set.before.is_none());
            assert!(set.before_id.is_none());
        }
    }

    #[test]
    fn repeated_decision_keys_collect() {
        let set = FilterSet::parse(Some("decision=deny&decision=escalate")).unwrap();
        assert_eq!(set.decisions, vec!["Deny", "Escalate"]);
    }

    #[test]
    fn decision_canonicalizes_case_insensitively() {
        for input in ["DENY", "deny", "Deny"] {
            let set = FilterSet::parse(Some(&format!("decision={input}"))).unwrap();
            assert_eq!(set.decisions, vec!["Deny"], "input '{input}'");
        }
    }

    #[test]
    fn bad_decision_value_errors_naming_the_value() {
        let err = FilterSet::parse(Some("decision=maybe")).unwrap_err();
        assert!(err.contains("maybe"), "error must name the value: {err}");
    }

    #[test]
    fn labels_validate_against_the_four_wire_strings() {
        let set = FilterSet::parse(Some(
            "label=public&label=INTERNAL&label=Confidential&label=highly_confidential",
        ))
        .unwrap();
        assert_eq!(
            set.labels,
            vec!["public", "internal", "confidential", "highly_confidential"],
            "case-insensitive in, canonical snake_case out"
        );

        let err = FilterSet::parse(Some("label=secret")).unwrap_err();
        assert!(err.contains("secret"), "error must name the value: {err}");
    }

    #[test]
    fn from_to_parse_z_and_encoded_offset_forms() {
        // Z-suffixed.
        let set = FilterSet::parse(Some("from=2026-06-01T00:00:00Z")).unwrap();
        let expected = DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(set.from, Some(expected));

        // %2B-encoded +00:00 offset — '+' is NOT treated as a space.
        let set = FilterSet::parse(Some("to=2026-06-01T00:00:00%2B00:00")).unwrap();
        assert_eq!(set.to, Some(expected));

        // A literal '+' survives undecoded (no plus-to-space mapping).
        let set = FilterSet::parse(Some("to=2026-06-01T00:00:00+00:00")).unwrap();
        assert_eq!(set.to, Some(expected));
    }

    #[test]
    fn malformed_timestamp_errors() {
        let err = FilterSet::parse(Some("from=yesterday")).unwrap_err();
        assert!(err.contains("from") && err.contains("yesterday"), "{err}");
    }

    #[test]
    fn limit_parses_and_clamps() {
        assert_eq!(FilterSet::parse(Some("limit=7")).unwrap().limit, 7);
        assert_eq!(FilterSet::parse(Some("limit=999")).unwrap().limit, 200);
        assert_eq!(FilterSet::parse(Some("limit=0")).unwrap().limit, 1);
        let err = FilterSet::parse(Some("limit=abc")).unwrap_err();
        assert!(err.contains("limit"), "{err}");
    }

    #[test]
    fn duplicate_scalars_error() {
        for query in [
            "limit=1&limit=2",
            "before=a&before=b",
            "before_id=a&before_id=b",
            "from=2026-06-01T00:00:00Z&from=2026-06-02T00:00:00Z",
        ] {
            let err = FilterSet::parse(Some(query)).unwrap_err();
            assert!(err.contains("duplicate"), "query '{query}': {err}");
        }
    }

    #[test]
    fn unknown_key_errors_naming_the_key() {
        let err = FilterSet::parse(Some("decison=deny")).unwrap_err();
        assert!(err.contains("decison"), "error must name the key: {err}");
    }

    #[test]
    fn token_key_is_silently_ignored() {
        let set = FilterSet::parse(Some("token=whatever&decision=deny")).unwrap();
        assert_eq!(set.decisions, vec!["Deny"]);
    }

    #[test]
    fn has_payload_filters_tracks_the_three_dimensions() {
        assert!(
            !FilterSet::parse(Some("from=2026-06-01T00:00:00Z"))
                .unwrap()
                .has_payload_filters()
        );
        assert!(
            FilterSet::parse(Some("decision=deny"))
                .unwrap()
                .has_payload_filters()
        );
        assert!(
            FilterSet::parse(Some("label=public"))
                .unwrap()
                .has_payload_filters()
        );
        assert!(
            FilterSet::parse(Some("policy_id=x"))
                .unwrap()
                .has_payload_filters()
        );
    }

    #[test]
    fn raw_label_matching_reads_only_the_monitor_key() {
        let snap = sondera_harness::MonitorSnapshot {
            verdict: sondera_harness::Verdict::Pending,
            state: "armed".to_string(),
            attributes: sondera_harness::MonitorAttributes::default(),
            untrusted_pending: true,
            taints: Vec::new(),
            label: sondera_harness::Label::Confidential,
        };
        let raw = serde_json::json!({
            "monitor": serde_json::to_value(&snap).unwrap(),
            "agent_secret_payload": "SENTINEL-never-read",
        })
        .to_string();
        assert!(raw_label_matches(&raw, &["confidential".to_string()]));
        assert!(!raw_label_matches(&raw, &["public".to_string()]));
        // Monitor-less or malformed raw simply does not match.
        assert!(!raw_label_matches("{}", &["confidential".to_string()]));
        assert!(!raw_label_matches(
            "not json",
            &["confidential".to_string()]
        ));
    }
}
