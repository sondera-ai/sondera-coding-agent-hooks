//! Pure identity/freshness rewrite logic for the seed-replay tool.
//!
//! Implements the per-run uuid remap + timestamp shift that makes re-seeding
//! collision-free. The remap is textual over the whole fixture by design:
//! witness ids inside `raw.monitor` and `Trajectory::"<id>"` resource strings
//! inside `raw.request` must be rewritten consistently with `event_id` /
//! `trajectory_id` / `causality.*`, and field-by-field surgery would miss
//! them. Re-using fixture ids would trip the turso `event_id UNIQUE`
//! constraint on the second run.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sondera_harness::Event;
use std::collections::HashMap;

/// Replace every uuid occurrence in `input` with a fresh v4 uuid,
/// consistently: the same source uuid maps to the same fresh uuid everywhere
/// in the text. Each call generates a new mapping (per-run freshness).
///
/// Detection is windowed: at each byte offset, the 36-char window is accepted
/// iff it parses as a hyphenated uuid. Hyphen positions make partial overlap
/// impossible, so matches are consumed atomically.
pub fn remap_uuids(input: &str) -> String {
    let mut map: HashMap<&str, String> = HashMap::new();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        // 36-byte window at a char boundary that parses as a hyphenated uuid.
        // `try_parse` also accepts the 32-char simple form, so require the
        // hyphenated layout explicitly (window length pins it to one uuid).
        if let Some(window) = input.get(i..i + 36)
            && window.as_bytes()[8] == b'-'
            && uuid::Uuid::try_parse(window).is_ok()
        {
            let fresh = map
                .entry(window)
                .or_insert_with(|| uuid::Uuid::new_v4().to_string());
            out.push_str(fresh);
            i += 36;
            continue;
        }
        // copy one full UTF-8 char
        let ch = input[i..].chars().next().expect("i is a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Parse one [`Event`] per non-empty line, in line order (line order IS
/// causal order for harness-generated fixtures). Fails loudly with the
/// 1-based line number on any malformed line.
pub fn parse_events(jsonl: &str) -> Result<Vec<Event>> {
    jsonl
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(idx, line)| {
            let n = idx + 1;
            serde_json::from_str::<Event>(line).with_context(|| format!("fixture line {n}"))
        })
        .collect()
}

/// Shift all event timestamps by one constant offset so the LAST (maximum)
/// timestamp equals `target_last`. Relative deltas and ordering are
/// preserved.
pub fn shift_to(events: &mut [Event], target_last: DateTime<Utc>) {
    let Some(max_ts) = events.iter().map(|e| e.timestamp).max() else {
        return;
    };
    let offset = target_last - max_ts;
    for event in events {
        event.timestamp += offset;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::collections::HashMap;

    const TRIPPING_FIXTURE: &str = include_str!("../fixtures/tripping.jsonl");

    /// Canonicalize a text by replacing each distinct uuid (in order of
    /// first appearance) with `UUID_<i>`. Two texts that differ only by a
    /// consistent uuid renaming canonicalize identically.
    fn canonicalize_uuids(input: &str) -> String {
        let mut map: HashMap<String, String> = HashMap::new();
        let bytes = input.as_bytes();
        let mut out = String::with_capacity(input.len());
        let mut i = 0;
        while i < bytes.len() {
            if let Some(window) = input.get(i..i + 36) {
                if uuid::Uuid::try_parse(window).is_ok() && window.contains('-') {
                    let next = format!("UUID_{}", map.len());
                    let token = map.entry(window.to_string()).or_insert(next);
                    out.push_str(token);
                    i += 36;
                    continue;
                }
            }
            // copy one full UTF-8 char
            let ch = input[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        out
    }

    fn collect_uuids(input: &str) -> Vec<String> {
        let mut found = Vec::new();
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if let Some(window) = input.get(i..i + 36) {
                if uuid::Uuid::try_parse(window).is_ok() && window.contains('-') {
                    found.push(window.to_string());
                    i += 36;
                    continue;
                }
            }
            i += 1;
        }
        found
    }

    const UUID_A: &str = "11111111-2222-3333-4444-555555555555";
    const UUID_B: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    #[test]
    fn remap_is_consistent_within_one_call() {
        let input = format!("evt-{UUID_A} corr-{UUID_B} again evt-{UUID_A}");
        let output = remap_uuids(&input);

        let uuids = collect_uuids(&output);
        assert_eq!(uuids.len(), 3, "all three uuid occurrences survive");
        assert_eq!(
            uuids[0], uuids[2],
            "same source uuid maps to same fresh uuid"
        );
        assert_ne!(uuids[0], uuids[1], "distinct source uuids stay distinct");
        assert_ne!(uuids[0], UUID_A, "fresh uuid differs from source");
        assert_ne!(uuids[1], UUID_B, "fresh uuid differs from source");
    }

    #[test]
    fn remap_preserves_structure_and_replaces_all_uuids() {
        let output = remap_uuids(TRIPPING_FIXTURE);
        assert_eq!(
            canonicalize_uuids(TRIPPING_FIXTURE),
            canonicalize_uuids(&output),
            "uuid relationship structure must be preserved under the mapping"
        );
        let old: std::collections::HashSet<_> =
            collect_uuids(TRIPPING_FIXTURE).into_iter().collect();
        let new: std::collections::HashSet<_> = collect_uuids(&output).into_iter().collect();
        assert!(
            old.is_disjoint(&new),
            "no source uuid may survive the remap"
        );
        assert_eq!(old.len(), new.len(), "distinct uuids stay distinct");
    }

    #[test]
    fn two_remap_calls_produce_different_outputs() {
        let first = remap_uuids(TRIPPING_FIXTURE);
        let second = remap_uuids(TRIPPING_FIXTURE);
        assert_ne!(first, second, "per-run freshness: each call gets new uuids");
        assert_ne!(first, TRIPPING_FIXTURE);
    }

    #[test]
    fn non_uuid_text_is_untouched() {
        let input = r#"{"id":"call-1","hash":"deadbeefdeadbeefdeadbeefdeadbeefdead","ts":"2026-06-10T20:00:00.123456Z","note":"36-characters-but-not-a-uuid-here!!!"}"#;
        assert_eq!(remap_uuids(input), input, "no uuid means no change");
    }

    #[test]
    fn parse_events_returns_one_event_per_nonempty_line_in_order() {
        let remapped = remap_uuids(TRIPPING_FIXTURE);
        let events = parse_events(&remapped).expect("real fixture must parse");
        let nonempty = TRIPPING_FIXTURE
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        assert_eq!(events.len(), nonempty);

        // line order preserved: re-serialize event_ids and check against text order
        let ids_in_text: Vec<String> = remapped
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["event_id"].as_str().unwrap().to_string()
            })
            .collect();
        let ids_parsed: Vec<String> = events.iter().map(|e| e.event_id.clone()).collect();
        assert_eq!(ids_parsed, ids_in_text);
    }

    #[test]
    fn parse_events_skips_blank_lines() {
        let remapped = remap_uuids(TRIPPING_FIXTURE);
        let with_blanks = format!("\n{}\n\n", remapped.replace('\n', "\n\n"));
        let events = parse_events(&with_blanks).expect("blank lines are skipped");
        let nonempty = TRIPPING_FIXTURE
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        assert_eq!(events.len(), nonempty);
    }

    #[test]
    fn parse_events_fails_loudly_naming_the_line() {
        let bad = "{not json}\n";
        let err = parse_events(bad).expect_err("malformed line must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("line 1"),
            "error must name the offending line, got: {msg}"
        );
    }

    #[test]
    fn shift_to_lands_last_event_on_target_and_preserves_deltas() {
        let remapped = remap_uuids(TRIPPING_FIXTURE);
        let mut events = parse_events(&remapped).unwrap();
        assert!(events.len() >= 2, "fixture must have at least two events");

        let original_deltas: Vec<i64> = events
            .windows(2)
            .map(|w| (w[1].timestamp - w[0].timestamp).num_milliseconds())
            .collect();

        let target = Utc::now() - Duration::seconds(2);
        shift_to(&mut events, target);

        let max_ts = events.iter().map(|e| e.timestamp).max().unwrap();
        assert_eq!(max_ts, target, "last event must land exactly on target");

        let new_deltas: Vec<i64> = events
            .windows(2)
            .map(|w| (w[1].timestamp - w[0].timestamp).num_milliseconds())
            .collect();
        assert_eq!(original_deltas, new_deltas, "relative deltas preserved");

        // ordering unchanged: timestamps remain non-decreasing
        assert!(
            events.windows(2).all(|w| w[0].timestamp <= w[1].timestamp),
            "timestamps must remain non-decreasing after shift"
        );
    }
}
