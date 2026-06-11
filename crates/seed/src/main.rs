//! `sondera-seed` — dev/demo seed-replay tool, not a production binary. It
//! loads two checked-in fixtures into the trajectory stores so the dashboard's
//! "tripping vs approved" contrast and live feed can be demonstrated without a
//! live agent or Ollama.
//!
//! The fixtures were each generated once through the real harness adjudicate
//! path. Seeding writes ONLY through harness storage APIs — never through
//! `crates/dashboard`, which stays structurally read-only.
//!
//! - per-run uuid remap + timestamp shift-to-now keeps re-seeding
//!   collision-free against the turso `event_id UNIQUE` constraint and lands
//!   the demo rows at the top of the last-activity-ordered list
//! - default mode: instant bulk load; `--replay`: per-event delays
//!   (`--delay-ms`, default 750) so the live feed / new-events pill / list
//!   reordering can be watched happening
//!
//! # Fixture regeneration (a dev task, never a demo-time dependency)
//!
//! 1. Ensure Ollama is serving at `http://localhost:11434` with the
//!    `gpt-oss-safeguard:20b` model pulled; pre-warm it with a 1-token
//!    generate request so cold model load cannot eat the guardrails' 30s
//!    timeout.
//! 2. Run ONE generator test at a time and capture the new JSONL file it
//!    appends under `~/.sondera/trajectories/test-multihop-*.jsonl`:
//!    ```text
//!    cargo +stable test -p sondera-harness --test multi_hop_integration \
//!      tripping_trajectory_file_write_denied_citing_multi_hop_forbid -- --ignored --exact
//!    ```
//!    Copy the new file over `crates/seed/fixtures/tripping.jsonl`.
//! 3. Repeat for `approved_trajectory_same_protected_write_allowed` →
//!    `crates/seed/fixtures/approved.jsonl`.
//! 4. Leak review before committing: grep both fixtures for your local
//!    username and for `/Users/` — both must return nothing; agent identity
//!    must stay the synthetic `test-agent`/`test-provider` pair.

mod remap;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use sondera_harness::{Event, TrajectoryStore};
use std::path::PathBuf;
use std::time::Duration;

/// Harness-generated tripping trajectory: untrusted read → protected write,
/// denied citing `multi-hop-forbid-file-protected-write-untrusted-pending`.
const TRIPPING_FIXTURE: &str = include_str!("../fixtures/tripping.jsonl");

/// Harness-generated approved trajectory: `Resumed("user")` between the
/// untrusted read and the SAME protected write → allowed.
const APPROVED_FIXTURE: &str = include_str!("../fixtures/approved.jsonl");

#[derive(Parser, Debug)]
#[command(
    name = "sondera-seed",
    about = "Dev/demo seed-replay tool: loads sample trajectories into Sondera's trajectory stores (NOT a production binary)"
)]
struct Args {
    /// Path to the trajectories database (defaults to ~/.sondera/trajectories.db)
    #[arg(long)]
    db_path: Option<PathBuf>,

    /// Re-append fixture events with per-event delays so the live feed is demonstrable
    #[arg(long)]
    replay: bool,

    /// Delay between events in --replay mode, in milliseconds
    #[arg(long, default_value_t = 750)]
    delay_ms: u64,

    /// Verbose logging (info + sondera debug); default is warn-only
    #[arg(short, long)]
    verbose: bool,
}

/// Remap, parse, and time-shift one embedded fixture so this run's copy has
/// fresh ids and lands at `target_last` on the last-activity-ordered list.
fn prepare_fixture(
    name: &str,
    text: &str,
    target_last: chrono::DateTime<Utc>,
) -> Result<Vec<Event>> {
    let remapped = remap::remap_uuids(text);
    let mut events =
        remap::parse_events(&remapped).with_context(|| format!("parsing {name} fixture"))?;
    remap::shift_to(&mut events, target_last);
    Ok(events)
}

/// Insert events in line order (line order IS causal order). The JSONL
/// append feeds the dashboard's tail watcher; tests skip it because
/// `write_trajectory_event` is home-anchored (`~/.sondera/trajectories/`)
/// and tests must never write there.
async fn seed_into_store(
    store: &TrajectoryStore,
    events: &[Event],
    write_jsonl: bool,
    delay: Option<Duration>,
) -> Result<()> {
    for (i, event) in events.iter().enumerate() {
        let line = i + 1;
        store
            .insert_event(event)
            .await
            .with_context(|| format!("turso insert failed at event line {line}"))?;
        if write_jsonl {
            sondera_harness::storage::file::write_trajectory_event(event)
                .with_context(|| format!("JSONL append failed at event line {line}"))?;
        }
        if let Some(d) = delay
            && line < events.len()
        {
            tokio::time::sleep(d).await;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Logging to stderr (workspace convention).
    let filter = if args.verbose {
        tracing_subscriber::EnvFilter::new("info,sondera=debug")
    } else {
        tracing_subscriber::EnvFilter::new("warn")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    // Default path resolved via the harness's own function so harness,
    // dashboard, and seeder can never disagree.
    let db_path = match args.db_path {
        Some(path) => path,
        None => sondera_harness::get_default_db_path()
            .context("resolving default trajectory DB path")?,
    };

    // ONE store for the whole run.
    let store = TrajectoryStore::open(&db_path)
        .await
        .with_context(|| format!("opening trajectory store at {}", db_path.display()))?;

    let delay = args.replay.then(|| Duration::from_millis(args.delay_ms));
    let mode = if args.replay { "replay" } else { "bulk" };

    // Tripping first at now-2s, approved at now: both land at the TOP of the
    // last-activity-ordered list, approved most recent.
    let now = Utc::now();
    let fixtures = [
        (
            "tripping",
            TRIPPING_FIXTURE,
            now - chrono::Duration::seconds(2),
        ),
        ("approved", APPROVED_FIXTURE, now),
    ];

    for (name, text, target) in fixtures {
        let events = prepare_fixture(name, text, target)?;
        let trajectory_id = events
            .first()
            .map(|e| e.trajectory_id.clone())
            .unwrap_or_default();
        seed_into_store(&store, &events, true, delay)
            .await
            .with_context(|| format!("seeding {name} fixture"))?;
        tracing::info!(
            fixture = name,
            trajectory_id = %trajectory_id,
            events = events.len(),
            mode,
            "seeded fixture"
        );
    }

    Ok(())
}

/// Fixture self-check suite: proves the remapped fixtures keep causal order,
/// resolvable causation links, resolvable monitor witness ids, and a single
/// trajectory identity — plus a double-seed test proving the turso
/// `event_id UNIQUE` collision cannot recur.
#[cfg(test)]
mod tests {
    use super::*;
    use sondera_harness::{Control, Decision, TrajectoryEvent};
    use std::collections::HashSet;

    const FIXTURES: [(&str, &str); 2] = [
        ("tripping", TRIPPING_FIXTURE),
        ("approved", APPROVED_FIXTURE),
    ];

    fn remapped_events(text: &str) -> Vec<Event> {
        remap::parse_events(&remap::remap_uuids(text)).expect("fixture must parse after remap")
    }

    /// Witness ids carried in `raw.monitor.attributes`
    /// (armed/tripped/cleared), when present and non-null.
    fn witness_ids(event: &Event) -> Vec<String> {
        let Some(attrs) = event
            .raw
            .as_ref()
            .and_then(|raw| raw.get("monitor"))
            .and_then(|monitor| monitor.get("attributes"))
        else {
            return Vec::new();
        };
        ["armed_event_id", "tripped_event_id", "cleared_event_id"]
            .iter()
            .filter_map(|key| attrs.get(*key))
            .filter_map(|v| v.as_str())
            .map(String::from)
            .collect()
    }

    #[test]
    fn timestamps_are_non_decreasing_in_line_order() {
        for (name, text) in FIXTURES {
            let events = remapped_events(text);
            assert!(
                events.windows(2).all(|w| w[0].timestamp <= w[1].timestamp),
                "{name}: line order must be causal (non-decreasing timestamps)"
            );
        }
    }

    #[test]
    fn every_causation_id_resolves_to_an_event_in_the_same_file() {
        for (name, text) in FIXTURES {
            let events = remapped_events(text);
            let ids: HashSet<&str> = events.iter().map(|e| e.event_id.as_str()).collect();
            for event in &events {
                if let Some(causation) = event.causality.causation_id.as_deref() {
                    assert!(
                        ids.contains(causation),
                        "{name}: causation_id {causation} of {} must resolve in-file",
                        event.event_id
                    );
                }
            }
        }
    }

    #[test]
    fn every_monitor_witness_id_resolves_to_an_event_in_the_same_file() {
        for (name, text) in FIXTURES {
            let events = remapped_events(text);
            let ids: HashSet<&str> = events.iter().map(|e| e.event_id.as_str()).collect();
            let mut seen = 0usize;
            for event in &events {
                for witness in witness_ids(event) {
                    seen += 1;
                    assert!(
                        ids.contains(witness.as_str()),
                        "{name}: witness id {witness} in raw.monitor of {} must resolve in-file",
                        event.event_id
                    );
                }
            }
            assert!(
                seen > 0,
                "{name}: fixture must carry monitor witness ids (Taint & Monitor view depends on them)"
            );
        }
    }

    #[test]
    fn all_events_share_one_trajectory_id() {
        for (name, text) in FIXTURES {
            let events = remapped_events(text);
            let trajectories: HashSet<&str> =
                events.iter().map(|e| e.trajectory_id.as_str()).collect();
            assert_eq!(
                trajectories.len(),
                1,
                "{name}: all events must belong to a single trajectory"
            );
        }
    }

    fn deny_count(events: &[Event]) -> usize {
        events
            .iter()
            .filter(|e| {
                matches!(
                    &e.event,
                    TrajectoryEvent::Control(Control::Adjudicated(adj))
                        if adj.decision == Decision::Deny
                )
            })
            .count()
    }

    #[test]
    fn tripping_fixture_contains_a_deny_adjudication() {
        let events = remapped_events(TRIPPING_FIXTURE);
        assert!(
            deny_count(&events) >= 1,
            "tripping fixture must carry at least one Deny adjudication"
        );
    }

    #[test]
    fn approved_fixture_has_user_resumed_and_no_deny() {
        let events = remapped_events(APPROVED_FIXTURE);
        let resumed_by_user = events.iter().any(|e| {
            matches!(
                &e.event,
                TrajectoryEvent::Control(Control::Resumed(r)) if r.resumed_by == "user"
            )
        });
        assert!(
            resumed_by_user,
            "approved fixture must carry a Resumed control event with resumed_by == \"user\""
        );
        assert_eq!(
            deny_count(&events),
            0,
            "approved fixture must carry no Deny adjudication"
        );
    }

    /// Two consecutive seeds of the same fixture into the same DB must both
    /// succeed (per-run uuid remap kills the `event_id UNIQUE` collision) and
    /// the row count must double. JSONL writes are skipped —
    /// `write_trajectory_event` is home-anchored and tests must not write to
    /// `~/.sondera`.
    #[tokio::test]
    async fn double_seed_succeeds_twice_and_row_count_doubles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("trajectories.db");
        let store = TrajectoryStore::open(&db_path).await.expect("open store");

        let first = remapped_events(TRIPPING_FIXTURE);
        seed_into_store(&store, &first, false, None)
            .await
            .expect("first seed must succeed");
        let after_first = store.count_events().await.expect("count");
        assert_eq!(after_first, first.len() as u64);

        let second = remapped_events(TRIPPING_FIXTURE);
        seed_into_store(&store, &second, false, None)
            .await
            .expect("second seed must succeed (no UNIQUE event_id collision)");
        let after_second = store.count_events().await.expect("count");
        assert_eq!(
            after_second,
            2 * first.len() as u64,
            "row count must double across two seeds"
        );
    }
}
