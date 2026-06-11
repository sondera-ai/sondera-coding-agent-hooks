//! Verdict backstop: force `Escalate` when Cedar allows in a `Violated` trajectory.
//!
//! Defense-in-depth merge applied to exactly one cell of the
//! (Verdict, Decision) matrix:
//!
//! ```text
//!                 Allow          Deny        Escalate
//!   Satisfied   identity       identity     identity
//!   Pending     identity       identity     identity
//!   Violated    ESCALATE       identity     identity
//! ```
//!
//! Design rules enforced here:
//!
//! - The forced decision is `Escalate`, never `Deny` — a Cedar Allow in a
//!   Violated trajectory is sent for human review, not blocked.
//! - `Violated` is latching and [`merge`] takes no event parameter:
//!   escalation depends only on `(Verdict, Decision)`, so every subsequent
//!   Cedar-Allow in a Violated trajectory escalates.
//! - A Cedar `Deny` passes through byte-identical — decision, reason, and
//!   annotations untouched.
//! - Applied on the Cedar path only, via one call site in `adjudicate`
//!   immediately after `response_to_adjudicated`; the Control early-return
//!   never reaches the merge.
//! - The forced `Escalate` carries a synthetic [`Annotation`] (policy id
//!   [`BACKSTOP_POLICY_ID`], description) plus a human-readable `reason`.
//! - The annotation's custom map carries `armed_event_id` / `tripped_event_id`
//!   witness entries only when the corresponding [`MonitorAttributes`] field
//!   is `Some` (mirrors the skip-if-`None` serde style).
//! - The `monitor-backstop-` policy-id prefix is reserved for synthetic
//!   monitor annotations and never used as a Cedar `@id`. Anti-spoofing
//!   requires both the reserved prefix and the `source = "monitor"` custom
//!   key — consumers must filter on the pair, not either alone.
//! - Cedar's own Allow annotations (e.g. `default-permit`) are kept in order
//!   with the backstop annotation appended last — never replaced.
//! - There is deliberately no config kill-switch: a toggle would be a tamper
//!   surface that fails open.
//! - Storage-fault-to-decision conversion is out of scope; `adjudicate`'s
//!   `anyhow::Error` propagation is unchanged by this module.
//!
//! Reason composition: `response_to_adjudicated` sets a `reason` even on Allow
//! when Cedar diagnostics carry errors; [`merge`] composes with such a
//! pre-existing reason (existing text first), never clobbers it.

use crate::monitors::{MonitorAttributes, Verdict};
use crate::types::{Adjudicated, Annotation, Decision};

/// Reserved synthetic policy id for the backstop annotation.
///
/// The `monitor-backstop-` prefix is reserved for monitor-synthesized
/// annotations; no Cedar policy may mint an `@id` under it.
pub const BACKSTOP_POLICY_ID: &str = "monitor-backstop-escalate-on-violated";

/// Human-readable reason for the forced escalation.
const BACKSTOP_REASON: &str = "Multi-hop monitor verdict is Violated; \
     Cedar-allowed event escalated for human review (monitor-backstop)";

/// Merge the monitor verdict into a Cedar adjudication.
///
/// Pure total function over `(Adjudicated, Verdict)`: the only non-identity
/// cell is `(Violated, Allow) -> Escalate`; every other cell returns the
/// input unchanged.
pub fn merge(adjudicated: Adjudicated, verdict: Verdict, attrs: &MonitorAttributes) -> Adjudicated {
    // Every cell except (Violated, Allow) is identity.
    if verdict != Verdict::Violated || adjudicated.decision != Decision::Allow {
        return adjudicated;
    }

    // Synthetic annotation with the reserved policy id and the source=monitor
    // discriminator, built in the transform.rs chaining style.
    let mut annotation = Annotation::new()
        .with_id(BACKSTOP_POLICY_ID.to_string())
        .with_description(
            "Multi-hop monitor: trajectory verdict is Violated; \
             Cedar-allowed event escalated for human review."
                .to_string(),
        )
        .with("source".to_string(), "monitor".to_string());
    // Copy witness ids only when present (skip-if-None style).
    if let Some(id) = &attrs.armed_event_id {
        annotation = annotation.with("armed_event_id".to_string(), id.clone());
    }
    if let Some(id) = &attrs.tripped_event_id {
        annotation = annotation.with("tripped_event_id".to_string(), id.clone());
    }

    // A forced Escalate is a decision-level event: warn!, never debug!.
    tracing::warn!(
        verdict = ?verdict,
        armed_event_id = ?attrs.armed_event_id,
        tripped_event_id = ?attrs.tripped_event_id,
        "Monitor backstop: forcing Escalate on Cedar Allow in a Violated trajectory"
    );

    let mut merged = adjudicated;
    merged.decision = Decision::Escalate;
    // Compose with any pre-existing reason (Cedar diagnostics errors surface
    // on Allow too) — existing text stays first.
    merged.reason = Some(match merged.reason.take() {
        Some(existing) => format!("{existing}; {BACKSTOP_REASON}"),
        None => BACKSTOP_REASON.to_string(),
    });
    // Append — Cedar's own annotations stay, in order, first.
    merged.annotations.push(annotation);
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERR_REASON: &str = "cedar eval error X";

    /// A Cedar Allow carrying the baseline `default-permit` annotation, as
    /// produced by `response_to_adjudicated` for an allowed event.
    fn cedar_allow() -> Adjudicated {
        Adjudicated::allow()
            .with_annotation(Annotation::new().with_id("default-permit".to_string()))
    }

    fn full_attrs() -> MonitorAttributes {
        MonitorAttributes {
            armed_event_id: Some("evt-armed-1".to_string()),
            cleared_event_id: None,
            tripped_event_id: Some("evt-tripped-2".to_string()),
        }
    }

    /// Find the backstop annotation in a merged result.
    fn backstop_annotation(adjudicated: &Adjudicated) -> &Annotation {
        adjudicated
            .annotations
            .iter()
            .find(|a| a.policy_id.as_deref() == Some(BACKSTOP_POLICY_ID))
            .expect("backstop annotation present")
    }

    // ---- (Violated, Allow) -> Escalate ----

    #[test]
    fn violated_allow_escalates_and_appends_backstop_annotation() {
        let merged = merge(cedar_allow(), Verdict::Violated, &full_attrs());

        assert_eq!(merged.decision, Decision::Escalate);
        // Cedar's own annotations kept, in order, first; backstop appended
        // last.
        assert_eq!(merged.annotations.len(), 2);
        assert_eq!(
            merged.annotations[0].policy_id.as_deref(),
            Some("default-permit")
        );
        assert_eq!(
            merged.annotations[1].policy_id.as_deref(),
            Some(BACKSTOP_POLICY_ID)
        );
        // Non-empty description and reason.
        let backstop = backstop_annotation(&merged);
        assert!(
            backstop
                .description
                .as_deref()
                .is_some_and(|d| !d.is_empty())
        );
        assert!(merged.reason.as_deref().is_some_and(|r| !r.is_empty()));
    }

    // ---- Witness-id conditionality ----

    #[test]
    fn backstop_annotation_carries_source_and_witness_ids_when_present() {
        let merged = merge(cedar_allow(), Verdict::Violated, &full_attrs());
        let backstop = backstop_annotation(&merged);

        // source discriminator.
        assert_eq!(
            backstop.annotations.get("source").map(String::as_str),
            Some("monitor")
        );
        // Witness ids copied from MonitorAttributes when Some.
        assert_eq!(
            backstop
                .annotations
                .get("armed_event_id")
                .map(String::as_str),
            Some("evt-armed-1")
        );
        assert_eq!(
            backstop
                .annotations
                .get("tripped_event_id")
                .map(String::as_str),
            Some("evt-tripped-2")
        );
    }

    #[test]
    fn backstop_annotation_omits_witness_ids_when_attrs_all_none() {
        let merged = merge(
            cedar_allow(),
            Verdict::Violated,
            &MonitorAttributes::default(),
        );
        let backstop = backstop_annotation(&merged);

        // skip-if-None — neither witness key present...
        assert!(!backstop.annotations.contains_key("armed_event_id"));
        assert!(!backstop.annotations.contains_key("tripped_event_id"));
        // ...while the source discriminator still is.
        assert_eq!(
            backstop.annotations.get("source").map(String::as_str),
            Some("monitor")
        );
    }

    // ---- Reason composition ----

    #[test]
    fn existing_reason_is_composed_not_clobbered() {
        let input = cedar_allow().with_reason(ERR_REASON);
        let merged = merge(input, Verdict::Violated, &full_attrs());

        let reason = merged.reason.expect("reason set");
        // Existing diagnostics text preserved first, backstop text appended.
        assert!(reason.starts_with(ERR_REASON));
        assert!(reason.len() > ERR_REASON.len());
        assert!(reason.contains("monitor"));
    }

    #[test]
    fn reason_is_backstop_text_alone_when_input_has_none() {
        let merged = merge(cedar_allow(), Verdict::Violated, &full_attrs());
        let reason = merged.reason.expect("reason set");

        assert!(!reason.is_empty());
        // No composition separator artifacts when there was nothing to
        // compose with.
        assert!(!reason.starts_with(';'));
        assert!(reason.contains("monitor"));
    }

    // ---- Identity cells: direct Eq against a pre-merge clone ----

    #[test]
    fn violated_deny_passes_through_unchanged() {
        let input = Adjudicated::deny()
            .with_reason("denied by multi-hop forbid")
            .with_annotation(
                Annotation::new()
                    .with_id("multi-hop-forbid-file-protected-write-untrusted-pending".to_string()),
            );
        let expected = input.clone();

        assert_eq!(merge(input, Verdict::Violated, &full_attrs()), expected);
    }

    #[test]
    fn pending_allow_passes_through_unchanged() {
        let input = cedar_allow();
        let expected = input.clone();

        assert_eq!(merge(input, Verdict::Pending, &full_attrs()), expected);
    }

    #[test]
    fn satisfied_allow_passes_through_unchanged() {
        let input = cedar_allow();
        let expected = input.clone();

        assert_eq!(merge(input, Verdict::Satisfied, &full_attrs()), expected);
    }

    #[test]
    fn violated_escalate_passes_through_unchanged_no_double_annotation() {
        // An already-escalated input (e.g. a previously merged value) must
        // not gain a second backstop annotation.
        let input = Adjudicated::escalate()
            .with_reason("already escalated")
            .with_annotation(Annotation::new().with_id(BACKSTOP_POLICY_ID.to_string()));
        let expected = input.clone();

        assert_eq!(merge(input, Verdict::Violated, &full_attrs()), expected);
    }

    // ---- Latching: no event parameter, only (Verdict, Decision) ----

    #[test]
    fn second_consecutive_violated_allow_also_escalates() {
        let attrs = full_attrs();

        let first = merge(cedar_allow(), Verdict::Violated, &attrs);
        assert_eq!(first.decision, Decision::Escalate);

        // Violated is latching: the next Cedar-Allow in the same trajectory
        // escalates too — merge has no event parameter to filter on.
        let second = merge(cedar_allow(), Verdict::Violated, &attrs);
        assert_eq!(second.decision, Decision::Escalate);
        assert_eq!(
            backstop_annotation(&second).policy_id.as_deref(),
            Some(BACKSTOP_POLICY_ID)
        );
    }
}
