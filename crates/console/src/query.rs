//! Wire request → domain query translation.
//!
//! Every AIP-flavored string a console request carries — the `filter` grammar,
//! `order_by`, `page_size`/`page_token` — is decoded here into the typed domain
//! queries the store surface takes. Nothing below this module parses a filter
//! clause or mints a page token, which is what keeps `sondera-types` and
//! `sondera-storage` free of wire vocabulary.
//!
//! Filters reject what they do not understand: a typo must narrow nothing
//! silently. Orderings do the opposite and fall back to the default, because an
//! unrecognized sort still returns the right rows in a defensible order.

use sondera_schema::names::agent_id_from_name;
use sondera_types::{
    AgentFilter, AgentOrderBy, AgentQuery, TrajectoryFilter, TrajectoryOrderBy, TrajectoryQuery,
    TrajectoryStatus, ValidationError,
};

/// Page size used when a request leaves it unset.
pub(crate) const DEFAULT_PAGE_SIZE: usize = 50;

/// Upper bound a requested page size is clamped to.
pub(crate) const MAX_PAGE_SIZE: usize = 250;

/// Normalize a wire page size into a store limit: non-positive means "unset"
/// (default), and anything larger than the service maximum is clamped.
pub fn limit(page_size: i32) -> usize {
    if page_size <= 0 {
        DEFAULT_PAGE_SIZE
    } else {
        (page_size as usize).min(MAX_PAGE_SIZE)
    }
}

/// Offset decoded from a page token.
///
/// Tokens are opaque to callers; this surface mints them as decimal offsets, and
/// an unparsable token reads as the first page rather than failing the request.
pub fn offset(page_token: &str) -> usize {
    page_token.parse().unwrap_or(0)
}

/// The token for the page following one that returned `returned` items at
/// `offset`, or empty when that page was the last one.
pub fn next_page_token(offset: usize, returned: usize, total: usize) -> String {
    let next = offset + returned;
    if returned == 0 || next >= total {
        String::new()
    } else {
        next.to_string()
    }
}

/// Split an `order_by` value into its field and direction.
///
/// Grammar is AIP-132's: `"field"`, `"field asc"`, or `"field desc"`. An empty
/// value means "the collection's default ordering", which every collection here
/// defines as descending.
fn order_parts(order_by: &str) -> (&str, bool) {
    match order_by.trim() {
        "" => ("", true),
        raw => match raw.rsplit_once(' ') {
            Some((field, "desc")) => (field.trim(), true),
            Some((field, "asc")) => (field.trim(), false),
            _ => (raw, true),
        },
    }
}

/// Split a filter string into its `key=value` clauses.
///
/// Whitespace-separated; a clause without `=` is a caller error rather than a
/// clause that silently matches everything.
fn clauses(filter: &str) -> impl Iterator<Item = Result<(&str, &str), ValidationError>> {
    filter.split_whitespace().map(|clause| {
        clause
            .split_once('=')
            .map(|(k, v)| (k.trim(), v.trim()))
            .ok_or_else(|| {
                ValidationError::message(format!(
                    "invalid filter clause '{clause}', expected key=value"
                ))
            })
    })
}

fn unsupported(key: &str) -> ValidationError {
    ValidationError::message(format!("unsupported filter key '{key}'"))
}

/// Parse the `ListAgents` / `AnalyzeAgents` filter grammar.
///
/// Supports `agent=agents/{agent}`, `provider={provider}`, and
/// `platform={platform}`.
pub fn agent_filter(filter: &str) -> Result<AgentFilter, ValidationError> {
    let mut parsed = AgentFilter::default();
    for clause in clauses(filter) {
        let (key, value) = clause?;
        match key {
            "agent" => {
                let id = agent_id_from_name(value)?;
                parsed.agent_id = Some(id.to_string());
            }
            "provider" => parsed.provider = Some(value.to_string()),
            "platform" => parsed.platform = Some(value.to_string()),
            other => return Err(unsupported(other)),
        }
    }
    Ok(parsed)
}

/// Parse the `ListTrajectories` / `StreamTrajectories` filter grammar.
///
/// Supports `agent=agents/{agent}`, `status={status}`, and
/// `decision=allow|deny|escalate`.
pub fn trajectory_filter(filter: &str) -> Result<TrajectoryFilter, ValidationError> {
    let mut parsed = TrajectoryFilter::default();
    for clause in clauses(filter) {
        let (key, value) = clause?;
        match key {
            "agent" => {
                let id = agent_id_from_name(value)?;
                parsed.agent_id = Some(id.to_string());
            }
            "status" => {
                parsed.status = Some(
                    value
                        .parse::<TrajectoryStatus>()
                        .map_err(ValidationError::message)?,
                );
            }
            "decision" => parsed.decision = Some(decision(value)?),
            other => return Err(unsupported(other)),
        }
    }
    Ok(parsed)
}

fn decision(value: &str) -> Result<sondera_types::Decision, ValidationError> {
    use sondera_types::Decision;
    match value.to_lowercase().as_str() {
        "allow" => Ok(Decision::Allow),
        "deny" => Ok(Decision::Deny),
        "escalate" => Ok(Decision::Escalate),
        other => Err(ValidationError::message(format!(
            "invalid decision '{other}', expected allow, deny, or escalate"
        ))),
    }
}

/// Build the domain query behind a `ListAgents` request.
pub fn agents(
    page_size: i32,
    page_token: &str,
    filter: &str,
    order_by: &str,
) -> Result<AgentQuery, ValidationError> {
    let (field, descending) = order_parts(order_by);
    Ok(AgentQuery {
        filter: agent_filter(filter)?,
        order_by: match field {
            // `display_name` is the wire's name for the agent id.
            "display_name" => AgentOrderBy::Id,
            "runs_today" => AgentOrderBy::RunsToday,
            // `last_active_time` and anything unrecognized.
            _ => AgentOrderBy::LastActive,
        },
        descending,
        offset: offset(page_token),
        limit: limit(page_size),
    })
}

/// Build the domain query behind a `ListTrajectories` request.
pub fn trajectories(
    page_size: i32,
    page_token: &str,
    filter: &str,
    order_by: &str,
) -> Result<TrajectoryQuery, ValidationError> {
    let (field, descending) = order_parts(order_by);
    Ok(TrajectoryQuery {
        filter: trajectory_filter(filter)?,
        order_by: match field {
            "event_count" => TrajectoryOrderBy::EventCount,
            "update_time" => TrajectoryOrderBy::UpdateTime,
            // `start_time` and anything unrecognized.
            _ => TrajectoryOrderBy::StartTime,
        },
        descending,
        offset: offset(page_token),
        limit: limit(page_size),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_types::Decision;

    #[test]
    fn page_size_defaults_and_clamps() {
        assert_eq!(limit(0), DEFAULT_PAGE_SIZE);
        assert_eq!(limit(-7), DEFAULT_PAGE_SIZE);
        assert_eq!(limit(42), 42);
        assert_eq!(limit(MAX_PAGE_SIZE as i32 + 1), MAX_PAGE_SIZE);
    }

    #[test]
    fn page_tokens_walk_offsets_and_stop_at_the_end() {
        assert_eq!(offset(""), 0);
        assert_eq!(next_page_token(0, 50, 120), "50");

        assert_eq!(offset("50"), 50);
        // Last page: offset + returned covers the total, so no further token.
        assert_eq!(next_page_token(50, 70, 120), "");
        // An empty page never mints a token either.
        assert_eq!(next_page_token(50, 0, 120), "");
    }

    #[test]
    fn an_unparsable_page_token_reads_as_the_first_page() {
        assert_eq!(offset("not-a-number"), 0);
    }

    #[test]
    fn agent_filters_parse_every_supported_clause() {
        let parsed =
            agent_filter("agent=agents/a provider=anthropic platform=claude-code").expect("parses");
        assert_eq!(parsed.agent_id.as_deref(), Some("a"));
        assert_eq!(parsed.provider.as_deref(), Some("anthropic"));
        assert_eq!(parsed.platform.as_deref(), Some("claude-code"));
        // An empty filter narrows nothing.
        assert_eq!(agent_filter("").unwrap(), AgentFilter::default());
    }

    #[test]
    fn an_agent_clause_is_given_as_a_resource_name_and_stored_as_an_id() {
        let parsed = agent_filter("agent=agents/claude-code-developer/rs-engineer").unwrap();
        assert_eq!(
            parsed.agent_id.as_deref(),
            Some("claude-code-developer/rs-engineer")
        );
        // A bare id is not a resource name and must be rejected.
        assert!(agent_filter("agent=a").is_err());
    }

    #[test]
    fn trajectory_filters_parse_every_supported_clause() {
        let parsed =
            trajectory_filter("agent=agents/a status=running decision=deny").expect("parses");
        assert_eq!(parsed.agent_id.as_deref(), Some("a"));
        assert_eq!(parsed.status, Some(TrajectoryStatus::Running));
        assert_eq!(parsed.decision, Some(Decision::Deny));
    }

    #[test]
    fn unknown_filter_keys_and_values_are_rejected_rather_than_ignored() {
        for filter in ["fleet=fleets/a", "garbage"] {
            assert!(
                agent_filter(filter).is_err(),
                "{filter:?} should be rejected"
            );
            assert!(
                trajectory_filter(filter).is_err(),
                "{filter:?} should be rejected"
            );
        }
        assert!(trajectory_filter("decision=maybe").is_err());
        assert!(trajectory_filter("status=halted").is_err());
    }

    #[test]
    fn order_by_maps_fields_and_direction() {
        let query = agents(0, "", "", "runs_today asc").unwrap();
        assert_eq!(query.order_by, AgentOrderBy::RunsToday);
        assert!(!query.descending);

        // `display_name` is the wire's name for the id.
        assert_eq!(
            agents(0, "", "", "display_name").unwrap().order_by,
            AgentOrderBy::Id
        );

        let query = trajectories(0, "", "", "event_count desc").unwrap();
        assert_eq!(query.order_by, TrajectoryOrderBy::EventCount);
        assert!(query.descending);
    }

    #[test]
    fn an_unrecognized_ordering_falls_back_to_the_default_rather_than_failing() {
        let query = agents(0, "", "", "favourite_colour").unwrap();
        assert_eq!(query.order_by, AgentOrderBy::LastActive);
        assert!(query.descending);

        let query = trajectories(0, "", "", "").unwrap();
        assert_eq!(query.order_by, TrajectoryOrderBy::StartTime);
        assert!(query.descending);
    }

    #[test]
    fn a_list_request_carries_its_window_into_the_domain_query() {
        let query = trajectories(10, "20", "status=failed", "").unwrap();
        assert_eq!(query.offset, 20);
        assert_eq!(query.limit, 10);
        assert_eq!(query.filter.status, Some(TrajectoryStatus::Failed));
    }
}
