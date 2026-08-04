//! AIP-122 resource names for the console collections.
//!
//! Resource names are a property of the wire contract, not of the domain: a
//! store addresses an agent or a run by its bare id, and only the messages
//! crossing the network carry `agents/{id}` / `trajectories/{id}`. So the
//! formatting and parsing live here, beside the DTO conversions that need them,
//! and `sondera-types` stays name-free.

use sondera_types::ValidationError;

/// Extract the bare id from a resource name (`"{collection}/{id}"`).
fn bare_id<'a>(name: &'a str, collection: &str) -> Result<&'a str, ValidationError> {
    let invalid = || ValidationError::message(format!("invalid resource name '{name}'"));
    let id = name.strip_prefix(collection).ok_or_else(invalid)?;
    let id = id.strip_prefix('/').ok_or_else(invalid)?;
    if id.is_empty() || id.contains('/') {
        return Err(invalid());
    }
    Ok(id)
}

/// Build the `agents/{id}` resource name for a bare agent id.
pub fn agent_name(id: &str) -> String {
    format!("agents/{id}")
}

/// Extract the bare agent id from an `agents/{id}` resource name.
///
/// Unlike the trajectory collection, agent ids are minted by the hooks from
/// provider + scope and can be **compound** — e.g.
/// `agents/claude-code-developer/rs-harness-engineer`, whose id is
/// `claude-code-developer/rs-harness-engineer`. So this intentionally does not use
/// the shared `bare_id` (which forbids `/`): it strips the `agents/` prefix
/// and accepts any non-empty remainder, slashes included. The id is only ever
/// bound as an opaque value (SQL parameter, display-name derivation), never
/// re-parsed as a resource path, so embedded slashes are safe.
pub fn agent_id_from_name(name: &str) -> Result<&str, ValidationError> {
    name.strip_prefix("agents/")
        .filter(|id| !id.is_empty())
        .ok_or_else(|| ValidationError::message(format!("invalid resource name '{name}'")))
}

/// Build the `trajectories/{id}` resource name for a bare trajectory id.
pub fn trajectory_name(id: &str) -> String {
    format!("trajectories/{id}")
}

/// Extract the bare trajectory id from a `trajectories/{id}` resource name.
pub fn trajectory_id_from_name(name: &str) -> Result<&str, ValidationError> {
    bare_id(name, "trajectories")
}

/// Build the `trajectories/{trajectory}/events/{event}` resource name.
pub fn trajectory_event_name(trajectory_id: &str, event_id: &str) -> String {
    format!("trajectories/{trajectory_id}/events/{event_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compound_agent_ids_keep_their_slashes() {
        assert_eq!(
            agent_id_from_name("agents/claude-code-developer/rs-engineer").unwrap(),
            "claude-code-developer/rs-engineer"
        );
        assert!(agent_id_from_name("agents/").is_err());
        assert!(agent_id_from_name("trajectories/x").is_err());
    }

    #[test]
    fn trajectory_names_round_trip_through_their_id() {
        assert_eq!(
            trajectory_id_from_name(&trajectory_name("run-1")).unwrap(),
            "run-1"
        );
    }

    #[test]
    fn trajectory_names_reject_empty_and_nested_ids() {
        assert!(trajectory_id_from_name("trajectories/").is_err());
        assert!(trajectory_id_from_name("trajectories/a/b").is_err());
        assert!(trajectory_id_from_name("agents/a").is_err());
        // A collection whose name merely prefixes the expected one is not a match.
        assert!(trajectory_id_from_name("trajectoriesX/a").is_err());
    }
}
