//! State events: context snapshots.
//!
//! State events capture a point-in-time view of the agent's environment —
//! working directory, open files, git branch, and arbitrary variables — rather
//! than an action or observation. They are one of the four [`TrajectoryEvent`]
//! categories.
//!
//! [`TrajectoryEvent`]: super::TrajectoryEvent

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Context snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum State {
    Snapshot(Snapshot),
}

/// Full environment snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Snapshot {
    pub snapshot_id: String,
    pub working_dir: Option<String>,
    pub open_files: Vec<String>,
    pub git_branch: Option<String>,
    pub variables: HashMap<String, serde_json::Value>,
}

impl Snapshot {
    pub fn new() -> Self {
        Self {
            snapshot_id: format!("snap-{}", uuid::Uuid::new_v4()),
            working_dir: None,
            open_files: Vec::new(),
            git_branch: None,
            variables: HashMap::new(),
        }
    }

    pub fn with_cwd(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    pub fn with_git_branch(mut self, branch: impl Into<String>) -> Self {
        self.git_branch = Some(branch.into());
        self
    }
}

impl Default for Snapshot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_builder() {
        let snap = Snapshot::new()
            .with_cwd("/workspace")
            .with_git_branch("main");

        assert_eq!(snap.working_dir.as_deref(), Some("/workspace"));
        assert_eq!(snap.git_branch.as_deref(), Some("main"));
    }
}
