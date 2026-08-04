//! Trajectory lifecycle status, derived from a run's control events.
//!
//! This module carries only the status vocabulary. Deriving a whole run's status
//! from its event list is [`Trajectory::summarize`](super::Trajectory::summarize),
//! next to the other rollups.

use super::Control;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Lifecycle status of a trajectory, derived from its control events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum TrajectoryStatus {
    /// No control events yet.
    #[default]
    Pending,
    /// After a `Started` or `Resumed` event.
    Running,
    /// After a `Completed` event.
    Completed,
    /// After a `Failed` event.
    Failed,
    /// After a `Terminated` event.
    Terminated,
    /// After a `Suspended` event.
    Suspended,
}

impl TrajectoryStatus {
    /// Map a single control event to a trajectory status.
    ///
    /// `Adjudicated` and `Scanned` are governance bookkeeping rather than
    /// lifecycle. They map to `Running` for the single-event case, but callers
    /// scanning a run backwards for its status must skip them outright —
    /// otherwise a verdict recorded after a terminal event pins a finished run
    /// to `Running`.
    pub fn from_control(control: &Control) -> Self {
        match control {
            Control::Started(_) | Control::Resumed(_) => Self::Running,
            Control::Completed(_) => Self::Completed,
            Control::Failed(_) => Self::Failed,
            Control::Terminated(_) => Self::Terminated,
            Control::Suspended(_) => Self::Suspended,
            Control::Adjudicated(_) | Control::Scanned(_) => Self::Running,
        }
    }

    /// The canonical lowercase label, as carried on the console wire surface.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Terminated => "terminated",
            Self::Suspended => "suspended",
        }
    }
}

impl fmt::Display for TrajectoryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TrajectoryStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "terminated" => Ok(Self::Terminated),
            "suspended" => Ok(Self::Suspended),
            _ => Err(format!(
                "Invalid trajectory status: '{s}'. Must be 'pending', 'running', 'completed', 'failed', 'terminated', or 'suspended'"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Completed, Started, Terminated};

    #[test]
    fn labels_round_trip_through_parse() {
        for status in [
            TrajectoryStatus::Pending,
            TrajectoryStatus::Running,
            TrajectoryStatus::Completed,
            TrajectoryStatus::Failed,
            TrajectoryStatus::Terminated,
            TrajectoryStatus::Suspended,
        ] {
            assert_eq!(status.to_string().parse::<TrajectoryStatus>(), Ok(status));
        }
    }

    #[test]
    fn parse_is_case_insensitive_and_rejects_unknown_labels() {
        assert_eq!(
            "COMPLETED".parse::<TrajectoryStatus>(),
            Ok(TrajectoryStatus::Completed)
        );
        assert!("halted".parse::<TrajectoryStatus>().is_err());
    }

    #[test]
    fn terminal_control_events_map_to_their_status() {
        assert_eq!(
            TrajectoryStatus::from_control(&Control::Completed(Completed::new())),
            TrajectoryStatus::Completed
        );
        assert_eq!(
            TrajectoryStatus::from_control(&Control::Terminated(Terminated::new("t", "system"))),
            TrajectoryStatus::Terminated
        );
        assert_eq!(
            TrajectoryStatus::from_control(&Control::Started(Started::new(crate::Agent::new(
                "a", "p", ""
            )))),
            TrajectoryStatus::Running
        );
    }
}
