//! Error type for trajectory scanner operations.

use sondera_provider::ProviderError;
use sondera_types::StoreError;
use thiserror::Error;

/// Errors from trajectory scanner operations.
///
/// Every variant means the same thing operationally: that scan produced
/// nothing, and the trajectory ships without the enrichment. Scanning is
/// best-effort by construction — it runs off the adjudication path — so a
/// failure here never changes a decision.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ScannerError {
    /// The provider client could not be constructed from the configuration.
    #[error("failed to build the scanner provider client: {0}")]
    ClientBuild(#[from] ProviderError),
    /// The model call exceeded [`ScannerConfig::timeout`](crate::ScannerConfig::timeout).
    #[error("scan timed out")]
    Timeout,
    /// The model call failed, or its output did not satisfy the rubric schema.
    ///
    /// Carries the provider's message. It can quote the model output that
    /// failed to parse — which is trajectory content — so this belongs in a
    /// local log, never in an outbound report. Use [`ScannerError::kind`] for
    /// anything that leaves the machine.
    #[error("model extraction failed: {0}")]
    Extraction(String),
    /// A transcript-level scan was asked for with no events to scan.
    #[error("no events provided for scanning")]
    NoEvents,
    /// The trajectory named by a store-backed scan has no events.
    #[error("trajectory not found: {0}")]
    TrajectoryNotFound(String),
    /// Loading the transcript failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl ScannerError {
    /// A bounded classification for low-cardinality log and metric fields.
    ///
    /// Deliberately not the `Display` text: the extraction variant embeds
    /// model output, so grouping on the rendered error would both explode
    /// cardinality and copy trajectory content into telemetry.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ClientBuild(_) => "client_build",
            Self::Timeout => "timeout",
            Self::Extraction(_) => "extraction",
            Self::NoEvents => "no_events",
            Self::TrajectoryNotFound(_) => "trajectory_not_found",
            Self::Store(_) => "store",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kind_label_never_carries_the_model_output() {
        let error = ScannerError::Extraction("expected `outcome`, found \"rm -rf /home\"".into());
        assert_eq!(error.kind(), "extraction");
        assert!(!error.kind().contains("rm -rf"));
    }
}
