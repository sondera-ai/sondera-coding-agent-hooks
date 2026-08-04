//! The one error type every hook produces.
//!
//! [`HookError`] is both the error a hook propagates with `?` and the
//! classification that decides how the hook degrades. There is no separate
//! taxonomy and **no string parsing anywhere**: a harness failure becomes a
//! hook failure through [`From<HarnessClientError>`](HookError::from), a total
//! match on typed variants that runs once at the boundary.
//!
//! Each variant answers three questions, and nothing else in the crate needs to
//! re-derive them:
//! - [`HookError::category`] — the dedup key, so one outage warns once.
//! - [`HookError::remediation`] — the `[sondera]`-prefixed stderr line.
//! - [`HookError::fallback_context`] — what a `SessionStart` passthrough says.
//!
//! The fail-closed denial text lives in [`crate::adjudication`], which matches
//! on the same variants.

use std::error::Error as StdError;

use sondera_harness_client::HarnessClientError;
use thiserror::Error;

type BoxError = Box<dyn StdError + Send + Sync + 'static>;

pub type Result<T> = std::result::Result<T, HookError>;

/// Everything a hook can fail at, from a malformed config file to a panicking
/// handler.
///
/// Ordering below follows the lifecycle: local pre-flight, then the harness
/// exchange, then the hook's own runtime, then the generic `?` carrier.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HookError {
    // ── Local pre-flight: no client exists yet ──────────────────────────────
    /// `~/.sondera/env` exists but could not be read or parsed.
    #[error("configuration error: {0}")]
    Config(String),

    // ── The harness exchange: produced by `From<HarnessClientError>` ────────
    /// The harness could not be reached at all — DNS, refused, TLS.
    #[error("harness unreachable: {0}")]
    Unreachable(String),

    /// The harness accepted the call, then exceeded the client's RPC budget.
    /// Distinct from [`Self::BudgetExceeded`]: the service was demonstrably
    /// reachable here, so the remediation may say so.
    #[error("harness timed out during adjudication")]
    ServiceTimeout,

    /// The harness was reached and rejected the request server-side — a policy
    /// or schema fault, never a connectivity one.
    #[error("harness rejected the request: {0}")]
    ServerRejected(String),

    /// The harness is reachable but not serving correctly, including responses
    /// that could not be decoded.
    #[error("harness unavailable: {0}")]
    ServiceUnavailable(String),

    // ── The hook's own runtime ──────────────────────────────────────────────
    /// The hook's wall-clock budget expired before enforcement completed.
    /// Setup may still have been in flight, so this must *not* claim the
    /// service was reachable.
    #[error("hook budget exceeded after {budget_secs}s before enforcement completed")]
    BudgetExceeded { budget_secs: u64 },

    /// A handler panicked; caught by [`crate::runner::catch_hook_panic`].
    #[error("hook panicked before enforcement completed")]
    Panicked,

    // ── The `?` carrier: installers, transcripts, stdin, config files ───────
    #[error("{0}")]
    Message(String),

    #[error("{message}: {source}")]
    Context {
        message: String,
        #[source]
        source: BoxError,
    },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Classify a harness failure into a hook failure.
///
/// This is the whole classifier: eight typed variants in, no string inspection.
/// It is deliberately lossy — four harness variants collapse into
/// [`HookError::ServerRejected`], because a harness that answered at all was by
/// definition reached, and the hook's behavior does not differ across them.
impl From<HarnessClientError> for HookError {
    fn from(error: HarnessClientError) -> Self {
        match error {
            HarnessClientError::Config(m) => Self::Config(m),
            HarnessClientError::Unavailable(m) => Self::Unreachable(m),
            HarnessClientError::Timeout => Self::ServiceTimeout,
            HarnessClientError::Server(m)
            | HarnessClientError::InvalidArgument(m)
            | HarnessClientError::NotFound(m)
            | HarnessClientError::AlreadyExists(m) => Self::ServerRejected(m),
            HarnessClientError::Decode(m) => Self::ServiceUnavailable(m),
        }
    }
}

impl HookError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn context(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Context {
            message: message.into(),
            source: Box::new(source),
        }
    }

    /// Deduplication key. One warning per category per hook runtime session, so
    /// an org-wide outage produces one line rather than one per tool call.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::ServerRejected(_) => "server",
            Self::Unreachable(_)
            | Self::ServiceTimeout
            | Self::ServiceUnavailable(_)
            | Self::BudgetExceeded { .. }
            | Self::Panicked
            | Self::Message(_)
            | Self::Context { .. }
            | Self::Io(_)
            | Self::Json(_) => "network",
        }
    }

    /// The `[sondera]`-prefixed line shown on stderr, with an actionable next
    /// step. Deduplicated by [`Self::category`].
    ///
    /// Distinct from [`Display`](std::fmt::Display), which is the log-facing
    /// rendering and carries the underlying detail.
    #[must_use]
    pub fn remediation(&self) -> &'static str {
        match self {
            Self::Config(_) => {
                "[sondera] Configuration error in ~/.sondera/env. Check file format."
            }
            Self::Unreachable(_) => {
                "[sondera] Cannot reach Sondera service. Start it with `sondera serve`, or point SONDERA_HARNESS_ENDPOINT at a running one (default http://127.0.0.1:50051)."
            }
            Self::ServiceTimeout => {
                "[sondera] Sondera service timed out while policy adjudication was in progress. The service was reachable; check harness latency/load or contact your admin."
            }
            Self::BudgetExceeded { .. } => {
                "[sondera] Sondera hook timed out before policy enforcement completed. Check hook setup latency, harness latency/load, or contact your admin."
            }
            Self::ServerRejected(_) => {
                "[sondera] Sondera service rejected the request (server-side policy/schema error, not a connectivity issue). Contact your admin."
            }
            Self::ServiceUnavailable(_)
            | Self::Panicked
            | Self::Message(_)
            | Self::Context { .. }
            | Self::Io(_)
            | Self::Json(_) => {
                "[sondera] Sondera service temporarily unavailable. Check that `sondera serve` is running at SONDERA_HARNESS_ENDPOINT, or contact your admin."
            }
        }
    }

    /// Context injected on a `SessionStart` that could not reach the harness.
    ///
    /// Steers toward the config file for a local fault and toward "temporarily
    /// unavailable" for everything else, so a user is never sent to edit
    /// settings over a network blip.
    ///
    /// Matched exhaustively rather than with a catch-all: silently bucketing a
    /// new failure mode into generic text is the class of bug this module
    /// exists to remove.
    #[must_use]
    pub fn fallback_context(&self) -> &'static str {
        match self {
            Self::Config(_) => {
                "Sondera is running in passthrough mode. Fix the syntax in ~/.sondera/env to enable policy enforcement."
            }
            Self::ServerRejected(_) => {
                "Sondera is running in passthrough mode. The governance service rejected the request due to a server-side policy configuration error; contact your admin."
            }
            Self::Unreachable(_)
            | Self::ServiceTimeout
            | Self::ServiceUnavailable(_)
            | Self::BudgetExceeded { .. }
            | Self::Panicked
            | Self::Message(_)
            | Self::Context { .. }
            | Self::Io(_)
            | Self::Json(_) => {
                "Sondera is running in passthrough mode. The governance service is temporarily unavailable."
            }
        }
    }

    /// One value of every variant, for tests that must cover the whole failure
    /// space — [`crate::runner::assert_fail_closed_matrix`] sweeps it so no
    /// failure mode turns an enforcement hook into a passthrough.
    ///
    /// Lives beside the enum so there is one list rather than one per test
    /// module. The list is hand-maintained, but a new variant cannot be added
    /// *silently*: [`Self::category`], [`Self::remediation`], and
    /// [`Self::fallback_context`] all match exhaustively, so the build breaks
    /// until its classification is decided — and this list is the next thing
    /// the author is looking at.
    #[must_use]
    pub fn every_variant() -> Vec<Self> {
        vec![
            Self::Config("bad env".into()),
            Self::Unreachable("connection refused".into()),
            Self::ServiceTimeout,
            Self::ServerRejected("schema mismatch".into()),
            Self::ServiceUnavailable("decode failed".into()),
            Self::BudgetExceeded { budget_secs: 30 },
            Self::Panicked,
            Self::message("unrecognized failure"),
            Self::context("while reading config", std::io::Error::other("io")),
            Self::Io(std::io::Error::other("io")),
            Self::Json(serde_json::from_str::<()>("{").expect_err("invalid JSON")),
        ]
    }
}

pub trait HookResultExt<T> {
    fn context(self, message: impl Into<String>) -> Result<T>;
    fn with_context(self, message: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E> HookResultExt<T> for std::result::Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.map_err(|source| HookError::context(message, source))
    }

    fn with_context(self, message: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|source| HookError::context(message(), source))
    }
}

impl<T> HookResultExt<T> for Option<T> {
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.ok_or_else(|| HookError::message(message.into()))
    }

    fn with_context(self, message: impl FnOnce() -> String) -> Result<T> {
        self.ok_or_else(|| HookError::message(message()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Classification from the harness client ───────────────────────────

    #[test]
    fn every_answered_request_is_a_server_rejection_not_a_network_fault() {
        // A harness that answered was reached and authenticated, so none of
        // these may steer the user toward connectivity checks.
        for error in [
            HarnessClientError::Server("Adjudication failed".into()),
            HarnessClientError::InvalidArgument("E_UNNORMALIZED_TRAJECTORY_EVENT".into()),
            HarnessClientError::NotFound("agent".into()),
            HarnessClientError::AlreadyExists("agent".into()),
        ] {
            let err = HookError::from(error);
            assert_eq!(err.category(), "server", "{err:?}");
        }
    }

    #[test]
    fn transport_failure_is_unreachable() {
        let err = HookError::from(HarnessClientError::Unavailable("connection refused".into()));
        assert!(matches!(err, HookError::Unreachable(_)), "{err:?}");
    }

    #[test]
    fn client_timeout_is_a_service_timeout() {
        let err = HookError::from(HarnessClientError::Timeout);
        assert!(matches!(err, HookError::ServiceTimeout), "{err:?}");
    }

    #[test]
    fn endpoint_misconfiguration_is_a_config_error_not_a_server_fault() {
        let err = HookError::from(HarnessClientError::Config("bad endpoint".into()));
        assert_eq!(err.category(), "config");
    }

    // ── Remediation text ─────────────────────────────────────────────────

    #[test]
    fn every_remediation_carries_the_sondera_prefix() {
        for error in HookError::every_variant() {
            assert!(
                error.remediation().starts_with("[sondera]"),
                "{error:?}: {}",
                error.remediation()
            );
        }
    }

    #[test]
    fn every_category_is_a_known_dedup_key() {
        for error in HookError::every_variant() {
            assert!(
                matches!(error.category(), "network" | "server" | "config"),
                "{error:?}: {}",
                error.category()
            );
        }
    }

    #[test]
    fn service_timeout_names_latency_and_claims_reachability() {
        let message = HookError::ServiceTimeout.remediation();
        assert!(message.contains("latency/load"));
        assert!(message.contains("reachable"));
    }

    #[test]
    fn hook_budget_timeout_does_not_claim_the_service_was_reachable() {
        // Setup may still have been in flight, so asserting reachability here
        // would send users to check a service that was never contacted.
        let message = HookError::BudgetExceeded { budget_secs: 30 }.remediation();
        assert!(message.contains("hook setup latency"));
        assert!(!message.contains("reachable"));
        assert!(!message.contains("sondera serve"));
    }

    #[test]
    fn server_rejection_does_not_steer_toward_connectivity() {
        let message = HookError::ServerRejected("schema".into()).remediation();
        assert!(message.contains("server-side"));
        assert!(!message.contains("sondera serve"));
    }

    // ── Fallback context ─────────────────────────────────────────────────

    #[test]
    fn a_config_fault_steers_at_the_file_not_at_connectivity() {
        let context = HookError::Config("bad env".into()).fallback_context();
        assert!(context.contains("~/.sondera/env"));
        assert!(!context.contains("temporarily unavailable"));
    }

    #[test]
    fn network_faults_never_send_the_user_to_edit_config() {
        for error in [
            HookError::Unreachable("refused".into()),
            HookError::ServiceTimeout,
            HookError::ServiceUnavailable("decode".into()),
            HookError::BudgetExceeded { budget_secs: 30 },
        ] {
            let context = error.fallback_context();
            assert!(context.contains("temporarily unavailable"), "{error:?}");
            assert!(!context.contains("~/.sondera/env"), "{error:?}");
        }
    }

    #[test]
    fn every_fallback_context_announces_passthrough_mode() {
        for error in HookError::every_variant() {
            assert!(
                error.fallback_context().contains("passthrough mode"),
                "{error:?}"
            );
        }
    }
}
