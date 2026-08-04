//! Shared helpers for handling harness adjudication results in hook adapters.

use sondera_types::{Adjudicated, Decision};

use crate::error::HookError;

/// Shared fail-closed denial shown when enforcement cannot reach the harness.
pub const FAIL_CLOSED_REASON: &str = "Sondera policy enforcement is unavailable, so this action was \
                                  denied by fail-closed enforcement. Check that `sondera serve` is \
                                  running and reachable at SONDERA_HARNESS_ENDPOINT, or contact \
                                  your admin.";

/// Fail-closed denial shown when the harness was reachable but adjudication
/// exceeded the hook budget. This deliberately avoids the connectivity steer
/// because a timeout can happen after a successful connection.
pub const FAIL_CLOSED_REASON_TIMEOUT: &str = "Sondera policy enforcement timed out, so this action \
                                  was denied by fail-closed enforcement. The service was reachable, \
                                  but adjudication exceeded the hook budget; check harness \
                                  latency/load or contact your admin.";

/// Fail-closed denial shown when the Claude hook's outer budget expired before
/// the hook handler completed. This avoids asserting that the harness was
/// reachable because setup/connect work may still have been in progress.
pub const FAIL_CLOSED_REASON_HOOK_TIMEOUT: &str = "Sondera policy enforcement timed out, so this \
                                  action was denied by fail-closed enforcement. The hook exceeded \
                                  its budget before enforcement completed; check hook setup \
                                  latency, harness latency/load, or contact your admin.";

/// Fail-closed denial shown when the harness was reachable but rejected the
/// request server-side (policy/schema error). Deliberately omits the
/// connectivity steer — the service is up — and points the user at an admin
/// instead. See [`HookError::ServerRejected`].
pub const FAIL_CLOSED_REASON_SERVER: &str = "Sondera policy enforcement rejected this action due to \
                                  a server-side policy configuration error (not a connectivity \
                                  issue). Contact your admin.";

/// Tool-output variant of [`FAIL_CLOSED_REASON_SERVER`] for the PostToolUse
/// degraded path, which blocks tool output rather than an action.
pub const FAIL_CLOSED_REASON_SERVER_POST_TOOL: &str = "Sondera policy enforcement rejected this \
                                  tool output due to a server-side policy configuration error (not \
                                  a connectivity issue). Contact your admin.";

/// Tool-output variant of [`FAIL_CLOSED_REASON`] for the PostToolUse degraded
/// path, which blocks tool output rather than an action.
pub const FAIL_CLOSED_REASON_POST_TOOL: &str = "Sondera policy enforcement is unavailable, so this \
                                  tool output was blocked by fail-closed enforcement. Check that \
                                  `sondera serve` is running and reachable at \
                                  SONDERA_HARNESS_ENDPOINT, or contact your admin.";

/// Tool-output variant of [`FAIL_CLOSED_REASON_TIMEOUT`] for the PostToolUse
/// degraded path.
pub const FAIL_CLOSED_REASON_TIMEOUT_POST_TOOL: &str = "Sondera policy enforcement timed out, so \
                                  this tool output was blocked by fail-closed enforcement. The \
                                  service was reachable, but adjudication exceeded the hook budget; \
                                  check harness latency/load or contact your admin.";

/// Tool-output variant of [`FAIL_CLOSED_REASON_HOOK_TIMEOUT`] for the
/// PostToolUse degraded path.
pub const FAIL_CLOSED_REASON_HOOK_TIMEOUT_POST_TOOL: &str = "Sondera policy enforcement timed out, \
                                  so this tool output was blocked by fail-closed enforcement. The \
                                  hook exceeded its budget before enforcement completed; check hook \
                                  setup latency, harness latency/load, or contact your admin.";

/// Select the fail-closed reason text for a failure. Timeouts and server-side
/// rejections get cause-specific messages (no connectivity steer); every other
/// failure keeps the connectivity/credentials default.
pub fn fail_closed_reason(error: &HookError) -> &'static str {
    match error {
        HookError::BudgetExceeded { .. } => FAIL_CLOSED_REASON_HOOK_TIMEOUT,
        HookError::ServiceTimeout => FAIL_CLOSED_REASON_TIMEOUT,
        HookError::ServerRejected(_) => FAIL_CLOSED_REASON_SERVER,
        _ => FAIL_CLOSED_REASON,
    }
}

/// Select the PostToolUse fail-closed reason text for a failure.
pub fn fail_closed_reason_post_tool(error: &HookError) -> &'static str {
    match error {
        HookError::BudgetExceeded { .. } => FAIL_CLOSED_REASON_HOOK_TIMEOUT_POST_TOOL,
        HookError::ServiceTimeout => FAIL_CLOSED_REASON_TIMEOUT_POST_TOOL,
        HookError::ServerRejected(_) => FAIL_CLOSED_REASON_SERVER_POST_TOOL,
        _ => FAIL_CLOSED_REASON_POST_TOOL,
    }
}

/// Log non-allow decisions returned on hook paths that cannot enforce a block.
pub fn warn_unenforceable_decision(hook: &str, adjudicated: &Adjudicated) {
    if adjudicated.decision != Decision::Allow {
        tracing::warn!(
            hook = hook,
            decision = ?adjudicated.decision,
            reason = ?adjudicated.reason.as_deref(),
            "adjudication decision observed on non-blocking hook response path"
        );
    }
}
