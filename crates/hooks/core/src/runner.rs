//! Shared fail-closed run loop for provider hook CLIs.
//!
//! Every adjudication hook must **fail closed**: the host agent only honors a
//! block/deny when the hook writes a decision to stdout and exits 0. A stdin or
//! parse error, a harness connection failure, a handler error, or a timeout
//! would otherwise escape as a non-zero exit with no decision on stdout, which
//! the host treats as "no opinion" and lets the action proceed (fail open).
//!
//! [`resolve_hook`] centralizes that contract so a provider adapter cannot
//! accidentally fail open: it reads the event, connects, and dispatches, and
//! funnels **every** failure into the provider's `degraded(&command, &error)`
//! response — which receives the classified [`crate::error::HookError`], so the
//! denial text can name the actual cause instead of always blaming connectivity.
//! This includes **panics**: the connect/dispatch future is run under
//! [`catch_unwind`](futures_util::future::FutureExt::catch_unwind), so an
//! `unwrap`, a slice out of bounds, or a stray `unreachable!()` in a provider
//! handler degrades to a deny instead of unwinding out of the process with no
//! decision on stdout (which the host would read as "no opinion" → fail open).
//!
//! The harness client (`sondera_harness_client::DEFAULT_TIMEOUT`) bounds the
//! connect and each adjudication RPC individually, but those budgets are
//! sequential, so a slow connect followed by a slow RPC can outlive the host's
//! own hook deadline. [`resolve_hook`] therefore also applies a single
//! [`hook_budget`] across the *whole* hook — stdin read included — so the
//! decision is always written well before the host gives up and proceeds
//! without one.

use std::fmt::Debug;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::LazyLock;
use std::time::Duration;

use futures_util::future::FutureExt;
use serde_json::Value;
use tokio::time::{Instant, timeout_at};

use crate::error::{HookError, Result};
use crate::read_stdin;

/// Default wall-clock budget for one hook invocation, covering the stdin read,
/// the harness connect, and the adjudication RPC together.
///
/// Host agents kill a hook that overruns their own deadline, and a killed hook
/// writes no decision — which the host reads as "no opinion" and lets the action
/// proceed. The budget must therefore sit under the host deadline (Claude Code
/// allows 60s per hook) while still covering a real adjudication.
///
/// 30s is chosen to bound the harness client's 30s connect *plus* its 30s
/// per-RPC budget, whose worst case is otherwise near a minute. It also has to
/// clear the guardrails: a single event costs a YARA scan plus one LLM call per
/// guardrail, which against a local 20B model on Ollama measures ~3s + ~5s each
/// — so the previous 8s budget could not complete even one shell-command
/// adjudication, and denied on timeout every time.
pub const DEFAULT_HOOK_BUDGET: Duration = Duration::from_secs(30);

/// Environment variable overriding [`DEFAULT_HOOK_BUDGET`], in whole seconds.
///
/// Raise it when guardrails run against a slow local model; lower it when the
/// host's own hook deadline is tighter than Claude Code's 60s. A value that is
/// unparseable or zero is ignored in favor of the default — a hook whose budget
/// is misconfigured to zero would deny every action — and one above
/// [`MAX_HOOK_BUDGET`] is capped there.
pub const HOOK_BUDGET_ENV: &str = "SONDERA_HOOK_BUDGET_SECS";

/// Ceiling on a [`HOOK_BUDGET_ENV`] override.
///
/// Far above any host's own hook deadline, so it never constrains a real
/// configuration. It exists to bound the value: the budget is added to an
/// `Instant` to form the deadline, and that addition *panics* on overflow —
/// before any of the panic guards below are in place. A hook that unwinds
/// writes no decision, which every host reads as "no opinion", so an
/// out-of-range budget would fail **open**.
pub const MAX_HOOK_BUDGET: Duration = Duration::from_secs(300);

/// The wall-clock budget for this process's hook invocation.
///
/// The environment is read once, so the deadline a hook enforces and the budget
/// it reports on overrun can never come from two different reads.
#[must_use]
pub fn hook_budget() -> Duration {
    static BUDGET: LazyLock<Duration> =
        LazyLock::new(|| parse_hook_budget(std::env::var(HOOK_BUDGET_ENV).ok().as_deref()));
    *BUDGET
}

/// Interpret a raw [`HOOK_BUDGET_ENV`] value. Split out so the clamping is
/// testable without a process-wide environment mutation.
fn parse_hook_budget(raw: Option<&str>) -> Duration {
    raw.and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map_or(DEFAULT_HOOK_BUDGET, Duration::from_secs)
        .min(MAX_HOOK_BUDGET)
}

/// Resolve a hook command to a response, **failing closed on every error path**.
///
/// The event is read from stdin (as raw JSON), then `connect` and `dispatch`
/// run. A stdin/parse error, a `connect` failure, a `dispatch` error, a panic,
/// or an overrun of the [`hook_budget`] all resolve to `degraded(&command, &error)`
/// rather than escaping as a process error — so the caller always has a
/// well-formed response to emit and the host never sees a bare non-zero exit on
/// an enforcement hook.
///
/// - `connect` performs the harness connection and returns the provider's
///   ready handler state (e.g. its `Hooks`).
/// - `dispatch` deserializes the raw event for `command` and runs the matching
///   handler.
///
/// The returned response is not written anywhere; the caller is responsible for
/// [`crate::output_response`] and any provider-specific exit-code handling
/// (e.g. Cursor's `exit(2)` on deny).
pub async fn resolve_hook<C, R, H, Connect, ConnectFut, Dispatch, DispatchFut>(
    command: C,
    degraded: impl Fn(&C, &HookError) -> R,
    connect: Connect,
    dispatch: Dispatch,
) -> R
where
    C: Clone + Debug,
    Connect: FnOnce() -> ConnectFut,
    ConnectFut: Future<Output = Result<H>>,
    Dispatch: FnOnce(H, C, Value) -> DispatchFut,
    DispatchFut: Future<Output = Result<R>>,
{
    let budget = hook_budget();
    let deadline = Instant::now() + budget;

    let raw_event = match read_event_within(deadline).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                error = %error,
                command = ?command,
                "Sondera hook could not read its event; failing closed"
            );
            return degraded(&command, &error);
        }
    };

    resolve_event(command, raw_event, deadline, degraded, connect, dispatch).await
}

/// Read the hook's raw JSON event from stdin, bounded by `deadline`.
///
/// The read runs on a blocking thread rather than inline: `read_to_string` on
/// stdin does not yield, so a host that holds the pipe open without sending EOF
/// would pin a runtime worker and make the surrounding timeout unable to fire.
/// On overrun the blocking read is abandoned (it cannot be cancelled) and the
/// caller fails closed — the process is about to emit its deny and exit.
///
/// # Errors
///
/// The failing stage is carried by the variant: a budget overrun is
/// [`HookError::BudgetExceeded`], a panicking reader is [`HookError::Panicked`],
/// and an unreadable or malformed event is [`HookError::Message`]. None of them
/// echo event content.
pub async fn read_event_within(deadline: Instant) -> Result<Value> {
    match timeout_at(deadline, tokio::task::spawn_blocking(read_stdin::<Value>)).await {
        Ok(Ok(Ok(value))) => Ok(value),
        Ok(Ok(Err(_))) => Err(HookError::message(
            "stdin could not be read or parsed as JSON",
        )),
        Ok(Err(_join)) => Err(HookError::Panicked),
        Err(_elapsed) => Err(HookError::BudgetExceeded {
            budget_secs: hook_budget().as_secs(),
        }),
    }
}

/// Connect, dispatch, and resolve to a response — failing closed on an error, a
/// panic, **or an overrun of `deadline`**.
///
/// Split out from [`resolve_hook`] (which owns the stdin read) so the
/// panic-safety and deadline of the enforcement path can be unit-tested without
/// driving real stdin. The connect/dispatch future is wrapped in
/// [`AssertUnwindSafe`] + `catch_unwind`: a handler error resolves to
/// `degraded` as before, and a *panic* is caught and also degrades rather than
/// unwinding out of the process.
async fn resolve_event<C, R, H, Connect, ConnectFut, Dispatch, DispatchFut>(
    command: C,
    raw_event: Value,
    deadline: Instant,
    degraded: impl Fn(&C, &HookError) -> R,
    connect: Connect,
    dispatch: Dispatch,
) -> R
where
    C: Clone + Debug,
    Connect: FnOnce() -> ConnectFut,
    ConnectFut: Future<Output = Result<H>>,
    Dispatch: FnOnce(H, C, Value) -> DispatchFut,
    DispatchFut: Future<Output = Result<R>>,
{
    let outcome = timeout_at(
        deadline,
        catch_hook_panic(async {
            let handler = connect().await?;
            dispatch(handler, command.clone(), raw_event).await
        }),
    )
    .await;

    let error = match outcome {
        Ok(Some(Ok(response))) => return response,
        Ok(Some(Err(error))) => {
            tracing::warn!(
                command = ?command,
                "Sondera hook adjudication failed; failing closed"
            );
            error
        }
        Ok(None) => {
            tracing::error!(
                command = ?command,
                "Sondera hook panicked during adjudication; failing closed"
            );
            HookError::Panicked
        }
        Err(_elapsed) => {
            tracing::error!(
                command = ?command,
                budget_secs = hook_budget().as_secs(),
                "Sondera hook exceeded its budget before enforcement completed; failing closed"
            );
            HookError::BudgetExceeded {
                budget_secs: hook_budget().as_secs(),
            }
        }
    };

    degraded(&command, &error)
}

/// Run a hook's connect/dispatch future to completion, **catching panics**.
///
/// [`resolve_hook`] gives its providers panic-safety for free, but a few hooks
/// (`claude`, `vscode`) own their stdin read, timeout, and degraded mapping and
/// cannot route through it. They wrap their connect/dispatch future in this
/// combinator so they get the same guard: a panic — an `unwrap`, a stray
/// `unreachable!()`, a slice out of bounds in a handler — is caught and
/// surfaced as `None` (the caller maps it to its fail-closed degraded response)
/// rather than unwinding out of the process with no decision on stdout, which
/// the host reads as "no opinion" and lets the action proceed (fail open).
///
/// Returns `Some(output)` when `future` completed, `None` when it panicked.
pub async fn catch_hook_panic<F, T>(future: F) -> Option<T>
where
    F: Future<Output = T>,
{
    AssertUnwindSafe(future).catch_unwind().await.ok()
}

/// Assert the full degraded-matrix invariant for a provider: every
/// adjudication-critical command must degrade to a deny, and every other
/// command must degrade open (not deny) — **for every failure mode**.
///
/// Providers call this from a unit test over their full command list so a new
/// enforcement hook cannot silently degrade open, an observation hook cannot
/// start over-blocking, and a newly added [`HookError`] variant cannot slip
/// through a `match` arm that quietly allows.
///
/// - `is_adjudication`: whether the command must fail closed.
/// - `degraded`: the provider's degraded-response builder.
/// - `is_deny`: whether a response actually blocks/denies.
pub fn assert_fail_closed_matrix<C: Debug, R>(
    commands: impl IntoIterator<Item = C>,
    is_adjudication: impl Fn(&C) -> bool,
    degraded: impl Fn(&C, &HookError) -> R,
    is_deny: impl Fn(&R) -> bool,
) {
    for command in commands {
        let must_deny = is_adjudication(&command);
        for error in HookError::every_variant() {
            let denied = is_deny(&degraded(&command, &error));
            if must_deny {
                assert!(
                    denied,
                    "adjudication command {command:?} must fail closed (deny) when degraded by {error:?}"
                );
            } else {
                assert!(
                    !denied,
                    "observation command {command:?} must degrade open (not deny) when degraded by {error:?}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HookError;

    #[derive(Clone, Debug)]
    struct Command;

    fn degraded(_command: &Command, _error: &HookError) -> &'static str {
        "DENY"
    }

    async fn ok_connect() -> Result<()> {
        Ok(())
    }

    /// A deadline no test can reach, so only the tested failure mode fires.
    fn far_future() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    #[tokio::test]
    async fn resolve_event_returns_handler_response_on_success() {
        let response =
            resolve_event(
                Command,
                Value::Null,
                far_future(),
                degraded,
                ok_connect,
                |_handler: (), _command: Command, _raw: Value| async move {
                    Ok::<_, HookError>("ALLOW")
                },
            )
            .await;
        assert_eq!(response, "ALLOW");
    }

    #[tokio::test]
    async fn resolve_event_degrades_on_dispatch_error() {
        let response = resolve_event(
            Command,
            Value::Null,
            far_future(),
            degraded,
            ok_connect,
            |_handler: (), _command: Command, _raw: Value| async move {
                Err::<&'static str, _>(HookError::message("adjudication failed"))
            },
        )
        .await;
        assert_eq!(response, "DENY", "a dispatch error must fail closed");
    }

    #[tokio::test]
    async fn resolve_event_degrades_on_dispatch_panic() {
        let response = resolve_event(
            Command,
            Value::Null,
            far_future(),
            degraded,
            ok_connect,
            |_handler: (), _command: Command, _raw: Value| async move {
                panic!("handler panicked mid-adjudication");
                #[allow(unreachable_code)]
                Ok::<_, HookError>("ALLOW")
            },
        )
        .await;
        assert_eq!(response, "DENY", "a panicking dispatch must fail closed");
    }

    #[tokio::test(start_paused = true)]
    async fn resolve_event_degrades_when_the_budget_is_exceeded() {
        let response = resolve_event(
            Command,
            Value::Null,
            Instant::now() + DEFAULT_HOOK_BUDGET,
            degraded,
            ok_connect,
            |_handler: (), _command: Command, _raw: Value| async move {
                // A harness that accepts the connection and then hangs: the
                // client's own 30s budget outlives the host's hook deadline.
                tokio::time::sleep(DEFAULT_HOOK_BUDGET * 4).await;
                Ok::<_, HookError>("ALLOW")
            },
        )
        .await;
        assert_eq!(response, "DENY", "a budget overrun must fail closed");
    }

    #[test]
    fn an_unset_or_unusable_budget_falls_back_to_the_default() {
        for raw in [None, Some(""), Some("not-a-number"), Some("-5"), Some("0")] {
            assert_eq!(parse_hook_budget(raw), DEFAULT_HOOK_BUDGET, "{raw:?}");
        }
    }

    #[test]
    fn a_configured_budget_is_honored() {
        assert_eq!(parse_hook_budget(Some(" 12 ")), Duration::from_secs(12));
    }

    #[test]
    fn an_out_of_range_budget_is_capped_rather_than_overflowing_the_deadline() {
        // `Instant + Duration` panics on overflow, and that addition happens
        // before any panic guard — an uncapped budget would unwind out of the
        // hook with no decision written, which every host reads as "no opinion".
        let budget = parse_hook_budget(Some(&u64::MAX.to_string()));

        assert_eq!(budget, MAX_HOOK_BUDGET);
        // The clamped value must actually be addable to an `Instant`.
        let _deadline = Instant::now() + budget;
    }

    #[tokio::test]
    async fn catch_hook_panic_returns_some_on_completion() {
        let out = catch_hook_panic(async { 7 }).await;
        assert_eq!(out, Some(7));
    }

    #[tokio::test]
    async fn catch_hook_panic_returns_none_on_panic() {
        let out = catch_hook_panic(async {
            panic!("boom");
            #[allow(unreachable_code)]
            0
        })
        .await;
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn resolve_event_degrades_on_connect_panic() {
        let response =
            resolve_event(
                Command,
                Value::Null,
                far_future(),
                degraded,
                || async {
                    panic!("connect panicked");
                    #[allow(unreachable_code)]
                    Ok::<(), HookError>(())
                },
                |_handler: (), _command: Command, _raw: Value| async move {
                    Ok::<_, HookError>("ALLOW")
                },
            )
            .await;
        assert_eq!(response, "DENY", "a panicking connect must fail closed");
    }
}
