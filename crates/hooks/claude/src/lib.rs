//! Sondera hook adapter for Claude Code.
//!
//! Exposes the `sondera hook claude` subtree: `install` / `uninstall` write the
//! hook block into `settings.json` at user, project, or local scope (see
//! [`install`]), and one subcommand per hook event reads that event's JSON on
//! stdin and writes a [`response::HookResponse`] on stdout. [`event`] holds the
//! event matrix and the 17 events `install` actually wires.
//!
//! Unlike most adapters, this crate owns its stdin read, budget, and degraded
//! mapping rather than delegating the whole loop to
//! [`sondera_hooks::runner::resolve_hook`] — the response shape is
//! per-event, so the fail-closed decision is made in
//! [`response::fail_closed_response`]. Preventive gates deny, retrospective
//! lifecycle hooks degrade open on a budget overrun specifically, and unhandled
//! events return no opinion. `crates/hooks/README.md` tabulates the full
//! posture.
//!
//! [`transcript`] reads Claude's session transcript for context the hook
//! payload omits; `truncate` bounds what is sent to the harness.
//!
//! Events are attributed to `provider = "anthropic"`, `platform =
//! "claude-code"`, under a `claude-code-<username>` agent id.
//! That id is the *install*; Claude's `session_id` is the run, and it
//! is the trajectory id every handler keys its events on. Collapsing the two
//! leaves the roster with a fresh single-run agent per session.
//!
//! Reference: <https://code.claude.com/docs/en/hooks>

pub mod event;
pub mod hooks;
pub mod install;
pub mod response;
pub mod transcript;
mod truncate;
pub mod types;

use crate::event::HookPlatform;
use crate::install::{InstallScope, install_hooks, uninstall_hooks};
use crate::response::{HookResponse, fail_closed_response as claude_fail_closed_response};
use clap::{Args, Subcommand};
pub use hooks::Hooks;
use serde_json::Value;
use sondera_harness_client::Agent;
use sondera_hooks::diagnostics::{hook_debug_enabled, should_warn};
use sondera_hooks::error::HookError;
use sondera_hooks::event::HookEvent;
use sondera_hooks::runner::{catch_hook_panic, hook_budget, read_event_within};
use sondera_hooks::{agent_id, flush_output, output_response};

#[derive(Args, Debug)]
pub struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(flatten)]
    Code(Command),
}

pub async fn run(cli: Cli) -> sondera_hooks::error::Result<()> {
    match cli.command {
        // Code connects to the harness lazily — install/uninstall and local
        // parse commands are handled before the harness is needed.
        Commands::Code(command) => main(command, cli.verbose, HookPlatform::ClaudeCode).await,
    }
}

/// The agent this hook reports as: the installation, not the session.
///
/// Sondera's identity model splits the two — an [`Agent`] is a long-lived
/// principal the roster names and policies can scope to, and a trajectory is one
/// run by that agent. Claude's `session_id` is the *run*, and every handler
/// already keys its trajectory on it, so the agent id has to come from
/// somewhere stable. [`sondera_hooks::agent_id`] is the `<platform>-<username>`
/// identity every other adapter registers.
fn hook_agent(platform: HookPlatform) -> Agent {
    Agent {
        id: agent_id(platform.as_str()),
        provider: "anthropic".to_string(),
        platform: platform.as_str().to_string(),
    }
}

fn degraded_hook_response(
    hook: &Command,
    error: &HookError,
    diagnostics_enabled: bool,
    hook_input: Option<&Value>,
    platform: HookPlatform,
) -> sondera_hooks::error::Result<HookResponse> {
    if should_warn(error.category()) {
        eprintln!("{}", error.remediation());
    }

    // Tag the degraded path so endpoint dashboards can pivot on
    // `error_id="E_HOOKS_CLAUDE_DEGRADED"` and split CnC connectivity errors
    // from event-decode / timeout failures via the `category` field. The
    // `error` field is gated on `SONDERA_HOOK_DEBUG` (`diagnostics_enabled`)
    // so raw error strings — which can leak prompt-derived context — stay off
    // the wire unless an operator explicitly asks for them.
    let hook_name = hook.hook_event_name().unwrap_or("unknown");
    if diagnostics_enabled {
        tracing::error!(
            error_id = "E_HOOKS_CLAUDE_DEGRADED",
            hook = %hook_name,
            platform = platform.as_str(),
            provider = platform.metric_provider(),
            category = error.category(),
            error = %error,
            "hooks.claude.degraded: fallback path entered"
        );
    } else {
        tracing::error!(
            error_id = "E_HOOKS_CLAUDE_DEGRADED",
            hook = %hook_name,
            platform = platform.as_str(),
            provider = platform.metric_provider(),
            category = error.category(),
            "hooks.claude.degraded: fallback path entered"
        );
    }

    if let Some(response) = claude_fail_closed_response(hook_name, hook_input, error) {
        return Ok(response);
    }

    if matches!(hook, Command::SessionStart) {
        return Ok(HookResponse::session_start_with_context(
            error.fallback_context().to_string(),
        ));
    }

    Ok(HookResponse::allow())
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    Install {
        #[arg(short = 'u', long, conflicts_with = "project")]
        user: bool,
        #[arg(short = 'p', long, conflicts_with = "user")]
        project: bool,
    },
    Uninstall {
        #[arg(short = 'u', long, conflicts_with = "project")]
        user: bool,
        #[arg(short = 'p', long, conflicts_with = "user")]
        project: bool,
    },
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    PostToolUseFailure,
    Notification,
    UserPromptSubmit,
    Stop,
    SubagentStart,
    SubagentStop,
    TeammateIdle,
    TaskCompleted,
    ConfigChange,
    InstructionsLoaded,
    WorktreeRemove,
    PreCompact,
    SessionStart,
    SessionEnd,
}

impl Command {
    fn hook_event_name(&self) -> Option<&'static str> {
        match self {
            Self::PreToolUse => Some("PreToolUse"),
            Self::PermissionRequest => Some("PermissionRequest"),
            Self::PostToolUse => Some("PostToolUse"),
            Self::PostToolUseFailure => Some("PostToolUseFailure"),
            Self::Notification => Some("Notification"),
            Self::UserPromptSubmit => Some("UserPromptSubmit"),
            Self::Stop => Some("Stop"),
            Self::SubagentStart => Some("SubagentStart"),
            Self::SubagentStop => Some("SubagentStop"),
            Self::TeammateIdle => Some("TeammateIdle"),
            Self::TaskCompleted => Some("TaskCompleted"),
            Self::ConfigChange => Some("ConfigChange"),
            Self::InstructionsLoaded => Some("InstructionsLoaded"),
            Self::WorktreeRemove => Some("WorktreeRemove"),
            Self::PreCompact => Some("PreCompact"),
            Self::SessionStart => Some("SessionStart"),
            Self::SessionEnd => Some("SessionEnd"),
            Self::Install { .. } | Self::Uninstall { .. } => None,
        }
    }
}

impl HookEvent for Command {
    fn is_adjudication(&self) -> bool {
        self.hook_event_name()
            .is_some_and(crate::event::is_fail_closed_hook)
    }
}

pub async fn main(
    cmd: Command,
    verbose: bool,
    platform: HookPlatform,
) -> sondera_hooks::error::Result<()> {
    match cmd {
        Command::Install { user, project } => {
            let scope = match (user, project) {
                (true, _) => InstallScope::User,
                (_, true) => InstallScope::Project,
                _ => InstallScope::Local,
            };
            install_hooks(scope, verbose)?;
            Ok(())
        }
        Command::Uninstall { user, project } => {
            let scope = match (user, project) {
                (true, _) => InstallScope::User,
                (_, true) => InstallScope::Project,
                _ => InstallScope::Local,
            };
            uninstall_hooks(scope)?;
            Ok(())
        }
        hook => {
            let diagnostics_enabled = verbose || hook_debug_enabled();
            // Read stdin once for all hook commands, under the same budget the
            // adjudication runs against — an unbounded read would hang past the
            // host's hook deadline, and propagating a read error out of `run`
            // would exit non-zero with no decision on stdout, which Claude reads
            // as "no opinion" and lets the action proceed. The budget is the
            // shared one, so every provider enforces the same wall-clock ceiling
            // ahead of the host's own hook deadline.
            let deadline = tokio::time::Instant::now() + hook_budget();
            let raw_event: Value = match read_event_within(deadline).await {
                Ok(value) => value,
                Err(error) => {
                    let response =
                        degraded_hook_response(&hook, &error, diagnostics_enabled, None, platform)?;
                    output_response(response)?;
                    flush_output();
                    return Ok(());
                }
            };

            let timeout_hook = hook.clone();
            let raw_event_for_degraded = raw_event.clone();
            let response = match tokio::time::timeout_at(
                deadline,
                catch_hook_panic(async {
                    let agent_def = hook_agent(platform);
                    // Try connecting to the harness; if it fails, handle degraded mode
                    let mut hooks = match sondera_harness_client::connect_harness_for_hook(
                        &agent_def,
                        "claude-code",
                    )
                    .await
                    {
                        Ok(harness) => Hooks::new(harness, agent_def, platform),
                        Err(err) => {
                            return degraded_hook_response(
                                &hook,
                                &HookError::from(err),
                                diagnostics_enabled,
                                Some(&raw_event),
                                platform,
                            );
                        }
                    };

                    match hook {
                        Command::PreToolUse => Ok(hooks
                            .handle_pre_tool_use(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::PermissionRequest => Ok(hooks
                            .handle_permission_request(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::PostToolUse => Ok(hooks
                            .handle_post_tool_use(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::PostToolUseFailure => Ok(hooks
                            .handle_post_tool_use_failure(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::Notification => Ok(hooks
                            .handle_notification(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::UserPromptSubmit => Ok(hooks
                            .handle_user_prompt_submit(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::Stop => Ok(hooks
                            .handle_stop(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::SubagentStart => Ok(hooks
                            .handle_subagent_start(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::SubagentStop => Ok(hooks
                            .handle_subagent_stop(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::TeammateIdle => Ok(hooks
                            .handle_teammate_idle(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::TaskCompleted => Ok(hooks
                            .handle_task_completed(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::ConfigChange => Ok(hooks
                            .handle_config_change(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::InstructionsLoaded => {
                            Ok(hooks
                                .handle_instructions_loaded(serde_json::from_value(raw_event)?)?)
                        }
                        Command::WorktreeRemove => {
                            Ok(hooks.handle_worktree_remove(serde_json::from_value(raw_event)?)?)
                        }
                        Command::PreCompact => Ok(hooks
                            .handle_pre_compact(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::SessionStart => Ok(hooks
                            .handle_session_start(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::SessionEnd => Ok(hooks
                            .handle_session_end(serde_json::from_value(raw_event)?)
                            .await?),
                        Command::Install { .. } | Command::Uninstall { .. } => {
                            unreachable!()
                        }
                    }
                }),
            )
            .await
            {
                Ok(Some(Ok(response))) => response,
                Ok(Some(Err(err))) => degraded_hook_response(
                    &timeout_hook,
                    &err,
                    diagnostics_enabled,
                    Some(&raw_event_for_degraded),
                    platform,
                )?,
                Ok(None) => degraded_hook_response(
                    &timeout_hook,
                    &HookError::Panicked,
                    diagnostics_enabled,
                    Some(&raw_event_for_degraded),
                    platform,
                )?,
                Err(_) => degraded_hook_response(
                    &timeout_hook,
                    &HookError::BudgetExceeded {
                        budget_secs: hook_budget().as_secs(),
                    },
                    diagnostics_enabled,
                    Some(&raw_event_for_degraded),
                    platform,
                )?,
            };
            output_response(response)?;
            flush_output();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::{
        BlockDecision, HookSpecificOutput, PermissionDecision, PermissionRequestBehavior,
    };
    use serde_json::json;

    fn assert_hook_budget_timeout_reason(reason: &str) {
        assert!(
            reason.contains("timed out"),
            "timeout reason should name timeout cause: {reason}"
        );
        assert!(
            reason.contains("hook setup latency"),
            "timeout reason should point at hook setup latency: {reason}"
        );
        assert!(
            !reason.contains("reachable"),
            "outer hook timeout reason must not claim harness reachability: {reason}"
        );
        assert!(
            !reason.contains("sondera serve"),
            "timeout reason must not steer toward connectivity checks: {reason}"
        );
        assert!(
            !reason.contains("connectivity"),
            "timeout reason must not steer toward connectivity: {reason}"
        );
    }

    /// The agent is the installation, so two sessions by one user report as one
    /// agent. Keying it on `session_id` instead — the shape this replaced — gave
    /// every session its own single-run agent, and the run feed had no stable
    /// identity to resolve a trajectory against.
    #[test]
    fn the_agent_id_is_stable_across_sessions() {
        let agent = hook_agent(HookPlatform::ClaudeCode);

        assert_eq!(agent, hook_agent(HookPlatform::ClaudeCode));
        // `<platform>-<username>`, which a bare session uuid can never look
        // like — the id names a user's install, and a trajectory id names one
        // of its runs.
        assert!(
            agent.id.starts_with("claude-code-"),
            "agent id should be <platform>-<username>: {}",
            agent.id
        );
        assert!(
            agent.id.len() > "claude-code-".len(),
            "agent id should carry a username: {}",
            agent.id
        );
    }

    /// Attribution the crate docs promise, asserted rather than assumed.
    #[test]
    fn events_are_attributed_to_anthropic_claude_code() {
        let agent = hook_agent(HookPlatform::ClaudeCode);

        assert_eq!(agent.provider, "anthropic");
        assert_eq!(agent.platform, "claude-code");
    }

    #[test]
    fn degraded_pre_tool_use_fails_closed_with_deny_json() {
        let response = degraded_hook_response(
            &Command::PreToolUse,
            &HookError::Unreachable("transport unavailable".into()),
            false,
            None,
            HookPlatform::ClaudeCode,
        )
        .expect("pre-tool fallback should serialize as a deny response");

        match response.hook_specific_output.as_ref() {
            Some(HookSpecificOutput::PreToolUse(output)) => {
                assert_eq!(output.hook_event_name, "PreToolUse");
                assert_eq!(output.permission_decision, Some(PermissionDecision::Deny));
                assert!(
                    output
                        .permission_decision_reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains("sondera serve")),
                    "deny reason should include an actionable diagnostic step"
                );
            }
            other => panic!("expected PreToolUse deny output, got {other:?}"),
        }
    }

    #[test]
    fn degraded_permission_request_fails_closed_with_interrupt() {
        let response = degraded_hook_response(
            &Command::PermissionRequest,
            &HookError::ServiceUnavailable("permission adjudication failed".into()),
            false,
            None,
            HookPlatform::ClaudeCode,
        )
        .expect("permission fallback should serialize as a deny response");

        match response.hook_specific_output.as_ref() {
            Some(HookSpecificOutput::PermissionRequest(output)) => {
                assert_eq!(output.hook_event_name, "PermissionRequest");
                assert_eq!(output.decision.behavior, PermissionRequestBehavior::Deny);
                assert_eq!(output.decision.interrupt, Some(true));
                assert!(
                    output
                        .decision
                        .message
                        .as_deref()
                        .is_some_and(|message| message.contains("sondera serve")),
                    "deny message should include an actionable diagnostic step"
                );
            }
            other => panic!("expected PermissionRequest deny output, got {other:?}"),
        }
    }

    #[test]
    fn degraded_permission_request_hook_budget_timeout_fails_closed_with_interrupt() {
        let timeout = HookError::BudgetExceeded { budget_secs: 30 };

        let response = degraded_hook_response(
            &Command::PermissionRequest,
            &timeout,
            false,
            None,
            HookPlatform::ClaudeCode,
        )
        .expect("permission timeout fallback should serialize as a deny response");

        match response.hook_specific_output.as_ref() {
            Some(HookSpecificOutput::PermissionRequest(output)) => {
                assert_eq!(output.hook_event_name, "PermissionRequest");
                assert_eq!(output.decision.behavior, PermissionRequestBehavior::Deny);
                assert_eq!(output.decision.interrupt, Some(true));
                assert_hook_budget_timeout_reason(
                    output.decision.message.as_deref().expect("deny message"),
                );
            }
            other => panic!("expected PermissionRequest deny output, got {other:?}"),
        }
    }

    #[test]
    fn degraded_user_prompt_submit_fails_closed_with_block() {
        let response = degraded_hook_response(
            &Command::UserPromptSubmit,
            &HookError::ServiceUnavailable("prompt".into()),
            false,
            None,
            HookPlatform::ClaudeCode,
        )
        .expect("prompt fallback should serialize as a block response");

        assert_eq!(response.decision, Some(BlockDecision::Block));
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("sondera serve")),
            "block reason should include an actionable diagnostic step"
        );
        assert!(matches!(
            response.hook_specific_output,
            Some(HookSpecificOutput::UserPromptSubmit(_))
        ));
    }

    #[test]
    fn degraded_blockable_lifecycle_hooks_fail_closed_on_service_errors() {
        for command in [
            Command::ConfigChange,
            Command::PreCompact,
            Command::SubagentStop,
        ] {
            let response = degraded_hook_response(
                &command,
                &HookError::ServiceUnavailable("hook".into()),
                false,
                None,
                HookPlatform::ClaudeCode,
            )
            .expect("blockable lifecycle fallback should serialize as a block response");

            assert_eq!(response.decision, Some(BlockDecision::Block), "{command:?}");
            assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("sondera serve")),
                "{command:?} should include actionable diagnostic guidance"
            );
        }

        for command in [Command::TaskCompleted, Command::TeammateIdle] {
            let response = degraded_hook_response(
                &command,
                &HookError::ServiceUnavailable("hook".into()),
                false,
                None,
                HookPlatform::ClaudeCode,
            )
            .expect("team lifecycle fallback should serialize as a stop response");

            assert!(
                !response.continue_execution,
                "{command:?} must halt with continue=false"
            );
            assert!(response.decision.is_none(), "{command:?}");
            assert!(
                response
                    .stop_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("sondera serve")),
                "{command:?} should include actionable diagnostic guidance"
            );
        }
    }

    #[test]
    fn degraded_hook_budget_timeout_lifecycle_hooks_degrade_open_without_doctor_steer() {
        for command in [
            Command::SubagentStop,
            Command::TaskCompleted,
            Command::TeammateIdle,
        ] {
            let timeout = HookError::BudgetExceeded { budget_secs: 30 };

            let response =
                degraded_hook_response(&command, &timeout, false, None, HookPlatform::ClaudeCode)
                    .expect("timeout fallback should serialize as a degraded-open warning");

            assert!(response.continue_execution, "{command:?}");
            assert!(response.decision.is_none(), "{command:?}");
            assert!(response.stop_reason.is_none(), "{command:?}");
            let reason = response.system_message.as_deref().expect("system message");
            assert_hook_budget_timeout_reason(reason);
        }
    }

    #[test]
    fn degraded_stop_timeout_allows_without_doctor_steer() {
        let timeout = HookError::BudgetExceeded { budget_secs: 30 };

        let response = degraded_hook_response(
            &Command::Stop,
            &timeout,
            false,
            None,
            HookPlatform::ClaudeCode,
        )
        .expect("Stop timeout fallback should allow Claude to stop");

        assert_eq!(
            serde_json::to_value(response).expect("serialize Stop timeout response"),
            serde_json::json!({})
        );
    }

    #[test]
    fn degraded_pre_compact_timeout_stays_fail_closed() {
        let timeout = HookError::BudgetExceeded { budget_secs: 30 };

        let response = degraded_hook_response(
            &Command::PreCompact,
            &timeout,
            false,
            None,
            HookPlatform::ClaudeCode,
        )
        .expect("PreCompact timeout fallback should serialize as a block response");

        assert_eq!(response.decision, Some(BlockDecision::Block));
        let reason = response.reason.as_deref().expect("block reason");
        assert_hook_budget_timeout_reason(reason);
    }

    #[test]
    fn degraded_config_change_timeout_stays_fail_closed() {
        let timeout = HookError::BudgetExceeded { budget_secs: 30 };

        let response = degraded_hook_response(
            &Command::ConfigChange,
            &timeout,
            false,
            None,
            HookPlatform::ClaudeCode,
        )
        .expect("ConfigChange timeout fallback should serialize as a block response");

        assert_eq!(response.decision, Some(BlockDecision::Block));
        let reason = response.reason.as_deref().expect("block reason");
        assert_hook_budget_timeout_reason(reason);
    }

    #[test]
    fn degraded_policy_settings_config_change_degrades_open() {
        let raw = json!({
            "hook_event_name": "ConfigChange",
            "source": "policy_settings",
        });
        let response = degraded_hook_response(
            &Command::ConfigChange,
            &HookError::ServiceUnavailable("hook".into()),
            false,
            Some(&raw),
            HookPlatform::ClaudeCode,
        )
        .expect("policy_settings config changes cannot be blocked by Claude");

        assert_eq!(
            serde_json::to_value(response).expect("serialize response"),
            serde_json::json!({})
        );

        let timeout = HookError::BudgetExceeded { budget_secs: 30 };
        let timeout_response = degraded_hook_response(
            &Command::ConfigChange,
            &timeout,
            false,
            Some(&raw),
            HookPlatform::ClaudeCode,
        )
        .expect("policy_settings timeout config changes cannot be blocked by Claude");

        assert_eq!(
            serde_json::to_value(timeout_response).expect("serialize response"),
            serde_json::json!({})
        );
    }

    #[test]
    fn session_start_server_rejection_points_at_the_admin() {
        let response = degraded_hook_response(
            &Command::SessionStart,
            &HookError::ServerRejected("schema mismatch".into()),
            false,
            None,
            HookPlatform::ClaudeCode,
        )
        .expect("session fallback should include guidance");

        let context = response
            .hook_specific_output
            .as_ref()
            .and_then(|output| match output {
                HookSpecificOutput::SessionStart(output) => output.additional_context.as_deref(),
                _ => None,
            })
            .expect("session fallback should include additional context");

        assert!(context.contains("server-side"));
        assert!(!context.contains("temporarily unavailable"));
    }

    #[test]
    fn command_hook_event_name_is_explicit_for_security_dispatch() {
        assert_eq!(Command::PreToolUse.hook_event_name(), Some("PreToolUse"));
        assert_eq!(Command::PostToolUse.hook_event_name(), Some("PostToolUse"));
        assert_eq!(
            Command::UserPromptSubmit.hook_event_name(),
            Some("UserPromptSubmit")
        );
        assert_eq!(
            (Command::Install {
                user: false,
                project: false,
            })
            .hook_event_name(),
            None
        );
    }

    #[test]
    fn degraded_post_tool_use_fails_closed_with_redacted_output() {
        let hook_input = json!({
            "tool_response": {
                "stdout": "secret tool output",
                "stderr": "secret error",
                "interrupted": true,
            }
        });
        let response = degraded_hook_response(
            &Command::PostToolUse,
            &HookError::ServiceUnavailable("post tool".into()),
            false,
            Some(&hook_input),
            HookPlatform::ClaudeCode,
        )
        .expect("post-tool fallback should block with redacted output");

        assert_eq!(response.decision, Some(BlockDecision::Block));
        match response.hook_specific_output.as_ref() {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                let updated = output
                    .updated_tool_output
                    .as_ref()
                    .expect("post-tool fallback should replace tool output");
                assert_eq!(
                    updated["stdout"],
                    "Output withheld by Sondera policy. See hook block reason."
                );
                assert_eq!(updated["interrupted"], false);
            }
            other => panic!("expected PostToolUse block output, got {other:?}"),
        }
    }

    #[test]
    fn degraded_post_tool_use_hook_budget_timeout_blocks_with_redacted_output() {
        let hook_input = json!({
            "tool_response": {
                "stdout": "secret tool output",
                "stderr": "secret error",
                "interrupted": true,
            }
        });
        let timeout = HookError::BudgetExceeded { budget_secs: 30 };

        let response = degraded_hook_response(
            &Command::PostToolUse,
            &timeout,
            false,
            Some(&hook_input),
            HookPlatform::ClaudeCode,
        )
        .expect("post-tool timeout fallback should block with redacted output");

        assert_eq!(response.decision, Some(BlockDecision::Block));
        assert_hook_budget_timeout_reason(response.reason.as_deref().expect("block reason"));
        match response.hook_specific_output.as_ref() {
            Some(HookSpecificOutput::PostToolUse(output)) => {
                let updated = output
                    .updated_tool_output
                    .as_ref()
                    .expect("post-tool fallback should replace tool output");
                assert_eq!(
                    updated["stdout"],
                    "Output withheld by Sondera policy. See hook block reason."
                );
                assert_eq!(updated["interrupted"], false);
            }
            other => panic!("expected PostToolUse block output, got {other:?}"),
        }
    }

    #[test]
    fn degraded_observation_hook_still_allows() {
        let response = degraded_hook_response(
            &Command::Notification,
            &HookError::Unreachable("observer unavailable".into()),
            false,
            None,
            HookPlatform::ClaudeCode,
        )
        .expect("non-adjudication hooks should continue in fallback mode");

        assert!(response.continue_execution);
        assert!(response.hook_specific_output.is_none());
        assert!(response.decision.is_none());
    }

    #[test]
    fn command_adjudication_uses_canonical_fail_closed_matrix() {
        for command in [
            Command::ConfigChange,
            Command::PermissionRequest,
            Command::PostToolUse,
            Command::PreCompact,
            Command::PreToolUse,
            Command::SubagentStop,
            Command::TaskCompleted,
            Command::TeammateIdle,
            Command::UserPromptSubmit,
        ] {
            assert!(command.is_adjudication(), "{command:?}");
        }

        for command in [
            Command::InstructionsLoaded,
            Command::Notification,
            Command::PostToolUseFailure,
            Command::SessionEnd,
            Command::SessionStart,
            Command::Stop,
            Command::SubagentStart,
            Command::WorktreeRemove,
        ] {
            assert!(!command.is_adjudication(), "{command:?}");
        }
    }
}
