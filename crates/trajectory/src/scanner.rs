//! Trajectory scanner: structured extraction over a runtime-selected provider.
//!
//! Provides [`TrajectoryScanner`] — the entry point for scanning trajectory
//! logs at message-level and transcript-level granularity. Named "scanner"
//! following AISI terminology for automated pattern detection tools.

use std::future::Future;
use std::pin::Pin;

use schemars::JsonSchema;
use serde::{Serialize, de::DeserializeOwned};
use sondera_provider::{AgentClientExt, Client, ClientConfig};
use sondera_types::{
    Control, Event, EventScanResult, Observation, PromptRole, TrajectoryEvent, TranscriptDigest,
    TranscriptScanResult,
};
use tracing::instrument;

use crate::config::ScannerConfig;
use crate::error::ScannerError;
use crate::rubric;

/// The platform whose turn-end signal is not a session-end signal.
const CODEX_PLATFORM: &str = "codex";

/// Boxed async scanner result used by [`TrajectoryScannerBackend`].
pub type ScannerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ScannerError>> + Send + 'a>>;

/// The background scanner contract the harness consumes.
///
/// Production uses [`TrajectoryScanner`]. This is a trait rather than the
/// concrete type so the harness's dispatch, persistence, and `Control::Scanned`
/// emission are testable without a live model: a test supplies a deterministic
/// backend and asserts on what got written.
pub trait TrajectoryScannerBackend: Send + Sync {
    /// Scan a single trajectory event.
    fn scan_event<'a>(&'a self, event: &'a Event) -> ScannerFuture<'a, EventScanResult>;

    /// Produce a final transcript digest.
    fn digest_transcript<'a>(
        &'a self,
        trajectory_id: &'a str,
        events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptDigest>;

    /// Produce a full behavioral transcript scan.
    fn scan_transcript<'a>(
        &'a self,
        trajectory_id: &'a str,
        events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptScanResult>;

    /// Produce a non-terminal transcript digest.
    fn digest_interim_transcript<'a>(
        &'a self,
        trajectory_id: &'a str,
        events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptDigest>;

    /// Active provider label for low-cardinality telemetry and log fields.
    fn provider_name(&self) -> &'static str;

    /// Active model name for telemetry and log fields.
    fn model(&self) -> &str;
}

/// LLM-based trajectory log scanner.
///
/// Implements three scanning granularities from the AISI pipeline:
///
/// 1. **Message-level** ([`scan_event`](Self::scan_event)) — classify and
///    grade individual trajectory events.
/// 2. **Transcript digest** ([`digest_transcript`](Self::digest_transcript)) —
///    summarize a full trajectory into phases and statistics.
/// 3. **Transcript scan** ([`scan_transcript`](Self::scan_transcript)) —
///    full behavioral analysis with signal detection.
///
/// The provider is chosen at runtime from [`ScannerConfig`], so nothing here is
/// gated on a compile-time vendor feature.
pub struct TrajectoryScanner {
    client: Client,
    config: ScannerConfig,
}

impl TrajectoryScanner {
    /// Whether a harness event should trigger transcript-level scanning.
    ///
    /// Transcript-level analysis is only meaningful once a trajectory reaches a
    /// terminal control state (`Completed`, `Failed`, or `Terminated`).
    #[must_use]
    pub fn should_scan_transcript_for_event(event: &Event) -> bool {
        matches!(&event.event, TrajectoryEvent::Control(control) if control.is_terminal())
    }

    /// Whether a non-terminal event should refresh the trajectory digest.
    ///
    /// Codex's `Stop` hook is turn-scoped rather than session-scoped, so it must
    /// not mark the Sondera trajectory complete — one Codex session stays one
    /// trajectory. It is still the right moment to refresh the digest for a
    /// long-running session.
    ///
    /// `Stop` is recognised by its shape rather than by a hook-event name: the
    /// upstream implementation reads `codex.hook_event_name` off the agent
    /// card, and this workspace's [`Agent`](sondera_types::Agent) carries no
    /// card. The codex adapter emits an assistant-role `Prompt` from exactly one
    /// place — its `Stop` handler, carrying `last_assistant_message` — so the
    /// pair (platform, assistant prompt) identifies the same events the name
    /// would have. A codex adapter that starts emitting assistant prompts
    /// elsewhere would widen this, costing extra digests and nothing else.
    #[must_use]
    pub fn should_digest_interim_transcript_for_event(event: &Event) -> bool {
        event.agent.platform == CODEX_PLATFORM
            && matches!(
                &event.event,
                TrajectoryEvent::Observation(Observation::Prompt(prompt))
                    if prompt.role == PromptRole::Assistant
            )
    }

    /// Build a scanner, constructing the provider client from `config`.
    ///
    /// # Errors
    ///
    /// [`ScannerError::ClientBuild`] if the provider client cannot be built —
    /// an unreachable endpoint, a missing Google Cloud project, or
    /// unresolvable Application Default Credentials.
    pub fn new(config: ScannerConfig) -> Result<Self, ScannerError> {
        let client = config.provider.client(
            &ClientConfig::new(config.api_key.expose())
                .maybe_base_url(config.base_url.as_deref())
                .maybe_project(config.project.as_deref())
                .maybe_location(config.location.as_deref()),
        )?;
        Ok(Self { client, config })
    }

    // ── Message-level scanning ──────────────────────────────────────────

    /// Scan a single trajectory event (message-level granularity).
    ///
    /// # Errors
    ///
    /// [`ScannerError::Timeout`] or [`ScannerError::Extraction`] when the model
    /// call fails or its output does not satisfy the rubric schema.
    #[instrument(
        skip_all,
        fields(
            event.id = %event.event_id,
            agent.id = %event.agent.id,
            trajectory.id = %event.trajectory_id,
        )
    )]
    pub async fn scan_event(&self, event: &Event) -> Result<EventScanResult, ScannerError> {
        let user_prompt = rubric::render_event_prompt(event);
        self.extract(rubric::EVENT_SCAN_RUBRIC, &user_prompt).await
    }

    // ── Transcript-level digest ─────────────────────────────────────────

    /// Produce a hierarchical digest of a trajectory transcript.
    ///
    /// # Errors
    ///
    /// [`ScannerError::NoEvents`] for an empty transcript; otherwise as
    /// [`scan_event`](Self::scan_event).
    #[instrument(
        skip_all,
        fields(trajectory.id = %trajectory_id, event_count = events.len()),
    )]
    pub async fn digest_transcript(
        &self,
        trajectory_id: &str,
        events: &[Event],
    ) -> Result<TranscriptDigest, ScannerError> {
        if events.is_empty() {
            return Err(ScannerError::NoEvents);
        }

        self.render_digest(trajectory_id, events).await
    }

    /// The digest extraction both the terminal and interim paths share. Which
    /// one ran is already recorded by the caller's `#[instrument]` span.
    async fn render_digest(
        &self,
        trajectory_id: &str,
        events: &[Event],
    ) -> Result<TranscriptDigest, ScannerError> {
        let user_prompt = rubric::render_transcript_prompt(
            "Summarize this trajectory transcript using the rubric above.",
            trajectory_id,
            events,
        );
        let mut digest: TranscriptDigest = self
            .extract(rubric::TRANSCRIPT_DIGEST_RUBRIC, &user_prompt)
            .await?;
        // The rubric asks the model to summarize a transcript, not to identify
        // it: pin the id from the caller so a hallucinated one cannot key a
        // digest to the wrong run.
        digest.trajectory_id = trajectory_id.to_string();
        Ok(digest)
    }

    /// Produce a non-terminal digest for an active trajectory.
    ///
    /// # Errors
    ///
    /// As [`digest_transcript`](Self::digest_transcript).
    #[instrument(
        skip_all,
        fields(trajectory.id = %trajectory_id, event_count = events.len()),
    )]
    pub async fn digest_interim_transcript(
        &self,
        trajectory_id: &str,
        events: &[Event],
    ) -> Result<TranscriptDigest, ScannerError> {
        if events.is_empty() {
            return Err(ScannerError::NoEvents);
        }

        let mut digest = self.render_digest(trajectory_id, events).await?;
        digest.interim = true;
        Ok(digest)
    }

    // ── Transcript-level behavioral scan ────────────────────────────────

    /// Full behavioral scan of a trajectory transcript.
    ///
    /// # Errors
    ///
    /// As [`digest_transcript`](Self::digest_transcript).
    #[instrument(
        skip_all,
        fields(trajectory.id = %trajectory_id, event_count = events.len()),
    )]
    pub async fn scan_transcript(
        &self,
        trajectory_id: &str,
        events: &[Event],
    ) -> Result<TranscriptScanResult, ScannerError> {
        if events.is_empty() {
            return Err(ScannerError::NoEvents);
        }

        let user_prompt = rubric::render_transcript_prompt(
            "Analyze this trajectory transcript for behavioral signals using the rubric above.",
            trajectory_id,
            events,
        );
        self.extract(rubric::TRANSCRIPT_SCAN_RUBRIC, &user_prompt)
            .await
    }

    // ── Accessors ───────────────────────────────────────────────────────

    /// The configured model name.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// The active provider's canonical name.
    #[must_use]
    pub fn provider_name(&self) -> &'static str {
        self.config.provider.name()
    }

    /// The configuration this scanner was built from.
    #[must_use]
    pub fn config(&self) -> &ScannerConfig {
        &self.config
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /// Drive the provider's extractor, which constrains the model to `T`'s JSON
    /// schema and returns the typed value.
    /// Errors are returned, never logged: the caller has the event and
    /// trajectory ids that make a failure actionable, and a library that logs
    /// what it also returns gets every failure reported twice.
    async fn extract<T>(&self, preamble: &str, user_prompt: &str) -> Result<T, ScannerError>
    where
        T: JsonSchema + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        let extractor = self
            .client
            .extractor::<T>(&self.config.model)
            .preamble(preamble)
            .additional_params(serde_json::json!({ "temperature": self.config.temperature }))
            .build();

        tokio::time::timeout(
            self.config.timeout,
            extractor.extract(user_prompt.to_string()),
        )
        .await
        .map_err(|_| ScannerError::Timeout)?
        .map_err(|error| ScannerError::Extraction(error.to_string()))
    }
}

impl TrajectoryScannerBackend for TrajectoryScanner {
    fn scan_event<'a>(&'a self, event: &'a Event) -> ScannerFuture<'a, EventScanResult> {
        Box::pin(TrajectoryScanner::scan_event(self, event))
    }

    fn digest_transcript<'a>(
        &'a self,
        trajectory_id: &'a str,
        events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptDigest> {
        Box::pin(TrajectoryScanner::digest_transcript(
            self,
            trajectory_id,
            events,
        ))
    }

    fn scan_transcript<'a>(
        &'a self,
        trajectory_id: &'a str,
        events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptScanResult> {
        Box::pin(TrajectoryScanner::scan_transcript(
            self,
            trajectory_id,
            events,
        ))
    }

    fn digest_interim_transcript<'a>(
        &'a self,
        trajectory_id: &'a str,
        events: &'a [Event],
    ) -> ScannerFuture<'a, TranscriptDigest> {
        Box::pin(TrajectoryScanner::digest_interim_transcript(
            self,
            trajectory_id,
            events,
        ))
    }

    fn provider_name(&self) -> &'static str {
        TrajectoryScanner::provider_name(self)
    }

    fn model(&self) -> &str {
        TrajectoryScanner::model(self)
    }
}

/// Whether an event is one the scanner produced itself.
///
/// The harness writes each scan back as a `Control::Scanned` event on the same
/// trajectory. Feeding those to the scanner would have it grade its own output
/// and, worse, trigger another scan — so every dispatch point filters on this.
#[must_use]
pub fn is_scanner_output(event: &Event) -> bool {
    matches!(&event.event, TrajectoryEvent::Control(Control::Scanned(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sondera_types::{
        Action, Adjudicated, Agent, Completed, Failed, Prompt, ShellCommand, Started, Terminated,
        Thought,
    };

    fn agent(platform: &str) -> Agent {
        Agent::new("agent-1", "test", platform)
    }

    fn event(payload: TrajectoryEvent) -> Event {
        Event::new(agent("test"), "traj-1", payload)
    }

    fn codex_event(payload: TrajectoryEvent) -> Event {
        Event::new(agent(CODEX_PLATFORM), "traj-1", payload)
    }

    #[test]
    fn terminal_control_events_trigger_transcript_scan() {
        for control in [
            Control::Completed(Completed::new()),
            Control::Failed(Failed::new("failed")),
            Control::Terminated(Terminated::new("timeout", "system")),
        ] {
            assert!(TrajectoryScanner::should_scan_transcript_for_event(&event(
                TrajectoryEvent::Control(control)
            )));
        }
    }

    #[test]
    fn non_terminal_and_non_control_events_do_not_trigger_transcript_scan() {
        let cases = [
            TrajectoryEvent::Control(Control::Started(Started::new(agent("test")))),
            TrajectoryEvent::Action(Action::ShellCommand(ShellCommand::new("pwd"))),
        ];

        for case in cases {
            assert!(!TrajectoryScanner::should_scan_transcript_for_event(
                &event(case)
            ));
        }
    }

    #[test]
    fn a_codex_turn_end_refreshes_the_digest_without_ending_the_run() {
        let ev = codex_event(TrajectoryEvent::Observation(Observation::Prompt(
            Prompt::assistant("Done."),
        )));

        assert!(TrajectoryScanner::should_digest_interim_transcript_for_event(&ev));
        // Crucially it must NOT also look terminal: one Codex session is one
        // trajectory, and a turn end is not a session end.
        assert!(!TrajectoryScanner::should_scan_transcript_for_event(&ev));
    }

    #[test]
    fn another_platforms_assistant_prompt_does_not_refresh_the_digest() {
        let ev = event(TrajectoryEvent::Observation(Observation::Prompt(
            Prompt::assistant("Done."),
        )));

        assert!(!TrajectoryScanner::should_digest_interim_transcript_for_event(&ev));
    }

    #[test]
    fn a_codex_user_prompt_does_not_refresh_the_digest() {
        // Only the assistant-role turn end is the signal; a user prompt is the
        // start of work, not the end of a turn.
        let ev = codex_event(TrajectoryEvent::Observation(Observation::Prompt(
            Prompt::user("do the thing"),
        )));

        assert!(!TrajectoryScanner::should_digest_interim_transcript_for_event(&ev));
    }

    #[test]
    fn a_codex_thought_does_not_refresh_the_digest() {
        let ev = codex_event(TrajectoryEvent::Observation(Observation::Thought(
            Thought::new("thinking"),
        )));

        assert!(!TrajectoryScanner::should_digest_interim_transcript_for_event(&ev));
    }

    #[test]
    fn scanner_output_is_recognised_so_scans_cannot_feed_themselves() {
        use sondera_types::{AgentIntent, EventScanResult, MessageType, Scanned, TranscriptDigest};

        let result = EventScanResult {
            explanation: String::new(),
            message_type: MessageType::ToolResult,
            intent: AgentIntent::Investigate,
            description: String::new(),
            key_entities: Vec::new(),
            is_side_effecting: false,
            signals: Vec::new(),
            confidence: 0.0,
            embedding: None,
        };
        let scanned = event(TrajectoryEvent::Control(Control::Scanned(
            Scanned::message("event-0", result),
        )));
        assert!(is_scanner_output(&scanned));

        // A digest is scanner output too — it must not re-enter the pipeline.
        let digest = event(TrajectoryEvent::Control(Control::Scanned(
            Scanned::transcript_digest(
                "event-0",
                TranscriptDigest {
                    trajectory_id: "traj-1".to_string(),
                    title: String::new(),
                    summary: String::new(),
                    interim: false,
                    phases: Vec::new(),
                    files_modified: Vec::new(),
                    tools_used: Vec::new(),
                    total_events: 0,
                    side_effecting_count: 0,
                },
            ),
        )));
        assert!(is_scanner_output(&digest));

        assert!(!is_scanner_output(&event(TrajectoryEvent::Control(
            Control::Adjudicated(Adjudicated::allow())
        ))));
        assert!(!is_scanner_output(&event(TrajectoryEvent::Action(
            Action::ShellCommand(ShellCommand::new("pwd"))
        ))));
    }
}
