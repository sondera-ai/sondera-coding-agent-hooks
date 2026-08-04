//! gRPC client for the console read surface.
//!
//! The TUI is a pure consumer of `sondera.console.v1` as served by
//! `sondera serve`. It holds no store handle and opens no database, so the
//! reading view can never disagree with what the console reports, and a change
//! to the store's internals never reaches this crate.

use crate::model::{AgentIdentity, Sparkline, TrajectoryRow, Transcript, short};
use sondera_schema::console_v1 as pb;
use sondera_schema::console_v1::console_service_client::ConsoleServiceClient;
use tonic::transport::Channel;

/// Page size for the run feed. The console clamps requests above its own
/// maximum, so this is a display budget rather than a protocol limit.
pub(crate) const TRAJECTORY_PAGE: i32 = 200;

/// Page size for one run's events.
const EVENT_PAGE: i32 = 250;

/// Page size for the agent roster, at the console's own maximum — the console
/// clamps to it either way (`MAX_PAGE_SIZE` in `crates/console/src/query.rs`).
/// A roster is one row per agent that has ever reported in, so this is usually
/// the whole thing in one call.
const AGENT_PAGE: i32 = 250;

/// How many activity strips one request may ask for.
///
/// The console rejects a larger batch outright, so this is a protocol limit
/// rather than a display budget — `MAX_SPARKLINE_BATCH` in
/// `crates/console/src/sparkline.rs`.
const SPARKLINE_BATCH: usize = 100;

/// A console client, cheap to clone — tonic channels are reference-counted and
/// multiplex over one HTTP/2 connection.
#[derive(Clone)]
pub struct ConsoleClient {
    inner: ConsoleServiceClient<Channel>,
}

/// What went wrong, phrased for a status line rather than a log.
#[derive(Debug, Clone)]
pub struct ClientError(pub String);

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ClientError {}

impl From<tonic::Status> for ClientError {
    fn from(status: tonic::Status) -> Self {
        Self(format!("{}: {}", status.code(), status.message()))
    }
}

impl ConsoleClient {
    /// Dial the console at `endpoint` (`http://host:port`).
    pub async fn connect(endpoint: &str) -> Result<Self, ClientError> {
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|e| ClientError(format!("invalid endpoint '{endpoint}': {e}")))?
            .connect()
            .await
            .map_err(|e| {
                ClientError(format!(
                    "could not reach the console at {endpoint} ({e}) — is `sondera serve` running?"
                ))
            })?;
        Ok(Self {
            inner: ConsoleServiceClient::new(channel),
        })
    }

    /// Fetch the run feed, newest first.
    ///
    /// `filter` is the console's AIP clause grammar (`agent=agents/x`,
    /// `decision=deny`, `status=running`). It is passed through untouched: an
    /// unrecognized key is the console's INVALID_ARGUMENT to report, not
    /// something to silently drop here.
    pub async fn trajectories(&self, filter: &str) -> Result<Vec<TrajectoryRow>, ClientError> {
        let response = self
            .clone()
            .inner
            .list_trajectories(pb::ListTrajectoriesRequest {
                page_size: TRAJECTORY_PAGE,
                page_token: String::new(),
                filter: filter.to_string(),
                order_by: "start_time desc".to_string(),
            })
            .await?
            .into_inner();
        Ok(response
            .trajectories
            .iter()
            .map(TrajectoryRow::from)
            .collect())
    }

    /// Fetch the agent roster as `(bare agent id, identity)` pairs.
    ///
    /// The feed's provider and platform columns are a client-side join, because
    /// `TrajectorySummary` carries only the agent's resource name: identity is
    /// harness-owned and lives on the agent, so it has to come from here. Keyed
    /// by the bare id, which is what [`TrajectoryRow::agent`] holds.
    ///
    /// Pages are followed to exhaustion, and the token loop terminates for the
    /// same reason [`ConsoleClient::transcript`]'s does: the console only mints
    /// a next token while items remain. A roster that stopped at the first page
    /// would leave later agents permanently unidentified in the feed, which is
    /// indistinguishable on screen from a console that never knew them.
    pub async fn agents(&self) -> Result<Vec<(String, AgentIdentity)>, ClientError> {
        let mut client = self.clone().inner;
        let mut agents = Vec::new();
        let mut page_token = String::new();
        loop {
            let response = client
                .list_agents(pb::ListAgentsRequest {
                    page_size: AGENT_PAGE,
                    page_token: page_token.clone(),
                    filter: String::new(),
                    order_by: String::new(),
                })
                .await?
                .into_inner();
            agents.extend(
                response
                    .agents
                    .iter()
                    .map(|agent| (short(&agent.name).to_string(), AgentIdentity::from(agent))),
            );
            if response.next_page_token.is_empty() {
                break;
            }
            page_token = response.next_page_token;
        }
        Ok(agents)
    }

    /// Open a live feed of new and updated run summaries matching `filter`.
    pub async fn stream_trajectories(
        &self,
        filter: &str,
    ) -> Result<tonic::Streaming<pb::TrajectorySummary>, ClientError> {
        Ok(self
            .clone()
            .inner
            .stream_trajectories(pb::StreamTrajectoriesRequest {
                filter: filter.to_string(),
            })
            .await?
            .into_inner())
    }

    /// Fetch the activity strips for `names`, as `(resource name, strip)` pairs.
    ///
    /// Requests are chunked to the console's batch limit and issued in order.
    /// A name the console cannot resolve is simply absent from the response —
    /// it skips deleted runs rather than failing the whole batch — so the
    /// result may be shorter than what was asked for, and the caller must treat
    /// a missing strip as unknown rather than as an empty run.
    pub async fn sparklines(
        &self,
        names: &[String],
    ) -> Result<Vec<(String, Sparkline)>, ClientError> {
        let mut client = self.clone().inner;
        let mut strips = Vec::with_capacity(names.len());
        for chunk in names.chunks(SPARKLINE_BATCH) {
            let response = client
                .batch_get_trajectory_sparklines(pb::BatchGetTrajectorySparklinesRequest {
                    names: chunk.to_vec(),
                })
                .await?
                .into_inner();
            strips.extend(
                response
                    .sparklines
                    .iter()
                    .map(|strip| (strip.trajectory.clone(), Sparkline::from(strip))),
            );
        }
        Ok(strips)
    }

    /// Fetch one run's header: the detail summary, which carries the digest and
    /// scan the list projection omits, with no events attached.
    ///
    /// This is what the live path opens with — the chrome can be drawn from the
    /// summary alone while the events arrive on the stream.
    pub async fn transcript_header(&self, name: &str) -> Result<Transcript, ClientError> {
        let summary = self.summary(name).await?;
        Ok(Transcript::build(&summary, &[]))
    }

    /// Open a live tail over one run's events: the stored backlog first, then
    /// events as the harness writes them.
    ///
    /// The stream carries the raw ledger grain — adjudications and scans arrive
    /// as their own control events rather than folded onto what they grade — so
    /// its consumer is [`crate::model::TranscriptTail`], not
    /// [`Transcript::build`].
    pub async fn stream_transcript(
        &self,
        name: &str,
    ) -> Result<tonic::Streaming<pb::TrajectoryEvent>, ClientError> {
        Ok(self
            .clone()
            .inner
            .stream_trajectory(pb::StreamTrajectoryRequest {
                trajectory: name.to_string(),
            })
            .await?
            .into_inner())
    }

    /// Fetch one run's full reading view: the detail summary (which carries the
    /// digest and scan the list projection omits) plus every event page.
    pub async fn transcript(&self, name: &str) -> Result<Transcript, ClientError> {
        let summary = self.summary(name).await?;
        let mut client = self.clone().inner;

        // Pages are followed to exhaustion: a transcript that stops at an
        // arbitrary page boundary would silently misrepresent the run, and the
        // token loop terminates because the console only mints a next token
        // while items remain.
        let mut details = Vec::new();
        let mut page_token = String::new();
        loop {
            let response = client
                .list_trajectory_events(pb::ListTrajectoryEventsRequest {
                    trajectory: name.to_string(),
                    page_size: EVENT_PAGE,
                    page_token: page_token.clone(),
                })
                .await?
                .into_inner();
            details.extend(response.details);
            if response.next_page_token.is_empty() {
                break;
            }
            page_token = response.next_page_token;
        }

        Ok(Transcript::build(&summary, &details))
    }

    async fn summary(&self, name: &str) -> Result<pb::TrajectorySummary, ClientError> {
        Ok(self
            .clone()
            .inner
            .get_trajectory(pb::GetTrajectoryRequest {
                name: name.to_string(),
            })
            .await?
            .into_inner())
    }
}
