//! gRPC server for the Sondera harness.
//!
//! Implements the generated `sondera.harness.v1` [`HarnessService`] over tonic,
//! fronting any [`Harness`] engine (e.g. [`CedarPolicyHarness`](crate::CedarPolicyHarness)).
//! Incoming wire [`sondera_schema`] events are decoded into
//! [`sondera_types::Event`] domain values via the DTO conversions, adjudicated,
//! and the results re-encoded as response events.
//!
//! There is no authentication: every caller adjudicates against the same policy
//! set and the same entity store.

use crate::scan::ScanDispatch;
use crate::types::{AdjudicatedEvent, Event, Harness};
use sondera_schema::harness_v1 as pb;
use sondera_schema::harness_v1::harness_service_server::{HarnessService, HarnessServiceServer};
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// Environment variable naming the address the server binds to.
const ADDR_ENV: &str = "SONDERA_HARNESS_ADDR";
/// Default bind address when [`ADDR_ENV`] is unset.
const DEFAULT_ADDR: &str = "127.0.0.1:50051";
/// 16 MiB, matching the client, to accommodate large trajectory events.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Resolve the server bind address from the environment, falling back to the
/// local default.
pub fn default_addr() -> SocketAddr {
    std::env::var(ADDR_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| DEFAULT_ADDR.parse().expect("valid default addr"))
}

/// tonic service adapter that dispatches `Adjudicates` RPCs to a [`Harness`].
pub struct HarnessGrpcService<H> {
    harness: Arc<H>,
    /// Background trajectory scanner, when one is configured. `None` is the
    /// default and the fully supported state: scanning is enrichment, and a
    /// harness without it enforces exactly the same policy.
    scans: Option<Arc<dyn ScanDispatch>>,
}

impl<H> HarnessGrpcService<H> {
    pub fn new(harness: Arc<H>) -> Self {
        Self {
            harness,
            scans: None,
        }
    }

    /// Scan each adjudicated event in the background through `scans`.
    ///
    /// A trait object rather than a type parameter so attaching a scanner does
    /// not change this service's type, and so the store the scanner writes
    /// through stays the caller's business.
    #[must_use]
    pub fn with_scans(mut self, scans: Arc<dyn ScanDispatch>) -> Self {
        self.scans = Some(scans);
        self
    }
}

#[tonic::async_trait]
impl<H: Harness + 'static> HarnessService for HarnessGrpcService<H> {
    async fn adjudicates(
        &self,
        request: Request<pb::AdjudicatesRequest>,
    ) -> Result<Response<pb::AdjudicatesResponse>, Status> {
        let req = request.into_inner();

        let mut out = Vec::with_capacity(req.events.len());
        for pb_event in &req.events {
            let event = Event::try_from(pb_event)
                .map_err(|e| Status::invalid_argument(format!("invalid event: {e}")))?;

            let source_event_id = event.event_id.clone();
            let source_trajectory_id = event.trajectory_id.clone();
            let source_agent_id = event.agent.id.clone();

            // Kept only when something will scan it: the payload can carry a
            // whole file or a shell command's output, so an unconditional clone
            // would double the ingest cost of every event to serve a feature
            // that is off by default.
            let to_scan = self.scans.is_some().then(|| event.clone());

            let adjudicated = self
                .harness
                .adjudicate(event)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

            // After the verdict, and only once the engine has persisted the
            // event — a transcript scan reads the run back out of the store,
            // and an event scan writes a row keyed by an event that must
            // already exist. Dispatch is fire-and-forget, so this does not
            // delay the response.
            if let (Some(scans), Some(event)) = (self.scans.as_ref(), to_scan) {
                scans.dispatch(event);
            }

            out.push(pb::Event::from(AdjudicatedEvent {
                adjudicated: &adjudicated,
                source_event_id: &source_event_id,
                source_trajectory_id: &source_trajectory_id,
                source_agent_id: &source_agent_id,
            }));
        }

        Ok(Response::new(pb::AdjudicatesResponse { events: out }))
    }
}

/// Build the tonic service for `harness`, with this transport's message-size
/// limits applied.
///
/// Exposed separately from [`serve`] so a caller that owns the listener — the
/// unified `sondera serve`, which puts this and the console on one port — adds
/// it to its own router instead of getting a server built around it.
pub fn grpc_service<H>(harness: Arc<H>) -> HarnessServiceServer<HarnessGrpcService<H>>
where
    H: Harness + 'static,
{
    wrap(HarnessGrpcService::new(harness))
}

/// [`grpc_service`], for a service the caller has already configured — with
/// [`HarnessGrpcService::with_scans`], say.
pub fn wrap<H>(service: HarnessGrpcService<H>) -> HarnessServiceServer<HarnessGrpcService<H>>
where
    H: Harness + 'static,
{
    HarnessServiceServer::new(service)
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES)
}

/// Serve the given [`Harness`] over gRPC on `addr` until the process exits.
pub async fn serve<H>(harness: H, addr: SocketAddr) -> Result<(), tonic::transport::Error>
where
    H: Harness + 'static,
{
    tracing::info!("Harness gRPC server listening on {addr}");
    tonic::transport::Server::builder()
        .add_service(grpc_service(Arc::new(harness)))
        .serve(addr)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::HarnessGrpcClient;
    use crate::types::{
        Adjudicated, Agent, Decision, Event, HarnessError, Observation, Thought, TrajectoryEvent,
    };

    /// A harness that allows everything, for transport round-trip testing.
    struct MockHarness;

    impl Harness for MockHarness {
        async fn adjudicate(&self, _event: Event) -> Result<Adjudicated, HarnessError> {
            Ok(Adjudicated::allow())
        }
    }

    fn test_agent() -> Agent {
        Agent {
            id: "test-agent".to_string(),
            provider: "test".to_string(),
            platform: String::new(),
        }
    }

    #[tokio::test]
    async fn grpc_client_server_roundtrip() {
        // Discover a free port, then bind the server to it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = tokio::spawn(async move {
            serve(MockHarness, addr).await.unwrap();
        });

        // Give the server a moment to start listening.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let client = HarnessGrpcClient::connect(format!("http://{addr}"))
            .await
            .expect("connect");

        let event = Event::new(
            test_agent(),
            "test-trajectory",
            TrajectoryEvent::Observation(Observation::Thought(Thought::new("hello"))),
        );
        let result = client.adjudicate(event).await.expect("adjudicate");
        assert_eq!(result.decision, Decision::Allow);

        server.abort();
    }
}
