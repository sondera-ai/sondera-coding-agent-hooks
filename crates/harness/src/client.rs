//! No-auth gRPC client for the `sondera.harness.v1` `HarnessService`.
//!
//! This is the lightweight surface `crates/hooks/*` consume (aliased as
//! `sondera_harness_client`). It wraps the generated tonic client, accepts and
//! returns [`sondera_types`] domain values (converting to/from the wire DTOs in
//! [`sondera_schema`]), and implements the [`HarnessClient`] trait so hooks can
//! stay generic over the transport.
//!
//! There is intentionally **no** authentication, credential brokering, or
//! trace propagation here — the endpoint is a plain host:port read from the
//! environment.

use std::time::Duration;

use crate::types::{Adjudicated, Agent, Event};
use sondera_schema::harness_v1 as pb;
use sondera_schema::harness_v1::harness_service_client::HarnessServiceClient;
use tonic::Request;
use tonic::transport::Channel;

/// Environment variable naming the harness gRPC endpoint (e.g. `http://127.0.0.1:50051`).
const ENDPOINT_ENV: &str = "SONDERA_HARNESS_ENDPOINT";
/// Default endpoint used when [`ENDPOINT_ENV`] is unset.
const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:50051";
/// 16 MiB, matching the server, to accommodate large trajectory events.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Default budget for a single harness interaction — applied to both the
/// initial connect and each adjudication RPC.
///
/// This is the one place the hook enforcement timeout lives: because the client
/// bounds every call, a hook whose harness hangs mid-adjudication gets a
/// [`HarnessClientError::Timeout`] (which its fail-closed path turns into a
/// deny) rather than blocking until the host agent kills the process — which
/// would emit no decision and fail *open*.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors raised by [`HarnessGrpcClient`].
///
/// There is deliberately no transport-local error type: the client speaks the
/// one shared [`sondera_types::HarnessClientError`], so a failure crosses from
/// the wire to a hook's fail-closed decision without ever being flattened to a
/// string and re-parsed.
pub use sondera_types::HarnessClientError;

/// Convenience alias for fallible client operations.
pub type Result<T> = std::result::Result<T, HarnessClientError>;

/// Resolve the harness endpoint from the environment, falling back to the
/// local default.
pub fn default_endpoint() -> String {
    std::env::var(ENDPOINT_ENV).unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string())
}

/// gRPC client for the Sondera harness. Cheaply cloneable.
#[derive(Clone)]
pub struct HarnessGrpcClient {
    inner: HarnessServiceClient<Channel>,
    /// Per-RPC deadline; defaults to `DEFAULT_TIMEOUT`.
    timeout: Duration,
}

impl HarnessGrpcClient {
    /// Connect to a harness gRPC endpoint (e.g. `http://127.0.0.1:50051`).
    ///
    /// TLS is negotiated automatically by tonic when the endpoint uses `https`.
    /// The connect and every subsequent RPC are bounded by `DEFAULT_TIMEOUT`;
    /// override the RPC budget with [`Self::with_timeout`].
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self> {
        let endpoint = endpoint.into();
        let channel = Channel::from_shared(endpoint.clone())
            .map_err(|e| {
                HarnessClientError::Config(format!("invalid harness endpoint {endpoint:?}: {e}"))
            })?
            .connect_timeout(DEFAULT_TIMEOUT)
            .connect()
            .await
            .map_err(|e| {
                HarnessClientError::Unavailable(format!(
                    "failed to connect to harness at {endpoint:?}: {e}"
                ))
            })?;

        let inner = HarnessServiceClient::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);
        Ok(Self {
            inner,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Override the per-RPC deadline (default `DEFAULT_TIMEOUT`).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Connect using the endpoint resolved by [`default_endpoint`].
    pub async fn default() -> Result<Self> {
        Self::connect(default_endpoint()).await
    }

    /// Adjudicate a batch of domain events, returning their decisions in order.
    pub async fn adjudicates(&self, events: Vec<Event>) -> Result<Vec<Adjudicated>> {
        let proto_events: Vec<pb::Event> = events.iter().map(pb::Event::from).collect();
        let mut inner = self.inner.clone();
        let rpc = inner.adjudicates(Request::new(pb::AdjudicatesRequest {
            events: proto_events,
        }));
        // Bound the RPC so a harness that accepts the connection then hangs
        // mid-adjudication surfaces a `Timeout` (which the hook fails closed on)
        // rather than blocking until the host agent kills the process.
        let response = match tokio::time::timeout(self.timeout, rpc).await {
            Ok(result) => result?,
            Err(_elapsed) => return Err(HarnessClientError::Timeout),
        };

        let resp = response.into_inner();
        let mut results = Vec::with_capacity(resp.events.len());
        for ev in &resp.events {
            let adj = Adjudicated::try_from(ev).map_err(|e| {
                HarnessClientError::Decode(format!("cannot decode adjudication response: {e}"))
            })?;
            results.push(adj);
        }
        Ok(results)
    }

    /// Adjudicate a single domain event.
    pub async fn adjudicate(&self, event: Event) -> Result<Adjudicated> {
        let mut results = self.adjudicates(vec![event]).await?;
        results
            .pop()
            .ok_or_else(|| HarnessClientError::Decode("empty adjudicates response".to_string()))
    }
}

impl crate::types::HarnessClient for HarnessGrpcClient {
    async fn adjudicate(&self, event: Event) -> Result<Adjudicated> {
        HarnessGrpcClient::adjudicate(self, event).await
    }

    async fn adjudicates(&self, events: Vec<Event>) -> Result<Vec<Adjudicated>> {
        HarnessGrpcClient::adjudicates(self, events).await
    }
}

/// Connect to the default harness endpoint.
pub async fn connect_harness() -> Result<HarnessGrpcClient> {
    HarnessGrpcClient::default().await
}

/// Connect a hook client for the given agent.
///
/// `agent` and `runtime` are informational only: nothing here brokers per-agent
/// credentials, and the endpoint comes from [`default_endpoint`] regardless.
pub async fn connect_harness_for_hook(agent: &Agent, runtime: &str) -> Result<HarnessGrpcClient> {
    tracing::debug!(agent = %agent.id, runtime, "connecting hook harness client");
    HarnessGrpcClient::default().await
}

/// Connect a hook client for the given bare agent id. See
/// [`connect_harness_for_hook`] for the no-auth semantics.
pub async fn connect_harness_for_hook_agent_id(
    agent_id: &str,
    runtime: &str,
) -> Result<HarnessGrpcClient> {
    tracing::debug!(agent = %agent_id, runtime, "connecting hook harness client");
    HarnessGrpcClient::default().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_timeout_is_thirty_seconds() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn an_unparseable_endpoint_is_a_config_error_not_a_server_error() {
        // `Config` exists so a local misconfiguration is never reported as a
        // server fault — the misclassification that sends users to check
        // connectivity when the service is reachable.
        let Err(err) = HarnessGrpcClient::connect("not a url").await else {
            panic!("an unparseable endpoint must not connect");
        };
        assert!(matches!(err, HarnessClientError::Config(_)), "{err:?}");
    }

    #[test]
    fn an_auth_status_from_a_fronting_proxy_is_a_server_error() {
        // This harness issues no `PermissionDenied`, so one can only come from
        // something in front of it. It must still land somewhere typed rather
        // than needing the message to be parsed.
        let err = HarnessClientError::from(tonic::Status::permission_denied("denied by proxy"));
        assert!(matches!(err, HarnessClientError::Server(_)), "{err:?}");
    }
}
