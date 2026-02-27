//! tarpc-based RPC service for the Sondera harness.
//!
//! This module provides a tarpc service definition for remote policy adjudication,
//! enabling IPC between client applications and the harness server.

use crate::harness::Harness;
use crate::types::{Adjudicated, Event};
use anyhow::Result;
use futures::prelude::*;
use std::path::Path;
use std::sync::Arc;
use tarpc::server::{BaseChannel, Channel};
use tarpc::{client, context};
use tokio_serde::formats::Json;

/// Default socket path for the harness IPC server.
///
/// Prefers `/var/run/sondera/` for system-wide visibility, falling back to
/// `~/.sondera/` when the system path is not writable.
pub fn default_socket_path() -> std::path::PathBuf {
    let system_dir = std::path::PathBuf::from("/var/run/sondera");
    if std::fs::create_dir_all(&system_dir).is_ok() {
        return system_dir.join("sondera-harness.sock");
    }

    dirs::home_dir()
        .map(|h| h.join(".sondera"))
        .unwrap_or_else(|| std::path::PathBuf::from("/var/run/sondera"))
        .join("sondera-harness.sock")
}

/// tarpc service definition for the Sondera harness.
#[tarpc::service]
pub trait HarnessService {
    /// Adjudicate an event against configured policies.
    async fn adjudicate(event: Event) -> Result<Adjudicated, String>;

    /// Health check endpoint.
    async fn health() -> bool;
}

/// Server implementation of the HarnessService.
pub struct HarnessServer<H> {
    harness: Arc<H>,
}

impl<H> Clone for HarnessServer<H> {
    fn clone(&self) -> Self {
        Self {
            harness: Arc::clone(&self.harness),
        }
    }
}

impl<H: Harness + 'static> HarnessServer<H> {
    pub fn new(harness: Arc<H>) -> Self {
        Self { harness }
    }
}

impl<H: Harness + 'static> HarnessService for HarnessServer<H> {
    async fn adjudicate(self, _: context::Context, event: Event) -> Result<Adjudicated, String> {
        self.harness
            .adjudicate(event)
            .await
            .map_err(|e| e.to_string())
    }

    async fn health(self, _: context::Context) -> bool {
        true
    }
}

/// Spawn a tarpc server listening on a Unix socket.
pub async fn serve<H>(harness: H, socket_path: &Path) -> Result<()>
where
    H: Harness + 'static,
{
    // Remove existing socket file if present.
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut listener = tarpc::serde_transport::unix::listen(socket_path, Json::default).await?;
    tracing::info!("Harness server listening on {:?}", socket_path);

    let server = HarnessServer::new(Arc::new(harness));

    // 64 MB — generous enough for large Cedar contexts/policies,
    // bounded enough to prevent OOM from malformed messages.
    listener.config_mut().max_frame_length(64 * 1024 * 1024);
    while let Some(accept_result) = listener.next().await {
        match accept_result {
            Ok(transport) => {
                let server = server.clone();
                tokio::spawn(async move {
                    let channel = BaseChannel::with_defaults(transport);
                    channel
                        .execute(server.serve())
                        .for_each(|response| async move {
                            tokio::spawn(response);
                        })
                        .await;
                });
            }
            Err(e) => {
                tracing::error!("Error accepting connection: {}", e);
            }
        }
    }

    Ok(())
}

/// tarpc client for connecting to a harness server.
#[derive(Clone)]
pub struct HarnessClient {
    inner: HarnessServiceClient,
}

impl HarnessClient {
    /// Connect to a harness server at the given Unix socket path.
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        let transport = tarpc::serde_transport::unix::connect(socket_path, Json::default).await?;
        let client = HarnessServiceClient::new(client::Config::default(), transport).spawn();
        Ok(Self { inner: client })
    }

    /// Connect to the default socket path.
    pub async fn connect_default() -> Result<Self> {
        Self::connect(&default_socket_path()).await
    }

    /// Health check.
    pub async fn health(&self) -> Result<bool> {
        self.inner
            .health(context::current())
            .await
            .map_err(|e| anyhow::anyhow!("RPC error: {}", e))
    }
}

impl Harness for HarnessClient {
    fn adjudicate(
        &self,
        event: Event,
    ) -> impl std::future::Future<Output = Result<Adjudicated>> + Send {
        let inner = self.inner.clone();
        async move {
            let mut ctx = context::current();
            ctx.deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
            inner
                .adjudicate(ctx, event)
                .await
                .map_err(|e| anyhow::anyhow!("RPC error: {}", e))?
                .map_err(|e| anyhow::anyhow!("Server error: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Agent, Control, Decision, Started, TrajectoryEvent};
    /// A mock harness for testing.
    struct MockHarness;

    impl Harness for MockHarness {
        async fn adjudicate(&self, _event: Event) -> Result<Adjudicated> {
            Ok(Adjudicated::allow())
        }
    }

    #[tokio::test]
    async fn test_client_server_roundtrip() {
        let socket_path =
            std::env::temp_dir().join(format!("sondera-test-{}.sock", uuid::Uuid::new_v4()));

        // Start server in background.
        let server_socket = socket_path.clone();
        let server_handle = tokio::spawn(async move {
            serve(MockHarness, &server_socket).await.unwrap();
        });

        // Give server time to start.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect client.
        let client = HarnessClient::connect(&socket_path).await.unwrap();

        // Test health check.
        assert!(client.health().await.unwrap());

        // Test adjudicate.
        let agent = Agent {
            id: "test-agent".to_string(),
            provider_id: "test".to_string(),
        };
        let event = Event::new(
            agent,
            "test-trajectory",
            TrajectoryEvent::Control(Control::Started(Started::new("test-agent"))),
        );
        let result = client.adjudicate(event).await.unwrap();
        assert_eq!(result.decision, Decision::Allow);

        // Cleanup.
        server_handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }
}
