//! Error type for provider client construction.

use thiserror::Error;

/// Errors that can occur while constructing a [`Client`](crate::Client) from a
/// [`Provider`](crate::Provider).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProviderError {
    /// A provider name supplied at runtime did not match any known provider.
    #[error("unknown provider: {0}")]
    UnknownProvider(String),

    /// The selected provider requires a base URL that was not supplied.
    #[error("provider `{provider}` requires a base URL to be configured")]
    MissingBaseUrl {
        /// Canonical name of the provider that needs a base URL.
        provider: &'static str,
    },

    /// The underlying rig client could not be constructed (e.g. an invalid
    /// endpoint or header).
    #[error("failed to build `{provider}` client: {source}")]
    ClientBuild {
        /// Canonical name of the provider whose client failed to build.
        provider: &'static str,
        /// The underlying rig HTTP client error.
        #[source]
        source: rig::http_client::Error,
    },

    /// The Vertex AI client could not be constructed.
    ///
    /// Separate from [`ProviderError::ClientBuild`] because Vertex AI is not a
    /// rig-core provider and fails for reasons the HTTP-level error cannot
    /// express: no Google Cloud project configured, or no Application Default
    /// Credentials resolvable on the host.
    #[error("failed to build `vertexai` client: {source}")]
    VertexClientBuild {
        /// The underlying `rig-vertexai` failure.
        #[source]
        source: rig_vertexai::client::VertexAiClientError,
    },
}
