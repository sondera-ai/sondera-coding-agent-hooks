//! Runtime-configurable, multi-provider LLM client abstraction.
//!
//! Sondera applications need to talk to chat-completion models, but the concrete
//! provider (OpenAI, Anthropic, a local Ollama server, …) is a deployment
//! choice that should be made at runtime from configuration — not fixed at
//! compile time. This crate provides that seam:
//!
//! - [`Provider`] is a registry of every supported provider. It parses from a
//!   configuration string ([`std::str::FromStr`]), enumerates via
//!   [`Provider::ALL`], and constructs a live client with [`Provider::client`]
//!   from a [`ClientConfig`].
//! - [`Client`] is a provider-agnostic enum wrapping the selected provider's
//!   rig client. It implements rig's [`CompletionClient`], so the usual
//!   `client.agent(model)` and `client.extractor::<T>(model)` builders work
//!   against whichever provider was chosen.
//! - [`DynCompletionModel`] is the object-safe trait that erases each provider's
//!   response types so [`Client`] can dispatch uniformly.
//!
//! Because [`Client`] implements [`CompletionClient`], any application crate
//! can build agents and extractors from a runtime-selected provider without
//! taking a direct dependency on rig:
//!
//! ```
//! use sondera_provider::{AgentClientExt, ClientConfig, Provider};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Provider and endpoint come from configuration at runtime.
//! let provider: Provider = "ollama".parse()?;
//! let client = provider.client(&ClientConfig::new("").base_url("http://localhost:11434"))?;
//!
//! // `client` is a rig `CompletionClient`, so the usual builders work — e.g.
//! // `client.extractor::<T>("model")` for schema-constrained structured output.
//! let _agent = client
//!     .agent("gpt-oss-safeguard:20b")
//!     .preamble("You are a helpful assistant.")
//!     .build();
//! # Ok(())
//! # }
//! ```

mod client;
mod error;
mod model;
mod provider;
mod secret;

pub use client::{Client, DynamicCompletionModel, NoStreamingResponse};
pub use error::ProviderError;
pub use model::DynCompletionModel;
pub use provider::{ClientConfig, Provider};
pub use secret::Secret;

// Re-exported so downstream crates can build extractors and agents from a [`Client`]
// without taking a direct dependency on rig. `CompletionClient` carries
// `completion_model`; `AgentClientExt` — blanket-implemented for every
// `CompletionClient` — carries `agent` and `extractor`. Both must be in scope
// for the full surface, so both are re-exported.
pub use rig::client::CompletionClient;
pub use rig_agent::client::AgentClientExt;
