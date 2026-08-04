//! The [`Provider`] registry: the set of LLM providers that can be selected and
//! configured at runtime.

use std::fmt;
use std::str::FromStr;

use rig::client::Nothing;
use rig::providers::azure::AzureOpenAIAuth;

use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::error::ProviderError;

/// Everything a [`Provider`] needs to construct a [`Client`], as gathered from
/// configuration.
///
/// A struct rather than a positional argument list because the providers differ
/// in what they require: most want a credential, Azure additionally requires a
/// base URL, and Vertex AI wants neither — it authenticates with Google
/// Application Default Credentials and is addressed by project and location
/// instead. Each provider reads only the fields that apply to it and ignores
/// the rest.
///
/// ```
/// use sondera_provider::{ClientConfig, Provider};
///
/// // A local Ollama server: no credential, custom endpoint.
/// let config = ClientConfig::new("").base_url("http://127.0.0.1:11434");
/// let _client = Provider::Ollama.client(&config)?;
/// # Ok::<(), sondera_provider::ProviderError>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct ClientConfig<'a> {
    /// The provider credential. Empty for providers that need none (Ollama,
    /// Vertex AI).
    pub api_key: &'a str,
    /// Endpoint override. Optional for most providers, required for
    /// [`Provider::Azure`], unused by [`Provider::VertexAi`].
    pub base_url: Option<&'a str>,
    /// Google Cloud project, used only by [`Provider::VertexAi`]. When absent
    /// the `GOOGLE_CLOUD_PROJECT` environment variable is consulted; if that is
    /// unset too, building the client fails.
    pub project: Option<&'a str>,
    /// Google Cloud location, used only by [`Provider::VertexAi`]. When absent
    /// the `GOOGLE_CLOUD_LOCATION` environment variable is consulted, falling
    /// back to `global` — the endpoint Google recommends for Gemini.
    pub location: Option<&'a str>,
}

impl<'a> ClientConfig<'a> {
    /// A configuration carrying only a credential, which is all most providers
    /// need. Empty is the right value for those that need none.
    #[must_use]
    pub const fn new(api_key: &'a str) -> Self {
        Self {
            api_key,
            base_url: None,
            project: None,
            location: None,
        }
    }

    /// Override the provider endpoint.
    #[must_use]
    pub const fn base_url(mut self, base_url: &'a str) -> Self {
        self.base_url = Some(base_url);
        self
    }

    /// Set the Google Cloud project ([`Provider::VertexAi`] only).
    #[must_use]
    pub const fn project(mut self, project: &'a str) -> Self {
        self.project = Some(project);
        self
    }

    /// Set the Google Cloud location ([`Provider::VertexAi`] only).
    #[must_use]
    pub const fn location(mut self, location: &'a str) -> Self {
        self.location = Some(location);
        self
    }

    /// As [`ClientConfig::base_url`], for a value that is already optional.
    #[must_use]
    pub const fn maybe_base_url(mut self, base_url: Option<&'a str>) -> Self {
        self.base_url = base_url;
        self
    }

    /// As [`ClientConfig::project`], for a value that is already optional.
    #[must_use]
    pub const fn maybe_project(mut self, project: Option<&'a str>) -> Self {
        self.project = project;
        self
    }

    /// As [`ClientConfig::location`], for a value that is already optional.
    #[must_use]
    pub const fn maybe_location(mut self, location: Option<&'a str>) -> Self {
        self.location = location;
        self
    }
}

/// An LLM provider selectable at runtime.
///
/// Parse one from a configuration string with [`FromStr`] (case-insensitive,
/// with a few aliases), enumerate the full set with [`Provider::ALL`], and
/// construct a live [`Client`] with [`Provider::client`].
///
/// ```
/// use sondera_provider::Provider;
///
/// assert_eq!("ollama".parse::<Provider>().unwrap(), Provider::Ollama);
/// assert_eq!("hf".parse::<Provider>().unwrap(), Provider::HuggingFace);
/// assert_eq!("vertex".parse::<Provider>().unwrap(), Provider::VertexAi);
/// assert_eq!(Provider::OpenAI.to_string(), "openai");
/// assert!("nope".parse::<Provider>().is_err());
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Provider {
    /// Anthropic API.
    Anthropic,
    /// Azure OpenAI API (requires a base URL).
    Azure,
    /// Cohere API.
    Cohere,
    /// DeepSeek API.
    DeepSeek,
    /// Google Gemini API — the Gemini Developer API, keyed by an AI Studio API
    /// key. For Gemini on Google Cloud, see [`Provider::VertexAi`].
    Gemini,
    /// Groq API.
    Groq,
    /// HuggingFace API (alias: `hf`).
    #[serde(alias = "hf")]
    HuggingFace,
    /// Hyperbolic API.
    Hyperbolic,
    /// Mira API.
    Mira,
    /// Moonshot API.
    Moonshot,
    /// OpenAI API (aliases: `openai-api`, `openai-compatible`).
    #[serde(alias = "openai-api", alias = "openai-compatible")]
    OpenAI,
    /// OpenRouter API.
    OpenRouter,
    /// Ollama API — local models, the default. Requires no credentials.
    #[default]
    Ollama,
    /// Perplexity API.
    Perplexity,
    /// TogetherAI API.
    Together,
    /// Google Cloud Vertex AI (aliases: `vertex`, `vertex-ai`).
    ///
    /// Serves Gemini — and the other Vertex-hosted models — under a Google
    /// Cloud project. Unlike every other provider here it takes no API key:
    /// it authenticates with Application Default Credentials, so `api_key` is
    /// ignored and `project`/`location` select the endpoint instead.
    #[serde(alias = "vertex", alias = "vertex-ai", alias = "vertex_ai")]
    VertexAi,
    /// xAI API.
    Xai,
}

impl Provider {
    /// Every provider this registry can build, for enumeration and discovery.
    pub const ALL: [Provider; 17] = [
        Provider::Anthropic,
        Provider::Azure,
        Provider::Cohere,
        Provider::DeepSeek,
        Provider::Gemini,
        Provider::Groq,
        Provider::HuggingFace,
        Provider::Hyperbolic,
        Provider::Mira,
        Provider::Moonshot,
        Provider::OpenAI,
        Provider::OpenRouter,
        Provider::Ollama,
        Provider::Perplexity,
        Provider::Together,
        Provider::VertexAi,
        Provider::Xai,
    ];

    /// The canonical lowercase name of this provider.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::Azure => "azure",
            Provider::Cohere => "cohere",
            Provider::DeepSeek => "deepseek",
            Provider::Gemini => "gemini",
            Provider::Groq => "groq",
            Provider::HuggingFace => "huggingface",
            Provider::Hyperbolic => "hyperbolic",
            Provider::Mira => "mira",
            Provider::Moonshot => "moonshot",
            Provider::OpenAI => "openai",
            Provider::OpenRouter => "openrouter",
            Provider::Ollama => "ollama",
            Provider::Perplexity => "perplexity",
            Provider::Together => "together",
            Provider::VertexAi => "vertexai",
            Provider::Xai => "xai",
        }
    }

    /// Construct a live [`Client`] for this provider.
    ///
    /// Each provider reads the [`ClientConfig`] fields that apply to it: the
    /// credential for the keyed providers, the base URL where an endpoint
    /// override is supported, and the project/location pair for
    /// [`Provider::VertexAi`].
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::MissingBaseUrl`] if a base URL is required but
    /// absent, [`ProviderError::VertexClientBuild`] if the Vertex AI client
    /// cannot be built (typically no project configured, or no Application
    /// Default Credentials on the host), or [`ProviderError::ClientBuild`] if
    /// any other provider's rig client cannot be constructed.
    ///
    /// # Panics
    ///
    /// [`Provider::VertexAi`] must be constructed from within a Tokio runtime:
    /// resolving Application Default Credentials starts a background token-cache
    /// refresh, and `google-cloud-auth` panics with "there is no reactor
    /// running" outside one. Every other provider builds anywhere. The harness
    /// builds its guardrails from an async fn, so this only bites callers
    /// constructing a client from synchronous code.
    pub fn client(self, config: &ClientConfig<'_>) -> Result<Client, ProviderError> {
        let ClientConfig {
            api_key,
            base_url,
            project,
            location,
        } = *config;

        // Providers whose client is built with `new(api_key)`, or with the
        // builder when a custom base URL is supplied.
        macro_rules! keyed_with_optional_base_url {
            ($variant:ident, $module:path) => {{
                use $module as provider;
                let built = match base_url {
                    Some(url) => provider::Client::builder()
                        .api_key(api_key)
                        .base_url(url)
                        .build(),
                    None => provider::Client::new(api_key),
                };
                Client::$variant(built.map_err(|source| ProviderError::ClientBuild {
                    provider: self.name(),
                    source,
                })?)
            }};
        }

        // Providers that only support `new(api_key)` (no custom base URL yet).
        macro_rules! keyed {
            ($variant:ident, $module:path) => {{
                use $module as provider;
                Client::$variant(provider::Client::new(api_key).map_err(|source| {
                    ProviderError::ClientBuild {
                        provider: self.name(),
                        source,
                    }
                })?)
            }};
        }

        let client = match self {
            Provider::Anthropic => {
                let builder = rig::providers::anthropic::Client::builder().api_key(api_key);
                let built = match base_url {
                    Some(url) => builder.base_url(url).build(),
                    None => builder.build(),
                };
                Client::Anthropic(built.map_err(|source| ProviderError::ClientBuild {
                    provider: self.name(),
                    source,
                })?)
            }
            Provider::Azure => {
                let url = base_url.ok_or(ProviderError::MissingBaseUrl {
                    provider: self.name(),
                })?;
                let built = rig::providers::azure::Client::builder()
                    .api_key(AzureOpenAIAuth::Token(api_key.to_string()))
                    .base_url(url)
                    .build();
                Client::Azure(built.map_err(|source| ProviderError::ClientBuild {
                    provider: self.name(),
                    source,
                })?)
            }
            Provider::Ollama => {
                let built = match base_url {
                    Some(url) => rig::providers::ollama::Client::builder()
                        .api_key(Nothing)
                        .base_url(url)
                        .build(),
                    None => rig::providers::ollama::Client::new(Nothing),
                };
                Client::Ollama(built.map_err(|source| ProviderError::ClientBuild {
                    provider: self.name(),
                    source,
                })?)
            }
            // Vertex AI takes no credential and no base URL: `rig-vertexai`
            // resolves Application Default Credentials itself and addresses the
            // endpoint by project and location. Both fall back to the
            // `GOOGLE_CLOUD_*` environment variables inside the builder, and
            // location further defaults to `global`, so only the project is
            // effectively required.
            Provider::VertexAi => {
                let mut builder = rig_vertexai::Client::builder();
                if let Some(project) = project {
                    builder = builder.with_project(project);
                }
                if let Some(location) = location {
                    builder = builder.with_location(location);
                }
                Client::VertexAi(
                    builder
                        .build()
                        .map_err(|source| ProviderError::VertexClientBuild { source })?,
                )
            }
            Provider::Cohere => keyed_with_optional_base_url!(Cohere, rig::providers::cohere),
            Provider::DeepSeek => keyed_with_optional_base_url!(DeepSeek, rig::providers::deepseek),
            Provider::Gemini => keyed_with_optional_base_url!(Gemini, rig::providers::gemini),
            Provider::Groq => keyed_with_optional_base_url!(Groq, rig::providers::groq),
            Provider::Hyperbolic => {
                keyed_with_optional_base_url!(Hyperbolic, rig::providers::hyperbolic)
            }
            Provider::Moonshot => keyed_with_optional_base_url!(Moonshot, rig::providers::moonshot),
            Provider::OpenAI => keyed_with_optional_base_url!(OpenAI, rig::providers::openai),
            Provider::OpenRouter => {
                keyed_with_optional_base_url!(OpenRouter, rig::providers::openrouter)
            }
            Provider::Perplexity => {
                keyed_with_optional_base_url!(Perplexity, rig::providers::perplexity)
            }
            Provider::HuggingFace => keyed!(HuggingFace, rig::providers::huggingface),
            Provider::Mira => keyed!(Mira, rig::providers::mira),
            Provider::Together => keyed!(Together, rig::providers::together),
            Provider::Xai => keyed!(Xai, rig::providers::xai),
        };

        Ok(client)
    }
}

impl FromStr for Provider {
    type Err = ProviderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let provider = match s.trim().to_ascii_lowercase().as_str() {
            "anthropic" => Provider::Anthropic,
            "azure" => Provider::Azure,
            "cohere" => Provider::Cohere,
            "deepseek" => Provider::DeepSeek,
            "gemini" => Provider::Gemini,
            "groq" => Provider::Groq,
            "huggingface" | "hf" => Provider::HuggingFace,
            "hyperbolic" => Provider::Hyperbolic,
            "mira" => Provider::Mira,
            "moonshot" => Provider::Moonshot,
            "openai" | "openai-api" | "openai-compatible" => Provider::OpenAI,
            "openrouter" => Provider::OpenRouter,
            "ollama" => Provider::Ollama,
            "perplexity" => Provider::Perplexity,
            "together" => Provider::Together,
            "vertexai" | "vertex" | "vertex-ai" | "vertex_ai" => Provider::VertexAi,
            "xai" => Provider::Xai,
            other => return Err(ProviderError::UnknownProvider(other.to_string())),
        };
        Ok(provider)
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_case_insensitive_and_supports_aliases() {
        assert_eq!("Ollama".parse::<Provider>().unwrap(), Provider::Ollama);
        assert_eq!(" OPENAI ".parse::<Provider>().unwrap(), Provider::OpenAI);
        assert_eq!(
            "openai-compatible".parse::<Provider>().unwrap(),
            Provider::OpenAI
        );
        assert_eq!("hf".parse::<Provider>().unwrap(), Provider::HuggingFace);
        for spelling in ["vertexai", "vertex", "vertex-ai", "vertex_ai", "VertexAI"] {
            assert_eq!(
                spelling.parse::<Provider>().unwrap(),
                Provider::VertexAi,
                "{spelling} should name Vertex AI"
            );
        }
    }

    #[test]
    fn parse_rejects_unknown_provider() {
        let err = "does-not-exist".parse::<Provider>().unwrap_err();
        assert!(matches!(err, ProviderError::UnknownProvider(_)));
    }

    #[test]
    fn name_round_trips_through_parse_for_all_variants() {
        for provider in Provider::ALL {
            assert_eq!(provider.name().parse::<Provider>().unwrap(), provider);
            assert_eq!(provider.to_string(), provider.name());
        }
    }

    #[test]
    fn default_is_ollama() {
        assert_eq!(Provider::default(), Provider::Ollama);
    }

    #[test]
    fn azure_requires_base_url() {
        // `Client` intentionally does not implement `Debug`, so match on the
        // result rather than calling `unwrap_err`.
        assert!(matches!(
            Provider::Azure.client(&ClientConfig::new("key")),
            Err(ProviderError::MissingBaseUrl { .. })
        ));
    }

    // Actually building a Vertex client is not a unit test: it reads ambient
    // Application Default Credentials and `GOOGLE_CLOUD_*`, and needs a Tokio
    // reactor. That lives in `tests/vertexai_integration.rs`.

    #[test]
    fn vertex_ai_needs_no_credential_or_base_url() {
        // Guards the shape of the config rather than the network: Vertex is the
        // one provider addressed by project/location instead of key/URL.
        let config = ClientConfig::new("")
            .project("demo")
            .location("us-central1");
        assert_eq!(config.project, Some("demo"));
        assert_eq!(config.location, Some("us-central1"));
        assert!(config.api_key.is_empty());
        assert!(config.base_url.is_none());
    }
}
