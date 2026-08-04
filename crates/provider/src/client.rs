//! The provider-agnostic [`Client`] enum and the adapter that lets it drive
//! rig's completion, agent, and extractor pipelines.

use std::fmt;

use rig::client::CompletionClient;
use rig::completion::{
    self, CompletionError, CompletionRequest, CompletionResponse, GetTokenUsage, Usage,
};
use rig::providers;
use rig::streaming::StreamingCompletionResponse;
use serde::{Deserialize, Serialize};

use crate::model::DynCompletionModel;

/// A constructed LLM provider client.
///
/// Exactly one variant is populated, chosen at runtime by
/// [`Provider::client`](crate::Provider::client). Because the variants wrap
/// distinct rig client types, use [`Client::completion_model_dyn`] (or the
/// [`CompletionClient`] implementation) to obtain a uniform completion model.
#[derive(Clone)]
#[non_exhaustive]
pub enum Client {
    /// Anthropic client.
    Anthropic(providers::anthropic::Client),
    /// Azure OpenAI client.
    Azure(providers::azure::Client),
    /// Cohere client.
    Cohere(providers::cohere::Client),
    /// DeepSeek client.
    DeepSeek(providers::deepseek::Client),
    /// Google Gemini client.
    Gemini(providers::gemini::Client),
    /// Groq client.
    Groq(providers::groq::Client),
    /// HuggingFace client.
    HuggingFace(providers::huggingface::Client),
    /// Hyperbolic client.
    Hyperbolic(providers::hyperbolic::Client),
    /// Mira client.
    Mira(providers::mira::Client),
    /// Moonshot client.
    Moonshot(providers::moonshot::Client),
    /// OpenAI client.
    OpenAI(providers::openai::Client),
    /// OpenRouter client.
    OpenRouter(providers::openrouter::Client),
    /// Ollama client (local models).
    Ollama(providers::ollama::Client),
    /// Perplexity client.
    Perplexity(providers::perplexity::Client),
    /// TogetherAI client.
    Together(providers::together::Client),
    /// Google Cloud Vertex AI client.
    VertexAi(rig_vertexai::Client),
    /// xAI client.
    Xai(providers::xai::Client),
}

impl Client {
    /// Build a completion model for `model`, erased behind a trait object so the
    /// return type is uniform across every provider variant.
    pub fn completion_model_dyn(&self, model: &str) -> Box<dyn DynCompletionModel> {
        macro_rules! dispatch {
            ($($variant:ident),* $(,)?) => {
                match self {
                    $( Client::$variant(client) => Box::new(client.completion_model(model)), )*
                }
            };
        }
        dispatch!(
            Anthropic,
            Azure,
            Cohere,
            DeepSeek,
            Gemini,
            Groq,
            HuggingFace,
            Hyperbolic,
            Mira,
            Moonshot,
            OpenAI,
            OpenRouter,
            Ollama,
            Perplexity,
            Together,
            VertexAi,
            Xai,
        )
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The wrapped rig provider clients do not uniformly implement `Debug`,
        // so identify the client by its provider variant.
        macro_rules! variant_name {
            ($($variant:ident),* $(,)?) => {
                match self { $( Client::$variant(_) => stringify!($variant), )* }
            };
        }
        let variant = variant_name!(
            Anthropic,
            Azure,
            Cohere,
            DeepSeek,
            Gemini,
            Groq,
            HuggingFace,
            Hyperbolic,
            Mira,
            Moonshot,
            OpenAI,
            OpenRouter,
            Ollama,
            Perplexity,
            Together,
            VertexAi,
            Xai,
        );
        f.debug_tuple("Client").field(&variant).finish()
    }
}

/// The streaming response type of [`DynamicCompletionModel`], which never
/// produces one.
///
/// rig requires `CompletionModel::StreamingResponse` to be a concrete,
/// serializable type carrying token usage even for a model that does not
/// stream. Since `DynamicCompletionModel::stream` always fails, no value of
/// this type is ever constructed; it exists to satisfy the bound and to say so
/// in the type name. (rig-core supplied a `FinalCompletionResponse` for this
/// through 0.35; 0.41 dropped it.)
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NoStreamingResponse {
    /// Always absent — retained so the shape matches a real usage report.
    pub usage: Option<Usage>,
}

impl GetTokenUsage for NoStreamingResponse {
    fn token_usage(&self) -> Usage {
        self.usage.unwrap_or_default()
    }
}

/// Adapter implementing rig's [`completion::CompletionModel`] on top of the
/// dynamic [`Client`].
///
/// This is the associated model type of the [`CompletionClient`] implementation
/// for [`Client`], which is what allows `client.agent(..)` and
/// `client.extractor::<T>(..)` to work against a runtime-selected provider. Raw
/// and streaming responses are erased: only unary completion is supported.
#[derive(Clone, Debug)]
pub struct DynamicCompletionModel {
    client: Client,
    model: String,
}

impl completion::CompletionModel for DynamicCompletionModel {
    type Response = ();
    type StreamingResponse = NoStreamingResponse;
    type Client = Client;

    fn make(client: &Self::Client, model: impl Into<String>) -> Self {
        Self {
            client: client.clone(),
            model: model.into(),
        }
    }

    async fn completion(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse<Self::Response>, CompletionError> {
        self.client
            .completion_model_dyn(&self.model)
            .completion(request)
            .await
    }

    async fn stream(
        &self,
        _request: CompletionRequest,
    ) -> Result<StreamingCompletionResponse<Self::StreamingResponse>, CompletionError> {
        Err(CompletionError::ResponseError(
            "streaming is not supported by the dynamic provider adapter".to_string(),
        ))
    }
}

impl CompletionClient for Client {
    type CompletionModel = DynamicCompletionModel;
}
