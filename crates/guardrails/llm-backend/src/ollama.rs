//! Ollama backend — wraps `ollama-rs` to call Ollama's native `/api/chat` endpoint.

use crate::LlmBackendError;
use ollama_rs::{
    Ollama,
    generation::chat::{ChatMessage, request::ChatMessageRequest},
    generation::parameters::{FormatType, JsonStructure},
    models::ModelOptions,
};
use std::time::Duration;

/// Ollama backend using the native Ollama API via `ollama-rs`.
#[derive(Clone)]
pub struct OllamaBackend {
    client: Ollama,
}

impl OllamaBackend {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let host_str: String = host.into();
        Self {
            client: Ollama::new(&host_str, port),
        }
    }

    /// Send a chat completion request via Ollama's `/api/chat` endpoint.
    ///
    /// The `json_schema` value is deserialized into a `schemars::Schema` and
    /// passed as `FormatType::StructuredJson` to constrain the model output.
    pub async fn chat_completion(
        &self,
        model: &str,
        system_prompt: &str,
        user_prompt: &str,
        json_schema: serde_json::Value,
        temperature: f32,
        timeout: Duration,
    ) -> Result<String, LlmBackendError> {
        let schema: schemars::Schema = serde_json::from_value(json_schema)
            .map_err(|e| LlmBackendError::InvalidResponse(format!("Invalid JSON schema: {e}")))?;

        let messages = vec![
            ChatMessage::system(system_prompt.to_string()),
            ChatMessage::user(user_prompt.to_string()),
        ];

        let format = FormatType::StructuredJson(Box::new(JsonStructure::new_for_schema(schema)));

        let request = ChatMessageRequest::new(model.to_string(), messages)
            .format(format)
            .options(ModelOptions::default().temperature(temperature));

        let response = tokio::time::timeout(timeout, self.client.send_chat_messages(request))
            .await
            .map_err(|_| LlmBackendError::Timeout(timeout.as_secs()))?
            .map_err(|e| LlmBackendError::RequestFailed(e.to_string()))?;

        Ok(response.message.content)
    }
}
