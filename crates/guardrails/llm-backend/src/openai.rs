//! OpenAI-compatible backend — uses `reqwest` to call `/v1/chat/completions`.
//!
//! Works with any OpenAI-compatible endpoint including DreamServer's LiteLLM,
//! llama-server, vLLM, and others.

use crate::LlmBackendError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// OpenAI-compatible backend using `reqwest`.
#[derive(Clone)]
pub struct OpenAiBackend {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    preamble_enabled: bool,
}

impl OpenAiBackend {
    pub fn new(base_url: impl Into<String>, api_key: Option<String>) -> Self {
        let preamble_enabled = std::env::var("SONDERA_OPENAI_PREAMBLE")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
            api_key,
            preamble_enabled,
        }
    }

    /// Send a chat completion request via OpenAI-compatible `/v1/chat/completions`.
    ///
    /// Structured output is requested via `response_format` with `json_schema` type.
    /// When `preamble_enabled` is true, a classification-focused instruction is
    /// prepended to the system prompt for general-purpose models.
    pub async fn chat_completion(
        &self,
        model: &str,
        system_prompt: &str,
        user_prompt: &str,
        json_schema: serde_json::Value,
        temperature: f32,
        timeout: Duration,
    ) -> Result<String, LlmBackendError> {
        let system_content = if self.preamble_enabled {
            format!(
                "You are a content classification system. Respond with ONLY a valid JSON object \
                 matching the required schema. No markdown, no explanation, no extra text.\n\n{}",
                system_prompt
            )
        } else {
            system_prompt.to_string()
        };

        // Resolve $ref references in the schema — some OpenAI-compatible servers
        // (e.g. llama-server) do not resolve $ref internally, so we inline them.
        let resolved_schema = resolve_refs(&json_schema);

        let request_body = ChatCompletionRequest {
            model: model.to_string(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: system_content,
                },
                Message {
                    role: "user".to_string(),
                    content: user_prompt.to_string(),
                },
            ],
            temperature,
            response_format: Some(ResponseFormat {
                r#type: "json_schema".to_string(),
                json_schema: Some(JsonSchemaFormat {
                    name: "response".to_string(),
                    strict: true,
                    schema: resolved_schema,
                }),
            }),
        };

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));

        let mut req = self.client.post(&url).json(&request_body);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }

        let response = tokio::time::timeout(timeout, req.send())
            .await
            .map_err(|_| LlmBackendError::Timeout(timeout.as_secs()))?
            .map_err(|e| LlmBackendError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(LlmBackendError::RequestFailed(format!(
                "HTTP {status}: {body}"
            )));
        }

        let body: ChatCompletionResponse = response.json().await.map_err(|e| {
            LlmBackendError::InvalidResponse(format!("Failed to parse response: {e}"))
        })?;

        let content = body
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .unwrap_or_default();

        if content.is_empty() {
            return Err(LlmBackendError::InvalidResponse(
                "Empty response content from model".to_string(),
            ));
        }

        Ok(content)
    }
}

// ---------------------------------------------------------------------------
// OpenAI API request/response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<Message>,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Debug, Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct ResponseFormat {
    r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    json_schema: Option<JsonSchemaFormat>,
}

#[derive(Debug, Serialize)]
struct JsonSchemaFormat {
    name: String,
    strict: bool,
    schema: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    #[serde(default)]
    content: String,
}

// ---------------------------------------------------------------------------
// JSON Schema $ref resolver
// ---------------------------------------------------------------------------

/// Inline all `$ref` pointers in a JSON Schema so that servers which do not
/// resolve `$ref` (e.g. llama-server) can still apply grammar constraints.
fn resolve_refs(schema: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;

    let defs = schema
        .get("$defs")
        .or_else(|| schema.get("definitions"))
        .cloned()
        .unwrap_or(Value::Object(Default::default()));

    fn inline(node: &Value, defs: &Value) -> Value {
        match node {
            Value::Object(map) => {
                if let Some(Value::String(r)) = map.get("$ref") {
                    // Resolve "#/$defs/Foo" or "#/definitions/Foo"
                    let name = r
                        .strip_prefix("#/$defs/")
                        .or_else(|| r.strip_prefix("#/definitions/"));
                    if let Some(def_name) = name {
                        if let Some(def) = defs.get(def_name) {
                            return inline(def, defs);
                        }
                    }
                }
                let mut out = serde_json::Map::new();
                for (k, v) in map {
                    if k == "$defs" || k == "definitions" {
                        continue; // strip the definitions block
                    }
                    out.insert(k.clone(), inline(v, defs));
                }
                Value::Object(out)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(|v| inline(v, defs)).collect()),
            other => other.clone(),
        }
    }

    inline(schema, &defs)
}
