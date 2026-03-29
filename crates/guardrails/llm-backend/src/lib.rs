//! LLM backend abstraction for Sondera guardrail crates.
//!
//! Provides a unified interface for calling LLM chat completions across different
//! backends. Currently supports:
//!
//! - **Ollama** — native Ollama API via `ollama-rs` (`/api/chat`)
//! - **OpenAI** — OpenAI-compatible API via `reqwest` (`/v1/chat/completions`)
//!
//! Backend selection is driven by [`BackendConfig`] which can be constructed
//! from environment variables via [`BackendConfig::from_env`].

mod ollama;
mod openai;

pub use self::ollama::OllamaBackend;
pub use self::openai::OpenAiBackend;

use std::time::Duration;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from LLM backend operations.
#[derive(Debug, Error)]
pub enum LlmBackendError {
    #[error("LLM request failed: {0}")]
    RequestFailed(String),
    #[error("LLM request timed out after {0}s")]
    Timeout(u64),
    #[error("LLM response parse error: {0}")]
    InvalidResponse(String),
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Backend selection and connection configuration.
///
/// Defaults to Ollama at `localhost:11434` for backward compatibility.
#[derive(Debug, Clone)]
pub enum BackendConfig {
    Ollama {
        host: String,
        port: u16,
    },
    OpenAi {
        base_url: String,
        api_key: Option<String>,
    },
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self::Ollama {
            host: "http://localhost".to_string(),
            port: 11434,
        }
    }
}

impl BackendConfig {
    /// Construct a [`BackendConfig`] from environment variables.
    ///
    /// | Variable | Default | Description |
    /// |----------|---------|-------------|
    /// | `SONDERA_BACKEND` | `ollama` | `ollama` or `openai` |
    /// | `SONDERA_OLLAMA_HOST` | `http://localhost` | Ollama host URL |
    /// | `SONDERA_OLLAMA_PORT` | `11434` | Ollama port |
    /// | `SONDERA_OPENAI_BASE_URL` | *(required)* | OpenAI-compatible endpoint |
    /// | `SONDERA_OPENAI_API_KEY` | *(none)* | Optional API key |
    pub fn from_env() -> Self {
        let backend = std::env::var("SONDERA_BACKEND").unwrap_or_else(|_| "ollama".to_string());

        match backend.as_str() {
            "openai" => {
                let base_url = std::env::var("SONDERA_OPENAI_BASE_URL")
                    .expect("SONDERA_OPENAI_BASE_URL must be set when SONDERA_BACKEND=openai");
                let api_key = std::env::var("SONDERA_OPENAI_API_KEY").ok();
                Self::OpenAi { base_url, api_key }
            }
            _ => {
                let host = std::env::var("SONDERA_OLLAMA_HOST")
                    .unwrap_or_else(|_| "http://localhost".to_string());
                let port = std::env::var("SONDERA_OLLAMA_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(11434);
                Self::Ollama { host, port }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LlmBackend enum
// ---------------------------------------------------------------------------

/// Unified LLM backend using enum dispatch.
///
/// Avoids async trait object safety issues by dispatching at the enum level.
/// Supports Ollama (native API) and OpenAI-compatible endpoints.
#[derive(Clone)]
pub enum LlmBackend {
    Ollama(OllamaBackend),
    OpenAi(OpenAiBackend),
}

impl LlmBackend {
    /// Construct from a [`BackendConfig`].
    pub fn from_config(config: &BackendConfig) -> Self {
        match config {
            BackendConfig::Ollama { host, port } => {
                Self::Ollama(OllamaBackend::new(host.clone(), *port))
            }
            BackendConfig::OpenAi { base_url, api_key } => {
                Self::OpenAi(OpenAiBackend::new(base_url.clone(), api_key.clone()))
            }
        }
    }

    /// Construct from environment variables.
    ///
    /// Reads `SONDERA_BACKEND` and related env vars.
    pub fn from_env() -> Self {
        Self::from_config(&BackendConfig::from_env())
    }

    /// Send a chat completion request with structured JSON output.
    ///
    /// Returns the raw response content string (expected to be valid JSON
    /// matching the provided schema).
    pub async fn chat_completion(
        &self,
        model: &str,
        system_prompt: &str,
        user_prompt: &str,
        json_schema: serde_json::Value,
        temperature: f32,
        timeout: Duration,
    ) -> Result<String, LlmBackendError> {
        match self {
            Self::Ollama(b) => {
                b.chat_completion(model, system_prompt, user_prompt, json_schema, temperature, timeout)
                    .await
            }
            Self::OpenAi(b) => {
                b.chat_completion(model, system_prompt, user_prompt, json_schema, temperature, timeout)
                    .await
            }
        }
    }
}

impl std::fmt::Debug for LlmBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ollama(_) => f.write_str("LlmBackend::Ollama"),
            Self::OpenAi(_) => f.write_str("LlmBackend::OpenAi"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_config_default_is_ollama() {
        let config = BackendConfig::default();
        match config {
            BackendConfig::Ollama { host, port } => {
                assert_eq!(host, "http://localhost");
                assert_eq!(port, 11434);
            }
            _ => panic!("Default should be Ollama"),
        }
    }

    #[test]
    fn backend_config_ollama_constructor() {
        let config = BackendConfig::Ollama {
            host: "http://192.168.1.1".to_string(),
            port: 11435,
        };
        match config {
            BackendConfig::Ollama { host, port } => {
                assert_eq!(host, "http://192.168.1.1");
                assert_eq!(port, 11435);
            }
            _ => panic!("Should be Ollama"),
        }
    }

    #[test]
    fn backend_config_openai_constructor() {
        let config = BackendConfig::OpenAi {
            base_url: "http://localhost:4000/v1".to_string(),
            api_key: Some("sk-test".to_string()),
        };
        match config {
            BackendConfig::OpenAi { base_url, api_key } => {
                assert_eq!(base_url, "http://localhost:4000/v1");
                assert_eq!(api_key.as_deref(), Some("sk-test"));
            }
            _ => panic!("Should be OpenAi"),
        }
    }

    #[test]
    fn llm_backend_from_config_ollama() {
        let config = BackendConfig::default();
        let backend = LlmBackend::from_config(&config);
        assert!(matches!(backend, LlmBackend::Ollama(_)));
    }

    #[test]
    fn llm_backend_from_config_openai() {
        let config = BackendConfig::OpenAi {
            base_url: "http://localhost:4000/v1".to_string(),
            api_key: None,
        };
        let backend = LlmBackend::from_config(&config);
        assert!(matches!(backend, LlmBackend::OpenAi(_)));
    }
}
