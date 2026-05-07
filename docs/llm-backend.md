# LLM Backend Abstraction

## Overview

The `sondera-llm-backend` crate provides a unified interface for LLM inference
across multiple backend types. It enables Sondera's guardrail crates (IFC and
Policy) to use either Ollama's native API or any OpenAI-compatible endpoint
(such as LiteLLM, vLLM, or DreamServer) without changing guardrail logic.

## Architecture

```
┌─────────────────────────────────────────────────┐
│               sondera-harness                   │
│                                                 │
│  ┌──────────────────┐  ┌─────────────────────┐  │
│  │  DataModel (IFC) │  │ PolicyModel (Policy) │  │
│  └────────┬─────────┘  └──────────┬──────────┘  │
│           └──────────┬────────────┘              │
│                      │                           │
│              ┌───────▼────────┐                  │
│              │   LlmBackend   │                  │
│              │  (enum dispatch)│                  │
│              └───┬────────┬───┘                  │
│                  │        │                      │
│        ┌─────────▼┐  ┌───▼──────────┐           │
│        │  Ollama   │  │   OpenAi     │           │
│        │ Backend   │  │  Backend     │           │
│        └─────┬─────┘  └──────┬──────┘           │
└──────────────┼───────────────┼───────────────────┘
               │               │
       ┌───────▼───────┐ ┌────▼──────────────────┐
       │ Ollama Server │ │ OpenAI-compatible API  │
       │ /api/chat     │ │ /v1/chat/completions   │
       └───────────────┘ │ (LiteLLM, DreamServer, │
                         │  vLLM, etc.)            │
                         └─────────────────────────┘
```

## Why Enum Dispatch

The backend uses `enum LlmBackend { Ollama(..), OpenAi(..) }` instead of
`Box<dyn Backend>` because:

- `async fn` in traits is not object-safe without `async-trait` (adds a
  dependency and heap allocation per call)
- Only 2 backends exist — a closed set that benefits from exhaustive matching
- Zero-overhead dispatch at compile time
- Adding a new backend is a single enum variant + match arm

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SONDERA_BACKEND` | `ollama` | Backend type: `ollama` or `openai` |
| `SONDERA_OLLAMA_HOST` | `http://localhost` | Ollama host URL |
| `SONDERA_OLLAMA_PORT` | `11434` | Ollama port |
| `SONDERA_OPENAI_BASE_URL` | (none) | OpenAI-compatible endpoint URL |
| `SONDERA_OPENAI_API_KEY` | (none) | Optional API key |
| `SONDERA_MODEL` | `gpt-oss-safeguard:20b` | Model name override |
| `SONDERA_OPENAI_PREAMBLE` | `true` | Prepend classification preamble for general-purpose models |

### Programmatic Configuration

```rust
use sondera_llm_backend::{BackendConfig, LlmBackend};

// Ollama (default)
let backend = LlmBackend::from_config(&BackendConfig::default());

// OpenAI-compatible
let backend = LlmBackend::from_config(&BackendConfig::OpenAi {
    base_url: "http://localhost:4000/v1".to_string(),
    api_key: Some("your-key".to_string()),
});

// From environment variables
let backend = LlmBackend::from_env();
```

## DreamServer Deployment

DreamServer exposes LiteLLM on port 4000, which proxies to llama-server on
port 8080. To use it with Sondera:

```bash
# Set environment variables (or add to ~/.sondera/env)
export SONDERA_BACKEND=openai
export SONDERA_OPENAI_BASE_URL=http://localhost:4000/v1
export SONDERA_OPENAI_API_KEY=<litellm-key>
export SONDERA_MODEL=default
```

Run the harness server:

```bash
sondera-harness-server --verbose
```

Or use the `policy-eval` binary directly:

```bash
policy-eval input.py --backend openai --base-url http://localhost:4000/v1
```

## Structured Output Mapping

Both backends enforce structured JSON output via JSON Schema:

| Aspect | Ollama | OpenAI-compatible |
|--------|--------|-------------------|
| Schema source | `schemars::schema_for!()` | Same |
| Wire format | `format: { type: "structured_json", schema: <value> }` | `response_format: { type: "json_schema", json_schema: { name: "response", strict: true, schema: <value> } }` |
| Response | Direct JSON string | `choices[0].message.content` |

## System Preamble (OpenAI Backend)

When using general-purpose models (not gpt-oss-safeguard), the OpenAI backend
optionally prepends a classification preamble to the system prompt. This helps
steer the model toward the expected structured output format.

Controlled by `SONDERA_OPENAI_PREAMBLE` (default: `true`). Set to `false` if
the model already understands the policy evaluation task format.

## Model Recommendations

| Model | Backend | Accuracy | Speed (CPU) | Notes |
|-------|---------|----------|-------------|-------|
| gpt-oss-safeguard:20b | Ollama | High | ~10-30s | Purpose-built for policy classification |
| DreamServer default | OpenAI | Medium-High | ~10-60s | General-purpose; preamble helps |
| Any OpenAI-compatible | OpenAI | Varies | Varies | Use structured output for best results |

## Crate Dependencies

```
sondera-harness
├── sondera-information-flow-control  (IFC guardrail)
│   └── sondera-llm-backend
├── sondera-policy                    (Policy guardrail)
│   └── sondera-llm-backend
└── sondera-llm-backend               (direct, for from_env())
```
