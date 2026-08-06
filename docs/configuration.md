# Configuration

Everything the harness reads lives under a `.sondera/` directory:

```
.sondera/
├── sondera.toml      # Bind address and guardrail model settings
├── policies/cedar/   # Cedar policies and schema — see Policies
├── ifc.toml          # Prompt templates for LLM-based data classification
└── policies.toml     # Prompt templates for LLM-based secure code generation evaluation
```

`sondera serve` loads from the nearest `.sondera/` at or above the working
directory and falls back per asset to `~/.sondera/`. The assets resolve
independently and nearest-wins, so a project `.sondera/` need only carry what it
overrides.

`crates/settings/src/lib.rs` owns the resolution semantics — scope precedence,
per-guardrail overrides, the opt-in `[scanner]` table, and where each cost is
paid. Read the `sondera_settings` docs there for the full rules.

## Server flags and environment

```bash
cargo run -p sondera -- serve \
  --config-dir /path/to/.sondera \
  --addr 127.0.0.1:50051 \
  --db /path/to/trajectories.db \
  -v
```

| What | Flag | Environment variable | Default |
|------|------|----------------------|---------|
| Harness bind address | `--addr` | `SONDERA_HARNESS_ADDR` | `127.0.0.1:50051` |
| Config directory | `--config-dir` | — | nearest `.sondera/`, then `~/.sondera/` |
| Trajectory database | `--db` | — | `~/.sondera/trajectories/trajectories.db` |
| Endpoint hook clients dial | — | `SONDERA_HARNESS_ENDPOINT` | `http://127.0.0.1:50051` |

## Optional LLM guardrails

The YARA signature engine and Cedar policy evaluation are deterministic and
always on. The two LLM-based classifiers — data sensitivity and secure code
policy — are probabilistic, sit on the adjudication path, and are disabled by
default. Both are gated by one key: set `enabled = true` under `[guardrails]` in
`.sondera/sondera.toml` and point them at a provider.

For [Ollama](https://ollama.com/) with the `gpt-oss-safeguard:20b` model:

```bash
# Install Ollama — see https://ollama.com/download for other platforms
brew install ollama

# Pull the model (~14 GB)
ollama pull gpt-oss-safeguard:20b
```

Ollama is the default when model guardrails are enabled, not a requirement: the
classifiers run against any provider in the registry — OpenAI-compatible
servers, Anthropic, Gemini, Google Cloud Vertex AI, and others — selected in
`.sondera/sondera.toml`.

Vertex AI is the one provider configured by project and location instead of a
key and URL, since it authenticates with Application Default Credentials:

```toml
[guardrails]
enabled = true
provider = "vertexai"
project = "my-gcp-project"
location = "us-central1"   # optional; defaults to `global`
model = "gemini-2.5-flash"
```

That needs `gcloud auth application-default login` (or a service account on
GCP); `project` and `location` fall back to `GOOGLE_CLOUD_PROJECT` and
`GOOGLE_CLOUD_LOCATION`.

Size the two classifiers separately with `[guardrails.data]` and
`[guardrails.policy]`, which override the shared table key by key.

### What gets sent to the provider

Only content carried by a normalized event is sent to the configured provider.
Shell commands never cause the harness to read guessed host paths; file content
reaches classification through explicit file-operation events.

### Cost

Enabling the classifiers adds latency to every decision they touch. Each fails
open when disabled, erroring, or slower than the adjudication budget — to
compliant with no violations, and to `Public` — so Cedar still runs and the
deterministic policies still decide.
