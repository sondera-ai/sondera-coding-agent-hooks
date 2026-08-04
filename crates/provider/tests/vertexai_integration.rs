//! Integration tests for the Google Cloud Vertex AI provider.
//!
//! Unlike every other provider in the registry, Vertex AI takes no API key: it
//! reads Application Default Credentials and is addressed by project and
//! location. That makes building a client an environment-dependent act, so it
//! is tested here rather than in the crate's unit tests.
//!
//! To run:
//!   cargo test -p sondera-provider --test vertexai_integration
//!
//! Prerequisites:
//!   gcloud auth application-default login
//!   export GOOGLE_CLOUD_PROJECT=<your-project>   # or pass it via ClientConfig
//!
//! Note these tests only construct the client — they issue no request and so
//! incur no cost. A misconfigured project surfaces on the first completion, not
//! here, because Vertex has no credential-verification endpoint.

use sondera_provider::{ClientConfig, Provider};

/// The project this run should use, or `None` when the environment has not been
/// set up. Every test short-circuits on `None` so a checkout without gcloud
/// credentials reports a pass rather than a spurious failure.
fn project() -> Option<String> {
    std::env::var("GOOGLE_CLOUD_PROJECT")
        .ok()
        .filter(|value| !value.is_empty())
}

#[tokio::test]
async fn builds_a_client_from_ambient_credentials() {
    let Some(project) = project() else {
        eprintln!("skipping: GOOGLE_CLOUD_PROJECT is unset");
        return;
    };

    let config = ClientConfig::new("").project(&project);
    let client = Provider::VertexAi
        .client(&config)
        .expect("a Vertex AI client should build from ADC");

    // `Client` does not implement `PartialEq`, and its `Debug` names only the
    // variant — which is exactly the assertion worth making: the registry
    // dispatched to the Vertex arm rather than falling through to another.
    assert_eq!(format!("{client:?}"), "Client(\"VertexAi\")");
}

#[tokio::test]
async fn an_explicit_location_is_accepted() {
    let Some(project) = project() else {
        eprintln!("skipping: GOOGLE_CLOUD_PROJECT is unset");
        return;
    };

    let config = ClientConfig::new("")
        .project(&project)
        .location("us-central1");

    assert!(
        Provider::VertexAi.client(&config).is_ok(),
        "a regional endpoint should build as readily as the default `global`"
    );
}

#[tokio::test]
async fn a_completion_model_is_reachable_through_the_dynamic_client() {
    let Some(project) = project() else {
        eprintln!("skipping: GOOGLE_CLOUD_PROJECT is unset");
        return;
    };

    let client = Provider::VertexAi
        .client(&ClientConfig::new("").project(&project))
        .expect("a Vertex AI client should build from ADC");

    // The point of the enum: a runtime-selected provider still yields the same
    // erased completion model the guardrails' extractors drive. Constructing it
    // issues no request.
    let _model = client.completion_model_dyn("gemini-2.5-flash");
}
