//! Integration tests for data sensitivity classification against a local Ollama server.
//!
//! These tests require a running Ollama instance with the `gpt-oss-safeguard:20b`
//! model pulled.
//!
//! To run:
//!   cargo test -p sondera-information-flow-control --test ollama_integration
//!
//! Prerequisites:
//!   ollama pull gpt-oss-safeguard:20b
//!   ollama serve  # default: http://localhost:11434

use sondera_information_flow_control::{
    DataModel, DataModelBuilder, Label, LabelTemplate, SensitivityClassification,
};

const BASELINE_TOML: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../policies/ifc.toml");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn baseline_model() -> DataModel {
    DataModel::from_toml(BASELINE_TOML).expect("baseline.toml should load")
}

fn single_label_model(label: LabelTemplate) -> DataModel {
    DataModelBuilder::new().label(label).build()
}

fn assert_sensitive(result: &SensitivityClassification, expected_label: Label) {
    assert!(
        result.is_sensitive(),
        "Expected sensitive result for {}, got public",
        expected_label.display_name()
    );
    let matching = result.findings_by_label(expected_label);
    assert!(
        !matching.is_empty(),
        "Expected finding with label {}, found: {:?}",
        expected_label.display_name(),
        result
            .findings
            .iter()
            .map(|f| f.label.display_name())
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// PUBLIC tests — should NOT be flagged as sensitive
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn public_press_release_is_not_sensitive() {
    let model = baseline_model();
    let content = "Our company was founded in 2010 and is headquartered in San Francisco. \
                   We are excited to announce our latest product launch.";
    let result = model.classify(content).await.unwrap();
    assert!(
        result.is_public(),
        "Public press release should not be sensitive, got: {result}"
    );
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn public_open_source_license_is_not_sensitive() {
    let model = baseline_model();
    let content = "MIT License - Permission is hereby granted, free of charge, to any person \
                   obtaining a copy of this software and associated documentation files.";
    let result = model.classify(content).await.unwrap();
    assert!(
        result.is_public(),
        "Open source license text should not be sensitive, got: {result}"
    );
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn public_event_announcement_is_not_sensitive() {
    let model = baseline_model();
    let content = "The annual developer conference is scheduled for March 15th at 10 AM PST. \
                   Registration is open to the public on our website.";
    let result = model.classify(content).await.unwrap();
    assert!(
        result.is_public(),
        "Public event announcement should not be sensitive, got: {result}"
    );
}

// ---------------------------------------------------------------------------
// INTERNAL tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn internal_meeting_notes_are_sensitive() {
    let model = baseline_model();
    let content = "Team standup notes: We discussed sprint planning for Q2. \
                   Action items include refactoring the auth module and updating \
                   the internal wiki. For internal use only.";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::Internal);
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn internal_company_memo_is_sensitive() {
    let model = baseline_model();
    let content = "Internal memo: The holiday schedule for this year has been updated. \
                   All employees should review the new policy on the company intranet. \
                   Do not share externally.";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::Internal);
}

// ---------------------------------------------------------------------------
// CONFIDENTIAL tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn confidential_revenue_data_is_sensitive() {
    let model = baseline_model();
    let content = "Q3 revenue was $12.5M with a 15% increase over Q2. \
                   The board has approved a revised forecast of $55M ARR for the fiscal year.";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::Confidential);
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn confidential_customer_list_is_sensitive() {
    let model = baseline_model();
    let content = "Customer list includes: Acme Corp ($500K ARR), TechStart Inc ($250K ARR), \
                   Global Systems ($1.2M ARR). Share only with authorized sales personnel.";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::Confidential);
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn confidential_pricing_strategy_is_sensitive() {
    let model = baseline_model();
    let content = "Pricing strategy: Enterprise tier at $50K/year, mid-market at $15K/year. \
                   We plan to increase Enterprise pricing by 20% in Q1 next year.";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::Confidential);
}

// ---------------------------------------------------------------------------
// HIGHLY CONFIDENTIAL tests — PII
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn highly_confidential_ssn_is_sensitive() {
    let model = baseline_model();
    let content = "Employee SSN: 123-45-6789";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::HighlyConfidential);
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn highly_confidential_full_pii_is_sensitive() {
    let model = baseline_model();
    let content = "John Smith, DOB: 1985-03-15, Address: 123 Main St, Anytown, USA 12345. \
                   Social Security Number: 987-65-4321.";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::HighlyConfidential);
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn highly_confidential_credit_card_is_sensitive() {
    let model = baseline_model();
    let content = "Credit card: 4111-1111-1111-1111, Exp: 12/25, CVV: 123";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::HighlyConfidential);
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn highly_confidential_passport_is_sensitive() {
    let model = baseline_model();
    let content = "Passport number: AB1234567, Expiry: 2028-05-20, \
                   Issued to: Jane Doe, Nationality: US";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::HighlyConfidential);
}

// ---------------------------------------------------------------------------
// HIGHLY CONFIDENTIAL tests — Credentials
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn highly_confidential_api_key_is_sensitive() {
    let model = baseline_model();
    let content = "API_KEY=sk-live-abc123def456ghi789";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::HighlyConfidential);
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn highly_confidential_database_password_is_sensitive() {
    let model = baseline_model();
    let content = "DB_PASSWORD=MyS3cur3P@ssw0rd!";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::HighlyConfidential);
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn highly_confidential_aws_secret_key_is_sensitive() {
    let model = baseline_model();
    let content = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::HighlyConfidential);
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn highly_confidential_private_key_is_sensitive() {
    let model = baseline_model();
    let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::HighlyConfidential);
}

// ---------------------------------------------------------------------------
// HIGHLY CONFIDENTIAL tests — Healthcare / Business Critical
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn highly_confidential_medical_record_is_sensitive() {
    let model = baseline_model();
    let content = "Patient diagnosis: Type 2 Diabetes, prescribed Metformin 500mg. \
                   Blood pressure 140/90, cholesterol 220.";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::HighlyConfidential);
}

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn highly_confidential_mna_data_is_sensitive() {
    let model = baseline_model();
    let content = "M&A target: Acquiring CompetitorCo for $500M, announcement in 2 weeks. \
                   Due diligence is in progress. Board approval obtained.";
    let result = model.classify(content).await.unwrap();
    assert_sensitive(&result, Label::HighlyConfidential);
}

// ---------------------------------------------------------------------------
// Single-label evaluation
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn single_label_pii_detection() {
    let label = LabelTemplate::new("PII_CHECK")
        .instructions(
            "Evaluate content for personally identifiable information. \
             If PII is present: {\"sensitive\": 1, \"sensitivity_category\": \"highly_confidential\"} \
             If no PII: {\"sensitive\": 0, \"sensitivity_category\": \"public\"}",
        )
        .category(Label::Public, "No personally identifiable information.")
        .category(
            Label::HighlyConfidential,
            "Contains names, SSN, addresses, phone numbers, or other PII.",
        )
        .example("The weather today is sunny.", false, Label::Public)
        .example("Employee SSN: 123-45-6789", true, Label::HighlyConfidential);

    let model = single_label_model(label);
    let content = "Contact Jane Doe at 555-0123, SSN 987-65-4321.";
    let result = model.classify(content).await.unwrap();
    assert!(result.is_sensitive());
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].label, Label::HighlyConfidential);
}

// ---------------------------------------------------------------------------
// Full baseline smoke test — public content passes all labels
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires running Ollama instance"]
async fn baseline_public_content_passes_all_labels() {
    let model = baseline_model();
    let content = "Welcome to our open-source project! This README explains how to get started. \
                   Clone the repository and run `cargo build` to compile. \
                   Licensed under MIT. Contributions are welcome via pull requests. \
                   Visit our website at https://example.com for documentation.";
    let result = model.classify(content).await.unwrap();
    assert!(
        result.is_public(),
        "Clearly public content should pass all baseline labels, got: {result}"
    );
}
