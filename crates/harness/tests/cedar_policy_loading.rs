//! Integration tests for loading Cedar policies and schemas from the policies directory.

use sondera_harness::CedarPolicyHarness;
use std::path::PathBuf;

const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

async fn load_harness() -> (CedarPolicyHarness, tempfile::TempDir) {
    let path = PathBuf::from(POLICIES_DIR);
    let temp_dir = tempfile::tempdir().expect("should create temp dir for entity store");
    let harness = CedarPolicyHarness::from_policy_dir_isolated(path, temp_dir.path())
        .await
        .expect("should load policies directory");
    (harness, temp_dir)
}

#[tokio::test]
async fn loads_policies_dir() {
    let (harness, _temp_dir) = load_harness().await;
    drop(harness);
}

#[tokio::test]
async fn policies_have_id_annotations() {
    let (harness, _temp_dir) = load_harness().await;

    // base.cedar contains @id("default-permit")
    let policy = harness
        .policy_set()
        .policy(&"default-permit".parse().unwrap());
    assert!(
        policy.is_some(),
        "expected policy with @id(\"default-permit\") to be loaded"
    );

    let policy = policy.unwrap();
    assert_eq!(
        policy.annotation("description"),
        Some("Permit all actions unless a forbid below fires.")
    );
}

#[tokio::test]
async fn schema_contains_expected_entity_types() {
    let (harness, _temp_dir) = load_harness().await;

    let schema = harness.schema();
    let entity_type_names: Vec<String> = schema.entity_types().map(|t| t.to_string()).collect();

    assert!(
        entity_type_names.contains(&"Agent".to_string()),
        "schema should contain Agent entity type, got: {entity_type_names:?}"
    );
    assert!(
        entity_type_names.contains(&"Trajectory".to_string()),
        "schema should contain Trajectory entity type, got: {entity_type_names:?}"
    );
    assert!(
        entity_type_names.contains(&"Message".to_string()),
        "schema should contain Message entity type, got: {entity_type_names:?}"
    );
}

#[tokio::test]
async fn schema_contains_expected_actions() {
    let (harness, _temp_dir) = load_harness().await;

    let schema = harness.schema();
    let action_names: Vec<String> = schema.actions().map(|a| a.to_string()).collect();

    assert!(
        action_names.iter().any(|a| a.contains("Prompt")),
        "schema should contain Prompt action, got: {action_names:?}"
    );
}

#[tokio::test]
async fn rejects_nonexistent_directory() {
    let path = PathBuf::from("/nonexistent/policies/dir");
    let storage_dir = tempfile::tempdir().expect("should create temp dir");
    let result = CedarPolicyHarness::from_policy_dir_isolated(path, storage_dir.path()).await;
    assert!(result.is_err(), "should fail for nonexistent directory");
}

#[tokio::test]
async fn rejects_directory_without_schema() {
    let dir = tempfile::tempdir().expect("should create temp dir");
    let storage_dir = tempfile::tempdir().expect("should create temp dir for storage");
    // Write a .cedar file but no .cedarschema
    std::fs::write(
        dir.path().join("test.cedar"),
        "@id(\"test\")\npermit (principal, action, resource);",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("ifc.toml"),
        "[[labels]]
name = \"TEST\"
description = \"Test label\"

[[labels.categories]]
label = \"public\"
definition = \"Public information.\"
",
    )
    .unwrap();

    let result =
        CedarPolicyHarness::from_policy_dir_isolated(dir.path().to_path_buf(), storage_dir.path())
            .await;
    match result {
        Ok(_) => panic!("should fail when no .cedarschema files are present"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("No .cedarschema files found"),
                "error should mention missing schema files, got: {msg}"
            );
        }
    }
}
