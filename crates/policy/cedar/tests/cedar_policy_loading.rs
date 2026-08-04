//! Integration tests for loading Cedar policies and schemas from the policies directory.

use sondera_cedar_policy::CedarPolicyHarness;
use std::path::PathBuf;

const CONFIG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../.sondera");

async fn load_harness() -> (CedarPolicyHarness, tempfile::TempDir) {
    let path = PathBuf::from(CONFIG_DIR);
    let temp_dir = tempfile::tempdir().expect("should create temp dir for entity store");
    let harness = CedarPolicyHarness::from_config_dir_isolated(path, temp_dir.path())
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

    // The base schema declares `namespace Sondera { … }`, so every type name is
    // qualified. Asserting the qualified form is deliberate: it is what
    // `euid`/`Request::new` must produce, and a bare-name assertion would pass
    // against an un-namespaced schema the engine can no longer build requests for.
    for expected in ["Sondera::Agent", "Sondera::Trajectory", "Sondera::Message"] {
        assert!(
            entity_type_names.contains(&expected.to_string()),
            "schema should contain {expected} entity type, got: {entity_type_names:?}"
        );
    }
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
    let result = CedarPolicyHarness::from_config_dir_isolated(path, storage_dir.path()).await;
    assert!(result.is_err(), "should fail for nonexistent directory");
}

#[tokio::test]
async fn rejects_directory_without_schema() {
    let dir = tempfile::tempdir().expect("should create temp dir");
    let storage_dir = tempfile::tempdir().expect("should create temp dir for storage");
    // A complete config directory except that the cedar corpus has no
    // `.cedarschema` anywhere. The other assets must be present so resolution
    // succeeds and the schema's absence is the only reason to fail; the rule is
    // nested a level down since the store walks recursively.
    let cedar_dir = dir.path().join("policies").join("cedar").join("rules");
    std::fs::create_dir_all(&cedar_dir).unwrap();
    std::fs::write(
        cedar_dir.join("test.cedar"),
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
    std::fs::write(
        dir.path().join("policies.toml"),
        "[[policies]]
name = \"TEST\"
description = \"Test policy\"

[[policies.categories]]
label = \"allow\"
definition = \"Permitted.\"
",
    )
    .unwrap();

    let result =
        CedarPolicyHarness::from_config_dir_isolated(dir.path().to_path_buf(), storage_dir.path())
            .await;
    match result {
        Ok(_) => panic!("should fail when no .cedarschema files are present"),
        Err(err) => {
            // `{:#}` to include the source chain: the store's error is wrapped
            // in the harness's "Failed to load policies from …" context.
            let msg = format!("{err:#}");
            assert!(
                msg.contains("no .cedarschema files found"),
                "error should mention missing schema files, got: {msg}"
            );
        }
    }
}
