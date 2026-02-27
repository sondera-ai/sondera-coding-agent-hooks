//! Cedar MCP Server for AI agent policy authoring.
//!
//! Exposes Cedar policy operations as MCP tools so AI agents can validate
//! schemas, load policies, manage entities, and run authorization checks
//! interactively. Includes resource templates and prompt guidance for
//! generating Cedar policies.
//!
//! Also surfaces guardrail context (YARA signature rules, policy templates,
//! IFC sensitivity labels) via `get_cedar_policy_context_features` so agents
//! can write policies that reference real detection categories.

use cedar_policy::{
    Authorizer, Context as CedarContext, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, Response, Schema, ValidationMode, Validator,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use turbomcp::prelude::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationResult {
    pub decision: String,
    pub reasons: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyAnalysis {
    pub policy_count: usize,
    pub policy_ids: Vec<String>,
}

#[derive(Clone)]
pub struct CedarMcpServer {
    state: Arc<CedarState>,
}

struct CedarState {
    schema: RwLock<Option<Schema>>,
    policy_set: RwLock<PolicySet>,
    entities: RwLock<Entities>,
    authorizer: Authorizer,
}

impl CedarMcpServer {
    pub fn new() -> Self {
        Self {
            state: Arc::new(CedarState {
                schema: RwLock::new(None),
                policy_set: RwLock::new(PolicySet::new()),
                entities: RwLock::new(Entities::empty()),
                authorizer: Authorizer::new(),
            }),
        }
    }
}

impl Default for CedarMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[server(name = "cedar-mcp", version = "1.0.0")]
impl CedarMcpServer {
    #[tool(
        "Get context feature values for signatures, policies, and information flow control to help with authoring Sondera Cedar Policies"
    )]
    async fn get_cedar_policy_context_features(&self, ctx: Context) -> McpResult<String> {
        ctx.info("Collecting Cedar policy context features").await?;

        // -- Signature rules --
        let rules = sondera_signature::list_rules();
        let mut signature_categories: std::collections::HashMap<String, Vec<serde_json::Value>> =
            std::collections::HashMap::new();

        for rule in &rules {
            let category = rule
                .metadata
                .get("category")
                .cloned()
                .unwrap_or_else(|| "uncategorized".to_string());

            let entry = serde_json::json!({
                "identifier": rule.identifier,
                "namespace": rule.namespace,
                "metadata": rule.metadata,
            });

            signature_categories
                .entry(category)
                .or_default()
                .push(entry);
        }

        // -- Policy templates --
        let policy_templates = sondera_policy::PolicyTemplate::parse_toml(include_str!(
            "../../../policies/policies.toml"
        ))
        .map_err(|e| McpError::Tool(format!("Failed to parse policy baseline: {}", e)))?;

        let policies_json: Vec<serde_json::Value> = policy_templates
            .iter()
            .map(|p| {
                let categories: Vec<serde_json::Value> = p
                    .categories
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "code": c.code,
                            "name": c.name,
                            "definition": c.definition,
                        })
                    })
                    .collect();

                serde_json::json!({
                    "name": p.name,
                    "prefix": p.prefix,
                    "description": p.description,
                    "categories": categories,
                })
            })
            .collect();

        // -- IFC sensitivity labels --
        let label_templates = sondera_information_flow_control::LabelTemplate::parse_toml(
            include_str!("../../../policies/ifc.toml"),
        )
        .map_err(|e| McpError::Tool(format!("Failed to parse IFC baseline: {}", e)))?;

        let labels_json: Vec<serde_json::Value> = label_templates
            .iter()
            .map(|l| {
                let categories: Vec<serde_json::Value> = l
                    .categories
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "label": c.label.serde_name(),
                            "display_name": c.label.display_name(),
                            "level": c.label.level(),
                            "definition": c.definition,
                        })
                    })
                    .collect();

                serde_json::json!({
                    "name": l.name,
                    "description": l.description,
                    "categories": categories,
                })
            })
            .collect();

        let result = serde_json::json!({
            "signatures": {
                "rule_count": rules.len(),
                "categories": signature_categories,
            },
            "policies": policies_json,
            "sensitivity_labels": labels_json,
        });

        ctx.info(&format!(
            "Collected {} signature rules, {} policy templates, {} label templates",
            rules.len(),
            policy_templates.len(),
            label_templates.len(),
        ))
        .await?;

        serde_json::to_string_pretty(&result).map_err(|e| McpError::Tool(e.to_string()))
    }
    #[tool("Validate Cedar policy syntax and semantics against optional schema")]
    async fn validate_policy(
        &self,
        ctx: Context,
        policy: String,
        schema: Option<String>,
    ) -> McpResult<String> {
        ctx.info("Validating Cedar policy").await?;

        let mut result = ValidationResult {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        let policy_set: PolicySet = match policy.parse() {
            Ok(ps) => ps,
            Err(e) => {
                result.valid = false;
                result.errors.push(format!("Policy parse error: {}", e));
                return serde_json::to_string_pretty(&result)
                    .map_err(|e| McpError::Tool(e.to_string()));
            }
        };

        if let Some(schema_src) = schema {
            match Schema::from_cedarschema_str(&schema_src) {
                Ok((parsed_schema, warnings)) => {
                    for warning in warnings {
                        result.warnings.push(format!("Schema warning: {}", warning));
                    }
                    let validator = Validator::new(parsed_schema);
                    let validation = validator.validate(&policy_set, ValidationMode::default());
                    if !validation.validation_passed() {
                        result.valid = false;
                        for err in validation.validation_errors() {
                            result.errors.push(format!("Validation error: {}", err));
                        }
                    }
                    for warning in validation.validation_warnings() {
                        result
                            .warnings
                            .push(format!("Validation warning: {}", warning));
                    }
                }
                Err(e) => {
                    result.valid = false;
                    result.errors.push(format!("Schema parse error: {}", e));
                }
            }
        }

        ctx.info(&format!("Validation result: valid={}", result.valid))
            .await?;
        serde_json::to_string_pretty(&result).map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Validate Cedar schema syntax and report errors")]
    async fn validate_schema(&self, ctx: Context, schema: String) -> McpResult<String> {
        ctx.info("Validating Cedar schema").await?;

        let mut result = ValidationResult {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        match Schema::from_cedarschema_str(&schema) {
            Ok((_, warnings)) => {
                for warning in warnings {
                    result.warnings.push(format!("Schema warning: {}", warning));
                }
            }
            Err(e) => {
                result.valid = false;
                result.errors.push(format!("Schema parse error: {}", e));
            }
        }

        ctx.info(&format!("Schema validation: valid={}", result.valid))
            .await?;
        serde_json::to_string_pretty(&result).map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Load a Cedar schema for subsequent operations")]
    async fn load_schema(&self, ctx: Context, schema: String) -> McpResult<String> {
        ctx.info("Loading Cedar schema").await?;

        match Schema::from_cedarschema_str(&schema) {
            Ok((parsed_schema, warnings)) => {
                let mut schema_lock = self.state.schema.write().await;
                *schema_lock = Some(parsed_schema);
                drop(schema_lock);

                let warning_msgs: Vec<String> =
                    warnings.into_iter().map(|w| w.to_string()).collect();
                ctx.info("Schema loaded successfully").await?;
                Ok(serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "warnings": warning_msgs
                }))
                .map_err(|e| McpError::Tool(e.to_string()))?)
            }
            Err(e) => Err(McpError::Tool(format!("Failed to parse schema: {}", e))),
        }
    }

    #[tool("Load Cedar policies for authorization checks")]
    async fn load_policies(&self, ctx: Context, policies: String) -> McpResult<String> {
        ctx.info("Loading Cedar policies").await?;

        let policy_set: PolicySet = policies
            .parse()
            .map_err(|e| McpError::Tool(format!("Failed to parse policies: {}", e)))?;

        let schema_lock = self.state.schema.read().await;
        if let Some(ref schema) = *schema_lock {
            let validator = Validator::new(schema.clone());
            let validation = validator.validate(&policy_set, ValidationMode::default());
            if !validation.validation_passed() {
                let errors: Vec<String> = validation
                    .validation_errors()
                    .map(|e| e.to_string())
                    .collect();
                drop(schema_lock);
                return Err(McpError::Tool(format!(
                    "Policy validation failed: {}",
                    errors.join("; ")
                )));
            }
        }
        drop(schema_lock);

        let policy_count = policy_set.policies().count();
        let mut policy_lock = self.state.policy_set.write().await;
        *policy_lock = policy_set;
        drop(policy_lock);

        ctx.info(&format!("Loaded {} policies", policy_count))
            .await?;
        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "policy_count": policy_count
        }))
        .map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Add an entity with type and ID to the store")]
    async fn add_entity(
        &self,
        ctx: Context,
        entity_type: String,
        entity_id: String,
        parents: Option<Vec<String>>,
    ) -> McpResult<String> {
        ctx.info(&format!("Adding entity {}::{}", entity_type, entity_id))
            .await?;

        let entity_type_name: EntityTypeName = entity_type
            .parse()
            .map_err(|e| McpError::Tool(format!("Invalid entity type: {}", e)))?;

        let uid = EntityUid::from_type_name_and_id(entity_type_name, EntityId::new(&entity_id));

        let parent_set: HashSet<EntityUid> = match parents {
            Some(parent_strs) => {
                let mut set = HashSet::new();
                for p in parent_strs {
                    let parent_uid: EntityUid = p.parse().map_err(|e| {
                        McpError::Tool(format!("Invalid parent UID '{}': {}", p, e))
                    })?;
                    set.insert(parent_uid);
                }
                set
            }
            None => HashSet::new(),
        };

        let entity = Entity::new_no_attrs(uid.clone(), parent_set);

        let schema_lock = self.state.schema.read().await;
        let schema_opt = schema_lock.as_ref();

        let mut entities_lock = self.state.entities.write().await;
        let taken: Entities = std::mem::take(&mut *entities_lock);
        *entities_lock = taken
            .add_entities([entity], schema_opt)
            .map_err(|e| McpError::Tool(format!("Failed to add entity: {}", e)))?;
        drop(entities_lock);
        drop(schema_lock);

        ctx.info(&format!("Added entity {}", uid)).await?;
        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "entity": uid.to_string()
        }))
        .map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Check authorization for principal/action/resource")]
    async fn is_authorized(
        &self,
        ctx: Context,
        principal: String,
        action: String,
        resource: String,
        context_json: Option<String>,
    ) -> McpResult<String> {
        ctx.info(&format!(
            "Checking: {} -> {} -> {}",
            principal, action, resource
        ))
        .await?;

        let principal_uid: EntityUid = principal
            .parse()
            .map_err(|e| McpError::Tool(format!("Invalid principal: {}", e)))?;

        let action_uid: EntityUid = format!("Action::\"{}\"", action)
            .parse()
            .map_err(|e| McpError::Tool(format!("Invalid action: {}", e)))?;

        let resource_uid: EntityUid = resource
            .parse()
            .map_err(|e| McpError::Tool(format!("Invalid resource: {}", e)))?;

        let ctx_cedar = match context_json {
            Some(json) => CedarContext::from_json_str(&json, None)
                .map_err(|e| McpError::Tool(format!("Invalid context JSON: {}", e)))?,
            None => CedarContext::empty(),
        };

        let schema_lock = self.state.schema.read().await;
        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            ctx_cedar,
            schema_lock.as_ref(),
        )
        .map_err(|e| McpError::Tool(format!("Failed to create request: {}", e)))?;
        drop(schema_lock);

        let policy_lock = self.state.policy_set.read().await;
        let entities_lock = self.state.entities.read().await;
        let response: Response =
            self.state
                .authorizer
                .is_authorized(&request, &policy_lock, &entities_lock);
        drop(policy_lock);
        drop(entities_lock);

        let result = AuthorizationResult {
            decision: match response.decision() {
                cedar_policy::Decision::Allow => "ALLOW".to_string(),
                cedar_policy::Decision::Deny => "DENY".to_string(),
            },
            reasons: response
                .diagnostics()
                .reason()
                .map(|id| id.to_string())
                .collect(),
            errors: response
                .diagnostics()
                .errors()
                .map(|e| e.to_string())
                .collect(),
        };

        ctx.info(&format!("Decision: {}", result.decision)).await?;
        serde_json::to_string_pretty(&result).map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Analyze loaded Cedar policies and return metadata")]
    async fn analyze_policies(&self, ctx: Context) -> McpResult<String> {
        ctx.info("Analyzing loaded policies").await?;

        let policy_lock = self.state.policy_set.read().await;
        let policy_ids: Vec<String> = policy_lock.policies().map(|p| p.id().to_string()).collect();
        let policy_count = policy_ids.len();
        drop(policy_lock);

        let analysis = PolicyAnalysis {
            policy_count,
            policy_ids,
        };

        ctx.info(&format!("Found {} policies", analysis.policy_count))
            .await?;
        serde_json::to_string_pretty(&analysis).map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Format Cedar policy source code")]
    async fn format_policy(&self, ctx: Context, policy: String) -> McpResult<String> {
        ctx.info("Formatting Cedar policy").await?;

        let policy_set: PolicySet = policy
            .parse()
            .map_err(|e| McpError::Tool(format!("Failed to parse policy: {}", e)))?;

        ctx.info("Policy formatted successfully").await?;
        Ok(policy_set.to_string())
    }

    #[tool("Clear all loaded state")]
    async fn clear_state(&self, ctx: Context) -> McpResult<String> {
        ctx.info("Clearing all state").await?;

        let mut schema_lock = self.state.schema.write().await;
        *schema_lock = None;
        drop(schema_lock);

        let mut policy_lock = self.state.policy_set.write().await;
        *policy_lock = PolicySet::new();
        drop(policy_lock);

        let mut entities_lock = self.state.entities.write().await;
        *entities_lock = Entities::empty();
        drop(entities_lock);

        ctx.info("State cleared").await?;
        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "message": "All state cleared"
        }))
        .map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Parse and analyze a Cedar schema returning actions")]
    async fn analyze_schema(&self, ctx: Context, schema: String) -> McpResult<String> {
        ctx.info("Analyzing Cedar schema").await?;

        let (parsed_schema, warnings) = Schema::from_cedarschema_str(&schema)
            .map_err(|e| McpError::Tool(format!("Failed to parse schema: {}", e)))?;

        let action_entities = parsed_schema
            .action_entities()
            .map_err(|e| McpError::Tool(format!("Failed to get action entities: {}", e)))?;

        let actions: Vec<String> = action_entities
            .iter()
            .map(|e| e.uid().to_string())
            .collect();
        let warning_msgs: Vec<String> = warnings.into_iter().map(|w| w.to_string()).collect();

        ctx.info(&format!("Schema analysis: {} actions", actions.len()))
            .await?;
        serde_json::to_string_pretty(&serde_json::json!({
            "actions": actions,
            "action_count": actions.len(),
            "warnings": warning_msgs
        }))
        .map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Merge multiple Cedar schema fragments into one")]
    async fn merge_schema_fragments(
        &self,
        ctx: Context,
        fragments: Vec<String>,
    ) -> McpResult<String> {
        ctx.info(&format!("Merging {} schema fragments", fragments.len()))
            .await?;

        if fragments.is_empty() {
            return Err(McpError::Tool("No schema fragments provided".to_string()));
        }

        let combined = fragments.join("\n\n");

        match Schema::from_cedarschema_str(&combined) {
            Ok((_, warnings)) => {
                let warning_msgs: Vec<String> =
                    warnings.into_iter().map(|w| w.to_string()).collect();
                ctx.info("Schema fragments merged successfully").await?;
                Ok(serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "merged_schema": combined,
                    "warnings": warning_msgs
                }))
                .map_err(|e| McpError::Tool(e.to_string()))?)
            }
            Err(e) => Err(McpError::Tool(format!(
                "Failed to merge schema fragments: {}",
                e
            ))),
        }
    }

    #[tool("Create Cedar schema fragment for entity type")]
    async fn create_entity_schema(
        &self,
        ctx: Context,
        entity_name: String,
        parents: Option<Vec<String>>,
        attributes: Option<String>,
    ) -> McpResult<String> {
        ctx.info(&format!("Creating schema for entity: {}", entity_name))
            .await?;

        let mut schema_fragment = String::new();

        if let Some(ref parent_types) = parents {
            if !parent_types.is_empty() {
                schema_fragment.push_str(&format!(
                    "entity {} in [{}]",
                    entity_name,
                    parent_types.join(", ")
                ));
            } else {
                schema_fragment.push_str(&format!("entity {}", entity_name));
            }
        } else {
            schema_fragment.push_str(&format!("entity {}", entity_name));
        }

        if let Some(attrs_json) = attributes {
            let attrs: serde_json::Value = serde_json::from_str(&attrs_json)
                .map_err(|e| McpError::Tool(format!("Invalid attributes JSON: {}", e)))?;
            if let serde_json::Value::Object(map) = attrs {
                if !map.is_empty() {
                    schema_fragment.push_str(" = {\n");
                    for (name, type_val) in map {
                        let type_str = type_val.as_str().unwrap_or("String");
                        schema_fragment.push_str(&format!("    {}: {},\n", name, type_str));
                    }
                    schema_fragment.push('}');
                } else {
                    schema_fragment.push(';');
                }
            } else {
                schema_fragment.push(';');
            }
        } else {
            schema_fragment.push(';');
        }

        ctx.info("Entity schema fragment created").await?;
        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "fragment": schema_fragment
        }))
        .map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Create Cedar schema fragment for action")]
    async fn create_action_schema(
        &self,
        ctx: Context,
        action_name: String,
        principal_types: Vec<String>,
        resource_types: Vec<String>,
    ) -> McpResult<String> {
        ctx.info(&format!("Creating schema for action: {}", action_name))
            .await?;

        if principal_types.is_empty() {
            return Err(McpError::Tool(
                "At least one principal type required".to_string(),
            ));
        }
        if resource_types.is_empty() {
            return Err(McpError::Tool(
                "At least one resource type required".to_string(),
            ));
        }

        let schema_fragment = format!(
            "action \"{}\" appliesTo {{\n    principal: [{}],\n    resource: [{}]\n}};",
            action_name,
            principal_types.join(", "),
            resource_types.join(", ")
        );

        ctx.info("Action schema fragment created").await?;
        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "fragment": schema_fragment
        }))
        .map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Validate Cedar policies against a schema")]
    async fn validate_policy_against_schema(
        &self,
        ctx: Context,
        policy: String,
        schema: String,
    ) -> McpResult<String> {
        ctx.info("Validating policy against schema").await?;

        let mut result = ValidationResult {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        let (parsed_schema, schema_warnings) = match Schema::from_cedarschema_str(&schema) {
            Ok(s) => s,
            Err(e) => {
                result.valid = false;
                result.errors.push(format!("Schema parse error: {}", e));
                return serde_json::to_string_pretty(&result)
                    .map_err(|e| McpError::Tool(e.to_string()));
            }
        };

        for warning in schema_warnings {
            result.warnings.push(format!("Schema warning: {}", warning));
        }

        let policy_set: PolicySet = match policy.parse() {
            Ok(ps) => ps,
            Err(e) => {
                result.valid = false;
                result.errors.push(format!("Policy parse error: {}", e));
                return serde_json::to_string_pretty(&result)
                    .map_err(|e| McpError::Tool(e.to_string()));
            }
        };

        let validator = Validator::new(parsed_schema);
        let validation = validator.validate(&policy_set, ValidationMode::default());

        if !validation.validation_passed() {
            result.valid = false;
            for err in validation.validation_errors() {
                result.errors.push(format!("Validation error: {}", err));
            }
        }

        for warning in validation.validation_warnings() {
            result
                .warnings
                .push(format!("Validation warning: {}", warning));
        }

        ctx.info(&format!("Validation: valid={}", result.valid))
            .await?;
        serde_json::to_string_pretty(&result).map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Validate entities JSON against a Cedar schema")]
    async fn validate_entities_against_schema(
        &self,
        ctx: Context,
        entities_json: String,
        schema: String,
    ) -> McpResult<String> {
        ctx.info("Validating entities against schema").await?;

        let mut result = ValidationResult {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        let (parsed_schema, schema_warnings) = match Schema::from_cedarschema_str(&schema) {
            Ok(s) => s,
            Err(e) => {
                result.valid = false;
                result.errors.push(format!("Schema parse error: {}", e));
                return serde_json::to_string_pretty(&result)
                    .map_err(|e| McpError::Tool(e.to_string()));
            }
        };

        for warning in schema_warnings {
            result.warnings.push(format!("Schema warning: {}", warning));
        }

        let entities = match Entities::from_json_str(&entities_json, Some(&parsed_schema)) {
            Ok(e) => e,
            Err(e) => {
                result.valid = false;
                result
                    .errors
                    .push(format!("Entity validation error: {}", e));
                return serde_json::to_string_pretty(&result)
                    .map_err(|e| McpError::Tool(e.to_string()));
            }
        };

        let entity_count = entities.iter().count();

        ctx.info(&format!("Validated {} entities", entity_count))
            .await?;
        serde_json::to_string_pretty(&serde_json::json!({
            "valid": result.valid,
            "entity_count": entity_count,
            "errors": result.errors,
            "warnings": result.warnings
        }))
        .map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Validate single entity against loaded schema")]
    async fn validate_entity(
        &self,
        ctx: Context,
        entity_type: String,
        entity_id: String,
    ) -> McpResult<String> {
        ctx.info(&format!("Validating entity {}::{}", entity_type, entity_id))
            .await?;

        let mut result = ValidationResult {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        let entity_type_name: EntityTypeName = match entity_type.parse() {
            Ok(t) => t,
            Err(e) => {
                result.valid = false;
                result.errors.push(format!("Invalid entity type: {}", e));
                return serde_json::to_string_pretty(&result)
                    .map_err(|e| McpError::Tool(e.to_string()));
            }
        };

        let uid = EntityUid::from_type_name_and_id(entity_type_name, EntityId::new(&entity_id));
        let entity = Entity::new_no_attrs(uid.clone(), HashSet::new());

        let schema_lock = self.state.schema.read().await;
        let entities = Entities::empty();
        match entities.add_entities([entity], schema_lock.as_ref()) {
            Ok(_) => {
                ctx.info(&format!("Entity {} validated", uid)).await?;
            }
            Err(e) => {
                result.valid = false;
                result
                    .errors
                    .push(format!("Entity validation failed: {}", e));
            }
        }
        drop(schema_lock);

        serde_json::to_string_pretty(&result).map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("List all entities in the entity store")]
    async fn list_entities(&self, ctx: Context) -> McpResult<String> {
        ctx.info("Listing entities").await?;

        let entities_lock = self.state.entities.read().await;
        let entity_list: Vec<serde_json::Value> = entities_lock
            .iter()
            .map(|e| {
                serde_json::json!({
                    "uid": e.uid().to_string(),
                    "type": e.uid().type_name().to_string(),
                })
            })
            .collect();
        let count = entity_list.len();
        drop(entities_lock);

        ctx.info(&format!("Found {} entities", count)).await?;
        serde_json::to_string_pretty(&serde_json::json!({
            "entity_count": count,
            "entities": entity_list
        }))
        .map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Remove an entity by UID from the store")]
    async fn remove_entity(&self, ctx: Context, entity_uid: String) -> McpResult<String> {
        ctx.info(&format!("Removing entity: {}", entity_uid))
            .await?;

        let uid: EntityUid = entity_uid
            .parse()
            .map_err(|e| McpError::Tool(format!("Invalid entity UID: {}", e)))?;

        let mut entities_lock = self.state.entities.write().await;
        let taken: Entities = std::mem::take(&mut *entities_lock);
        *entities_lock = taken
            .remove_entities([uid.clone()])
            .map_err(|e| McpError::Tool(format!("Failed to remove entity: {}", e)))?;
        drop(entities_lock);

        ctx.info(&format!("Entity {} removed", uid)).await?;
        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "removed": uid.to_string()
        }))
        .map_err(|e| McpError::Tool(e.to_string()))
    }

    #[tool("Get schema loading status")]
    async fn get_schema_status(&self, ctx: Context) -> McpResult<String> {
        ctx.info("Getting schema status").await?;

        let schema_lock = self.state.schema.read().await;
        let status = match schema_lock.as_ref() {
            Some(schema) => {
                let action_count = schema
                    .action_entities()
                    .map(|e| e.iter().count())
                    .unwrap_or(0);
                serde_json::json!({ "loaded": true, "action_count": action_count })
            }
            None => serde_json::json!({ "loaded": false }),
        };
        drop(schema_lock);

        serde_json::to_string_pretty(&status).map_err(|e| McpError::Tool(e.to_string()))
    }

    #[resource("cedar://templates/agent-schema")]
    async fn agent_schema_template(&self, _uri: String) -> McpResult<String> {
        Ok(AGENT_SCHEMA_TEMPLATE.to_string())
    }

    #[resource("cedar://templates/default-allow")]
    async fn default_allow_template(&self, _uri: String) -> McpResult<String> {
        Ok("// Default allow policy\npermit (principal, action, resource);\n".to_string())
    }

    #[resource("cedar://templates/tool-restrictions")]
    async fn tool_restrictions_template(&self, _uri: String) -> McpResult<String> {
        Ok(TOOL_RESTRICTIONS_TEMPLATE.to_string())
    }

    #[prompt("Generate a Cedar policy for {use_case}")]
    async fn policy_guidance(&self, use_case: String) -> McpResult<String> {
        Ok(format!(
            "You are helping create a Cedar policy for: {}\n\nCedar syntax:\n- permit (principal, action, resource);\n- forbid (principal, action, resource) when {{ condition }};\n\nEntity UID format: Type::\"id\"",
            use_case
        ))
    }
}

const AGENT_SCHEMA_TEMPLATE: &str = r#"// Cedar schema for AI Coding Agent governance
entity Agent;
entity Tool;
entity Prompt;
entity File;
entity Repository;

action "pre_run" appliesTo { principal: [Agent], resource: [Tool, Prompt] };
action "pre_model" appliesTo { principal: [Agent], resource: [Tool, Prompt] };
action "post_model" appliesTo { principal: [Agent], resource: [Tool, Prompt] };
action "pre_tool" appliesTo { principal: [Agent], resource: [Tool, File, Repository] };
action "post_tool" appliesTo { principal: [Agent], resource: [Tool, File, Repository] };
action "post_run" appliesTo { principal: [Agent], resource: [Tool, Prompt] };
action "read" appliesTo { principal: [Agent], resource: [File, Repository] };
action "write" appliesTo { principal: [Agent], resource: [File, Repository] };
action "execute" appliesTo { principal: [Agent], resource: [Tool] };
"#;

const TOOL_RESTRICTIONS_TEMPLATE: &str = r#"// Tool restriction policies
permit (principal, action in [Action::"pre_tool", Action::"post_tool", Action::"execute"], resource);
forbid (principal, action == Action::"execute", resource == Tool::"rm");
forbid (principal, action == Action::"execute", resource == Tool::"sudo");
"#;
