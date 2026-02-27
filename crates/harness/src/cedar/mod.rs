pub mod entity;
mod transform;

use crate::cedar::entity::Trajectory;
use crate::harness::Harness;
use crate::storage::entity::EntityStore;
use crate::storage::file;
use crate::storage::turso::{TrajectoryStore, get_default_db_path};
use crate::{
    Actor, Adjudicated, Agent, Causality, Control, EntityBuilder, Event, TrajectoryEvent, euid,
};
use anyhow::{Context as AnyhowContext, Result};
use cedar_policy::{
    Authorizer, Context, Entity, EntityId, EntityUid, PolicyId, PolicySet, Request, Response,
    Schema, SchemaFragment,
};
use sondera_information_flow_control::DataModel;
use sondera_policy::PolicyModel;
use std::collections::HashSet;
use std::path::PathBuf;
use tracing::{debug, warn};

pub struct CedarPolicyHarness {
    authorizer: Authorizer,
    entity_store: EntityStore,
    trajectory_store: TrajectoryStore,
    schema: Schema,
    policy_set: PolicySet,
    data_model: DataModel,
    policy_model: PolicyModel,
}

impl CedarPolicyHarness {
    /// Load a CedarPolicyHarness from a directory containing `.cedarschema` and `.cedar` files.
    ///
    /// Expects exactly one `.cedarschema` file and zero or more `.cedar` policy files.
    /// Agent entities are created dynamically based on the agent field in each Event.
    pub async fn from_policy_dir(path: PathBuf) -> Result<Self> {
        anyhow::ensure!(
            path.is_dir(),
            "Policy directory does not exist: {}",
            path.display()
        );

        let mut schema_fragments: Vec<SchemaFragment> = Vec::new();
        let mut policy_set = PolicySet::new();

        for entry in std::fs::read_dir(&path).context(format!(
            "Failed to read policy directory: {}",
            path.display()
        ))? {
            let entry = entry?;
            let file_path = entry.path();

            match file_path.extension().and_then(|e| e.to_str()) {
                Some("cedarschema") => {
                    let content = std::fs::read_to_string(&file_path)
                        .context(format!("Failed to read schema: {}", file_path.display()))?;
                    let (fragment, warnings) = SchemaFragment::from_cedarschema_str(&content)
                        .context(format!(
                            "Failed to parse schema fragment: {}",
                            file_path.display()
                        ))?;
                    for warning in warnings {
                        warn!(
                            "Cedar Schema Warning in {}: {}",
                            file_path.display(),
                            warning
                        );
                    }
                    schema_fragments.push(fragment);
                }
                Some("cedar") => {
                    let content = std::fs::read_to_string(&file_path)
                        .context(format!("Failed to read policy: {}", file_path.display()))?;
                    // Parse all policies in the file, then re-add with @id annotation as ID
                    let file_policies: PolicySet = content.parse().context(format!(
                        "Failed to parse Cedar policies: {}",
                        file_path.display()
                    ))?;
                    for policy in file_policies.policies() {
                        let id_str = policy
                            .annotation("id")
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| policy.id().as_ref());
                        let named = policy.new_id(PolicyId::new(id_str));
                        debug!(
                            "Adding policy {:?} from {}",
                            named.id().to_string(),
                            file_path.display()
                        );
                        policy_set.add(named).context(format!(
                            "Duplicate policy id {:?} in {}",
                            id_str,
                            file_path.display()
                        ))?;
                    }
                }
                _ => {}
            }
        }

        anyhow::ensure!(
            !schema_fragments.is_empty(),
            "No .cedarschema files found in {}",
            path.display()
        );

        let schema = Schema::from_schema_fragments(schema_fragments)
            .context("Failed to merge schema fragments")?;

        let entity_store_path = file::get_storage_dir()?.join("entities");

        let entity_store = EntityStore::open(&entity_store_path).context(format!(
            "Failed to open entity store: {}",
            entity_store_path.display()
        ))?;

        let trajectory_db_path = get_default_db_path()?;
        let trajectory_store =
            TrajectoryStore::open(&trajectory_db_path)
                .await
                .context(format!(
                    "Failed to open trajectory store: {}",
                    trajectory_db_path.display()
                ))?;

        // Add Label entity types matching the sensitivity lattice.
        // Names must match Label enum's Display impl and ifc.cedar policy references.
        let highly_confidential_label =
            EntityBuilder::new(euid("Label", "HighlyConfidential")?).build()?;
        let confidential_label = EntityBuilder::new(euid("Label", "Confidential")?)
            .parent_uid(highly_confidential_label.uid())
            .build()?;
        let internal_label = EntityBuilder::new(euid("Label", "Internal")?)
            .parent_uid(confidential_label.uid())
            .build()?;
        let public_label = EntityBuilder::new(euid("Label", "Public")?)
            .parent_uid(internal_label.uid())
            .build()?;

        entity_store.upsert(&highly_confidential_label)?;
        entity_store.upsert(&confidential_label)?;
        entity_store.upsert(&internal_label)?;
        entity_store.upsert(&public_label)?;

        let data_model_path = path.join("ifc.toml");
        let data_model = DataModel::from_toml(data_model_path)?;

        let policy_model_path = path.join("policies.toml");
        let policy_model = PolicyModel::from_toml(policy_model_path)?;

        Ok(Self {
            authorizer: Authorizer::new(),
            entity_store,
            trajectory_store,
            schema,
            policy_set,
            data_model,
            policy_model,
        })
    }

    /// Ensure the agent entity exists in the entity store.
    fn ensure_agent_entity(&self, agent: &Agent) -> Result<()> {
        let agent_uid = EntityUid::from_type_name_and_id(
            "Agent".parse().context("Invalid entity type name: Agent")?,
            EntityId::new(&agent.id),
        );

        if self.entity_store.get(&agent_uid)?.is_none() {
            let agent_entity = Entity::new_no_attrs(agent_uid, HashSet::new());
            self.entity_store.upsert(&agent_entity)?;
        }
        Ok(())
    }

    /// Get the loaded policy set.
    pub fn policy_set(&self) -> &PolicySet {
        &self.policy_set
    }

    /// Get the loaded schema.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    pub fn is_authorized(&self, request: &Request) -> Result<Response> {
        let entities = self.entity_store.entities()?;
        Ok(self
            .authorizer
            .is_authorized(request, &self.policy_set, &entities))
    }

    pub fn validate_request(
        &self,
        principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        context: Option<Context>,
    ) -> Result<Request> {
        let ctx = context.unwrap_or_else(Context::empty);
        let request = Request::new(principal, action, resource, ctx, Some(&self.schema))?;
        Ok(request)
    }

    /// Add an entity to the entity store.
    /// Returns an error if an entity with the same UID already exists.
    pub fn add_entity(&self, entity: Entity) -> Result<()> {
        if self.entity_store.get(&entity.uid())?.is_some() {
            anyhow::bail!("Entity already exists: {}", entity.uid());
        }
        self.entity_store.upsert(&entity)?;
        Ok(())
    }

    /// Upsert an entity into the entity store.
    /// If an entity with the same UID exists, it will be replaced.
    pub fn upsert_entity(&self, entity: Entity) -> Result<()> {
        self.entity_store.upsert(&entity)?;
        Ok(())
    }

    /// Get an entity from the entity store by its UID.
    pub fn get_entity(&self, uid: &EntityUid) -> Result<Option<Entity>> {
        self.entity_store.get(uid)
    }

    /// Remove an entity from the entity store by its UID.
    pub fn remove_entity(&self, uid: EntityUid) -> Result<()> {
        self.entity_store.delete(&uid)?;
        Ok(())
    }
}

impl Harness for CedarPolicyHarness {
    async fn adjudicate(&self, event: Event) -> Result<Adjudicated> {
        debug!("Trajectory Event: {:?}", event);
        // Ensure the agent entity exists in the store
        self.ensure_agent_entity(&event.agent)?;

        // Write to both JSONL file storage and Turso
        file::write_trajectory_event(&event)?;
        self.trajectory_store.insert_event(&event).await?;

        if let TrajectoryEvent::Control(control) = &event.event {
            if let Control::Started(_) = control {
                debug!("Starting trajectory: {}", event.trajectory_id);
                // Create a Trajectory entity for the trajectory.
                let trajectory = Trajectory::new(&event.trajectory_id);
                self.upsert_entity(trajectory.into_entity()?)?;
            }
            // Don't authorize control events.
            return Ok(Adjudicated::allow());
        }

        let request = self.build_request(&event).await?;
        let response = self.is_authorized(&request)?;

        let adjudicated = self.response_to_adjudicated(&response);

        // Build raw payload capturing the Cedar request and response for the trajectory log.
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();
        let reason_policies: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();
        let raw = serde_json::json!({
            "request": {
                "principal": request.principal().map(|p| p.to_string()),
                "action": request.action().map(|a| a.to_string()),
                "resource": request.resource().map(|r| r.to_string()),
                "context": request.context().and_then(|c| c.to_json_value().ok()),
            },
            "response": {
                "decision": format!("{:?}", response.decision()),
                "reason": reason_policies,
                "errors": errors,
            },
        });

        // Write the adjudication as a Control event on the same trajectory.
        let adjudicated_event = Event::new(
            event.agent.clone(),
            &event.trajectory_id,
            TrajectoryEvent::Control(Control::Adjudicated(adjudicated.clone())),
        )
        .with_actor(Actor::policy("cedar"))
        .with_causality(Causality::default().caused_by(&event.event_id))
        .with_raw(raw);

        // Latest trajectory entity.
        let trajectory: Trajectory = match self
            .entity_store
            .get(&euid("Trajectory", &event.trajectory_id)?)?
        {
            Some(entity) => entity.try_into()?,
            None => {
                debug!(
                    "Trajectory entity {:?} not found after adjudication, creating.",
                    &event.trajectory_id
                );
                Trajectory::new(&event.trajectory_id)
            }
        };

        debug!("Adjudicated Event: {:?}", adjudicated_event);
        debug!("Trajectory: {:?}", trajectory);

        // Write adjudication event to both storages
        file::write_trajectory_event(&adjudicated_event)?;
        self.trajectory_store
            .insert_event(&adjudicated_event)
            .await?;

        Ok(adjudicated)
    }
}
