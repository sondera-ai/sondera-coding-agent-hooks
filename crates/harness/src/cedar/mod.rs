pub mod entity;
mod transform;

use crate::cedar::entity::Trajectory;
use crate::harness::Harness;
use crate::monitors::{
    Monitor, MonitorConfig, MonitorSnapshot, MonitorState, UntrustedThenProtectedWrite, Verdict,
    backstop,
};
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
use globset::GlobSet;
use sondera_information_flow_control::DataModel;
use sondera_policy::PolicyModel;
use std::collections::HashSet;
use std::path::PathBuf;
use tracing::{debug, instrument, warn};

pub struct CedarPolicyHarness {
    authorizer: Authorizer,
    entity_store: EntityStore,
    trajectory_store: TrajectoryStore,
    schema: Schema,
    policy_set: PolicySet,
    data_model: DataModel,
    policy_model: PolicyModel,
    monitor_config: MonitorConfig,
    monitor_glob_set: GlobSet,
}

impl CedarPolicyHarness {
    /// Load a CedarPolicyHarness from a directory containing `.cedarschema` and `.cedar` files.
    ///
    /// Expects exactly one `.cedarschema` file and zero or more `.cedar` policy files.
    /// Agent entities are created dynamically based on the agent field in each Event.
    pub async fn from_policy_dir(path: PathBuf) -> Result<Self> {
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

        Self::build(path, entity_store, trajectory_store).await
    }

    /// Load a CedarPolicyHarness with isolated storage for testing.
    ///
    /// Uses the given directory for the entity store and an in-memory trajectory store,
    /// so each test gets its own independent storage without file-lock contention.
    pub async fn from_policy_dir_isolated(
        path: PathBuf,
        storage_dir: &std::path::Path,
    ) -> Result<Self> {
        let entity_store = EntityStore::open(storage_dir.join("entities")).context(format!(
            "Failed to open entity store: {}",
            storage_dir.display()
        ))?;

        let trajectory_store = TrajectoryStore::open_in_memory()
            .await
            .context("Failed to open in-memory trajectory store")?;

        Self::build(path, entity_store, trajectory_store).await
    }

    async fn build(
        path: PathBuf,
        entity_store: EntityStore,
        trajectory_store: TrajectoryStore,
    ) -> Result<Self> {
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

        // Multi-hop monitor config: an absent monitor.toml silently uses
        // built-in defaults; a present-but-malformed file is fatal at startup
        // — identical posture to Cedar parse errors.
        let monitor_toml = path.join("monitor.toml");
        let monitor_config = if monitor_toml.exists() {
            let content = std::fs::read_to_string(&monitor_toml)
                .context(format!("Failed to read {}", monitor_toml.display()))?;
            MonitorConfig::load_from_toml(&content)
                .context(format!("Failed to parse {}", monitor_toml.display()))?
        } else {
            MonitorConfig::default()
        };
        // Compile configured protected-path globs once at startup (fatal on
        // invalid patterns); the same compiled set is the single source of
        // truth for both the monitor FSM and Cedar context population.
        let monitor_glob_set = monitor_config.build_glob_set().context(format!(
            "Invalid protected_path_globs in {}",
            monitor_toml.display()
        ))?;

        Ok(Self {
            authorizer: Authorizer::new(),
            entity_store,
            trajectory_store,
            schema,
            policy_set,
            data_model,
            policy_model,
            monitor_config,
            monitor_glob_set,
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

    /// Load persisted multi-hop monitor state for a trajectory.
    pub fn get_monitor_state(&self, trajectory_id: &str) -> Result<Option<MonitorState>> {
        self.entity_store.get_monitor_state(trajectory_id)
    }

    /// Persist multi-hop monitor state for a trajectory.
    pub fn put_monitor_state(&self, trajectory_id: &str, state: &MonitorState) -> Result<()> {
        self.entity_store.put_monitor_state(trajectory_id, state)
    }
}

impl Harness for CedarPolicyHarness {
    #[instrument(
        skip(self, event),
        fields(
            trajectory_id = %event.trajectory_id,
            event_id = %event.event_id,
            agent = %event.agent.id,
        )
    )]
    async fn adjudicate(&self, event: Event) -> Result<Adjudicated> {
        debug!("Trajectory Event: {:?}", event);
        // Ensure the agent entity exists in the store
        self.ensure_agent_entity(&event.agent)?;

        // Write to both JSONL file storage and Turso
        file::write_trajectory_event(&event)?;
        self.trajectory_store.insert_event(&event).await?;

        // Ordering contract: load → observe → persist → write-attribute →
        // build-request → is_authorized. The Control bypass sits between
        // persist and write-attribute — Control events advance and persist the
        // FSM but never reach Cedar.
        let mut monitor = match self.entity_store.get_monitor_state(&event.trajectory_id)? {
            Some(state) => {
                UntrustedThenProtectedWrite::with_state(self.monitor_config.clone(), state)?
            }
            // First event of the trajectory: fresh (Clean) monitor.
            None => UntrustedThenProtectedWrite::new(self.monitor_config.clone())?,
        };
        // Observe every ingested event, including Control events.
        monitor.observe(&event)?;
        // Persist unconditionally on every observe.
        self.entity_store
            .put_monitor_state(&event.trajectory_id, monitor.state())?;
        debug!("Monitor state persisted: {:?}", monitor.state());
        // Derive Armed-or-Violated via the public verdict API — mapping only
        // Armed→true would let the tripping write itself through.
        let untrusted_pending = matches!(monitor.verdict(), Verdict::Pending | Verdict::Violated);

        if let TrajectoryEvent::Control(control) = &event.event {
            if let Control::Started(_) = control {
                debug!("Starting trajectory: {}", event.trajectory_id);
                // Create a Trajectory entity for the trajectory.
                let trajectory = Trajectory::new(&event.trajectory_id);
                self.upsert_entity(trajectory.into_entity()?)?;
            }

            // Synthetic snapshot record for state-changing Control events: the
            // original event's dual-write above is untouched — this is a new
            // record written after it, never instead of it. Started is the init
            // snapshot and Resumed is the only FSM-transitioning Control
            // variant; the others are observe-no-ops. The record is written
            // directly to storage and never re-enters adjudicate, and
            // Control::Adjudicated is itself an observe-no-op — no feedback
            // loop. Actor::policy("monitor") discriminates this record from the
            // Cedar path's Actor::policy("cedar"); deny/escalate counts are
            // unaffected since the payload is an Allow.
            if matches!(control, Control::Started(_) | Control::Resumed(_)) {
                let trajectory: Trajectory = match self
                    .entity_store
                    .get(&euid("Trajectory", &event.trajectory_id)?)?
                {
                    Some(entity) => entity.try_into()?,
                    None => {
                        debug!(
                            "Trajectory entity {:?} not found for snapshot record, creating.",
                            &event.trajectory_id
                        );
                        Trajectory::new(&event.trajectory_id)
                    }
                };
                // observe + persist already ran above, so the snapshot
                // reflects the post-observe state (e.g. Resumed("user")
                // clearing Armed shows "clean" with cleared_event_id set).
                let snapshot = MonitorSnapshot::from_monitor(
                    &monitor,
                    untrusted_pending,
                    trajectory.taints.clone(),
                    trajectory.label,
                );
                let snapshot_event = Event::new(
                    event.agent.clone(),
                    &event.trajectory_id,
                    TrajectoryEvent::Control(Control::Adjudicated(Adjudicated::allow())),
                )
                .with_actor(Actor::policy("monitor"))
                .with_causality(Causality::default().caused_by(&event.event_id))
                .with_raw(serde_json::json!({
                    "monitor": serde_json::to_value(&snapshot)?,
                }));
                file::write_trajectory_event(&snapshot_event)?;
                self.trajectory_store.insert_event(&snapshot_event).await?;
            }

            // Control events are not authorized; the snapshot record above is
            // additive.
            return Ok(Adjudicated::allow());
        }

        let request = self.build_request(&event, untrusted_pending).await?;
        let response = self.is_authorized(&request)?;

        // Verdict backstop, the single call site: merge runs before the
        // raw/adjudicated_event build so the persisted record and the returned
        // decision are the same post-merge struct.
        let adjudicated = backstop::merge(
            self.response_to_adjudicated(&response),
            monitor.verdict(),
            &monitor.attributes(),
        );

        // Latest trajectory entity — hoisted above the raw build so the mirror
        // snapshot can carry taints/label. A functional no-op for existing
        // behavior: post-`is_authorized`, build_request's centralized upsert
        // has already refreshed step_count/untrusted_pending/label.
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
        debug!("Trajectory: {:?}", trajectory);

        // Mirror snapshot built from the same `monitor` binding alive since the
        // observe block and the same `untrusted_pending` bool from the single
        // derivation site — a re-loaded or pre-observe snapshot would be off by
        // one event.
        let snapshot = MonitorSnapshot::from_monitor(
            &monitor,
            untrusted_pending,
            trajectory.taints.clone(),
            trajectory.label,
        );

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
            // Place the serde-serialized typed MonitorSnapshot under its key —
            // present on every Cedar-path record, Clean trajectories included.
            "monitor": serde_json::to_value(&snapshot)?,
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

        debug!("Adjudicated Event: {:?}", adjudicated_event);

        // Write adjudication event to both storages
        file::write_trajectory_event(&adjudicated_event)?;
        self.trajectory_store
            .insert_event(&adjudicated_event)
            .await?;

        Ok(adjudicated)
    }
}
