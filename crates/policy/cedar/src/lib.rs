//! Cedar policy adjudication engine and request-context transformation.
//!
//! The engine compiles policy assets, projects typed trajectory events into
//! Cedar requests, evaluates them fail-closed, and persists the resulting
//! trajectory and entity state.

mod entity;
mod path_normalize;
mod shell_parse;
mod transform;
mod url_parse;

pub use entity::{EntityBuilder, Trajectory, euid, json_to_restricted_expr};
pub use sondera_information_flow_control::Label;

// The `.sondera` configuration surface now lives in `sondera-settings`: the
// trajectory scanner and the CLI read the same file, and neither should have to
// link the Cedar engine to do it. Re-exported so `sondera_cedar_policy::Settings`
// keeps resolving for existing embedders.
pub use sondera_settings::{
    HarnessSettings, PolicyAssets, ScannerSettings, Settings, SettingsError,
};

use anyhow::{Context as AnyhowContext, Result};
use cedar_policy::{Authorizer, Context, Entity, EntityUid, PolicySet, Request, Response, Schema};
use sondera_information_flow_control::{DataModel, LabelTemplate};
use sondera_policy::{PolicyModel, PolicyTemplate};
use sondera_storage::{TrajectoryStore, file, get_default_db_path};
use sondera_types::{
    Actor, Adjudicated, Agent, Causality, Control, Decision, EntityReaderWriter, Event, Harness,
    HarnessError, Mode, PolicyStore, PolicyStoreQuery, StaticPolicyStore, TrajectoryEvent,
    TrajectoryReaderWriter,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, instrument, warn};

/// Build the policy-category classifier from its template file.
///
/// `None` when the file declares no templates. That is a misconfiguration, and a
/// model built over it would turn every event's classification into a
/// `NoPolicies` error — failing open, but logging once per adjudication forever.
/// Report it once here instead and leave the classifier off.
fn load_policy_model(
    template_path: &Path,
    config: sondera_policy::PolicyModelConfig,
) -> Result<Option<PolicyModel>> {
    let templates = PolicyTemplate::load_from_toml(template_path).with_context(|| {
        format!(
            "Failed to load policy templates from {}",
            template_path.display()
        )
    })?;

    if templates.is_empty() {
        warn!(
            path = %template_path.display(),
            "No policy templates declared; policy-category classification stays off"
        );
        return Ok(None);
    }
    Ok(Some(PolicyModel::with_config(templates, config)?))
}

pub struct CedarPolicyHarness {
    authorizer: Authorizer,
    /// One database holding the trajectory event ledger, the agent registry,
    /// and the Cedar entities adjudication evaluates against.
    ///
    /// Shared rather than owned so a process running the console alongside the
    /// harness reads through the same connection the events are written on,
    /// instead of opening the file a second time.
    store: Arc<TrajectoryStore>,
    schema: Schema,
    policy_set: PolicySet,
    mode: Mode,
    // Both classifiers are optional and gated by the same setting: a deployment
    // that never sets `[guardrails] enabled` pays for no model provider, and the
    // deterministic YARA + Cedar path still adjudicates every event.
    data_model: Option<DataModel>,
    policy_model: Option<PolicyModel>,
}

impl CedarPolicyHarness {
    /// Load a CedarPolicyHarness from resolved [`Settings`].
    ///
    /// The policy assets come from the `.sondera` directories the settings were
    /// discovered in ([`Settings::policy_assets`]): Cedar rules and schema
    /// through a [`StaticPolicyStore`] over `policies/cedar/` and its
    /// subdirectories, and the guardrail prompt templates from `ifc.toml` and
    /// `policies.toml`. Agent entities are created dynamically from the agent
    /// field in each Event.
    ///
    /// `settings` is passed in rather than loaded here: the caller already reads
    /// the same files for the bind address, and resolving the configuration once
    /// is what keeps the CLI and the guardrails from ending up with two
    /// different views of it.
    pub async fn from_settings(settings: Settings) -> Result<Self> {
        let db_path = get_default_db_path()?;
        let store = TrajectoryStore::open(&db_path)
            .await
            .context(format!("Failed to open store: {}", db_path.display()))?;

        Self::from_settings_with_store(settings, Arc::new(store)).await
    }

    /// Load a CedarPolicyHarness against a store the caller already opened.
    ///
    /// [`from_settings`](Self::from_settings) opens the process-wide store
    /// itself; this is for a caller that has to hand the same store to something
    /// else as well — `sondera serve` gives it to the console read surface — so
    /// that one file is not opened twice in one process.
    pub async fn from_settings_with_store(
        settings: Settings,
        store: Arc<TrajectoryStore>,
    ) -> Result<Self> {
        let assets = settings.policy_assets()?;
        Self::build(assets, store, settings).await
    }

    /// Load a CedarPolicyHarness with isolated storage for testing.
    ///
    /// Opens the single store under the given directory, so each test gets its
    /// own independent database rather than sharing `~/.sondera`.
    /// `config_dir` is used alone, and optional model guardrails are disabled
    /// rather than loaded from [`Settings::load`], so neither a developer's own
    /// `sondera.toml` nor their `~/.sondera` policy assets can change what a
    /// test exercises.
    pub async fn from_config_dir_isolated(
        config_dir: PathBuf,
        storage_dir: &std::path::Path,
    ) -> Result<Self> {
        Self::from_config_dir_isolated_with_settings(config_dir, storage_dir, Settings::default())
            .await
    }

    /// Load an isolated harness with explicit model settings for integration tests.
    pub async fn from_config_dir_isolated_with_settings(
        config_dir: PathBuf,
        storage_dir: &std::path::Path,
        settings: Settings,
    ) -> Result<Self> {
        let store = TrajectoryStore::open(storage_dir.join("trajectories.db"))
            .await
            .context(format!("Failed to open store: {}", storage_dir.display()))?;

        let assets = PolicyAssets::in_config_dir(config_dir)?;
        Self::build(assets, Arc::new(store), settings).await
    }

    async fn build(
        assets: PolicyAssets,
        store: Arc<TrajectoryStore>,
        settings: Settings,
    ) -> Result<Self> {
        let cedar_dir = &assets.cedar_dir;

        // Cedar comes from a `PolicyStore`, never from this module reading files.
        // `StaticPolicyStore` walks the cedar directory and every subdirectory;
        // the guardrail prompt templates live outside it and are loaded below.
        let policy_store: Arc<dyn PolicyStore> =
            Arc::new(StaticPolicyStore::load(cedar_dir).with_context(|| {
                format!("Failed to load policies from {}", cedar_dir.display())
            })?);

        let compiled = policy_store
            .compile_policy_set(&PolicyStoreQuery::default())
            .await
            .with_context(|| format!("Failed to compile policies from {}", cedar_dir.display()))?;
        debug!(
            policies = compiled.policy_set.policies().count(),
            mode = %compiled.mode,
            "Compiled policy set"
        );
        let (policy_set, schema, mode) = (compiled.policy_set, compiled.schema, compiled.mode);

        // Add Label entity types matching the sensitivity lattice.
        // Names must match Label enum's Display impl and the `resource.label` /
        // `context.label` references in the `ifc-forbid-*.cedar` policies.
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

        store.upsert(&highly_confidential_label).await?;
        store.upsert(&confidential_label).await?;
        store.upsert(&internal_label).await?;
        store.upsert(&public_label).await?;

        // The `.toml` files in the config directory carry the label and policy
        // templates; which model evaluates them comes from `sondera.toml`.
        let (data_model, policy_model) = if settings.guardrails_enabled {
            debug!(
                sources = ?settings.sources,
                data_provider = %settings.data_model.provider,
                data_model = %settings.data_model.model,
                policy_provider = %settings.policy_model.provider,
                policy_model = %settings.policy_model.model,
                "Enabled optional model guardrails"
            );
            let labels =
                LabelTemplate::load_from_toml(&assets.ifc_template).with_context(|| {
                    format!(
                        "Failed to load label templates from {}",
                        assets.ifc_template.display()
                    )
                })?;
            (
                Some(DataModel::with_config(labels, settings.data_model)?),
                load_policy_model(&assets.policy_template, settings.policy_model)?,
            )
        } else {
            debug!("Optional model guardrails disabled; using deterministic context only");
            (None, None)
        };

        Ok(Self {
            authorizer: Authorizer::new(),
            store,
            schema,
            policy_set,
            mode,
            data_model,
            policy_model,
        })
    }

    /// Ensure the agent entity exists in the entity store.
    async fn ensure_agent_entity(&self, agent: &Agent) -> Result<()> {
        // Through `euid` so the type is namespace-qualified: a bare
        // `Agent::"x"` here would not be the principal the request names.
        let agent_uid = euid("Agent", &agent.id)?;

        if self.store.get(&agent_uid).await?.is_none() {
            let agent_entity = Entity::new_no_attrs(agent_uid, HashSet::new());
            self.store.upsert(&agent_entity).await?;
        }
        Ok(())
    }

    /// Get the loaded policy set.
    pub fn policy_set(&self) -> &PolicySet {
        &self.policy_set
    }

    /// The evaluation mode the loaded policy set was compiled with.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Get the loaded schema.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    pub async fn is_authorized(&self, request: &Request) -> Result<Response> {
        // `None` rather than `Some(&self.schema)`: the loaded schema declares no
        // action hierarchies, so there are no parent links for Cedar to
        // materialize and passing it would only cost a re-validation.
        let entities = self.store.entities(None).await?;
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
    pub async fn add_entity(&self, entity: Entity) -> Result<()> {
        if self.store.get(&entity.uid()).await?.is_some() {
            anyhow::bail!("Entity already exists: {}", entity.uid());
        }
        self.store.upsert(&entity).await?;
        Ok(())
    }

    /// Upsert an entity into the entity store.
    /// If an entity with the same UID exists, it will be replaced.
    pub async fn upsert_entity(&self, entity: Entity) -> Result<()> {
        self.store.upsert(&entity).await?;
        Ok(())
    }

    /// Get an entity from the entity store by its UID.
    pub async fn get_entity(&self, uid: &EntityUid) -> Result<Option<Entity>> {
        Ok(self.store.get(uid).await?)
    }

    /// Remove an entity from the entity store by its UID.
    pub async fn remove_entity(&self, uid: EntityUid) -> Result<()> {
        self.store.delete(&uid).await?;
        Ok(())
    }
}

impl Harness for CedarPolicyHarness {
    async fn adjudicate(&self, event: Event) -> std::result::Result<Adjudicated, HarnessError> {
        self.adjudicate_event(event)
            .await
            .map_err(|e| HarnessError::message(format!("{e:#}")))
    }
}

impl CedarPolicyHarness {
    /// Adjudicate a single event against the loaded Cedar policies, persisting
    /// the source event and the resulting `Control::Adjudicated` event.
    ///
    /// The source event is written *after* the verdict, and written redacted
    /// unless the verdict was a clean `Allow`. Adjudication needs whatever file
    /// body the hook attached — content-keyed policy cannot match bytes it
    /// cannot see — but once a read has been refused, persisting those bytes
    /// would leave the ledger holding the very secret the policy just blocked.
    /// See [`Event::redact_file_content`].
    ///
    /// Redaction keys on the decision alone, not on [`Mode`]: a `Monitor`
    /// deployment does not block the read, but the policy that fired still
    /// named those bytes sensitive, and this database outlives the run either
    /// way. The cost is that a monitored run's transcript shows the marker
    /// rather than the content that tripped the rule.
    #[instrument(
        skip(self, event),
        fields(
            trajectory_id = %event.trajectory_id,
            event_id = %event.event_id,
            agent = %event.agent.id,
        )
    )]
    async fn adjudicate_event(&self, event: Event) -> Result<Adjudicated> {
        debug!("Trajectory Event: {:?}", event);
        // Ensure the agent entity exists in the store
        self.ensure_agent_entity(&event.agent).await?;

        if let TrajectoryEvent::Control(control) = &event.event {
            // Control events are lifecycle records carrying no file body, and
            // they are not adjudicated, so they persist as they arrived.
            self.persist(&event).await?;

            if let Control::Started(_) = control {
                debug!("Starting trajectory: {}", event.trajectory_id);
                // Create a Trajectory entity for the trajectory.
                let trajectory = Trajectory::new(&event.trajectory_id);
                self.upsert_entity(trajectory.into_entity()?).await?;
            }
            // Don't authorize control events.
            return Ok(Adjudicated::allow());
        }

        let outcome = self.evaluate(&event).await;

        // Anything short of a clean `Allow` persists redacted. A `Deny` or an
        // `Escalate` refused the operation; an adjudication that errored
        // produced no verdict at all, so it fails closed here the same way the
        // hooks fail closed on the decision itself.
        let event = match &outcome {
            Ok(adjudicated) if adjudicated.decision == Decision::Allow => event,
            _ => event.redact_file_content(),
        };

        // Persist before propagating an adjudication error: an event the engine
        // could not decide still belongs in the ledger. Both failures are fatal
        // and both fail the caller closed, but the adjudication error is
        // reported in preference to a storage error that followed it — it is
        // the one that says why the event has no verdict.
        let persisted = self.persist(&event).await;
        let adjudicated = outcome?;
        persisted?;

        // Write the adjudication as a Control event on the same trajectory.
        // The `sondera_types::Event` envelope carries no raw provider payload
        // (the wire schema strips it), so the Cedar request/response detail is
        // captured in tracing rather than on the persisted event.
        let adjudicated_event = Event::new(
            event.agent.clone(),
            &event.trajectory_id,
            TrajectoryEvent::Control(Control::Adjudicated(adjudicated.clone())),
        )
        .with_actor(Actor::policy("cedar"))
        .with_causality(Causality::default().caused_by(&event.event_id));

        // Latest trajectory entity.
        let trajectory: Trajectory = match self
            .store
            .get(&euid("Trajectory", &event.trajectory_id)?)
            .await?
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

        self.persist(&adjudicated_event).await?;

        Ok(adjudicated)
    }

    /// Evaluate one event against the policy set, without persisting anything.
    ///
    /// Split out from [`adjudicate_event`](Self::adjudicate_event) so the
    /// verdict — including the error case — is a value the caller can inspect
    /// before deciding what form of the event reaches storage.
    async fn evaluate(&self, event: &Event) -> Result<Adjudicated> {
        let request = self.build_request(event).await?;
        let response = self.is_authorized(&request).await?;
        Ok(self.response_to_adjudicated(&response))
    }

    /// Append `event` to both ledgers: the per-trajectory JSONL file and Turso.
    ///
    /// The single write site for trajectory events, so redaction cannot be
    /// applied to one store and forgotten on the other.
    async fn persist(&self, event: &Event) -> Result<()> {
        file::write_trajectory_event(event).await?;
        self.store.insert_event(event).await?;
        Ok(())
    }
}
