use crate::monitors::MonitorState;
use anyhow::{Context, Result};
use cedar_policy::{Entities, Entity, EntityUid};
use fjall::{Database, Keyspace};
use std::path::Path;
use tracing::debug;

pub struct EntityStore {
    db: Database,
    entities: Keyspace,
    /// Dedicated keyspace for multi-hop monitor state, keyed by the plain
    /// trajectory id. Never read by Cedar and invisible to
    /// [`EntityStore::entities`], so the full Cedar scan is not inflated.
    monitor_state: Keyspace,
}

impl EntityStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Database::builder(path.as_ref()).open()?;
        let entities = db.keyspace("entities", fjall::KeyspaceCreateOptions::default)?;
        let monitor_state = db.keyspace("monitor_state", fjall::KeyspaceCreateOptions::default)?;
        Ok(Self {
            db,
            entities,
            monitor_state,
        })
    }

    pub fn upsert(&self, entity: &Entity) -> Result<()> {
        let key = entity.uid().to_string();
        let mut buf = Vec::new();
        entity.write_to_json(&mut buf)?;
        self.entities.insert(&key, buf)?;
        debug!("upserted: {:?}", entity.uid().to_string());
        Ok(())
    }

    pub fn get(&self, uid: &EntityUid) -> Result<Option<Entity>> {
        let key = uid.to_string();
        let Some(bytes) = self.entities.get(&key)? else {
            return Ok(None);
        };
        let json_str = std::str::from_utf8(&bytes).context("invalid UTF-8")?;
        let entity = Entity::from_json_str(json_str, None)?;
        debug!("get: {:?}", entity.uid().to_string());
        Ok(Some(entity))
    }

    pub fn delete(&self, uid: &EntityUid) -> Result<()> {
        self.entities.remove(uid.to_string())?;
        debug!("delete: {:?}", uid.to_string());
        Ok(())
    }

    pub fn entities(&self) -> Result<Entities> {
        let mut all = Vec::new();
        for kv in self.entities.iter() {
            let (_, value) = kv.into_inner()?;
            let json_str = std::str::from_utf8(&value).context("invalid UTF-8")?;
            let entity = Entity::from_json_str(json_str, None)?;
            all.push(entity);
        }
        debug!("entities: n={:?}", all.len());
        Ok(Entities::from_entities(all, None)?)
    }

    /// Load persisted multi-hop monitor state for a trajectory.
    ///
    /// O(1) keyed get on the dedicated `monitor_state` keyspace; the key is
    /// the plain trajectory id. Returns `Ok(None)` for a trajectory that has
    /// never been observed. Storage faults propagate as `anyhow::Error`.
    pub fn get_monitor_state(&self, trajectory_id: &str) -> Result<Option<MonitorState>> {
        let Some(bytes) = self.monitor_state.get(trajectory_id)? else {
            return Ok(None);
        };
        let state: MonitorState =
            serde_json::from_slice(&bytes).context("corrupt monitor state")?;
        debug!("get_monitor_state: {:?}", trajectory_id);
        Ok(Some(state))
    }

    /// Persist multi-hop monitor state for a trajectory.
    ///
    /// O(1) keyed put on the dedicated `monitor_state` keyspace, keyed by
    /// the plain trajectory id. Storage faults propagate as `anyhow::Error`.
    pub fn put_monitor_state(&self, trajectory_id: &str, state: &MonitorState) -> Result<()> {
        let buf = serde_json::to_vec(state)?;
        self.monitor_state.insert(trajectory_id, buf)?;
        debug!("put_monitor_state: {:?}", trajectory_id);
        Ok(())
    }

    pub fn persist(&self) -> Result<()> {
        self.db.persist(fjall::PersistMode::SyncAll)?;
        Ok(())
    }
}
