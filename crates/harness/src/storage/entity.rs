use anyhow::{Context, Result};
use cedar_policy::{Entities, Entity, EntityUid};
use fjall::{Database, Keyspace};
use std::path::Path;
use tracing::debug;

pub struct EntityStore {
    db: Database,
    entities: Keyspace,
}

impl EntityStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Database::builder(path.as_ref()).open()?;
        let entities = db.keyspace("entities", fjall::KeyspaceCreateOptions::default)?;
        Ok(Self { db, entities })
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

    pub fn persist(&self) -> Result<()> {
        self.db.persist(fjall::PersistMode::SyncAll)?;
        Ok(())
    }
}
