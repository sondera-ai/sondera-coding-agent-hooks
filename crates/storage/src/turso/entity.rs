//! [`EntityReaderWriter`] over the Turso ledger.
//!
//! Cedar entities are persisted in their Cedar JSON encoding, keyed by uid, in
//! the same database as the trajectory events they are derived from. That is
//! what lets one adjudication append an event and raise the trajectory's
//! sensitivity label without coordinating two database files.
//!
//! The module is behind the `cedar` feature, so the console — which reads
//! agents and trajectories and has no use for entities — does not link
//! `cedar-policy`. The `entities` table itself is created unconditionally; see
//! the schema in [`super`].

use super::TrajectoryStore;
use anyhow::Result;
use cedar_policy::{Entities, Entity, EntityUid, Schema};
use sondera_types::{EntityReaderWriter, EntityStoreError};
use tracing::debug;

impl TrajectoryStore {
    /// Atomically read-modify-write the entity stored at `uid`.
    ///
    /// `f` receives the currently stored entity (`None` when absent) and returns
    /// the entity to store, or `None` to leave the slot untouched.
    ///
    /// Whole-entity `upsert`s cannot be composed safely from a separate `get`:
    /// two concurrent adjudications on the same trajectory interleave so that
    /// one writer's stale copy overwrites the other's raised sensitivity label,
    /// silently reverting the label and letting a later action be judged
    /// against a lower label than it should be. Callers that mutate an existing
    /// entity must go through this method rather than `get` + `upsert`.
    ///
    /// The guard is process-local: it serializes the adjudications running
    /// inside one harness, not writers in separate processes. Two harnesses
    /// pointed at the same database file can still lose an update this way.
    ///
    /// # Errors
    ///
    /// Returns an error if the read, `f`, or the write fails.
    pub async fn update_entity<F>(&self, uid: &EntityUid, f: F) -> Result<()>
    where
        F: FnOnce(Option<Entity>) -> Result<Option<Entity>>,
    {
        let _guard = self.update_lock.lock().await;
        if let Some(updated) = f(self.get(uid).await?)? {
            self.upsert(&updated).await?;
        }
        Ok(())
    }
}

/// Encode an entity in Cedar's JSON representation.
fn entity_to_json(entity: &Entity) -> Result<String, EntityStoreError> {
    let mut buf = Vec::new();
    entity
        .write_to_json(&mut buf)
        .map_err(|e| EntityStoreError::source("failed to serialize entity", e))?;
    String::from_utf8(buf).map_err(|e| EntityStoreError::source("entity JSON is not UTF-8", e))
}

/// Read the `entity_json` column out of a selected row.
///
/// Every entity query selects that column and nothing else, so the index is
/// always 0.
fn entity_json_column(row: &turso::Row) -> Result<String, EntityStoreError> {
    row.get::<String>(0)
        .map_err(|e| EntityStoreError::source("failed to read entity_json column", e))
}

/// A connection for one entity operation, in this surface's error type.
///
/// Entity reads and writes report [`EntityStoreError`] rather than the
/// trajectory surface's [`StoreError`], so the shared helper's failure is
/// translated here rather than given a blanket `From`.
fn entity_connection(store: &TrajectoryStore) -> Result<turso::Connection, EntityStoreError> {
    store
        .connection()
        .map_err(|e| EntityStoreError::source("failed to open a database connection", e))
}

/// Decode an entity from Cedar's JSON representation.
fn entity_from_json(json: &str) -> Result<Entity, EntityStoreError> {
    Entity::from_json_str(json, None)
        .map_err(|e| EntityStoreError::source("failed to deserialize entity", e))
}

impl EntityReaderWriter for TrajectoryStore {
    async fn upsert(&self, entity: &Entity) -> Result<(), EntityStoreError> {
        let uid = entity.uid().to_string();
        let json = entity_to_json(entity)?;

        entity_connection(self)?
            .execute(
                r#"
                INSERT INTO entities (uid, entity_json)
                VALUES (?1, ?2)
                ON CONFLICT (uid)
                DO UPDATE SET entity_json = excluded.entity_json
                "#,
                [uid.as_str(), json.as_str()],
            )
            .await
            .map_err(|e| EntityStoreError::source("failed to upsert entity", e))?;

        debug!("upserted: {:?}", uid);
        Ok(())
    }

    async fn get(&self, uid: &EntityUid) -> Result<Option<Entity>, EntityStoreError> {
        let key = uid.to_string();
        let mut rows = entity_connection(self)?
            .query(
                "SELECT entity_json FROM entities WHERE uid = ?1",
                [key.as_str()],
            )
            .await
            .map_err(|e| EntityStoreError::source("failed to read entity", e))?;

        let Some(row) = rows
            .next()
            .await
            .map_err(|e| EntityStoreError::source("failed to read entity row", e))?
        else {
            return Ok(None);
        };

        let entity = entity_from_json(&entity_json_column(&row)?)?;
        debug!("get: {:?}", key);
        Ok(Some(entity))
    }

    async fn delete(&self, uid: &EntityUid) -> Result<(), EntityStoreError> {
        let key = uid.to_string();
        entity_connection(self)?
            .execute("DELETE FROM entities WHERE uid = ?1", [key.as_str()])
            .await
            .map_err(|e| EntityStoreError::source("failed to delete entity", e))?;

        debug!("delete: {:?}", key);
        Ok(())
    }

    async fn entities(&self, schema: Option<&Schema>) -> Result<Entities, EntityStoreError> {
        let mut rows = entity_connection(self)?
            .query("SELECT entity_json FROM entities", ())
            .await
            .map_err(|e| EntityStoreError::source("failed to list entities", e))?;

        let mut all = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| EntityStoreError::source("failed to read entity row", e))?
        {
            all.push(entity_from_json(&entity_json_column(&row)?)?);
        }

        debug!("entities: n={:?}", all.len());
        Entities::from_entities(all, schema)
            .map_err(|e| EntityStoreError::source("failed to build entity set", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::{EntityId, EntityTypeName, EvalResult, RestrictedExpression};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    /// The store is entity-shape agnostic — it round-trips whatever Cedar JSON
    /// it is handed — so these tests build entities with the raw `cedar-policy`
    /// API rather than depending on the harness engine's `EntityBuilder`, which
    /// would make this crate depend on its own consumer.
    fn euid(type_name: &str, id: &str) -> EntityUid {
        let entity_type: EntityTypeName = format!("Sondera::{type_name}")
            .parse()
            .expect("valid entity type");
        EntityUid::from_type_name_and_id(entity_type, EntityId::new(id))
    }

    fn counter_entity(uid: &EntityUid, count: i64) -> Entity {
        Entity::new(
            uid.clone(),
            HashMap::from([(
                "step_count".to_string(),
                RestrictedExpression::new_long(count),
            )]),
            HashSet::new(),
        )
        .expect("counter entity should build")
    }

    async fn store() -> TrajectoryStore {
        TrajectoryStore::open_in_memory()
            .await
            .expect("store should open")
    }

    async fn read_count(store: &TrajectoryStore, uid: &EntityUid) -> i64 {
        match store
            .get(uid)
            .await
            .expect("read should succeed")
            .expect("entity should exist")
            .attr("step_count")
            .expect("attr should exist")
            .expect("attr should evaluate")
        {
            EvalResult::Long(n) => n,
            other => panic!("step_count should be a Long, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_creates_the_entity_when_absent() {
        let store = store().await;
        let uid = euid("Trajectory", "t1");

        store
            .update_entity(&uid, |existing| {
                assert!(existing.is_none(), "slot should start empty");
                Ok(Some(counter_entity(&uid, 1)))
            })
            .await
            .expect("update should succeed");

        assert_eq!(read_count(&store, &uid).await, 1);
    }

    #[tokio::test]
    async fn update_leaves_the_entity_untouched_when_the_updater_returns_none() {
        let store = store().await;
        let uid = euid("Trajectory", "t1");
        store.upsert(&counter_entity(&uid, 7)).await.expect("seed");

        store
            .update_entity(&uid, |_| Ok(None))
            .await
            .expect("update");

        assert_eq!(read_count(&store, &uid).await, 7);
    }

    #[tokio::test]
    async fn upsert_replaces_the_stored_entity() {
        let store = store().await;
        let uid = euid("Trajectory", "t1");

        store
            .upsert(&counter_entity(&uid, 1))
            .await
            .expect("first write");
        store
            .upsert(&counter_entity(&uid, 2))
            .await
            .expect("second write");

        assert_eq!(read_count(&store, &uid).await, 2);
        let entities = store.entities(None).await.expect("entities");
        assert_eq!(entities.iter().count(), 1, "upsert should not duplicate");
    }

    #[tokio::test]
    async fn delete_removes_the_entity() {
        let store = store().await;
        let uid = euid("Trajectory", "t1");
        store.upsert(&counter_entity(&uid, 1)).await.expect("seed");

        store.delete(&uid).await.expect("delete should succeed");

        assert!(
            store.get(&uid).await.expect("read").is_none(),
            "entity should be gone"
        );
    }

    /// Entities and trajectory events now share one database, so writing either
    /// must leave the other's table alone.
    #[tokio::test]
    async fn entities_and_trajectory_events_coexist_in_one_database() {
        use sondera_types::{
            Agent, Event, Observation, Thought, TrajectoryEvent, TrajectoryReaderWriter,
        };

        let store = store().await;
        let uid = euid("Trajectory", "run-1");
        store.upsert(&counter_entity(&uid, 1)).await.expect("seed");

        store
            .insert_event(&Event::new(
                Agent::new("a", "test", ""),
                "run-1",
                TrajectoryEvent::Observation(Observation::Thought(Thought::new("t"))),
            ))
            .await
            .expect("event insert");

        assert_eq!(read_count(&store, &uid).await, 1);
        assert_eq!(store.trajectory_events("run-1").await.unwrap().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_updates_do_not_lose_writes() {
        // The label race this guards: a `get` + whole-entity `upsert` pair run
        // concurrently lets one writer's stale copy clobber the other's write,
        // which for a Trajectory silently reverts a raised sensitivity label.
        const WRITERS: i64 = 8;
        const INCREMENTS: i64 = 50;

        let store = Arc::new(store().await);
        let uid = euid("Trajectory", "t1");
        store.upsert(&counter_entity(&uid, 0)).await.expect("seed");

        let mut tasks = Vec::new();
        for _ in 0..WRITERS {
            let store = Arc::clone(&store);
            let uid = uid.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..INCREMENTS {
                    store
                        .update_entity(&uid, |existing| {
                            let entity = existing.expect("seeded entity should exist");
                            let current =
                                match entity.attr("step_count").expect("attr").expect("eval") {
                                    EvalResult::Long(n) => n,
                                    other => {
                                        panic!("step_count should be a Long, got {other:?}")
                                    }
                                };
                            Ok(Some(counter_entity(&uid, current + 1)))
                        })
                        .await
                        .expect("update should succeed");
                }
            }));
        }
        for task in tasks {
            task.await.expect("writer task should not panic");
        }

        assert_eq!(read_count(&store, &uid).await, WRITERS * INCREMENTS);
    }
}
