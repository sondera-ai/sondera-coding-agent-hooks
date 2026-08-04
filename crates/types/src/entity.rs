//! Entity storage trait for Cedar policy entities.
//!
//! Abstracts over Cedar entity persistence so the policy engine remains
//! storage-agnostic. Turso implements this trait for durable entity storage.

use crate::error::EntityStoreError;
type Result<T> = std::result::Result<T, EntityStoreError>;
use cedar_policy::{Entities, Entity, EntityUid, Schema};
use std::future::Future;

/// Trait for Cedar entity storage backends.
///
/// The policy engine uses this trait through generic bounds rather than
/// `dyn EntityReaderWriter`, so the async methods use RPITIT with explicit
/// `Send` futures instead of `#[async_trait]` boxing.
pub trait EntityReaderWriter: Send + Sync {
    /// Insert or replace a Cedar entity.
    fn upsert(&self, entity: &Entity) -> impl Future<Output = Result<()>> + Send;

    /// Look up a Cedar entity by its UID.
    fn get(&self, uid: &EntityUid) -> impl Future<Output = Result<Option<Entity>>> + Send;

    /// Remove a Cedar entity by its UID.
    fn delete(&self, uid: &EntityUid) -> impl Future<Output = Result<()>> + Send;

    /// Return all Cedar entities for authorization queries. When a schema is
    /// provided, Cedar materializes action-entity parent links from the
    /// schema's `in [...]` declarations — required for policies that use
    /// `action in Action::"X"` to match typed children like
    /// `Action::"ToolCall::send_email"`. Passing `None` yields entities with
    /// no derived action hierarchy.
    fn entities(&self, schema: Option<&Schema>) -> impl Future<Output = Result<Entities>> + Send;
}
