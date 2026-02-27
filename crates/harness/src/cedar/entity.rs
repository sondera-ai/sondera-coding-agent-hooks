use anyhow::Result;
use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, EvalResult, RestrictedExpression};
use sondera_information_flow_control::Label;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trajectory {
    pub trajectory_id: String,
    pub step_count: i64,
    pub label: Label,
    pub taints: Vec<String>,
}

impl Trajectory {
    pub fn new(trajectory_id: impl Into<String>) -> Self {
        Self {
            trajectory_id: trajectory_id.into(),
            step_count: 0,
            label: Label::default(),
            taints: Vec::new(),
        }
    }
}

impl Trajectory {
    /// Convert this Trajectory into a Cedar Entity.
    ///
    /// Returns an error if any taint name is an invalid entity type or the
    /// entity cannot be constructed.
    pub fn into_entity(self) -> Result<Entity> {
        let mut taint_refs: HashSet<EntityUid> = HashSet::new();
        for taint in &self.taints {
            taint_refs.insert(euid("Taint", taint.as_str())?);
        }
        EntityBuilder::from_type_and_id("Trajectory", &self.trajectory_id)?
            .long("step_count", self.step_count)
            .entity_ref("label", "Label", &self.label.to_string())?
            .entity_set("taints", &taint_refs)
            .build()
    }
}

impl TryFrom<Entity> for Trajectory {
    type Error = anyhow::Error;

    fn try_from(entity: Entity) -> Result<Self> {
        let trajectory_id = entity.uid().id().unescaped().to_string();
        let step_count = entity
            .attr("step_count")
            .and_then(|r| r.ok())
            .and_then(|v| match v {
                EvalResult::Long(n) => Some(n),
                _ => None,
            })
            .unwrap_or(0);

        let label = entity
            .attr("label")
            .and_then(|r| r.ok())
            .and_then(|v| match v {
                EvalResult::EntityUid(uid) => Label::from_str(uid.id().unescaped()).ok(),
                EvalResult::String(s) => Label::from_str(&s).ok(),
                _ => None,
            })
            .unwrap_or_default();

        let taints = entity
            .attr("taints")
            .and_then(|r| r.ok())
            .and_then(|v| match v {
                EvalResult::Set(set) => Some(
                    set.iter()
                        .filter_map(|item| match item {
                            EvalResult::EntityUid(uid) => Some(uid.id().unescaped().to_string()),
                            _ => None,
                        })
                        .collect(),
                ),
                _ => None,
            })
            .unwrap_or_default();

        Ok(Trajectory {
            trajectory_id,
            step_count,
            label,
            taints,
        })
    }
}

/// Convert a `serde_json::Value` to a Cedar `RestrictedExpression`.
pub fn json_to_restricted_expr(value: &serde_json::Value) -> Result<RestrictedExpression> {
    match value {
        serde_json::Value::Bool(b) => Ok(RestrictedExpression::new_bool(*b)),
        serde_json::Value::Number(n) => {
            let i = n
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("Cedar only supports integer numbers, got: {n}"))?;
            Ok(RestrictedExpression::new_long(i))
        }
        serde_json::Value::String(s) => Ok(RestrictedExpression::new_string(s.clone())),
        serde_json::Value::Array(arr) => {
            let items: Result<Vec<RestrictedExpression>> =
                arr.iter().map(json_to_restricted_expr).collect();
            Ok(RestrictedExpression::new_set(items?))
        }
        serde_json::Value::Object(obj) => {
            // Check for Cedar entity reference: {"__entity": {"type": "...", "id": "..."}}
            if let Some(entity_ref) = obj.get("__entity") {
                let type_name = entity_ref
                    .get("type")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("__entity missing 'type' field"))?;
                let id = entity_ref
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("__entity missing 'id' field"))?;
                let uid = euid(type_name, id)?;
                return Ok(RestrictedExpression::new_entity_uid(uid));
            }
            let fields: Result<Vec<(String, RestrictedExpression)>> = obj
                .iter()
                .map(|(k, v)| {
                    let expr = json_to_restricted_expr(v)?;
                    Ok((k.clone(), expr))
                })
                .collect();
            RestrictedExpression::new_record(fields?)
                .map_err(|e| anyhow::anyhow!("Failed to create record expression: {e}"))
        }
        serde_json::Value::Null => {
            anyhow::bail!("Cedar does not support null values")
        }
    }
}

/// Builder for constructing Cedar entities with a fluent API.
///
/// # Example
///
/// ```
/// # use sondera_harness::EntityBuilder;
/// # use cedar_policy::{EntityId, EntityTypeName, EntityUid};
/// # use std::str::FromStr;
/// let uid = EntityUid::from_type_name_and_id(
///     EntityTypeName::from_str("Agent").unwrap(),
///     EntityId::new("agent-1"),
/// );
/// let entity = EntityBuilder::new(uid)
///     .string("name", "Claude")
///     .long("step_count", 5)
///     .bool("active", true)
///     .build()
///     .unwrap();
/// ```
pub struct EntityBuilder {
    euid: EntityUid,
    attrs: HashMap<String, RestrictedExpression>,
    parents: HashSet<EntityUid>,
}

impl EntityBuilder {
    /// Create a new builder for an entity with the given UID.
    pub fn new(euid: EntityUid) -> Self {
        Self {
            euid,
            attrs: HashMap::new(),
            parents: HashSet::new(),
        }
    }

    /// Create a new builder from a type name and ID string.
    pub fn from_type_and_id(type_name: &str, id: &str) -> Result<Self> {
        let uid = euid(type_name, id)?;
        Ok(Self::new(uid))
    }

    /// Add a string attribute.
    pub fn string(mut self, key: impl Into<String>, value: &str) -> Self {
        self.attrs.insert(
            key.into(),
            RestrictedExpression::new_string(value.to_string()),
        );
        self
    }

    /// Add a long (integer) attribute.
    pub fn long(mut self, key: impl Into<String>, value: i64) -> Self {
        self.attrs
            .insert(key.into(), RestrictedExpression::new_long(value));
        self
    }

    /// Add a boolean attribute.
    pub fn bool(mut self, key: impl Into<String>, value: bool) -> Self {
        self.attrs
            .insert(key.into(), RestrictedExpression::new_bool(value));
        self
    }

    /// Add an entity reference attribute.
    pub fn entity_ref(mut self, key: impl Into<String>, type_name: &str, id: &str) -> Result<Self> {
        let uid = euid(type_name, id)?;
        self.attrs
            .insert(key.into(), RestrictedExpression::new_entity_uid(uid));
        Ok(self)
    }

    /// Add a set-of-strings attribute.
    pub fn string_set(mut self, key: impl Into<String>, values: &[&str]) -> Self {
        let items: Vec<RestrictedExpression> = values
            .iter()
            .map(|s| RestrictedExpression::new_string(s.to_string()))
            .collect();
        self.attrs
            .insert(key.into(), RestrictedExpression::new_set(items));
        self
    }

    /// Add a set-of-entity-references attribute.
    pub fn entity_set(mut self, key: impl Into<String>, uids: &HashSet<EntityUid>) -> Self {
        let items: Vec<RestrictedExpression> = uids
            .iter()
            .map(|uid| RestrictedExpression::new_entity_uid(uid.clone()))
            .collect();
        self.attrs
            .insert(key.into(), RestrictedExpression::new_set(items));
        self
    }

    /// Add an attribute from a raw Cedar expression string.
    pub fn expr(mut self, key: impl Into<String>, expression: &str) -> Result<Self> {
        let restricted: RestrictedExpression = expression
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse expression: {e}"))?;
        self.attrs.insert(key.into(), restricted);
        Ok(self)
    }

    /// Add an attribute from a `serde_json::Value`.
    pub fn json_attr(mut self, key: impl Into<String>, value: &serde_json::Value) -> Result<Self> {
        let expr = json_to_restricted_expr(value)?;
        self.attrs.insert(key.into(), expr);
        Ok(self)
    }

    /// Merge all attributes from a JSON object into the entity's attributes.
    pub fn json_attrs(mut self, value: &serde_json::Value) -> Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("Expected JSON object for attributes"))?;
        for (key, val) in obj {
            let expr = json_to_restricted_expr(val)?;
            self.attrs.insert(key.clone(), expr);
        }
        Ok(self)
    }

    /// Add a parent entity by type name and ID.
    pub fn parent(mut self, type_name: &str, id: &str) -> Result<Self> {
        let uid = euid(type_name, id)?;
        self.parents.insert(uid);
        Ok(self)
    }

    /// Add a parent entity by UID.
    pub fn parent_uid(mut self, uid: EntityUid) -> Self {
        self.parents.insert(uid);
        self
    }

    /// Build the Cedar `Entity`.
    pub fn build(self) -> Result<Entity> {
        Entity::new(self.euid, self.attrs, self.parents)
            .map_err(|e| anyhow::anyhow!("Failed to build entity: {e}"))
    }
}

/// Construct an `EntityUid` from a type name string and ID string.
pub fn euid(type_name: &str, id: &str) -> Result<EntityUid> {
    let entity_type: EntityTypeName = type_name
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid entity type: {}", type_name))?;
    Ok(EntityUid::from_type_name_and_id(
        entity_type,
        EntityId::new(id),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_entity_no_attrs() {
        let uid = euid("Agent", "test-agent").unwrap();
        let entity = EntityBuilder::new(uid).build().unwrap();
        assert_eq!(entity.uid().id().unescaped(), "test-agent");
        assert_eq!(entity.uid().type_name().to_string(), "Agent");
    }

    #[test]
    fn build_entity_from_type_and_id() {
        let entity = EntityBuilder::from_type_and_id("Agent", "a1")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(entity.uid().id().unescaped(), "a1");
    }

    #[test]
    fn build_entity_with_string_attr() {
        let entity = EntityBuilder::from_type_and_id("Agent", "a1")
            .unwrap()
            .string("provider_id", "anthropic")
            .build()
            .unwrap();
        assert!(entity.attr("provider_id").is_some());
    }

    #[test]
    fn build_entity_with_long_attr() {
        let entity = EntityBuilder::from_type_and_id("Trajectory", "t1")
            .unwrap()
            .long("step_count", 42)
            .build()
            .unwrap();
        assert!(entity.attr("step_count").is_some());
    }

    #[test]
    fn build_entity_with_bool_attr() {
        let entity = EntityBuilder::from_type_and_id("Agent", "a1")
            .unwrap()
            .bool("active", true)
            .build()
            .unwrap();
        assert!(entity.attr("active").is_some());
    }

    #[test]
    fn build_entity_with_entity_ref() {
        let entity = EntityBuilder::from_type_and_id("Message", "m1")
            .unwrap()
            .entity_ref("label", "Label", "Confidential")
            .unwrap()
            .build()
            .unwrap();
        assert!(entity.attr("label").is_some());
    }

    #[test]
    fn build_entity_with_string_set() {
        let entity = EntityBuilder::from_type_and_id("Agent", "a1")
            .unwrap()
            .string_set("categories", &["prompt_injection", "data_exfiltration"])
            .build()
            .unwrap();
        assert!(entity.attr("categories").is_some());
    }

    #[test]
    fn build_entity_with_raw_expr() {
        let entity = EntityBuilder::from_type_and_id("Agent", "a1")
            .unwrap()
            .expr("name", "\"Claude\"")
            .unwrap()
            .build()
            .unwrap();
        assert!(entity.attr("name").is_some());
    }

    #[test]
    fn build_entity_with_parent() {
        let entity = EntityBuilder::from_type_and_id("Message", "m1")
            .unwrap()
            .parent("Trajectory", "t1")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(entity.uid().id().unescaped(), "m1");
    }

    #[test]
    fn build_entity_with_json_attrs() {
        let attrs = serde_json::json!({
            "provider_id": "anthropic",
        });
        let entity = EntityBuilder::from_type_and_id("Agent", "a1")
            .unwrap()
            .json_attrs(&attrs)
            .unwrap()
            .build()
            .unwrap();
        assert!(entity.attr("provider_id").is_some());
    }

    #[test]
    fn json_to_expr_string() {
        let val = serde_json::json!("hello");
        let expr = json_to_restricted_expr(&val).unwrap();
        // Verify it round-trips through RestrictedExpression
        drop(expr);
    }

    #[test]
    fn json_to_expr_bool() {
        let val = serde_json::json!(true);
        let expr = json_to_restricted_expr(&val).unwrap();
        drop(expr);
    }

    #[test]
    fn json_to_expr_number() {
        let val = serde_json::json!(42);
        let expr = json_to_restricted_expr(&val).unwrap();
        drop(expr);
    }

    #[test]
    fn json_to_expr_array() {
        let val = serde_json::json!(["a", "b", "c"]);
        let expr = json_to_restricted_expr(&val).unwrap();
        drop(expr);
    }

    #[test]
    fn json_to_expr_object() {
        let val = serde_json::json!({"key": "value", "count": 5});
        let expr = json_to_restricted_expr(&val).unwrap();
        drop(expr);
    }

    #[test]
    fn json_to_expr_entity_ref() {
        let val = serde_json::json!({"__entity": {"type": "Label", "id": "Confidential"}});
        let expr = json_to_restricted_expr(&val).unwrap();
        drop(expr);
    }

    #[test]
    fn json_to_expr_null_fails() {
        let val = serde_json::Value::Null;
        assert!(json_to_restricted_expr(&val).is_err());
    }

    #[test]
    fn json_to_expr_float_fails() {
        let val = serde_json::json!(3.15);
        assert!(json_to_restricted_expr(&val).is_err());
    }
}
