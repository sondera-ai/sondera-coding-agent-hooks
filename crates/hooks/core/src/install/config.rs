//! Backup / read / write of a provider's JSON hook-config file.
//!
//! Every provider installer edits a JSON document in place: back the file up,
//! read it (or start from an empty object when it does not exist yet), splice
//! our hooks in or out, and write it back pretty-printed. The providers differ
//! only in *where* the file lives and *what* they splice — so that surrounding
//! I/O lives here once instead of being re-derived, subtly differently, in each
//! installer.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::{HookError, HookResultExt as _, Result};

/// Timestamp used to name backup files.
///
/// Millisecond precision, so two installs within the same second do not
/// collide and silently discard the first backup.
#[must_use]
pub fn backup_timestamp() -> String {
    chrono::Local::now().format("%Y%m%d_%H%M%S_%3f").to_string()
}

/// Copy `path` to a timestamped sibling before it is rewritten.
///
/// Returns `Ok(None)` when there is nothing to back up because the config does
/// not exist yet.
pub fn backup(path: &Path) -> Result<Option<PathBuf>> {
    backup_at(path, &backup_timestamp())
}

/// [`backup`] with an explicit timestamp, so tests can assert on the produced
/// path without racing the clock.
pub fn backup_at(path: &Path, timestamp: &str) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }

    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("json");
    let backup_path = path.with_extension(format!("backup.{timestamp}.{extension}"));

    fs::copy(path, &backup_path)
        .with_context(|| format!("failed to back up {} before rewriting it", path.display()))?;
    Ok(Some(backup_path))
}

/// How one provider's config document is encoded on disk.
///
/// Most hosts read JSON, but not all — Hermes keeps its config in YAML and VS
/// Code accepts comments and trailing commas in its settings. The *flow* around
/// the document is identical in every case, so the encoding is supplied by the
/// provider crate that knows it rather than pulled into this one: a decoder for
/// a format only one provider speaks does not belong in the shared crate, but
/// the backup/read/splice/write flow around it does.
pub trait ConfigDocument {
    /// Decode the document at `path` as an object, or an empty object when it
    /// does not exist yet. See [`read_object`] for the JSON contract every
    /// implementation should follow.
    fn read(&self, path: &Path) -> Result<Map<String, Value>>;

    /// Encode `config` to `path`, creating parent directories.
    fn write(&self, path: &Path, config: &Map<String, Value>) -> Result<()>;
}

/// The JSON document format, used by every provider that has not said
/// otherwise.
#[derive(Debug, Clone, Copy, Default)]
pub struct Json;

impl ConfigDocument for Json {
    fn read(&self, path: &Path) -> Result<Map<String, Value>> {
        read_object(path)
    }

    fn write(&self, path: &Path, config: &Map<String, Value>) -> Result<()> {
        write_object(path, config)
    }
}

/// Read the config at `path` as a JSON object.
///
/// A missing or empty file reads as an empty object — "not installed yet" is a
/// normal starting state, not an error. A file that parses as valid JSON but is
/// not an object *is* an error: overwriting it would destroy user data.
pub fn read_object(path: &Path) -> Result<Map<String, Value>> {
    let Some(content) = read_to_object_source(path)? else {
        return Ok(Map::new());
    };

    match serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {} as JSON", path.display()))?
    {
        Value::Object(map) => Ok(map),
        _ => Err(not_an_object(path)),
    }
}

/// The text of a config document, or `None` when there is nothing to decode
/// because the file is absent or empty.
///
/// Shared by [`read_object`] and the provider-side [`ConfigDocument`]
/// implementations, so "not installed yet" reads the same way in every format.
pub fn read_to_object_source(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(Some(content).filter(|content| !content.trim().is_empty()))
}

/// The error for a config document whose root is not an object.
#[must_use]
pub fn not_an_object(path: &Path) -> HookError {
    HookError::message(format!("{} is not an object", path.display()))
}

/// Write `config` to `path` pretty-printed, creating parent directories.
pub fn write_object(path: &Path, config: &Map<String, Value>) -> Result<()> {
    // Serialized directly rather than through `Value::Object(config.clone())`:
    // `config` is the host's whole settings document, not just our subtree.
    write_value(path, config)
}

/// [`write_object`] for a config whose root is any serializable value.
pub fn write_value(path: &Path, config: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let content =
        serde_json::to_string_pretty(config).context("failed to serialize hook config")?;
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_config_reads_as_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            read_object(&dir.path().join("absent.json"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn empty_config_reads_as_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.json");
        fs::write(&path, "   \n").unwrap();
        assert!(read_object(&path).unwrap().is_empty());
    }

    #[test]
    fn non_object_config_is_an_error_rather_than_silently_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("array.json");
        fs::write(&path, "[1, 2, 3]").unwrap();
        assert!(read_object(&path).is_err());
    }

    #[test]
    fn write_then_read_round_trips_through_nested_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deeper").join("hooks.json");

        let mut config = Map::new();
        config.insert("hooks".into(), json!({"PreToolUse": []}));
        write_object(&path, &config).unwrap();

        assert_eq!(read_object(&path).unwrap(), config);
    }

    #[test]
    fn backup_of_a_missing_config_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(backup(&dir.path().join("absent.json")).unwrap(), None);
    }

    #[test]
    fn backup_copies_the_config_and_keeps_its_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, r#"{"hooks":{}}"#).unwrap();

        let backup_path = backup_at(&path, "20260731_120000_000").unwrap().unwrap();

        assert_eq!(
            backup_path.file_name().unwrap(),
            "settings.backup.20260731_120000_000.json"
        );
        assert_eq!(fs::read_to_string(&backup_path).unwrap(), r#"{"hooks":{}}"#);
        assert!(path.exists(), "the original must be left in place");
    }

    #[test]
    fn backups_within_the_same_second_do_not_collide() {
        // Second-granularity naming silently discarded the earlier backup when
        // an install and an uninstall ran back to back.
        let first = backup_timestamp();
        let second = backup_timestamp();
        assert_eq!(first.len(), second.len());
        assert_eq!(first.matches('_').count(), 2, "expected millisecond suffix");
    }
}
