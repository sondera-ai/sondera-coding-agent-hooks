//! Simple file-based storage for trajectory ID mappings and agent information.
//!
//! Each Claude Code session has a unique session_id that persists across
//! multiple hook invocations. We map this to a Sondera trajectory_id.
//!
//! We also store registered agent information to avoid re-registering on every invocation.

use crate::Event;
use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// Get the storage directory for claude trajectory mappings
pub fn get_storage_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    let storage_dir = home.join(".sondera");
    fs::create_dir_all(&storage_dir)?;
    Ok(storage_dir)
}

/// Get the path to the trajectory mappings file
fn get_trajectory_file(trajectory_id: &str) -> Result<PathBuf> {
    let trajectories_dir = get_storage_dir()?.join("trajectories");
    fs::create_dir_all(&trajectories_dir)?;
    Ok(trajectories_dir.join(format!("{}.jsonl", trajectory_id)))
}

pub fn write_trajectory_event(event: &Event) -> Result<()> {
    let trajectory_file = get_trajectory_file(&event.trajectory_id)?;
    let json = serde_json::to_string(event).context("Failed to serialize Event")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&trajectory_file)
        .context(format!(
            "Failed to open trajectory file: {}",
            trajectory_file.display()
        ))?;
    writeln!(file, "{}", json).context("Failed to write to trajectory file")?;
    Ok(())
}
