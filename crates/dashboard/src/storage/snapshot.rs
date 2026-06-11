//! Snapshot-copy isolation for the live trajectories database.
//!
//! turso 0.4.4 takes a non-blocking exclusive fcntl lock on every database
//! file it opens, and multi-process access is unsupported upstream. The
//! dashboard therefore NEVER opens the live `trajectories.db`: a naive open
//! would either fail under a running harness or — worse — take the lock
//! first and block harness startup, putting the dashboard in the
//! adjudication path by side effect. Instead the db file and its `-wal`
//! sidecar are copied to a dashboard-private directory and the COPY is
//! opened.
//!
//! The guarantee is structural, carried by the type system: only a
//! [`CopyPath`] can be opened, and a [`CopyPath`] can only be minted by
//! [`copy_live_db`], which copies first. In-process tests cannot prove
//! cross-process lock safety (turso dedupes same-process opens by canonical
//! path), so this code-structure assertion IS the proof.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic suffix so refreshes within this process never reuse a copy
/// filename: turso dedupes same-process opens by canonical path, so a fresh
/// name guarantees a genuinely fresh open of the new copy. Combined with
/// the pid, concurrent dashboard instances never fight over the copy's own
/// fcntl lock.
static COPY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A path guaranteed to point at a dashboard-private COPY of the
/// trajectories database — never the live file.
///
/// The field is private and the only constructor is [`copy_live_db`]; the
/// live path therefore structurally cannot reach a turso `Builder`.
pub(crate) struct CopyPath(PathBuf);

impl CopyPath {
    /// Read access to the copied db path (for bookkeeping/cleanup only —
    /// a `CopyPath` can never be constructed from an arbitrary path).
    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}

/// The `-wal` sidecar path for a database file (verified turso naming:
/// `trajectories.db` -> `trajectories.db-wal`).
pub(crate) fn wal_path(db: &Path) -> PathBuf {
    let mut s = db.as_os_str().to_os_string();
    s.push("-wal");
    PathBuf::from(s)
}

/// Copy the live database (and, if present, its WAL sidecar) into
/// `copy_dir` under a process-unique filename pair, returning the only
/// token [`open_snapshot`] accepts.
///
/// Creating the cache directory is fine — only the database itself must
/// never be created, not the dashboard's own cache dir. The caller has
/// already checked that the live file exists.
pub(crate) fn copy_live_db(live: &Path, copy_dir: &Path) -> Result<CopyPath> {
    std::fs::create_dir_all(copy_dir)
        .with_context(|| format!("failed to create copy dir {}", copy_dir.display()))?;

    let n = COPY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let copy_db = copy_dir.join(format!("snapshot-{}-{}.db", std::process::id(), n));

    std::fs::copy(live, &copy_db)
        .with_context(|| format!("failed to copy live db to {}", copy_db.display()))?;

    let live_wal = wal_path(live);
    if live_wal.exists() {
        let copy_wal = wal_path(&copy_db);
        if let Err(e) = std::fs::copy(&live_wal, &copy_wal) {
            // A failed WAL copy would orphan the already-copied .db (no
            // Snapshot is ever constructed to own it) — remove it before
            // propagating the error.
            let _ = std::fs::remove_file(&copy_db);
            return Err(e)
                .with_context(|| format!("failed to copy wal sidecar to {}", copy_wal.display()));
        }
    }

    Ok(CopyPath(copy_db))
}

/// Open a snapshot copy and harden its connection.
///
/// This is the SOLE turso open call site in the crate; the connection is
/// made read-only via `PRAGMA query_only = true` immediately after connect
/// (belt-and-suspenders read-only enforcement). The pragma is a
/// per-connection flag, so it lives in this single constructor path and
/// connections are created nowhere else.
pub(crate) async fn open_snapshot(copy: CopyPath) -> Result<(turso::Database, turso::Connection)> {
    let path = copy.as_path().to_string_lossy();
    let db = turso::Builder::new_local(&path)
        .build()
        .await
        .context("failed to open snapshot copy")?;
    let conn = db.connect().context("failed to connect to snapshot copy")?;
    conn.execute("PRAGMA query_only = true", ())
        .await
        .context("failed to set query_only on the snapshot connection")?;
    Ok((db, conn))
}
