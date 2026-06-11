//! notify-based JSONL tail: the primary live-feed source.
//!
//! Watches the trajectories directory (NonRecursive) for `*.jsonl`
//! appends, reads new bytes from per-file offsets initialized at EOF
//! (history never replays), parses complete lines only (a wake can observe
//! a torn line), and publishes each parsed [`sondera_harness::Event`]
//! through [`super::publish`].
//!
//! Threading: the notify handler runs on the watcher's OWN thread, so the
//! bridge into tokio is `blocking_send` on an mpsc channel — never
//! `.await` there. The watcher itself is MOVED into the long-lived tail
//! task: dropping it silently stops all events.
//!
//! The tail task never panics on I/O or parse errors — every failure is a
//! `warn!` with file path + offset only, NEVER line contents, and the loop
//! continues.

use axum::extract::ws::Utf8Bytes;
use notify::Watcher;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tokio::sync::broadcast;

/// Split `buf` at the LAST `b'\n'`: return the complete lines (lossy
/// UTF-8, trailing `\r` trimmed) and the consumed byte count through that
/// newline. Partial trailing bytes stay unconsumed — incomplete-line means
/// wait for the next wake; invalid-JSON-on-complete-line means warn + skip
/// (`writeln!` may issue multiple syscalls per line, so a wake can observe
/// a torn line).
pub fn split_complete_lines(buf: &[u8]) -> (Vec<String>, usize) {
    match buf.iter().rposition(|&b| b == b'\n') {
        Some(pos) => {
            let consumed = pos + 1;
            let lines = buf[..pos]
                .split(|&b| b == b'\n')
                .map(|line| {
                    String::from_utf8_lossy(line)
                        .trim_end_matches('\r')
                        .to_string()
                })
                .filter(|line| !line.is_empty())
                .collect();
            (lines, consumed)
        }
        None => (Vec::new(), 0),
    }
}

/// Start the notify watcher + tail task. Returns `Err` if the watcher
/// cannot be created or the directory cannot be watched (the Turso-poll
/// fallback trigger); the caller degrades loudly but keeps serving REST.
///
/// On success: existing `*.jsonl` file lengths are snapshotted as initial
/// offsets (EOF — no history replay) and the tail task takes ownership of
/// the watcher.
pub fn spawn_tail(dir: PathBuf, tx: broadcast::Sender<Utf8Bytes>) -> anyhow::Result<()> {
    // Canonicalize so offset keys match the paths notify delivers (macOS
    // FSEvents reports real paths — e.g. /private/var vs the /var symlink).
    let dir = dir.canonicalize().unwrap_or(dir);

    let (bridge_tx, mut rx) = tokio::sync::mpsc::channel::<notify::Event>(1024);
    let mut watcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            // Handler runs on the watcher's OWN thread — blocking_send is
            // the bridge into the runtime (never .await here).
            Ok(event) => {
                let _ = bridge_tx.blocking_send(event);
            }
            Err(err) => tracing::warn!(error = %err, "notify watch error"),
        })?;
    watcher.watch(&dir, notify::RecursiveMode::NonRecursive)?;

    // Snapshot existing *.jsonl lengths as initial offsets (EOF).
    let mut offsets: HashMap<PathBuf, u64> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "jsonl")
                && let Ok(meta) = entry.metadata()
            {
                offsets.insert(path, meta.len());
            }
        }
    }

    tokio::spawn(async move {
        // Take OWNERSHIP of the watcher: dropping it silently stops all
        // events.
        let _watcher = watcher;
        while let Some(event) = rx.recv().await {
            // Any EventKind is just "check for new bytes" — re-reading to
            // EOF makes macOS FSEvents coalescing harmless.
            for path in &event.paths {
                if path.extension().is_some_and(|ext| ext == "jsonl") {
                    process_file(path, &mut offsets, &tx);
                }
            }
        }
        tracing::warn!("JSONL tail bridge closed; live feed stopped");
    });

    Ok(())
}

/// Read new bytes from `path` past the stored offset, publish every
/// complete parsed line, and advance the offset by the consumed count
/// only. All errors warn + return — the tail task never dies; warnings
/// carry file path and offset only, never line contents.
fn process_file(
    path: &Path,
    offsets: &mut HashMap<PathBuf, u64>,
    tx: &broadcast::Sender<Utf8Bytes>,
) {
    // Newly created files start at offset 0 (their full content is new).
    let offset = offsets.entry(path.to_path_buf()).or_insert(0);

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            // Removed/renamed between wake and open — not fatal.
            tracing::warn!(file = %path.display(), error = %err, "tail: cannot open file");
            return;
        }
    };
    let file_len = match file.metadata() {
        Ok(meta) => meta.len(),
        Err(err) => {
            tracing::warn!(file = %path.display(), error = %err, "tail: cannot stat file");
            return;
        }
    };

    // Defensive truncation check: append-only files shouldn't shrink;
    // don't wedge if one does.
    if file_len < *offset {
        tracing::warn!(
            file = %path.display(),
            offset = *offset,
            file_len,
            "tail: file shrank; resetting offset"
        );
        *offset = 0;
    }
    if file_len == *offset {
        return; // no new bytes
    }

    if let Err(err) = file.seek(SeekFrom::Start(*offset)) {
        tracing::warn!(file = %path.display(), offset = *offset, error = %err, "tail: seek failed");
        return;
    }
    let mut buf = Vec::new();
    if let Err(err) = file.read_to_end(&mut buf) {
        tracing::warn!(file = %path.display(), offset = *offset, error = %err, "tail: read failed");
        return;
    }

    let (lines, consumed) = split_complete_lines(&buf);
    for line in lines {
        match serde_json::from_str::<sondera_harness::Event>(&line) {
            Ok(event) => super::publish(tx, &event),
            Err(err) => {
                // File path and offset only — NEVER line contents.
                tracing::warn!(
                    file = %path.display(),
                    offset = *offset,
                    error = %err,
                    "tail: malformed JSONL line skipped"
                );
            }
        }
    }
    // Advance past consumed complete lines only; a partial trailing line
    // is re-read on the next wake.
    *offset += consumed as u64;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_all_complete_lines() {
        let (lines, consumed) = split_complete_lines(b"a\nb\n");
        assert_eq!(lines, vec!["a", "b"]);
        assert_eq!(consumed, 4, "consumes through the final newline");
    }

    #[test]
    fn holds_partial_trailing_line() {
        let (lines, consumed) = split_complete_lines(b"a\npartial");
        assert_eq!(lines, vec!["a"]);
        assert_eq!(
            consumed, 2,
            "partial trailing bytes stay unconsumed (Pitfall 7)"
        );
    }

    #[test]
    fn no_newline_consumes_nothing() {
        let (lines, consumed) = split_complete_lines(b"partial-only");
        assert!(lines.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn empty_buffer_yields_nothing() {
        let (lines, consumed) = split_complete_lines(b"");
        assert!(lines.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn trailing_cr_trimmed() {
        let (lines, consumed) = split_complete_lines(b"a\r\nb\r\n");
        assert_eq!(lines, vec!["a", "b"], "CRLF lines tolerated via trim");
        assert_eq!(consumed, 6);
    }
}
