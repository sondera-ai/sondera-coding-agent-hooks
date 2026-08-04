//! Parse Claude Code JSONL transcript files to extract assistant messages
//! as trajectory events with their original timestamps.
//!
//! Uses byte-offset cursors per session to avoid re-sending messages
//! across multiple stop hook invocations.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sondera_hooks::error::Result;
use std::borrow::Cow;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

use sondera_harness_client::{Observation, Prompt, PromptRole, Thought, TrajectoryEvent};
use sondera_hooks::content::{ContentBlock, ContentBlocks};

use crate::truncate::{MAX_EVENT_TEXT_BYTES, truncate_event_text};

const CURSOR_RETENTION: Duration = Duration::from_secs(60 * 60 * 24 * 30);
const CURSOR_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);
const CURSOR_PRUNE_MARKER: &str = ".last_prune";

// ============================================================================
// JSONL deserialization types
// ============================================================================

/// A single line from Claude Code's JSONL transcript.
#[derive(Debug, Deserialize)]
struct TranscriptLine {
    #[serde(rename = "type")]
    line_type: String,
    timestamp: DateTime<Utc>,
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    message: Option<MessagePayload>,
}

/// The `message` field from an assistant transcript line.
#[derive(Debug, Deserialize)]
struct MessagePayload {
    role: String,
    #[serde(default)]
    content: ContentBlocks,
}

// ============================================================================
// Extracted event
// ============================================================================

/// A trajectory event extracted from a transcript line, preserving its original timestamp.
pub struct ExtractedEvent {
    pub timestamp: DateTime<Utc>,
    pub event: TrajectoryEvent,
    pub uuid: String,
    pub cursor_after_line: u64,
}

fn line_has_extractable_assistant_event(line: &TranscriptLine) -> bool {
    line.line_type == "assistant"
        && line.message.as_ref().is_some_and(|message| {
            message.role == "assistant"
                && message.content.0.iter().any(|block| match block {
                    ContentBlock::Text { text } => !text.trim().is_empty(),
                    ContentBlock::Thinking { thinking } => !thinking.trim().is_empty(),
                    _ => false,
                })
        })
}

// ============================================================================
// Transcript parsing
// ============================================================================

/// Parse a JSONL transcript file starting from `cursor` byte offset.
///
/// Returns extracted assistant message events (text and thinking blocks)
/// and the new byte offset for cursor tracking.
///
/// Tool use blocks are skipped since they are already captured by
/// PreToolUse/PostToolUse hooks.
pub fn parse_transcript(transcript_path: &str, cursor: u64) -> Result<(Vec<ExtractedEvent>, u64)> {
    let file = std::fs::File::open(transcript_path)?;
    let file_len = file.metadata()?.len();

    if cursor >= file_len {
        return Ok((Vec::new(), cursor));
    }

    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(cursor))?;

    let mut events = Vec::new();
    let mut new_cursor = cursor;
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        let bytes_read = reader.read_line(&mut line_buf)?;
        if bytes_read == 0 {
            break;
        }
        new_cursor += bytes_read as u64;

        let trimmed = line_buf.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Best-effort: skip malformed lines
        let line: TranscriptLine = match serde_json::from_str(trimmed) {
            Ok(l) => l,
            Err(_) => continue,
        };

        if !line_has_extractable_assistant_event(&line) {
            continue;
        }

        let Some(message) = line.message else {
            continue;
        };

        for block in message.content.0 {
            match block {
                ContentBlock::Text { ref text } if !text.trim().is_empty() => {
                    let body = truncate_event_text(text, MAX_EVENT_TEXT_BYTES);
                    if matches!(body, Cow::Owned(_)) {
                        warn!(
                            original_bytes = text.len(),
                            cap_bytes = MAX_EVENT_TEXT_BYTES,
                            uuid = %line.uuid,
                            "Truncated assistant text block to fit gRPC message limit"
                        );
                    }
                    events.push(ExtractedEvent {
                        timestamp: line.timestamp,
                        event: TrajectoryEvent::Observation(Observation::Prompt(
                            Prompt::assistant(body.as_ref()),
                        )),
                        uuid: line.uuid.clone(),
                        cursor_after_line: new_cursor,
                    });
                }
                ContentBlock::Thinking { ref thinking } if !thinking.trim().is_empty() => {
                    let body = truncate_event_text(thinking, MAX_EVENT_TEXT_BYTES);
                    if matches!(body, Cow::Owned(_)) {
                        warn!(
                            original_bytes = thinking.len(),
                            cap_bytes = MAX_EVENT_TEXT_BYTES,
                            uuid = %line.uuid,
                            "Truncated assistant thinking block to fit gRPC message limit"
                        );
                    }
                    events.push(ExtractedEvent {
                        timestamp: line.timestamp,
                        event: TrajectoryEvent::Observation(Observation::Thought(Thought::new(
                            body.as_ref(),
                        ))),
                        uuid: line.uuid.clone(),
                        cursor_after_line: new_cursor,
                    });
                }
                // Tool use blocks: already captured by PreToolUse/PostToolUse hooks
                _ => {}
            }
        }
    }

    Ok((events, new_cursor))
}

/// The newest assistant *text* reply visible when parsing forward from
/// `cursor`, or `None` if no assistant text block is present past the cursor
/// yet.
///
/// The Stop hook uses this to decide whether the current turn's final message
/// has actually been written to the transcript. Only `text` blocks count: a
/// turn whose `thinking` line has been flushed but whose `text` line has not is
/// deliberately reported as "not present yet", because the reply we wait for is
/// the assistant's final text, not its thoughts.
///
/// The returned text has already passed through `parse_transcript`'s
/// `truncate_event_text` cap, so callers comparing it against the Stop
/// payload's `last_assistant_message` must truncate that value the same way
/// before comparing — otherwise a reply large enough to be capped would never
/// match itself.
pub fn newest_assistant_reply(transcript_path: &str, cursor: u64) -> Result<Option<String>> {
    let (events, _) = parse_transcript(transcript_path, cursor)?;
    Ok(events
        .into_iter()
        .rev()
        .find_map(|extracted| match extracted.event {
            TrajectoryEvent::Observation(Observation::Prompt(prompt))
                if prompt.role == PromptRole::Assistant =>
            {
                Some(prompt.content)
            }
            _ => None,
        }))
}

/// Return the byte offset for the start of the last assistant *turn* — the
/// first JSONL line of the contiguous run of `assistant` lines that contains
/// the final extractable assistant event.
///
/// A single assistant response can span several JSONL lines (e.g. a `thinking`
/// line followed by a separate `text` line, with `progress`/system lines
/// interleaved). Anchoring on the start of the run — rather than the last line
/// alone — keeps the turn's thoughts when the Stop cursor is seeded here, so a
/// `thinking` line that precedes the final `text` line is not skipped.
///
/// Only `user` lines (real prompts and `tool_result` payloads, both serialized
/// as `type: "user"`) mark a turn boundary and break the run; assistant lines
/// extend it and any other meta line (`progress`, `system`, malformed, empty)
/// is transparent.
pub fn last_assistant_turn_start(transcript_path: &str) -> Result<Option<u64>> {
    let file = std::fs::File::open(transcript_path)?;
    let mut reader = BufReader::new(file);
    let mut line_buf = String::new();
    let mut cursor = 0_u64;
    let mut run_start: Option<u64> = None;
    let mut last_turn_start: Option<u64> = None;

    loop {
        line_buf.clear();
        let line_start = cursor;
        let bytes_read = reader.read_line(&mut line_buf)?;
        if bytes_read == 0 {
            break;
        }
        cursor += bytes_read as u64;

        let trimmed = line_buf.trim();
        if trimmed.is_empty() {
            continue;
        }

        let line: TranscriptLine = match serde_json::from_str(trimmed) {
            Ok(line) => line,
            Err(_) => continue,
        };

        if line.line_type == "assistant" {
            // Open the run on the first assistant line; later lines of the same
            // response (thinking, text, tool_use) extend it.
            run_start.get_or_insert(line_start);
            // Anchor the turn only on a line that yields a trajectory event, so
            // a trailing tool_use-only line never moves the seed past the text.
            if line_has_extractable_assistant_event(&line) {
                last_turn_start = run_start;
            }
        } else if line.line_type == "user" {
            // A user prompt or tool_result closes the current assistant turn.
            run_start = None;
        }
        // Other line types (progress, system, …) are transparent: they neither
        // open nor break a run, so they can't split a turn's thinking from its
        // text.
    }

    Ok(last_turn_start)
}

// ============================================================================
// Cursor management
// ============================================================================

/// Get the cursor file path for a session.
fn cursor_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        sondera_hooks::error::HookError::message("Could not determine home directory")
    })?;
    let dir = home
        .join(".sondera")
        .join("claude")
        .join("transcript_cursors");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Get the cursor file path for a session.
fn cursor_path(session_id: &str) -> Result<PathBuf> {
    Ok(cursor_dir()?.join(format!("{session_id}.cursor")))
}

fn retry_cursor_path(session_id: &str) -> Result<PathBuf> {
    Ok(cursor_dir()?.join(format!("{session_id}.retry.cursor")))
}

fn prune_stale_cursor_files(dir: &Path) {
    let Some(cutoff) = SystemTime::now().checked_sub(CURSOR_RETENTION) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("cursor") {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata
            .modified()
            .ok()
            .is_some_and(|modified| modified < cutoff)
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn maybe_prune_stale_cursor_files(dir: &Path) {
    let marker_path = dir.join(CURSOR_PRUNE_MARKER);
    let marker_age = std::fs::metadata(&marker_path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok());
    let should_prune = match marker_age {
        Some(age) => age >= CURSOR_PRUNE_INTERVAL,
        None => true,
    };

    if !should_prune {
        return;
    }

    prune_stale_cursor_files(dir);
    let _ = std::fs::write(marker_path, b"");
}

fn temporary_cursor_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .unwrap_or("cursor");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    path.with_file_name(format!("{file_name}.tmp.{}.{unique}", std::process::id()))
}

/// Read the byte-offset cursor for a session. Returns 0 if no cursor exists.
pub fn read_cursor(session_id: &str) -> u64 {
    read_cursor_if_present(session_id).unwrap_or(0)
}

fn read_offset_if_present(session_id: &str, path: Result<PathBuf>, label: &str) -> Option<u64> {
    let path = match path {
        Ok(path) => path,
        Err(err) => {
            warn!(session_id, "Could not resolve {label} path: {err}");
            return None;
        }
    };
    match std::fs::read_to_string(&path) {
        Ok(contents) => match contents.trim().parse::<u64>() {
            Ok(offset) => Some(offset),
            Err(err) => {
                warn!(
                    session_id,
                    cursor_path = %path.display(),
                    "Ignoring invalid {label}: {err}"
                );
                None
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            warn!(
                session_id,
                cursor_path = %path.display(),
                "Could not read {label}: {err}"
            );
            None
        }
    }
}

/// Read the byte-offset cursor for a session if a cursor file exists.
pub fn read_cursor_if_present(session_id: &str) -> Option<u64> {
    read_offset_if_present(
        session_id,
        cursor_path(session_id),
        "Claude transcript cursor",
    )
}

pub fn read_retry_cursor_if_present(session_id: &str) -> Option<u64> {
    read_offset_if_present(
        session_id,
        retry_cursor_path(session_id),
        "Claude transcript retry cursor",
    )
}

/// Read the retry cursor for `session_id`, but only if it still points inside a
/// transcript of `transcript_len` bytes. A retry cursor at or past EOF is stale
/// (the tail it marked has already been consumed), so it's treated as absent.
pub fn read_retry_cursor_if_active(session_id: &str, transcript_len: u64) -> Option<u64> {
    read_retry_cursor_if_present(session_id).filter(|cursor| *cursor < transcript_len)
}

fn write_offset(path: PathBuf, offset: u64) -> Result<()> {
    let temporary_path = temporary_cursor_path(&path);

    std::fs::write(&temporary_path, offset.to_string())?;
    if let Err(err) = std::fs::rename(&temporary_path, &path) {
        let _ = std::fs::remove_file(&temporary_path);
        return Err(err.into());
    }

    if let Some(dir) = path.parent() {
        maybe_prune_stale_cursor_files(dir);
    }
    Ok(())
}

/// Write the byte-offset cursor for a session.
pub fn write_cursor(session_id: &str, offset: u64) -> Result<()> {
    write_offset(cursor_path(session_id)?, offset)
}

pub fn write_retry_cursor(session_id: &str, offset: u64) -> Result<()> {
    write_offset(retry_cursor_path(session_id)?, offset)
}

pub fn remove_retry_cursor(session_id: &str) {
    if let Ok(path) = retry_cursor_path(session_id) {
        let _ = std::fs::remove_file(path);
    }
}

/// Remove the cursor file for a session (called on session end).
pub fn remove_cursor(session_id: &str) {
    if let Ok(path) = cursor_path(session_id) {
        let _ = std::fs::remove_file(path);
    }
    remove_retry_cursor(session_id);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::truncate::TRUNCATION_MARKER;
    use std::io::Write;

    fn write_jsonl(dir: &std::path::Path, lines: &[&str]) -> String {
        let path = dir.join("transcript.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        for line in lines {
            writeln!(f, "{}", line).unwrap();
        }
        path.to_string_lossy().into_owned()
    }

    fn assistant_text_line(ts: &str, uuid: &str, text: &str) -> String {
        format!(
            r#"{{"type":"assistant","timestamp":"{ts}","uuid":"{uuid}","message":{{"role":"assistant","content":[{{"type":"text","text":"{text}"}}]}}}}"#
        )
    }

    fn assistant_thinking_line(ts: &str, uuid: &str, thinking: &str) -> String {
        format!(
            r#"{{"type":"assistant","timestamp":"{ts}","uuid":"{uuid}","message":{{"role":"assistant","content":[{{"type":"thinking","thinking":"{thinking}"}}]}}}}"#
        )
    }

    fn assistant_tool_use_line(ts: &str, uuid: &str) -> String {
        format!(
            r#"{{"type":"assistant","timestamp":"{ts}","uuid":"{uuid}","message":{{"role":"assistant","content":[{{"type":"tool_use","id":"toolu_1","name":"Bash","input":{{"command":"ls"}}}}]}}}}"#
        )
    }

    fn user_line(ts: &str, uuid: &str) -> String {
        format!(
            r#"{{"type":"user","timestamp":"{ts}","uuid":"{uuid}","message":{{"role":"user","content":"hello"}}}}"#
        )
    }

    fn progress_line(ts: &str) -> String {
        format!(r#"{{"type":"progress","timestamp":"{ts}","data":{{"type":"hook_progress"}}}}"#)
    }

    #[test]
    fn test_parse_assistant_text_block() {
        let dir = tempfile::tempdir().unwrap();
        let line = assistant_text_line("2026-02-11T19:08:42.922Z", "uuid-1", "Hello world");
        let path = write_jsonl(dir.path(), &[&line]);

        let (events, _cursor) = parse_transcript(&path, 0).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0].event {
            TrajectoryEvent::Observation(Observation::Prompt(p)) => {
                assert_eq!(p.content, "Hello world");
                assert_eq!(p.role, sondera_harness_client::PromptRole::Assistant);
            }
            other => panic!("Expected Prompt::assistant, got: {:?}", other),
        }
    }

    #[test]
    fn test_parse_assistant_thinking_block() {
        let dir = tempfile::tempdir().unwrap();
        let line = assistant_thinking_line("2026-02-11T19:08:43.000Z", "uuid-2", "Let me think...");
        let path = write_jsonl(dir.path(), &[&line]);

        let (events, _) = parse_transcript(&path, 0).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0].event {
            TrajectoryEvent::Observation(Observation::Thought(t)) => {
                assert_eq!(t.thought, "Let me think...");
            }
            other => panic!("Expected Thought, got: {:?}", other),
        }
    }

    #[test]
    fn test_parse_skips_tool_use_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let line = assistant_tool_use_line("2026-02-11T19:08:44.000Z", "uuid-3");
        let path = write_jsonl(dir.path(), &[&line]);

        let (events, _) = parse_transcript(&path, 0).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_mixed_content() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"type":"assistant","timestamp":"2026-02-11T19:08:45.000Z","uuid":"uuid-4","message":{"role":"assistant","content":[{"type":"thinking","thinking":"reasoning here"},{"type":"text","text":"response text"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls"}}]}}"#.to_string();
        let path = write_jsonl(dir.path(), &[&line]);

        let (events, _) = parse_transcript(&path, 0).unwrap();
        assert_eq!(events.len(), 2);
        // Thinking comes first in content array
        assert!(matches!(
            &events[0].event,
            TrajectoryEvent::Observation(Observation::Thought(_))
        ));
        assert!(matches!(
            &events[1].event,
            TrajectoryEvent::Observation(Observation::Prompt(_))
        ));
    }

    #[test]
    fn test_parse_skips_non_assistant_lines() {
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            user_line("2026-02-11T19:08:40.000Z", "uuid-u"),
            progress_line("2026-02-11T19:08:41.000Z"),
            assistant_text_line("2026-02-11T19:08:42.000Z", "uuid-a", "only this one"),
        ];
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let path = write_jsonl(dir.path(), &line_refs);

        let (events, _) = parse_transcript(&path, 0).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_cursor_deduplication() {
        let dir = tempfile::tempdir().unwrap();
        let path_str = dir.path().join("transcript.jsonl");
        let path = path_str.to_string_lossy().into_owned();

        // Write first line
        {
            let mut f = std::fs::File::create(&path_str).unwrap();
            writeln!(
                f,
                "{}",
                assistant_text_line("2026-02-11T19:08:42.000Z", "uuid-1", "first")
            )
            .unwrap();
        }

        let (events, cursor) = parse_transcript(&path, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert!(cursor > 0);

        // Append second line
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path_str)
                .unwrap();
            writeln!(
                f,
                "{}",
                assistant_text_line("2026-02-11T19:08:43.000Z", "uuid-2", "second")
            )
            .unwrap();
        }

        // Parse from cursor — should only get second line
        let (events, _) = parse_transcript(&path, cursor).unwrap();
        assert_eq!(events.len(), 1);
        match &events[0].event {
            TrajectoryEvent::Observation(Observation::Prompt(p)) => {
                assert_eq!(p.content, "second");
            }
            other => panic!("Expected 'second', got: {:?}", other),
        }
    }

    #[test]
    fn test_parse_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_jsonl(dir.path(), &[]);

        let (events, cursor) = parse_transcript(&path, 0).unwrap();
        assert!(events.is_empty());
        assert_eq!(cursor, 0);
    }

    #[test]
    fn test_parse_malformed_lines_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let good = assistant_text_line("2026-02-11T19:08:42.000Z", "uuid-1", "good line");
        let path = write_jsonl(dir.path(), &["not valid json", &good, "{bad: json}"]);

        let (events, _) = parse_transcript(&path, 0).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_timestamp_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let line = assistant_text_line("2026-02-11T19:08:42.922Z", "uuid-1", "hello");
        let path = write_jsonl(dir.path(), &[&line]);

        let (events, _) = parse_transcript(&path, 0).unwrap();
        assert_eq!(events.len(), 1);
        let expected: DateTime<Utc> = "2026-02-11T19:08:42.922Z".parse().unwrap();
        assert_eq!(events[0].timestamp, expected);
    }

    #[test]
    fn test_cursor_read_write_roundtrip() {
        // Use a unique session ID to avoid conflicts with other tests
        let session_id = format!(
            "test-cursor-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        write_cursor(&session_id, 12345).unwrap();
        assert_eq!(read_cursor(&session_id), 12345);
        remove_cursor(&session_id);
        assert_eq!(read_cursor(&session_id), 0);
    }

    #[test]
    fn test_parse_truncates_oversize_text_block() {
        let dir = tempfile::tempdir().unwrap();
        let big = "a".repeat(MAX_EVENT_TEXT_BYTES + 1_024);
        let line = assistant_text_line("2026-02-11T19:08:42.000Z", "uuid-big", &big);
        let path = write_jsonl(dir.path(), &[&line]);
        // `write_jsonl` appends a trailing newline; the cursor must track the
        // raw JSONL byte length so the next invocation seeks past the entire
        // line, not past the truncated `p.content`. A regression that
        // accidentally advanced the cursor by the truncated content length
        // would cause the next read to start mid-line and silently drop
        // events — pin it here.
        let raw_line_bytes = line.len() as u64 + 1;

        let (events, cursor) = parse_transcript(&path, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            cursor, raw_line_bytes,
            "cursor must advance by raw JSONL bytes, not by truncated content length"
        );
        match &events[0].event {
            TrajectoryEvent::Observation(Observation::Prompt(p)) => {
                assert!(p.content.len() < big.len());
                assert!(p.content.ends_with(TRUNCATION_MARKER));
            }
            other => panic!("Expected Prompt::assistant, got: {:?}", other),
        }
    }

    #[test]
    fn test_skips_empty_text_blocks() {
        let dir = tempfile::tempdir().unwrap();
        // Text block with whitespace-only content
        let line = r#"{"type":"assistant","timestamp":"2026-02-11T19:08:42.000Z","uuid":"uuid-1","message":{"role":"assistant","content":[{"type":"text","text":"\n\n"}]}}"#.to_string();
        let path = write_jsonl(dir.path(), &[&line]);

        let (events, _) = parse_transcript(&path, 0).unwrap();
        assert!(events.is_empty());
    }

    /// Byte offset of `lines[idx]` once written by `write_jsonl` (each line gets
    /// a trailing `\n`).
    fn line_offset(lines: &[String], idx: usize) -> u64 {
        lines[..idx].iter().map(|l| l.len() as u64 + 1).sum()
    }

    #[test]
    fn turn_start_includes_thinking_line_before_text() {
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            user_line("2026-02-11T19:08:40.000Z", "uuid-u"),
            assistant_thinking_line("2026-02-11T19:08:41.000Z", "uuid-t", "reasoning"),
            assistant_text_line("2026-02-11T19:08:42.000Z", "uuid-a", "final answer"),
        ];
        let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let path = write_jsonl(dir.path(), &refs);

        // The seed must land on the thinking line, not the trailing text line,
        // so the turn's thoughts survive.
        let start = last_assistant_turn_start(&path).unwrap();
        assert_eq!(start, Some(line_offset(&lines, 1)));

        // Parsing from the seed recovers both the thought and the assistant text.
        let (events, _) = parse_transcript(&path, start.unwrap()).unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[0].event,
            TrajectoryEvent::Observation(Observation::Thought(_))
        ));
        assert!(matches!(
            &events[1].event,
            TrajectoryEvent::Observation(Observation::Prompt(_))
        ));
    }

    #[test]
    fn turn_start_breaks_run_on_user_line() {
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            assistant_thinking_line("2026-02-11T19:08:40.000Z", "uuid-t0", "old reasoning"),
            assistant_text_line("2026-02-11T19:08:41.000Z", "uuid-a0", "old answer"),
            user_line("2026-02-11T19:08:42.000Z", "uuid-u"),
            assistant_thinking_line("2026-02-11T19:08:43.000Z", "uuid-t1", "new reasoning"),
            assistant_text_line("2026-02-11T19:08:44.000Z", "uuid-a1", "new answer"),
        ];
        let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let path = write_jsonl(dir.path(), &refs);

        // Only the final turn (after the user line) is seeded; the prior turn is
        // excluded so Stop never replays history.
        let start = last_assistant_turn_start(&path).unwrap();
        assert_eq!(start, Some(line_offset(&lines, 3)));
    }

    #[test]
    fn turn_start_is_transparent_to_interleaved_progress_lines() {
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            assistant_thinking_line("2026-02-11T19:08:41.000Z", "uuid-t", "reasoning"),
            progress_line("2026-02-11T19:08:41.500Z"),
            assistant_text_line("2026-02-11T19:08:42.000Z", "uuid-a", "final answer"),
        ];
        let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let path = write_jsonl(dir.path(), &refs);

        // A progress line between thinking and text must not split the turn.
        let start = last_assistant_turn_start(&path).unwrap();
        assert_eq!(start, Some(line_offset(&lines, 0)));
    }

    #[test]
    fn turn_start_ignores_trailing_tool_use_only_line() {
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            assistant_thinking_line("2026-02-11T19:08:41.000Z", "uuid-t", "reasoning"),
            assistant_text_line("2026-02-11T19:08:42.000Z", "uuid-a", "final answer"),
            assistant_tool_use_line("2026-02-11T19:08:43.000Z", "uuid-tool"),
        ];
        let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let path = write_jsonl(dir.path(), &refs);

        // The trailing tool_use-only line shares the run, so the anchor stays at
        // the thinking line — the whole turn is captured.
        let start = last_assistant_turn_start(&path).unwrap();
        assert_eq!(start, Some(line_offset(&lines, 0)));
    }

    #[test]
    fn turn_start_none_without_assistant_events() {
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            user_line("2026-02-11T19:08:40.000Z", "uuid-u"),
            progress_line("2026-02-11T19:08:41.000Z"),
        ];
        let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let path = write_jsonl(dir.path(), &refs);

        assert_eq!(last_assistant_turn_start(&path).unwrap(), None);
    }

    #[test]
    fn newest_reply_returns_last_assistant_text() {
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            assistant_text_line("2026-02-11T19:08:41.000Z", "uuid-1", "first reply"),
            user_line("2026-02-11T19:08:42.000Z", "uuid-u"),
            assistant_text_line("2026-02-11T19:08:43.000Z", "uuid-2", "second reply"),
        ];
        let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let path = write_jsonl(dir.path(), &refs);

        assert_eq!(
            newest_assistant_reply(&path, 0).unwrap(),
            Some("second reply".to_string())
        );
    }

    #[test]
    fn newest_reply_none_when_only_thinking_present() {
        // A turn whose thinking line is written but whose text line is not must
        // read as "not caught up" — only assistant *text* counts as a reply.
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            user_line("2026-02-11T19:08:41.000Z", "uuid-u"),
            assistant_thinking_line("2026-02-11T19:08:42.000Z", "uuid-t", "still thinking"),
        ];
        let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let path = write_jsonl(dir.path(), &refs);

        assert_eq!(newest_assistant_reply(&path, 0).unwrap(), None);
    }

    #[test]
    fn newest_reply_ignores_replies_behind_the_cursor() {
        // Only content past the cursor counts, so an identical earlier reply
        // ("Done." twice) can't be re-matched once it's behind the cursor.
        let dir = tempfile::tempdir().unwrap();
        let earlier = assistant_text_line("2026-02-11T19:08:41.000Z", "uuid-1", "Done.");
        let between = user_line("2026-02-11T19:08:42.000Z", "uuid-u");
        let path = write_jsonl(dir.path(), &[&earlier, &between]);
        let cursor_at_eof = std::fs::metadata(&path).unwrap().len();

        assert_eq!(newest_assistant_reply(&path, cursor_at_eof).unwrap(), None);
    }

    #[test]
    fn newest_reply_truncates_like_the_parser() {
        // The reply is truncated the same way `parse_transcript` truncates, so a
        // reply too large to fit the gRPC cap still compares equal to itself.
        let dir = tempfile::tempdir().unwrap();
        let oversized = "x".repeat(MAX_EVENT_TEXT_BYTES + 128);
        let line = assistant_text_line("2026-02-11T19:08:41.000Z", "uuid-1", &oversized);
        let path = write_jsonl(dir.path(), &[&line]);

        let reply = newest_assistant_reply(&path, 0).unwrap().expect("a reply");
        assert!(reply.ends_with(TRUNCATION_MARKER));
        assert_eq!(
            reply,
            truncate_event_text(&oversized, MAX_EVENT_TEXT_BYTES).into_owned()
        );
    }
}
