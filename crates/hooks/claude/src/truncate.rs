//! Per-event text/thinking byte cap used by the Claude Code stop-hook
//! transcript parser (`crate::transcript`).
//!
//! The parser emits one `TrajectoryEvent` per assistant text or thinking block
//! and sends each via a single `adjudicate` RPC; the cap bounds the per-RPC
//! payload at the source so it cannot exceed the harness gRPC
//! `max_decoding_message_size`.

use serde_json::Value as JsonValue;
use sondera_harness_client::{Action, Control, Observation};
use std::borrow::Cow;
use std::io;

/// Per-event content byte cap.
///
/// The harness server and client both raise `max_decoding_message_size` and
/// `max_encoding_message_size` to 16 MiB (see `apps/harness-service/src/main.rs`
/// and `crates/harness/client/src/client.rs`). We cap raw payloads at 15 MiB
/// to leave 1 MiB of headroom for the agent metadata, trajectory id, and
/// protobuf framing that ride along on each `adjudicate` RPC — preserves the
/// same 1 MiB *absolute* headroom as the original fix (3 MiB content under a
/// 4 MiB limit), not the same ratio: the ratio shrinks from 25% to 6.25% of
/// the cap, which is worth keeping in mind as payload sizes trend up.
///
/// **Scope.** This bound applies to the *content* of a single trajectory event
/// (the sum of user-data-bearing string / JSON fields inside one
/// `Action` / `Observation` / `Control`). The `cap_*_strings` helpers
/// thread a shared budget through each variant's fields, so a
/// `ShellCommandOutput` whose `stdout` and `stderr` are both individually
/// huge cannot combine to exceed this cap.
///
/// **Unguarded headroom.** The 1 MiB headroom budget covers everything *outside*
/// the capped content fields — `Agent` identity, trajectory id, and protobuf
/// framing. It is an unenforced operational assumption, not a runtime-checked
/// bound.
pub(crate) const MAX_EVENT_TEXT_BYTES: usize = 15 * 1024 * 1024;

/// Marker appended when text is truncated, so downstream policy review can
/// tell the content was clipped at the hook.
pub(crate) const TRUNCATION_MARKER: &str =
    "\n\n[…truncated by Sondera claude hook to fit gRPC message limit]";

/// Truncate `s` to at most `max_bytes`, respecting UTF-8 char boundaries.
///
/// Returns the original string when it already fits. Otherwise allocates a
/// shorter `String` ending at the nearest char boundary and appends
/// [`TRUNCATION_MARKER`].
///
/// `max_bytes` bounds the *content* prefix, not the returned string: when
/// truncation fires, the output length is `cut + TRUNCATION_MARKER.len()` (65
/// bytes over the cap). Sized to fit comfortably inside the gRPC headroom
/// budget — see [`MAX_EVENT_TEXT_BYTES`].
pub(crate) fn truncate_event_text(s: &str, max_bytes: usize) -> Cow<'_, str> {
    if s.len() <= max_bytes {
        return Cow::Borrowed(s);
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::with_capacity(cut + TRUNCATION_MARKER.len());
    out.push_str(&s[..cut]);
    out.push_str(TRUNCATION_MARKER);
    Cow::Owned(out)
}

/// In-place variant of [`truncate_event_text`]. Returns `true` when the
/// string was over `max_bytes` and got rewritten with [`TRUNCATION_MARKER`].
pub(crate) fn cap_string(s: &mut String, max_bytes: usize) -> bool {
    if let Cow::Owned(truncated) = truncate_event_text(s, max_bytes) {
        *s = truncated;
        true
    } else {
        false
    }
}

/// `io::Write` shim that only counts bytes and aborts the writer once a
/// limit is exceeded. Used by [`cap_json_value`] to discover whether a
/// `JsonValue` serializes within budget without materializing the result
/// string — `adjudicate` runs on every hook call, so the under-cap path is
/// hot and the previous "serialize-to-String, check len, throw away"
/// pattern allocated up to `MAX_EVENT_TEXT_BYTES` on every miss.
struct CountingWriter {
    written: usize,
    limit: usize,
}

impl io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written = self.written.saturating_add(buf.len());
        if self.written > self.limit {
            // Any error short-circuits `serde_json::to_writer`; the kind is
            // arbitrary — `cap_json_value` only checks `is_err()`.
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns `true` if `v` serializes to JSON within `max_bytes`, without
/// allocating the result string.
fn json_fits_within(v: &JsonValue, max_bytes: usize) -> bool {
    let mut w = CountingWriter {
        written: 0,
        limit: max_bytes,
    };
    serde_json::to_writer(&mut w, v).is_ok()
}

/// Measure the serialized JSON byte size of `v` without allocating. Used by
/// [`consume_json_budget`] after a cap fires, because `cap_json_value` may have
/// collapsed `v` to a `JsonValue::String` whose serialized length differs from
/// the original.
fn serialized_json_size(v: &JsonValue) -> usize {
    let mut w = CountingWriter {
        written: 0,
        limit: usize::MAX,
    };
    let _ = serde_json::to_writer(&mut w, v);
    w.written
}

/// Cap `s` against `*budget`, then debit the *content* bytes from `budget`.
///
/// Threading a shared budget through every user-data-bearing field of a
/// variant gives a per-event aggregate cap: each subsequent field sees the
/// budget already consumed by earlier fields, so a `ShellCommandOutput` with
/// both `stdout` and `stderr` over the per-field limit cannot combine to
/// exceed [`MAX_EVENT_TEXT_BYTES`] worth of content. Order matters — earlier
/// fields get first claim on the budget. The variant arms place the
/// typically-larger / more informative field first (e.g. `stdout` before
/// `stderr`, `command` before `working_dir`).
///
/// Marker bytes don't count against `budget`. If `cap_string` fires, the
/// resulting string is `cut + TRUNCATION_MARKER.len()` bytes long; the
/// marker portion is fixed overhead and is absorbed by the 1 MiB headroom in
/// [`MAX_EVENT_TEXT_BYTES`], not by the per-event content budget. Without
/// this carve-out, a string that is one byte over the budget would zero out
/// every subsequent field (saturating-subtract on a `budget + 65` deduction),
/// which would surprise operators reading stderr-only-marker logs after a
/// barely-oversize stdout.
fn consume_string_budget(s: &mut String, budget: &mut usize) -> bool {
    let before = s.len();
    let truncated = cap_string(s, *budget);
    let charged = if truncated {
        // s.len() == cut + TRUNCATION_MARKER.len(). Charge only the content
        // prefix; the marker is fixed overhead, not part of the shared budget.
        s.len().saturating_sub(TRUNCATION_MARKER.len())
    } else {
        before
    };
    *budget = budget.saturating_sub(charged);
    truncated
}

/// `consume_string_budget` for JSON-valued fields.
///
/// Under-cap path (no truncation): charges the serialized JSON byte count —
/// that's what would land on the wire if encoded as JSON downstream.
///
/// Over-cap path (`cap_json_value` collapsed `v` to `JsonValue::String(prefix +
/// marker)`): charges the *raw content prefix bytes only*, mirroring
/// `consume_string_budget`. Using `serialized_json_size` here would
/// over-charge by the JSON-quote and `\n`-escape inflation around both the
/// marker and the content prefix (>= 4 bytes from quotes + escaped marker
/// newlines, plus per-char inflation for any control bytes inside the
/// prefix). The two-helper accounting is now symmetric: both charge content
/// bytes only, regardless of how the value would be reserialized.
fn consume_json_budget(v: &mut JsonValue, budget: &mut usize) -> bool {
    let truncated = cap_json_value(v, *budget);
    let charged = if truncated {
        // Post-cap, v is always a JsonValue::String whose inner string ends
        // with TRUNCATION_MARKER (both code paths in `cap_json_value` produce
        // this shape). Charge the content prefix.
        match v {
            JsonValue::String(s) => s.len().saturating_sub(TRUNCATION_MARKER.len()),
            // Defensive: cap_json_value's `true` arms always collapse to
            // JsonValue::String, so this is unreachable in current code.
            _ => serialized_json_size(v),
        }
    } else {
        serialized_json_size(v)
    };
    *budget = budget.saturating_sub(charged);
    truncated
}

/// Cap a `JsonValue` by its serialized byte size.
///
/// `ToolUse.input` and `ToolResult.content` arrive as arbitrary JSON — a
/// `cat large_file.txt` shell result can produce a multi-MiB string, an
/// MCP tool can return a deeply nested blob, etc. Without a cap, a single
/// oversized tool block produces a `TrajectoryEvent` that fails the
/// adjudicate RPC with `RESOURCE_EXHAUSTED`, stalling the session.
///
/// Strategy:
///
/// - `JsonValue::String` → truncate the string in place; structure preserved.
/// - any other variant → check fit against [`CountingWriter`] without
///   allocating; only on overflow re-serialize to a `String` and replace
///   the whole value with a `JsonValue::String` carrying the truncated
///   stringification. Structure is lost on truncation, but the marker is
///   visible to policy review and the gRPC frame is bounded.
///
/// **Layer note.** `max_bytes` bounds *content* bytes (post-cap UTF-8 string
/// length). When the outer event is later serialized through `pb::Event::from`
/// the strings ride on `google.protobuf.Struct::Value::string_value`, which
/// uses native proto3 UTF-8 on the wire — no JSON escaping, so wire-level
/// frame size stays at content + small framing overhead. Downstream consumers
/// that *re-serialize as JSON* (logging, DB JSONB columns) will pay JSON-quote
/// inflation that this cap does not account for. Worst-case inflation is ~6×
/// for adversarial control-character content (`\u00XX`) and ~2× for ASCII
/// strings whose every byte is `"` or `\`; for natural text the overhead is
/// in the low single-digit percent and absorbed by [`MAX_EVENT_TEXT_BYTES`]'s
/// 1 MiB headroom.
///
/// Returns `true` when a truncation actually fired.
pub(crate) fn cap_json_value(v: &mut JsonValue, max_bytes: usize) -> bool {
    if let JsonValue::String(s) = v {
        return cap_string(s, max_bytes);
    }
    if json_fits_within(v, max_bytes) {
        return false;
    }
    // Over the cap — pay the full serialization cost to recover a truncated
    // prefix. `serde_json::to_string` only fails on non-serializable types
    // (e.g. maps with non-string keys); `JsonValue` is always serializable,
    // so `unwrap_or_default` is a defensive no-op.
    //
    // This allocates a String of the entire pre-truncation value (so a 20 MiB
    // object incurs a one-shot 20 MiB allocation), which is unavoidable
    // without a streaming truncating writer for `serde_json`. Streaming
    // truncation is achievable but adds non-trivial surface area; the cost is
    // bounded to once-per-overage (the `json_fits_within` fast path skips it
    // entirely for the common under-cap case), so the implementation chooses
    // simplicity over allocation-free truncation here.
    let serialized = serde_json::to_string(&*v).unwrap_or_default();
    let truncated = truncate_event_text(&serialized, max_bytes).into_owned();
    *v = JsonValue::String(truncated);
    true
}

/// Walk an [`Action`] and cap its user-data-bearing fields against a shared
/// `max_bytes` aggregate budget. Returns `true` if at least one field was
/// truncated.
///
/// Bash `command`, `Write`/`Edit` `content` / `old_content`, and unknown-tool
/// `arguments` are the realistic blow-out paths — a `Write` of a multi-MiB
/// generated file or a `cat` piped into `Bash` can produce a single tool_use
/// payload over the gRPC cap. `WebFetch.url` / `prompt` and
/// `ShellCommand.working_dir` are capped too for symmetry, though they are
/// tiny in practice (a malformed audit record could still surface a giant
/// `cwd`, so the cap fires defensively).
///
/// Fields are walked in order: the typically-larger / more informative field
/// in each variant gets first claim on the budget so later fields are clipped
/// or marker-only when the budget is exhausted. This prevents two
/// independently-capped fields (e.g. `Edit.content` + `Edit.old_content`,
/// each at 15 MiB) from combining to exceed [`MAX_EVENT_TEXT_BYTES`] on the
/// wire.
pub(crate) fn cap_action_strings(action: &mut Action, max_bytes: usize) -> bool {
    let mut budget = max_bytes;
    let mut truncated = false;
    match action {
        Action::ShellCommand(cmd) => {
            truncated |= consume_string_budget(&mut cmd.command, &mut budget);
            if let Some(wd) = cmd.working_dir.as_mut() {
                truncated |= consume_string_budget(wd, &mut budget);
            }
        }
        Action::FileOperation(op) => {
            if let Some(c) = op.content.as_mut() {
                truncated |= consume_string_budget(c, &mut budget);
            }
            if let Some(c) = op.old_content.as_mut() {
                truncated |= consume_string_budget(c, &mut budget);
            }
        }
        Action::WebFetch(fetch) => {
            truncated |= consume_string_budget(&mut fetch.prompt, &mut budget);
            truncated |= consume_string_budget(&mut fetch.url, &mut budget);
        }
        Action::ToolCall(call) => {
            truncated |= consume_json_budget(&mut call.arguments, &mut budget);
        }
    }
    truncated
}

/// Walk an [`Observation`] and cap its user-data-bearing fields against a
/// shared `max_bytes` aggregate budget. Returns `true` if at least one field
/// was truncated.
///
/// `ShellCommandOutput.stdout` / `stderr`, `WebFetchOutput.result`, the
/// optional `FileOperationResult.content`, and unknown-tool `ToolOutput.output`
/// are the realistic blow-out paths — a `cat` of a multi-MiB file or a
/// `Read` of an oversized blob can produce a single post-tool payload over
/// the gRPC cap. Without a cap the blocking `PostToolUse` hook fails with
/// `RESOURCE_EXHAUSTED` and stalls the session waiting on adjudication.
///
/// Multi-field variants (`ShellCommandOutput`, `FileOperationResult`,
/// `WebFetchOutput`, `ToolOutput`) thread a shared budget so two independently
/// large fields cannot combine to exceed [`MAX_EVENT_TEXT_BYTES`] on the wire.
/// The typically-larger / more-useful field per variant goes first
/// (`stdout` before `stderr`, `result` before `url`, payload before error).
pub(crate) fn cap_observation_strings(obs: &mut Observation, max_bytes: usize) -> bool {
    let mut budget = max_bytes;
    let mut truncated = false;
    match obs {
        Observation::Prompt(p) => {
            truncated |= consume_string_budget(&mut p.content, &mut budget);
        }
        Observation::Thought(t) => {
            truncated |= consume_string_budget(&mut t.thought, &mut budget);
        }
        Observation::ToolOutput(o) => {
            truncated |= consume_json_budget(&mut o.output, &mut budget);
            if let Some(e) = o.error.as_mut() {
                truncated |= consume_string_budget(e, &mut budget);
            }
        }
        Observation::ShellCommandOutput(o) => {
            truncated |= consume_string_budget(&mut o.stdout, &mut budget);
            truncated |= consume_string_budget(&mut o.stderr, &mut budget);
        }
        Observation::WebFetchOutput(o) => {
            truncated |= consume_string_budget(&mut o.result, &mut budget);
            truncated |= consume_string_budget(&mut o.url, &mut budget);
        }
        Observation::FileOperationResult(o) => {
            if let Some(c) = o.content.as_mut() {
                truncated |= consume_string_budget(c, &mut budget);
            }
            if let Some(e) = o.error.as_mut() {
                truncated |= consume_string_budget(e, &mut budget);
            }
        }
    }
    truncated
}

/// Walk a [`Control`] and cap its user-supplied string fields against a
/// shared `max_bytes` aggregate budget. Returns `true` if at least one field
/// was truncated.
///
/// Lifecycle reasons (`Suspended`, `Resumed`, `Terminated`) and completion
/// summaries (`Completed.summary`, `Started.task`) flow user / task-runner
/// text into `adjudicate`. Bounded in practice — a task subject usually fits
/// in a screen — but a misbehaving caller can still send a multi-MiB blob
/// that would otherwise overflow the harness gRPC frame. `Adjudicated` and
/// `Scanned` carry server-generated payloads and are not capped here.
///
/// Only `Terminated` carries two strings (`reason`, `terminated_by`); the
/// shared budget keeps their combined size within [`MAX_EVENT_TEXT_BYTES`].
pub(crate) fn cap_control_strings(control: &mut Control, max_bytes: usize) -> bool {
    let mut budget = max_bytes;
    let mut truncated = false;
    match control {
        Control::Started(s) => {
            if let Some(t) = s.task.as_mut() {
                truncated |= consume_string_budget(t, &mut budget);
            }
        }
        Control::Completed(c) => {
            if let Some(s) = c.summary.as_mut() {
                truncated |= consume_string_budget(s, &mut budget);
            }
        }
        Control::Failed(f) => {
            truncated |= consume_string_budget(&mut f.reason, &mut budget);
        }
        Control::Terminated(t) => {
            truncated |= consume_string_budget(&mut t.reason, &mut budget);
            truncated |= consume_string_budget(&mut t.terminated_by, &mut budget);
        }
        Control::Suspended(s) => {
            truncated |= consume_string_budget(&mut s.reason, &mut budget);
        }
        Control::Resumed(r) => {
            truncated |= consume_string_budget(&mut r.resumed_by, &mut budget);
        }
        Control::Adjudicated(_) | Control::Scanned(_) => {}
    }
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sondera_harness_client::{
        Completed, Failed, FileOpType, FileOperation, FileOperationResult, Resumed, ShellCommand,
        ShellCommandOutput, Started, Suspended, Terminated, ToolCall, ToolOutput, WebFetchOutput,
    };

    #[test]
    fn passthrough_short_input() {
        let s = "hello";
        let out = truncate_event_text(s, 100);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, "hello");
    }

    #[test]
    fn clips_with_marker_when_oversized() {
        let s = "a".repeat(10);
        let out = truncate_event_text(&s, 4);
        assert!(matches!(out, Cow::Owned(_)));
        assert!(out.starts_with("aaaa"));
        assert!(out.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn respects_utf8_char_boundary() {
        // Each "é" is 2 bytes; cap of 5 would land mid-char if naive.
        let s = "ééééé";
        assert_eq!(s.len(), 10);
        let out = truncate_event_text(s, 5);
        let trimmed = out.trim_end_matches(TRUNCATION_MARKER);
        assert!(trimmed.is_char_boundary(trimmed.len()));
        assert_eq!(trimmed, "éé");
    }

    #[test]
    fn cap_string_truncates_in_place() {
        let mut s = "a".repeat(10);
        assert!(cap_string(&mut s, 4));
        assert!(s.starts_with("aaaa"));
        assert!(s.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_string_passthrough_short_input() {
        let mut s = "hi".to_string();
        assert!(!cap_string(&mut s, 100));
        assert_eq!(s, "hi");
    }

    #[test]
    fn cap_json_value_string_truncates_in_place() {
        let mut v = JsonValue::String("a".repeat(10));
        assert!(cap_json_value(&mut v, 4));
        let s = v.as_str().expect("still a string after truncation");
        assert!(s.starts_with("aaaa"));
        assert!(s.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_json_value_object_collapses_to_string_when_oversized() {
        // A nested object whose serialized form exceeds the cap collapses
        // to a `JsonValue::String` so the gRPC frame is bounded; structure
        // is sacrificed but the marker is visible.
        let big = "a".repeat(100);
        let mut v = json!({"command": big});
        assert!(cap_json_value(&mut v, 20));
        let s = v.as_str().expect("collapsed to string");
        assert!(s.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_json_value_small_object_preserved() {
        let mut v = json!({"command": "ls"});
        assert!(!cap_json_value(&mut v, 1024));
        assert!(v.is_object());
    }

    #[test]
    fn json_fits_within_returns_true_for_small_payload() {
        let v = json!({"command": "ls", "args": ["-la", "/tmp"]});
        assert!(json_fits_within(&v, 1024));
    }

    #[test]
    fn json_fits_within_returns_false_at_or_over_cap() {
        // A single big string inside an object will push the serialized form
        // past `max_bytes`; the counting writer must bail without allocating
        // the full string.
        let v = json!({"k": "a".repeat(200)});
        assert!(!json_fits_within(&v, 50));
    }

    #[test]
    fn cap_json_value_no_truncation_preserves_structure() {
        // Smoke-test that the under-cap path leaves the value structurally
        // untouched (regression guard for the CountingWriter path).
        let original = json!({"a": 1, "b": [true, null, "x"], "c": {"d": "e"}});
        let mut v = original.clone();
        assert!(!cap_json_value(&mut v, 10_000));
        assert_eq!(v, original);
    }

    #[test]
    fn marker_byte_length_is_65() {
        // The doc comment on `truncate_event_text` references 65 bytes; pin
        // it so a stray edit to the marker can't silently invalidate the
        // gRPC headroom math without failing CI.
        assert_eq!(TRUNCATION_MARKER.len(), 65);
    }

    #[test]
    fn cap_action_strings_caps_shell_command_and_working_dir() {
        let mut action = Action::ShellCommand(ShellCommand {
            call_id: "c-1".into(),
            command: "a".repeat(100),
            working_dir: Some("b".repeat(100)),
        });
        assert!(cap_action_strings(&mut action, 20));
        let Action::ShellCommand(cmd) = action else {
            panic!("expected ShellCommand");
        };
        assert!(cmd.command.ends_with(TRUNCATION_MARKER));
        let wd = cmd.working_dir.expect("working_dir preserved");
        assert!(wd.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_action_strings_passthrough_small_working_dir() {
        let mut action = Action::ShellCommand(ShellCommand {
            call_id: "c-1".into(),
            command: "ls".into(),
            working_dir: Some("/tmp".into()),
        });
        assert!(!cap_action_strings(&mut action, 1024));
    }

    #[test]
    fn cap_action_strings_caps_file_operation_content() {
        let mut action = Action::FileOperation(FileOperation {
            call_id: "c-2".into(),
            operation: FileOpType::Write,
            path: "/tmp/x".into(),
            content: Some("a".repeat(100)),
            old_content: Some("b".repeat(100)),
        });
        assert!(cap_action_strings(&mut action, 20));
        let Action::FileOperation(op) = action else {
            panic!("expected FileOperation");
        };
        assert!(op.content.unwrap().ends_with(TRUNCATION_MARKER));
        assert!(op.old_content.unwrap().ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_action_strings_caps_tool_call_arguments() {
        let mut action = Action::ToolCall(ToolCall {
            call_id: "c-3".into(),
            tool: "X".into(),
            arguments: json!({"k": "a".repeat(100)}),
        });
        assert!(cap_action_strings(&mut action, 20));
    }

    #[test]
    fn cap_observation_strings_caps_shell_command_output() {
        let mut obs = Observation::ShellCommandOutput(ShellCommandOutput::new(
            "c-1",
            0,
            "a".repeat(100),
            "b".repeat(100),
        ));
        assert!(cap_observation_strings(&mut obs, 20));
        let Observation::ShellCommandOutput(o) = obs else {
            panic!("expected ShellCommandOutput");
        };
        assert!(o.stdout.ends_with(TRUNCATION_MARKER));
        assert!(o.stderr.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_observation_strings_caps_web_fetch_output() {
        let mut obs = Observation::WebFetchOutput(WebFetchOutput::new(
            "c-1",
            "u".repeat(100),
            200,
            "r".repeat(100),
        ));
        assert!(cap_observation_strings(&mut obs, 20));
        let Observation::WebFetchOutput(o) = obs else {
            panic!("expected WebFetchOutput");
        };
        assert!(o.url.ends_with(TRUNCATION_MARKER));
        assert!(o.result.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_observation_strings_caps_file_operation_result_content() {
        let mut obs = Observation::FileOperationResult(
            FileOperationResult::success("c-1").with_content("a".repeat(100)),
        );
        assert!(cap_observation_strings(&mut obs, 20));
        let Observation::FileOperationResult(o) = obs else {
            panic!("expected FileOperationResult");
        };
        assert!(o.content.unwrap().ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_observation_strings_caps_tool_output() {
        let mut obs =
            Observation::ToolOutput(ToolOutput::success("c-1", json!({"k": "a".repeat(100)})));
        assert!(cap_observation_strings(&mut obs, 20));
    }

    #[test]
    fn cap_observation_strings_passthrough_small_payload() {
        let mut obs = Observation::ShellCommandOutput(ShellCommandOutput::new("c-1", 0, "ok", ""));
        assert!(!cap_observation_strings(&mut obs, 1024));
    }

    #[test]
    fn cap_control_strings_caps_completed_summary() {
        let mut control = Control::Completed(Completed::new().with_summary("a".repeat(100)));
        assert!(cap_control_strings(&mut control, 20));
        let Control::Completed(c) = control else {
            panic!("expected Completed");
        };
        assert!(c.summary.unwrap().ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_control_strings_caps_started_task() {
        use sondera_harness_client::Agent;
        let agent = Agent {
            id: "a-1".into(),
            provider: "test".into(),
            platform: "test".into(),
        };
        let mut control = Control::Started(Started::new(agent).with_task("a".repeat(100)));
        assert!(cap_control_strings(&mut control, 20));
        let Control::Started(s) = control else {
            panic!("expected Started");
        };
        assert!(s.task.unwrap().ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_control_strings_caps_failed_reason() {
        let mut control = Control::Failed(Failed::new("a".repeat(100)));
        assert!(cap_control_strings(&mut control, 20));
    }

    #[test]
    fn cap_control_strings_caps_terminated_fields() {
        let mut control = Control::Terminated(Terminated::new("a".repeat(100), "b".repeat(100)));
        assert!(cap_control_strings(&mut control, 20));
        let Control::Terminated(t) = control else {
            panic!("expected Terminated");
        };
        assert!(t.reason.ends_with(TRUNCATION_MARKER));
        assert!(t.terminated_by.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn cap_control_strings_caps_suspended_and_resumed() {
        let mut s = Control::Suspended(Suspended::new("a".repeat(100)));
        assert!(cap_control_strings(&mut s, 20));
        let mut r = Control::Resumed(Resumed::new("a".repeat(100)));
        assert!(cap_control_strings(&mut r, 20));
    }

    #[test]
    fn cap_control_strings_passthrough_small_payload() {
        let mut control = Control::Completed(Completed::new().with_summary("done"));
        assert!(!cap_control_strings(&mut control, 1024));
    }

    // ========================================================================
    // Aggregate-budget tests — verify shared budget across multi-field variants
    // (regression guard for the "per-field caps allow 2N total" bug).
    // ========================================================================

    fn obs_serialized_size(o: &Observation) -> usize {
        serde_json::to_string(o).unwrap().len()
    }

    fn action_serialized_size(a: &Action) -> usize {
        serde_json::to_string(a).unwrap().len()
    }

    #[test]
    fn cap_observation_strings_shared_budget_across_stdout_stderr() {
        // Both fields independently exceed the budget. Aggregate must stay
        // close to `max_bytes` — *not* 2× max_bytes.
        let budget: usize = 100;
        let mut obs = Observation::ShellCommandOutput(ShellCommandOutput::new(
            "c-1",
            0,
            "a".repeat(200),
            "b".repeat(200),
        ));
        assert!(cap_observation_strings(&mut obs, budget));
        let size = obs_serialized_size(&obs);
        // Allow up to budget + per-truncation marker overhead (65 bytes × #fields)
        // plus the JSON framing for the struct (~60 bytes). 4× budget would
        // indicate the bug.
        assert!(
            size <= budget + 2 * TRUNCATION_MARKER.len() + 200,
            "ShellCommandOutput serialized to {size} bytes, expected <= {}",
            budget + 2 * TRUNCATION_MARKER.len() + 200
        );
    }

    #[test]
    fn cap_observation_strings_shared_budget_across_web_fetch() {
        let budget: usize = 100;
        let mut obs = Observation::WebFetchOutput(WebFetchOutput::new(
            "c-1",
            "u".repeat(200),
            200,
            "r".repeat(200),
        ));
        assert!(cap_observation_strings(&mut obs, budget));
        let size = obs_serialized_size(&obs);
        assert!(
            size <= budget + 2 * TRUNCATION_MARKER.len() + 200,
            "WebFetchOutput serialized to {size} bytes"
        );
    }

    #[test]
    fn cap_action_strings_shared_budget_across_edit_content() {
        // The original bug: Edit with both `content` and `old_content` large
        // produced a ~2× MAX_EVENT_TEXT_BYTES payload because each was capped
        // independently. Shared budget must hold the sum near `max_bytes`.
        let budget: usize = 100;
        let mut action = Action::FileOperation(FileOperation {
            call_id: "c-1".into(),
            operation: FileOpType::Edit,
            path: "/tmp/x".into(),
            content: Some("a".repeat(200)),
            old_content: Some("b".repeat(200)),
        });
        assert!(cap_action_strings(&mut action, budget));
        let size = action_serialized_size(&action);
        assert!(
            size <= budget + 2 * TRUNCATION_MARKER.len() + 200,
            "FileOperation serialized to {size} bytes"
        );
    }

    #[test]
    fn cap_observation_strings_first_field_consumes_budget_second_marker_only() {
        // stdout fills the budget; stderr is left with budget=0 → marker only.
        let mut obs = Observation::ShellCommandOutput(ShellCommandOutput::new(
            "c-1",
            0,
            "a".repeat(200),
            "b".repeat(200),
        ));
        assert!(cap_observation_strings(&mut obs, 100));
        let Observation::ShellCommandOutput(o) = obs else {
            panic!("expected ShellCommandOutput");
        };
        // stdout: 100 bytes of 'a' + marker.
        assert!(o.stdout.starts_with("aaaa"));
        assert!(o.stdout.ends_with(TRUNCATION_MARKER));
        assert_eq!(o.stdout.len(), 100 + TRUNCATION_MARKER.len());
        // stderr: budget exhausted → exactly the marker, no original content.
        // (Can't grep for 'b' as a substring — the marker itself contains 'b'
        // in "by Sondera".)
        assert_eq!(o.stderr, TRUNCATION_MARKER);
    }

    #[test]
    fn consume_string_budget_carves_out_marker_overhead() {
        // When UTF-8 boundary walks the cut below `budget`, the carve-out
        // preserves the leftover. Without it, the marker-overhead 65 bytes
        // would over-charge the deduction and saturate budget to 0.
        //
        // Setup: budget=5, s="ééééé" (each `é` is 2 bytes, total 10 bytes).
        // truncate_event_text walks cut from 5 → 4 (next char boundary), so
        // content = 4 bytes, post-cap s.len() = 4 + 65 = 69. The carve-out
        // charges 4 (content only) and leaves 5 - 4 = 1 byte of budget for
        // subsequent fields. Without the carve-out, the deduction would be
        // 69, saturating budget to 0 and zeroing every later field.
        let mut budget: usize = 5;
        let mut s = "ééééé".to_string();
        assert!(consume_string_budget(&mut s, &mut budget));
        assert_eq!(
            budget, 1,
            "marker overhead must not be charged to the content budget"
        );
    }

    #[test]
    fn consume_json_budget_charges_content_bytes_not_serialized() {
        // After cap_json_value collapses a non-String value over the budget,
        // `v` is a JsonValue::String of the form `prefix + marker`. The carve-
        // out charges the raw content prefix, NOT serialized_json_size(v).
        // serialized_json_size adds ~4 bytes of JSON quoting/escape inflation
        // (surrounding "" + `\n`-escaped marker), which the previous
        // `serialized_size - marker.len()` accounting under-counted by.
        let mut budget: usize = 1024;
        let mut v = json!({"large": "a".repeat(2048)});
        assert!(consume_json_budget(&mut v, &mut budget));
        let JsonValue::String(s) = &v else {
            panic!("cap_json_value should have collapsed v to JsonValue::String");
        };
        let content_bytes = s.len() - TRUNCATION_MARKER.len();
        assert_eq!(
            budget,
            1024 - content_bytes,
            "consume_json_budget must charge content bytes only, not JSON-serialized bytes"
        );
    }

    #[test]
    fn cap_control_strings_shared_budget_across_terminated_fields() {
        let budget: usize = 100;
        let mut control = Control::Terminated(Terminated::new("a".repeat(200), "b".repeat(200)));
        assert!(cap_control_strings(&mut control, budget));
        let size = serde_json::to_string(&control).unwrap().len();
        assert!(
            size <= budget + 2 * TRUNCATION_MARKER.len() + 200,
            "Terminated serialized to {size} bytes"
        );
    }
}
