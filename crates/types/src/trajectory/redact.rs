//! Redaction of file bodies on the way to persistent storage.
//!
//! Adjudication needs a file's bytes: content-keyed policy cannot match what it
//! cannot see, so a hook that re-derives a read — a VS Code `@`-mention, say —
//! sends the content along with the path. The ledger does not need them. When
//! the verdict refuses the operation, keeping the bytes leaves the harness
//! storing exactly the secret it just denied the agent, in a database that
//! outlives the run.
//!
//! [`Event::redact_file_content`] rewrites each file body as a
//! [`redaction_marker`] carrying the original's byte length and a truncated
//! SHA-256. Everything that makes the event auditable — path, call id,
//! operation, and the whole envelope — is left alone.
//!
//! Only file bodies are covered: [`FileOperation`] content and `old_content`,
//! and [`FileOperationResult`] content. Shell output and generic tool output
//! can carry the same bytes by another route (`cat ~/.ssh/id_rsa` is a
//! [`ShellCommandOutput`](super::ShellCommandOutput), not a file read) and are
//! deliberately left intact — the transcript would lose most of its substance
//! if they were not.

use super::action::{Action, FileOperation};
use super::event::{Event, TrajectoryEvent};
use super::observation::{FileOperationResult, Observation};
use sha2::{Digest, Sha256};

/// Hex digits of the SHA-256 digest a marker carries.
///
/// 16 digits is 64 bits, which is far more than enough to tell two reads of the
/// same file from reads of different ones at ledger scale, and short enough
/// that a redacted event still reads as one line in the TUI transcript.
const FINGERPRINT_HEX: usize = 16;

/// Render the marker that replaces `content` in the ledger.
///
/// The marker is stable for identical content, so two redacted reads of the
/// same file remain correlatable after the bytes are gone.
///
/// The digest **identifies** content; it does not protect it. A short or
/// low-entropy file can be recovered from its SHA-256 by guessing candidates,
/// so treat a marker as a correlation handle — not as grounds for sending a
/// redacted event somewhere the original would not have been allowed to go.
///
/// ```
/// # use sondera_types::redaction_marker;
/// assert_eq!(redaction_marker("hi"), redaction_marker("hi"));
/// assert_ne!(redaction_marker("hi"), redaction_marker("ho"));
/// ```
#[must_use]
pub fn redaction_marker(content: &str) -> String {
    let digest = format!("{:x}", Sha256::digest(content.as_bytes()));
    let fingerprint = digest.get(..FINGERPRINT_HEX).unwrap_or(digest.as_str());
    format!("[redacted: {} bytes, sha256:{fingerprint}]", content.len())
}

/// Redact an optional body, leaving `None` as `None`.
///
/// An empty body is still redacted rather than passed through: the rule stays
/// "a persisted body is a marker", with no length threshold for a reader to
/// second-guess.
fn redact(content: Option<String>) -> Option<String> {
    content.map(|body| redaction_marker(&body))
}

impl Event {
    /// Return this event with every file body replaced by its
    /// [`redaction_marker`].
    ///
    /// Consumes and returns the event rather than mutating in place so the
    /// persistence path cannot hold both versions by accident.
    #[must_use]
    pub fn redact_file_content(mut self) -> Self {
        self.event = self.event.redact_file_content();
        self
    }
}

impl TrajectoryEvent {
    /// Return this event's payload with every file body replaced by its
    /// [`redaction_marker`]. Payloads carrying no file body are returned
    /// unchanged.
    #[must_use]
    pub fn redact_file_content(self) -> Self {
        match self {
            Self::Action(Action::FileOperation(op)) => {
                Self::Action(Action::FileOperation(FileOperation {
                    content: redact(op.content),
                    old_content: redact(op.old_content),
                    ..op
                }))
            }
            Self::Observation(Observation::FileOperationResult(result)) => {
                Self::Observation(Observation::FileOperationResult(FileOperationResult {
                    content: redact(result.content),
                    ..result
                }))
            }
            unchanged => unchanged,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Agent, FileOpType, ShellCommandOutput};

    const SECRET: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 deploy@host\n";

    fn agent() -> Agent {
        Agent {
            id: "agent-1".to_string(),
            provider: "test".to_string(),
            platform: String::new(),
        }
    }

    fn read_event(payload: TrajectoryEvent) -> Event {
        Event::new(agent(), "traj-1", payload)
    }

    fn file_operation(event: &Event) -> &FileOperation {
        match &event.event {
            TrajectoryEvent::Action(Action::FileOperation(op)) => op,
            other => panic!("expected a file operation, got {other}"),
        }
    }

    #[test]
    fn marker_reports_byte_length_and_a_short_digest() {
        let marker = redaction_marker("abc");
        assert!(
            marker.starts_with("[redacted: 3 bytes, sha256:"),
            "{marker}"
        );
        assert!(marker.ends_with(']'), "{marker}");
        // 16 hex digits, no more: the rest of the digest is dropped.
        assert_eq!(
            marker, "[redacted: 3 bytes, sha256:ba7816bf8f01cfea]",
            "digest must be SHA-256 truncated to {FINGERPRINT_HEX} digits"
        );
    }

    #[test]
    fn redacting_a_read_drops_the_body_and_keeps_the_path() {
        let event = read_event(TrajectoryEvent::Action(Action::FileOperation(
            FileOperation {
                call_id: "call-1".to_string(),
                operation: FileOpType::Read,
                path: "/home/dev/.ssh/authorized_keys".to_string(),
                content: Some(SECRET.to_string()),
                old_content: None,
            },
        )));
        let event_id = event.event_id.clone();

        let redacted = event.redact_file_content();
        let op = file_operation(&redacted);

        assert_eq!(
            op.content.as_deref(),
            Some(redaction_marker(SECRET).as_str())
        );
        assert_eq!(op.path, "/home/dev/.ssh/authorized_keys");
        assert_eq!(op.call_id, "call-1");
        assert_eq!(op.operation, FileOpType::Read);
        assert_eq!(redacted.event_id, event_id, "envelope must survive intact");

        let json = serde_json::to_string(&redacted.event).expect("serialize");
        assert!(!json.contains("AAAAC3NzaC1lZDI1NTE5"), "{json}");
    }

    #[test]
    fn redacting_an_edit_drops_both_sides_of_the_diff() {
        let event = read_event(TrajectoryEvent::Action(Action::FileOperation(
            FileOperation::edit("/app/.env", "OLD=1", "NEW=2"),
        )));

        let redacted = event.redact_file_content();
        let op = file_operation(&redacted);

        assert_eq!(
            op.content.as_deref(),
            Some(redaction_marker("NEW=2").as_str())
        );
        assert_eq!(
            op.old_content.as_deref(),
            Some(redaction_marker("OLD=1").as_str())
        );
    }

    #[test]
    fn redacting_a_result_drops_the_body_and_keeps_the_outcome() {
        let event = read_event(TrajectoryEvent::Observation(
            Observation::FileOperationResult(
                FileOperationResult::success("call-1")
                    .with_path("/app/.env")
                    .with_content(SECRET),
            ),
        ));

        let redacted = event.redact_file_content();
        let TrajectoryEvent::Observation(Observation::FileOperationResult(result)) =
            &redacted.event
        else {
            panic!("expected a file operation result");
        };

        assert_eq!(
            result.content.as_deref(),
            Some(redaction_marker(SECRET).as_str())
        );
        assert_eq!(result.path.as_deref(), Some("/app/.env"));
        assert!(result.success);
    }

    #[test]
    fn a_read_that_carried_no_body_stays_empty() {
        let event = read_event(TrajectoryEvent::Action(Action::FileOperation(
            FileOperation::read("/app/main.rs"),
        )));

        let op = event.redact_file_content();
        let op = file_operation(&op);
        assert_eq!(op.content, None);
        assert_eq!(op.old_content, None);
    }

    #[test]
    fn payloads_without_a_file_body_are_untouched() {
        // Shell output is out of scope by design; pinning it here so widening
        // the match arm is a deliberate change and not a silent one.
        let payload = TrajectoryEvent::Observation(Observation::ShellCommandOutput(
            ShellCommandOutput::new("call-1", 0, SECRET, ""),
        ));

        assert_eq!(payload.clone().redact_file_content(), payload);
    }
}
