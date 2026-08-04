//! Event payload → renderable content blocks.
//!
//! The detail pane's job is to show what actually happened, in the form it
//! happened in: a shell command as shell, a file write as source in that file's
//! language, a prompt as markdown, a tool payload as JSON. This module makes
//! that call once, per payload variant, and emits a flat [`Block`] list. The
//! renderer in [`crate::render`] turns blocks into styled text and never
//! re-decides what anything is.

use crate::model::{DigestView, ScanView, prompt_role_label};
use sondera_schema::harness_v1 as hb;
use sondera_schema::wire::{proto_struct_to_json_value, proto_value_to_json};

/// The languages the highlighter knows. Anything else renders as plain
/// monospace in a well, which is still better than pretending it is prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Bash,
    Json,
    Rust,
    Python,
    JavaScript,
    Go,
    Toml,
    Yaml,
    Markdown,
    Plain,
}

impl Lang {
    /// Infer a language from a file path's extension.
    pub fn from_path(path: &str) -> Self {
        let ext = path.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
        match ext.to_ascii_lowercase().as_str() {
            "rs" => Self::Rust,
            "py" | "pyi" => Self::Python,
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "svelte" => Self::JavaScript,
            "go" => Self::Go,
            "toml" => Self::Toml,
            "yaml" | "yml" => Self::Yaml,
            "json" => Self::Json,
            "md" | "markdown" => Self::Markdown,
            "sh" | "bash" | "zsh" | "fish" => Self::Bash,
            _ => Self::Plain,
        }
    }

    /// Resolve a fenced code block's info string (```rust) to a language.
    pub fn from_tag(tag: &str) -> Self {
        match tag.trim().to_ascii_lowercase().as_str() {
            "rust" | "rs" => Self::Rust,
            "python" | "py" => Self::Python,
            "javascript" | "js" | "typescript" | "ts" | "tsx" | "jsx" => Self::JavaScript,
            "go" => Self::Go,
            "toml" => Self::Toml,
            "yaml" | "yml" => Self::Yaml,
            "json" => Self::Json,
            "sh" | "bash" | "shell" | "zsh" | "console" => Self::Bash,
            "markdown" | "md" => Self::Markdown,
            _ => Self::Plain,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Json => "json",
            Self::Rust => "rust",
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::Go => "go",
            Self::Toml => "toml",
            Self::Yaml => "yaml",
            Self::Markdown => "markdown",
            Self::Plain => "text",
        }
    }
}

/// One unit of detail-pane content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    /// An uppercase section marker.
    Eyebrow(String),
    /// A dense `key  value` metadata row.
    Field { key: String, value: String },
    /// Free text rendered as markdown.
    Prose(String),
    /// Verbatim content in a recessed well, syntax-highlighted.
    Code {
        lang: Lang,
        caption: Option<String>,
        text: String,
    },
    /// A bulleted list item.
    Bullet(String),
    /// Vertical breathing room between sections.
    Gap,
}

impl Block {
    fn field(key: &str, value: impl Into<String>) -> Self {
        Self::Field {
            key: key.to_string(),
            value: value.into(),
        }
    }

    fn captioned(lang: Lang, caption: &str, text: impl Into<String>) -> Self {
        Self::Code {
            lang,
            caption: Some(caption.to_string()),
            text: text.into(),
        }
    }
}

/// What the event *is*, before anything was decided about it.
///
/// The detail pane's content is this followed by [`governance_blocks`], in that
/// fixed and progressive order: what happened, then the verdict on it, then
/// what the scanner made of it. The two halves are built separately because a
/// live tail learns the verdict *after* the event — the payload section is
/// built once, and the governance tail is rebuilt whenever an adjudication or
/// scan lands on it.
pub(crate) fn payload_blocks(payload: Option<&hb::TrajectoryEvent>) -> Vec<Block> {
    use hb::trajectory_event::Category;

    let Some(category) = payload.and_then(|p| p.category.as_ref()) else {
        return vec![Block::Prose("No payload recorded for this event.".into())];
    };

    match category {
        Category::Action(action) => action_blocks(action),
        Category::Observation(observation) => observation_blocks(observation),
        Category::Control(control) => control_blocks(control),
        Category::State(state) => state_blocks(state),
    }
}

fn action_blocks(action: &hb::Action) -> Vec<Block> {
    use hb::action::Kind;

    let mut blocks = vec![Block::Eyebrow("action".into())];
    match action.kind.as_ref() {
        Some(Kind::ToolCall(call)) => {
            blocks.push(Block::field("tool", call.tool.clone()));
            blocks.push(Block::field("call", call.call_id.clone()));
            blocks.push(Block::Gap);
            match call.arguments.as_ref() {
                Some(args) if !args.fields.is_empty() => blocks.push(Block::captioned(
                    Lang::Json,
                    "arguments",
                    pretty_json(&proto_struct_to_json_value(args)),
                )),
                _ => blocks.push(Block::Prose("No arguments.".into())),
            }
        }
        Some(Kind::ShellCommand(cmd)) => {
            if let Some(dir) = cmd.working_dir.as_ref().filter(|d| !d.is_empty()) {
                blocks.push(Block::field("cwd", dir.clone()));
            }
            blocks.push(Block::field("call", cmd.call_id.clone()));
            blocks.push(Block::Gap);
            blocks.push(Block::captioned(Lang::Bash, "command", cmd.command.clone()));
        }
        Some(Kind::WebFetch(fetch)) => {
            blocks.push(Block::field("url", fetch.url.clone()));
            blocks.push(Block::field("call", fetch.call_id.clone()));
            if !fetch.prompt.is_empty() {
                blocks.push(Block::Gap);
                blocks.push(Block::Eyebrow("prompt".into()));
                blocks.push(Block::Prose(fetch.prompt.clone()));
            }
        }
        Some(Kind::FileOperation(op)) => {
            blocks.push(Block::field("path", op.path.clone()));
            blocks.push(Block::field("call", op.call_id.clone()));
            let lang = Lang::from_path(&op.path);
            // An edit shows both sides: the replaced text is the only way to
            // judge whether the new content is the change that was intended.
            if let Some(old) = op.old_content.as_ref().filter(|c| !c.is_empty()) {
                blocks.push(Block::Gap);
                blocks.push(Block::captioned(lang, "replaced", old.clone()));
            }
            if let Some(content) = op.content.as_ref().filter(|c| !c.is_empty()) {
                blocks.push(Block::Gap);
                blocks.push(Block::captioned(lang, "content", content.clone()));
            }
        }
        None => blocks.push(Block::Prose("Unrecognized action.".into())),
    }
    blocks
}

fn observation_blocks(observation: &hb::Observation) -> Vec<Block> {
    use hb::observation::Kind;

    let mut blocks = vec![Block::Eyebrow("observation".into())];
    match observation.kind.as_ref() {
        // A prompt is authored prose. Rendering it as markdown is the whole
        // point: agents write fenced code and lists into these.
        Some(Kind::Prompt(prompt)) => {
            blocks.push(Block::field("role", prompt_role_label(prompt.role)));
            blocks.push(Block::Gap);
            blocks.push(Block::Prose(prompt.content.clone()));
        }
        Some(Kind::Thought(thought)) => {
            blocks.push(Block::Prose(thought.thought.clone()));
        }
        Some(Kind::ToolOutput(output)) => {
            blocks.push(Block::field("call", output.call_id.clone()));
            blocks.push(Block::field(
                "status",
                if output.success { "success" } else { "failed" },
            ));
            if let Some(error) = output.error.as_ref().filter(|e| !e.is_empty()) {
                blocks.push(Block::Gap);
                blocks.push(Block::Eyebrow("error".into()));
                blocks.push(Block::Prose(error.clone()));
            }
            if let Some(value) = output.output.as_ref() {
                let json = proto_value_to_json(value);
                blocks.push(Block::Gap);
                // Tool output is very often a plain string of prose or logs;
                // wrapping that in JSON quotes and escapes would make it
                // unreadable, so a bare string renders as its own text.
                match json.as_str() {
                    Some(text) => {
                        blocks.push(Block::captioned(Lang::Plain, "output", text.to_string()))
                    }
                    None => blocks.push(Block::captioned(Lang::Json, "output", pretty_json(&json))),
                }
            }
        }
        Some(Kind::ShellCommandOutput(output)) => {
            blocks.push(Block::field("call", output.call_id.clone()));
            blocks.push(Block::field("exit", output.exit_code.to_string()));
            if !output.stdout.is_empty() {
                blocks.push(Block::Gap);
                blocks.push(Block::captioned(
                    Lang::Plain,
                    "stdout",
                    output.stdout.clone(),
                ));
            }
            if !output.stderr.is_empty() {
                blocks.push(Block::Gap);
                blocks.push(Block::captioned(
                    Lang::Plain,
                    "stderr",
                    output.stderr.clone(),
                ));
            }
            if output.stdout.is_empty() && output.stderr.is_empty() {
                blocks.push(Block::Gap);
                blocks.push(Block::Prose("No output captured.".into()));
            }
        }
        Some(Kind::WebFetchOutput(output)) => {
            blocks.push(Block::field("url", output.url.clone()));
            blocks.push(Block::field("status", output.code.to_string()));
            if !output.result.is_empty() {
                blocks.push(Block::Gap);
                blocks.push(Block::Prose(output.result.clone()));
            }
        }
        Some(Kind::FileOperationResult(result)) => {
            blocks.push(Block::field("call", result.call_id.clone()));
            blocks.push(Block::field(
                "status",
                if result.success { "success" } else { "failed" },
            ));
            let lang = result
                .path
                .as_deref()
                .map(Lang::from_path)
                .unwrap_or(Lang::Plain);
            if let Some(path) = result.path.as_ref().filter(|p| !p.is_empty()) {
                blocks.push(Block::field("path", path.clone()));
            }
            if let Some(error) = result.error.as_ref().filter(|e| !e.is_empty()) {
                blocks.push(Block::Gap);
                blocks.push(Block::Eyebrow("error".into()));
                blocks.push(Block::Prose(error.clone()));
            }
            if let Some(content) = result.content.as_ref().filter(|c| !c.is_empty()) {
                blocks.push(Block::Gap);
                blocks.push(Block::captioned(lang, "content", content.clone()));
            }
        }
        None => blocks.push(Block::Prose("Unrecognized observation.".into())),
    }
    blocks
}

fn control_blocks(control: &hb::Control) -> Vec<Block> {
    use hb::control::Kind;

    let mut blocks = vec![Block::Eyebrow("control".into())];
    match control.kind.as_ref() {
        Some(Kind::Started(started)) => {
            if let Some(agent) = started.agent.as_ref() {
                blocks.push(Block::field("agent", agent.id.clone()));
                blocks.push(Block::field("provider", agent.provider.clone()));
                if !agent.platform.is_empty() {
                    blocks.push(Block::field("platform", agent.platform.clone()));
                }
            }
            if let Some(task) = started.task.as_ref().filter(|t| !t.is_empty()) {
                blocks.push(Block::Gap);
                blocks.push(Block::Eyebrow("task".into()));
                blocks.push(Block::Prose(task.clone()));
            }
        }
        Some(Kind::Completed(done)) => {
            blocks.push(Block::field("outcome", "completed"));
            if let Some(summary) = done.summary.as_ref().filter(|s| !s.is_empty()) {
                blocks.push(Block::Gap);
                blocks.push(Block::Prose(summary.clone()));
            }
        }
        Some(Kind::Failed(failed)) => {
            blocks.push(Block::field("outcome", "failed"));
            blocks.push(Block::Gap);
            blocks.push(Block::Prose(failed.reason.clone()));
        }
        Some(Kind::Terminated(term)) => {
            blocks.push(Block::field("outcome", "terminated"));
            blocks.push(Block::field("by", term.terminated_by.clone()));
            blocks.push(Block::Gap);
            blocks.push(Block::Prose(term.reason.clone()));
        }
        Some(Kind::Suspended(susp)) => {
            blocks.push(Block::field("outcome", "suspended"));
            blocks.push(Block::Gap);
            blocks.push(Block::Prose(susp.reason.clone()));
        }
        Some(Kind::Resumed(res)) => {
            blocks.push(Block::field("outcome", "resumed"));
            blocks.push(Block::field("by", res.resumed_by.clone()));
        }
        // A standalone adjudication or scan event is rare on this surface — the
        // console folds both onto the event they describe — but a page can
        // still contain one, so it renders rather than showing an empty pane.
        Some(Kind::Adjudicated(adjudication)) => blocks.extend(adjudication_blocks(adjudication)),
        Some(Kind::Scanned(_)) => {
            blocks.push(Block::Prose(
                "Scanner output, folded onto the event it describes.".into(),
            ));
        }
        None => blocks.push(Block::Prose("Unrecognized control event.".into())),
    }
    blocks
}

fn state_blocks(state: &hb::State) -> Vec<Block> {
    let mut blocks = vec![Block::Eyebrow("state".into())];
    match state.kind.as_ref() {
        Some(hb::state::Kind::Snapshot(snap)) => {
            blocks.push(Block::field("snapshot", snap.snapshot_id.clone()));
            if let Some(dir) = snap.working_dir.as_ref().filter(|d| !d.is_empty()) {
                blocks.push(Block::field("cwd", dir.clone()));
            }
            if let Some(branch) = snap.git_branch.as_ref().filter(|b| !b.is_empty()) {
                blocks.push(Block::field("branch", branch.clone()));
            }
            if !snap.open_files.is_empty() {
                blocks.push(Block::Gap);
                blocks.push(Block::Eyebrow("open files".into()));
                blocks.extend(snap.open_files.iter().cloned().map(Block::Bullet));
            }
            if !snap.variables.is_empty() {
                let json = serde_json::Value::Object(
                    snap.variables
                        .iter()
                        .map(|(k, v)| (k.clone(), proto_value_to_json(v)))
                        .collect(),
                );
                blocks.push(Block::Gap);
                blocks.push(Block::captioned(
                    Lang::Json,
                    "variables",
                    pretty_json(&json),
                ));
            }
        }
        None => blocks.push(Block::Prose("Unrecognized state event.".into())),
    }
    blocks
}

/// The verdict and the scanner's read of it, in that order, each preceded by
/// the gap that separates it from the payload above.
///
/// Empty when neither is present, so a node with nothing folded onto it renders
/// exactly its payload. A deny is useless without the clause that produced it,
/// so the adjudication section always carries its reason and matched policies —
/// never a bare verdict.
pub(crate) fn governance_blocks(
    adjudication: Option<&hb::Adjudicated>,
    scan: Option<&hb::EventScanResult>,
) -> Vec<Block> {
    let mut blocks = Vec::new();

    if let Some(adjudication) = adjudication {
        blocks.push(Block::Gap);
        blocks.extend(adjudication_blocks(adjudication));
    }

    if let Some(scan) = scan {
        blocks.push(Block::Gap);
        blocks.extend(scan_blocks(scan));
    }

    blocks
}

/// The verdict, with everything needed to argue with it.
fn adjudication_blocks(adjudication: &hb::Adjudicated) -> Vec<Block> {
    let mut blocks = vec![Block::Eyebrow("adjudication".into())];

    blocks.push(Block::field(
        "decision",
        decision_label(adjudication.decision),
    ));
    blocks.push(Block::field("mode", mode_label(adjudication.mode)));
    if let Some(reason) = adjudication.reason.as_ref().filter(|r| !r.is_empty()) {
        blocks.push(Block::Prose(reason.clone()));
    }

    for policy in &adjudication.metadata {
        let id = policy.policy_id.clone().unwrap_or_else(|| "—".into());
        blocks.push(Block::field("policy", id));
        if let Some(description) = policy.description.as_ref().filter(|d| !d.is_empty()) {
            blocks.push(Block::Bullet(description.clone()));
        }
    }

    if let Some(guardrails) = adjudication.guardrails.as_ref() {
        if let Some(signature) = guardrails.signature.as_ref().filter(|s| s.triggered) {
            let severity = signature.severity.clone().unwrap_or_else(|| "—".into());
            blocks.push(Block::field("signature", severity));
            for matched in &signature.matches {
                blocks.push(Block::Bullet(match matched.namespace.as_ref() {
                    Some(ns) if !ns.is_empty() => format!("{ns}::{}", matched.rule),
                    _ => matched.rule.clone(),
                }));
            }
        }
        if let Some(ifc) = guardrails.ifc.as_ref() {
            blocks.push(Block::field("sensitivity", ifc.label.clone()));
        }
    }

    if let Some(steering) = adjudication.steering.as_ref() {
        blocks.push(Block::Gap);
        blocks.push(Block::Eyebrow("steering".into()));
        blocks.push(Block::Prose(steering.explanation.clone()));
        blocks.extend(steering.instructions.iter().cloned().map(Block::Bullet));
    }

    blocks
}

fn scan_blocks(scan: &hb::EventScanResult) -> Vec<Block> {
    let mut blocks = vec![Block::Eyebrow("scanner".into())];

    if !scan.description.is_empty() {
        blocks.push(Block::Prose(scan.description.clone()));
    }
    // What the scanner decided this event *is*, beside how sure it was. The
    // classification is the part a reader can disagree with; the confidence
    // alone is not falsifiable.
    if let Some(message_type) = message_type_label(scan.message_type) {
        blocks.push(Block::field("classified", message_type));
    }
    blocks.push(Block::field(
        "confidence",
        format!("{:.0}%", scan.confidence * 100.0),
    ));
    blocks.push(Block::field(
        "effects",
        if scan.is_side_effecting {
            "side-effecting"
        } else {
            "none"
        },
    ));
    if !scan.key_entities.is_empty() {
        blocks.push(Block::field("entities", scan.key_entities.join(", ")));
    }
    if !scan.explanation.is_empty() {
        blocks.push(Block::Gap);
        blocks.push(Block::Eyebrow("reasoning".into()));
        blocks.push(Block::Prose(scan.explanation.clone()));
    }

    blocks
}

/// The structural class the scanner assigned an event, or `None` when it
/// assigned none — which reads as absence rather than as a default class.
fn message_type_label(value: i32) -> Option<&'static str> {
    Some(match hb::MessageType::try_from(value).ok()? {
        hb::MessageType::ToolCall => "tool call",
        hb::MessageType::ToolResult => "tool result",
        hb::MessageType::UserInput => "user input",
        hb::MessageType::Reasoning => "reasoning",
        hb::MessageType::Lifecycle => "lifecycle",
        hb::MessageType::Adjudication => "adjudication",
        hb::MessageType::StateCapture => "state capture",
        hb::MessageType::Unspecified => return None,
    })
}

// ============================================================================
// Run-level scanner output
// ============================================================================

/// The scanner's read of the whole run, as blocks for the insight panel.
///
/// Digest first, then behavioral scan, in the order the scanner produces them
/// and the order a reader needs them: *what happened* before *what to make of
/// it*. Either half may be absent — a run in flight has a digest and no scan —
/// so each contributes only if it has something to say.
///
/// Free prose (the digest summary, the scanner's reasoning, its behavioral
/// notes) goes out as [`Block::Prose`], which the renderer treats as markdown.
/// The scanner is a language model writing for a human: it emits headings,
/// lists, and backticked paths, and rendering those literally would put
/// `**the**` in a governance console.
pub fn insight_blocks(digest: Option<&DigestView>, scan: Option<&ScanView>) -> Vec<Block> {
    let mut blocks = Vec::new();

    if let Some(digest) = digest.filter(|digest| !digest.is_empty()) {
        blocks.extend(digest_blocks(digest));
    }
    if let Some(scan) = scan {
        if !blocks.is_empty() {
            blocks.push(Block::Gap);
        }
        blocks.extend(transcript_scan_blocks(scan));
    }

    blocks
}

fn digest_blocks(digest: &DigestView) -> Vec<Block> {
    // An interim digest describes a run that is still going. Saying so in the
    // eyebrow means a reader never quotes a mid-run summary as the outcome.
    let mut blocks = vec![Block::Eyebrow(
        if digest.interim {
            "digest · interim"
        } else {
            "digest"
        }
        .into(),
    )];

    if !digest.summary.is_empty() {
        blocks.push(Block::Prose(digest.summary.clone()));
    }

    blocks.push(Block::field(
        "events",
        format!(
            "{} · {} side-effecting",
            digest.total_events, digest.side_effecting_count
        ),
    ));
    if !digest.tools_used.is_empty() {
        blocks.push(Block::field("tools", digest.tools_used.join(", ")));
    }

    if !digest.phases.is_empty() {
        blocks.push(Block::Gap);
        blocks.push(Block::Eyebrow("phases".into()));
        blocks.extend(digest.phases.iter().map(|phase| {
            let mut text = phase.name.clone();
            if phase.event_count > 0 {
                text.push_str(&format!(" ({})", phase.event_count));
            }
            if !phase.description.is_empty() {
                text.push_str(&format!(" — {}", phase.description));
            }
            Block::Bullet(text)
        }));
    }

    // Files the run *changed*, listed rather than counted: which files a run
    // touched is the question a reviewer opens a transcript to answer.
    if !digest.files_modified.is_empty() {
        blocks.push(Block::Gap);
        blocks.push(Block::Eyebrow("files modified".into()));
        blocks.extend(digest.files_modified.iter().cloned().map(Block::Bullet));
    }

    blocks
}

fn transcript_scan_blocks(scan: &ScanView) -> Vec<Block> {
    let mut blocks = vec![Block::Eyebrow("behavioral scan".into())];

    if !scan.outcome_description.is_empty() {
        blocks.push(Block::Prose(scan.outcome_description.clone()));
    }
    if !scan.outcome.is_empty() {
        blocks.push(Block::field("outcome", scan.outcome.clone()));
    }
    blocks.push(Block::field(
        "confidence",
        format!("{:.0}%", scan.confidence * 100.0),
    ));
    if !scan.adjudication_summary.is_empty() {
        blocks.push(Block::field(
            "adjudication",
            scan.adjudication_summary.clone(),
        ));
    }

    // Signals are the governance payload of the whole scan, so they lead the
    // detail rather than trailing the notes. Each carries its own severity: an
    // aggregate of `high` says nothing about which of five signals earned it.
    if !scan.signals.is_empty() {
        blocks.push(Block::Gap);
        blocks.push(Block::Eyebrow("signals".into()));
        blocks.extend(scan.signals.iter().map(|signal| {
            // Focus rides with every signal: `destructive operation` focused on
            // the environment is a tool that broke something, focused on the
            // agent it is the agent that did. Same category, different owner.
            let focus = if signal.focus.is_empty() {
                String::new()
            } else {
                format!("{} · ", signal.focus)
            };
            Block::Bullet(format!(
                "{} · {focus}{} — {}",
                signal.severity.label(),
                signal.category,
                signal.description
            ))
        }));
    }

    if !scan.behavioral_notes.is_empty() {
        blocks.push(Block::Gap);
        blocks.push(Block::Eyebrow("behaviour".into()));
        blocks.extend(scan.behavioral_notes.iter().cloned().map(Block::Bullet));
    }

    // The reasoning last, and always present when the scanner produced one: a
    // grade whose argument is not reachable is a verdict, not a decision aid.
    if !scan.explanation.is_empty() {
        blocks.push(Block::Gap);
        blocks.push(Block::Eyebrow("reasoning".into()));
        blocks.push(Block::Prose(scan.explanation.clone()));
    }

    blocks
}

fn decision_label(value: i32) -> &'static str {
    match hb::Decision::try_from(value) {
        Ok(hb::Decision::Allow) => "allow",
        Ok(hb::Decision::Deny) => "deny",
        Ok(hb::Decision::Escalate) => "escalate",
        _ => "unadjudicated",
    }
}

/// The engine mode at evaluation time.
///
/// An unreadable mode reads as `govern`, not as the permissive default: the
/// proto is explicit that a dropped field must never under-report an enforced
/// decision in the audit trail.
fn mode_label(value: i32) -> &'static str {
    match hb::Mode::try_from(value) {
        Ok(hb::Mode::Monitor) => "monitor",
        Ok(hb::Mode::Steer) => "steer",
        _ => "govern",
    }
}

fn pretty_json(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_code(blocks: &[Block], lang: Lang, caption: &str) -> bool {
        blocks.iter().any(|block| {
            matches!(block, Block::Code { lang: l, caption: Some(c), .. }
                if *l == lang && c == caption)
        })
    }

    #[test]
    fn a_shell_command_renders_as_bash() {
        let action = hb::Action {
            kind: Some(hb::action::Kind::ShellCommand(hb::ShellCommand {
                call_id: "c1".into(),
                command: "rm -rf /tmp/x".into(),
                working_dir: Some("/repo".into()),
            })),
        };
        let blocks = action_blocks(&action);
        assert!(has_code(&blocks, Lang::Bash, "command"));
        assert!(blocks.contains(&Block::field("cwd", "/repo")));
    }

    #[test]
    fn a_file_write_picks_the_language_from_the_path() {
        let action = hb::Action {
            kind: Some(hb::action::Kind::FileOperation(hb::FileOperation {
                call_id: "c1".into(),
                operation: hb::file_operation::FileOpType::Write.into(),
                path: "src/main.rs".into(),
                content: Some("fn main() {}".into()),
                old_content: None,
            })),
        };
        assert!(has_code(&action_blocks(&action), Lang::Rust, "content"));
    }

    #[test]
    fn an_edit_shows_the_replaced_text_too() {
        let action = hb::Action {
            kind: Some(hb::action::Kind::FileOperation(hb::FileOperation {
                call_id: "c1".into(),
                operation: hb::file_operation::FileOpType::Edit.into(),
                path: "a.py".into(),
                content: Some("new".into()),
                old_content: Some("old".into()),
            })),
        };
        let blocks = action_blocks(&action);
        assert!(has_code(&blocks, Lang::Python, "replaced"));
        assert!(has_code(&blocks, Lang::Python, "content"));
    }

    #[test]
    fn string_tool_output_is_not_wrapped_in_json_quotes() {
        let observation = hb::Observation {
            kind: Some(hb::observation::Kind::ToolOutput(hb::ToolOutput {
                call_id: "c1".into(),
                success: true,
                output: Some(prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("hello\nworld".into())),
                }),
                error: None,
            })),
        };
        let blocks = observation_blocks(&observation);
        assert!(blocks.contains(&Block::Code {
            lang: Lang::Plain,
            caption: Some("output".into()),
            text: "hello\nworld".into(),
        }));
    }

    #[test]
    fn a_prompt_renders_as_prose_not_code() {
        let observation = hb::Observation {
            kind: Some(hb::observation::Kind::Prompt(hb::Prompt {
                content: "# Task\nDo the thing".into(),
                role: hb::prompt::PromptRole::User.into(),
            })),
        };
        let blocks = observation_blocks(&observation);
        assert!(blocks.contains(&Block::Prose("# Task\nDo the thing".into())));
    }

    #[test]
    fn a_deny_always_carries_its_reason_and_policy() {
        let adjudication = hb::Adjudicated {
            decision: hb::Decision::Deny.into(),
            mode: hb::Mode::Govern.into(),
            reason: Some("destructive path".into()),
            metadata: vec![hb::PolicyMetadata {
                policy_id: Some("no-rm-rf".into()),
                description: Some("blocks recursive deletes".into()),
                ..hb::PolicyMetadata::default()
            }],
            guardrails: None,
            steering: None,
        };
        let blocks = adjudication_blocks(&adjudication);
        assert!(blocks.contains(&Block::field("decision", "deny")));
        assert!(blocks.contains(&Block::Prose("destructive path".into())));
        assert!(blocks.contains(&Block::field("policy", "no-rm-rf")));
    }

    #[test]
    fn an_unreadable_mode_reads_as_govern() {
        assert_eq!(mode_label(0), "govern");
        assert_eq!(mode_label(99), "govern");
        assert_eq!(mode_label(hb::Mode::Monitor.into()), "monitor");
    }

    #[test]
    fn a_missing_payload_says_so_instead_of_rendering_empty() {
        assert_eq!(
            payload_blocks(None),
            vec![Block::Prose("No payload recorded for this event.".into())]
        );
    }

    #[test]
    fn language_inference_covers_paths_and_fence_tags() {
        assert_eq!(Lang::from_path("a/b/c.rs"), Lang::Rust);
        assert_eq!(Lang::from_path("Makefile"), Lang::Plain);
        assert_eq!(Lang::from_tag("```"), Lang::Plain);
        assert_eq!(Lang::from_tag("Bash"), Lang::Bash);
    }
}
