//! Trajectory log analysis using structured LLM output.
//!
//! Implements the AISI "Seven Simple Steps for Log Analysis in AI Systems"
//! (Dubois et al., 2026) framework for automated trajectory scanning: LLM-based
//! scanners that turn unstructured agent trajectory logs into structured,
//! measurable signals.
//!
//! Scanning is **enrichment, not enforcement**. It runs off the adjudication
//! path, after the harness has already returned a decision, so a scan that
//! fails, times out, or is never configured changes nothing about what an agent
//! was allowed to do. Nothing in this crate may be made load-bearing for a
//! decision.
//!
//! # Scanner layers
//!
//! Following the AISI pipeline, analysis operates at three granularities:
//!
//! 1. **Message-level** ([`EventScanResult`]) — classifies individual
//!    trajectory events by message type, agent intent, and detected signals.
//!    Analogous to AISI's per-message scanners.
//!
//! 2. **Transcript-level digest** ([`TranscriptDigest`]) — hierarchical
//!    summarization of an entire trajectory into phases, tools, and files.
//!    Groups events into logical work stages (investigation, implementation,
//!    verification).
//!
//! 3. **Transcript-level scan** ([`TranscriptScanResult`]) — behavioral
//!    analysis of a full trajectory with signal detection, outcome assessment,
//!    and governance audit. Uses the AISI signal taxonomy (Tables 2-3) to
//!    detect environment issues, agent incoherence, refusal behaviour, and
//!    policy violations.
//!
//! The result types themselves live in `sondera-types`, not here: the storage
//! layer and the console read them without linking a model provider.
//!
//! # Design principles (from AISI Table 6)
//!
//! - **Rubric-based prompts**: each scanner uses a self-contained rubric with
//!   anchored definitions, positive/negative examples, and scoring criteria.
//! - **Explanation before grade**: scanners produce a reasoning explanation
//!   before assigning classifications, improving faithfulness.
//! - **Confidence scoring**: all scan results include a confidence level so
//!   callers can identify uncertain classifications for human review.
//! - **Structured output**: results derive `schemars::JsonSchema`, which the
//!   provider's extractor uses to constrain the model.
//!
//! # Example
//!
//! ```no_run
//! use sondera_trajectory::{ScannerConfig, TrajectoryScanner};
//!
//! # async fn example(event: sondera_types::Event) -> Result<(), Box<dyn std::error::Error>> {
//! let scanner = TrajectoryScanner::new(ScannerConfig::with_model("gemini-2.5-flash"))?;
//!
//! // Message level: one event.
//! let result = scanner.scan_event(&event).await?;
//! println!("{:?}: {}", result.message_type, result.description);
//!
//! // Transcript level: the whole run.
//! let events = vec![event];
//! let scan = scanner.scan_transcript("traj-1", &events).await?;
//! println!("outcome {:?}, {} signals", scan.outcome, scan.signals.len());
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! Dubois, M., Zorer, E., Hamin, M., et al. (2026). *Seven simple steps for
//! log analysis in AI systems.* UK AI Security Institute (AISI).
//!
//! # License
//!
//! MIT — see LICENSE in the repository root.

mod config;
mod error;
mod rubric;
mod scanner;

pub use config::{DEFAULT_TIMEOUT, ScannerConfig};
pub use error::ScannerError;
pub use scanner::{ScannerFuture, TrajectoryScanner, TrajectoryScannerBackend, is_scanner_output};

// The rubrics are the scanner's contract with the model: an evaluation harness
// that wants to diff prompt revisions, or a test that asserts a rubric still
// names a signal category, needs to read them without going through a live
// provider.
pub use rubric::{
    EVENT_SCAN_RUBRIC, MAX_EVENT_CHARS, MAX_PROMPT_CHARS, TRANSCRIPT_DIGEST_RUBRIC,
    TRANSCRIPT_SCAN_RUBRIC, render_event_prompt, render_transcript_prompt,
};

// The scan result vocabulary, re-exported so a consumer of this crate does not
// need a second `use` from `sondera_types` to name what a scan returned.
pub use sondera_types::{
    AgentIntent, EventScanResult, MessageType, Scanned, Signal, SignalCategory, SignalFocus,
    SignalSeverity, TranscriptDigest, TranscriptOutcome, TranscriptPhase, TranscriptScan,
    TranscriptScanResult,
};
