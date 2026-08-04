//! Trajectory-payload domain ↔ proto conversions.
//!
//! The leaf half of the event model: every `TrajectoryEvent` category and the
//! messages beneath it. The `Event` envelope and the `Adjudicated` response
//! encoding live in [`crate::event`].
//!
//! Every domain ↔ proto pair is a standard conversion, written once here and
//! reached through `.into()` / `.try_into()?` everywhere else — including from
//! the enclosing message's own conversion, so a leaf is never converted inline
//! at two different call sites:
//!
//! - **Encoding is infallible** — `impl From<&Domain> for pb::Message`.
//! - **Decoding is fallible only where it can be** — `TryFrom` for a message
//!   carrying an enum or a `REQUIRED` submessage, plain `From` for the rest, so
//!   the signature says which conversions can actually reject. When a message
//!   that decodes via `From` later gains an enum or a `REQUIRED` field, the
//!   `From` impl has to be *replaced* by a `TryFrom` — the two cannot coexist,
//!   because `core` blanket-implements `TryFrom` for anything that implements
//!   `Into`. The compiler flags every affected call site, so the migration is
//!   mechanical; it is a deliberate trade for keeping "this cannot fail" in the
//!   signature rather than spraying `?` over conversions that never reject.
//!
//! Three things are worth knowing:
//!
//! - **Enums.** Proto enums carry a `*_UNSPECIFIED = 0` zero value the domain
//!   enums have no counterpart for. Decoding `UNSPECIFIED` — or an unknown
//!   discriminant from a newer producer — is an error rather than a silent
//!   fallback: an audit record must not invent a decision, severity, or file
//!   operation the producer did not send. See [`ProtoEnum`].
//! - **Free-form fields.** `ToolCall.arguments`, `ToolOutput.output`, and
//!   `Snapshot.variables` go through `google.protobuf.Struct`/`Value`. See the
//!   precision note in [`crate::wire`].
//! - **Index widths.** The domain uses `u32` for event indices and counts; the
//!   wire uses `int32` (AIP requires signed integers). See [`u32_to_i32`].

use crate::decode::{decode_error, require, unrecognized_enum};
use crate::harness_v1 as pb;
use crate::wire::{
    json_to_proto_value, json_value_to_proto_struct, proto_struct_to_json_value,
    proto_value_to_json,
};
use sondera_types::{
    Action, Adjudicated, AgentIntent, Completed, Control, Decision, EventScanResult, Failed,
    FileOpType, FileOperation, FileOperationResult, GuardrailResults, IfcGuardrailResult,
    MessageType, Mode, Observation, PolicyMetadata, Prompt, PromptRole, Resumed, Scanned,
    ShellCommand, ShellCommandOutput, Signal, SignalCategory, SignalFocus, SignalSeverity,
    SignatureGuardrailMatch, SignatureGuardrailResult, Snapshot, Started, State, Steering,
    Suspended, Terminated, Thought, ToolCall, ToolOutput, TrajectoryEvent, TranscriptDigest,
    TranscriptOutcome, TranscriptPhase, TranscriptScanResult, ValidationError, WebFetch,
    WebFetchOutput,
};

// ============================================================================
// Scalar helpers
// ============================================================================

/// Narrow a domain `u32` index/count to the wire's `int32`.
///
/// AIP-141 requires signed integers on the wire, but the domain models event
/// indices and counts as `u32`. Values above `i32::MAX` saturate: these are
/// positions within a single trajectory transcript, so the ceiling is far above
/// any real transcript, and saturating keeps one absurd index from failing the
/// encode of an entire audit record.
fn u32_to_i32(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// Widen a wire `int32` index/count back to the domain's `u32`.
///
/// Negative values are not producible by [`u32_to_i32`]; a negative here means a
/// malformed producer, and clamping to 0 keeps a bad index from wrapping to a
/// huge one.
fn i32_to_u32(value: i32) -> u32 {
    u32::try_from(value).unwrap_or(0)
}

/// Encode a domain index sequence as the wire's signed one.
fn encode_indices(indices: &[u32]) -> Vec<i32> {
    indices.iter().copied().map(u32_to_i32).collect()
}

/// Decode a wire index sequence back into the domain's unsigned one.
fn decode_indices(indices: &[i32]) -> Vec<u32> {
    indices.iter().copied().map(i32_to_u32).collect()
}

/// Decode every element of a repeated field, failing on the first rejection.
fn decode_all<'a, P, D>(items: &'a [P]) -> Result<Vec<D>, ValidationError>
where
    D: TryFrom<&'a P, Error = ValidationError>,
{
    items.iter().map(D::try_from).collect()
}

// ============================================================================
// Enums
// ============================================================================

/// A domain enum with a generated proto counterpart.
///
/// prost represents an enum field as a bare `i32`, but `impl TryFrom<i32> for
/// <domain enum>` cannot be written here — the orphan rule forbids it, since
/// `i32` and the domain enums are both foreign to this crate. This trait is the
/// bridge: the mapping itself lives in the `From`/`TryFrom` impls between the
/// two enum types, and [`decode_enum`] reaches them from a wire `i32`.
trait ProtoEnum: Copy + Sized + TryFrom<Self::Proto> {
    /// The generated proto enum this maps onto.
    type Proto: TryFrom<i32>;

    /// This value's wire discriminant.
    fn encode(self) -> i32;
}

/// Decode a wire enum discriminant into `field`'s domain counterpart.
///
/// `UNSPECIFIED` and a discriminant this build does not know are rejected
/// identically: either way the producer sent no value this version can act on,
/// and defaulting would invent one. The caller names the field, because one
/// enum serves several of them.
fn decode_enum<D: ProtoEnum>(raw: i32, field: &str) -> Result<D, ValidationError> {
    D::Proto::try_from(raw)
        .ok()
        .and_then(|proto| D::try_from(proto).ok())
        .ok_or_else(|| unrecognized_enum(field))
}

/// Define the `From`/`TryFrom` pair and the [`ProtoEnum`] bridge for one enum.
///
/// `$name` is the domain type's name, used only when the standalone
/// `TryFrom<pb::Enum>` is called outside a field decode; [`decode_enum`] names
/// the wire field instead.
macro_rules! enum_conv {
    (
        $name:literal, $domain:ty, $proto:ty,
        $( $d:ident <=> $p:ident ),+ $(,)?
    ) => {
        impl From<$domain> for $proto {
            fn from(value: $domain) -> Self {
                match value {
                    $( <$domain>::$d => Self::$p, )+
                }
            }
        }

        impl TryFrom<$proto> for $domain {
            type Error = ValidationError;

            fn try_from(value: $proto) -> Result<Self, Self::Error> {
                match value {
                    $( <$proto>::$p => Ok(Self::$d), )+
                    _ => Err(decode_error(concat!(
                        "unrecognized ", $name, " value."
                    ))),
                }
            }
        }

        impl ProtoEnum for $domain {
            type Proto = $proto;

            fn encode(self) -> i32 {
                <$proto>::from(self) as i32
            }
        }
    };
}

enum_conv!(
    "ActorType", sondera_types::ActorType, pb::actor::ActorType,
    Human <=> Human, Agent <=> Agent, System <=> System, Policy <=> Policy,
);

enum_conv!(
    "FileOpType", FileOpType, pb::file_operation::FileOpType,
    Read <=> Read, Write <=> Write, Edit <=> Edit, Delete <=> Delete,
);

enum_conv!(
    "PromptRole", PromptRole, pb::prompt::PromptRole,
    User <=> User, System <=> System, Assistant <=> Assistant,
);

enum_conv!(
    "Decision", Decision, pb::Decision,
    Allow <=> Allow, Deny <=> Deny, Escalate <=> Escalate,
);

enum_conv!(
    "Mode", Mode, pb::Mode,
    Monitor <=> Monitor, Govern <=> Govern, Steer <=> Steer,
);

enum_conv!(
    "SignalFocus", SignalFocus, pb::SignalFocus,
    Environment <=> Environment, Agent <=> Agent, Governance <=> Governance,
);

enum_conv!(
    "SignalSeverity", SignalSeverity, pb::SignalSeverity,
    Info <=> Info, Low <=> Low, Medium <=> Medium, High <=> High, Critical <=> Critical,
);

enum_conv!(
    "SignalCategory", SignalCategory, pb::SignalCategory,
    InputIssues <=> InputIssues,
    InfrastructureFailure <=> InfrastructureFailure,
    TaskDesign <=> TaskDesign,
    StaticKnowledge <=> StaticKnowledge,
    LowLevelIncoherence <=> LowLevelIncoherence,
    HighLevelIncoherence <=> HighLevelIncoherence,
    SelfCorrection <=> SelfCorrection,
    RefusalBehaviour <=> RefusalBehaviour,
    ToolMisuse <=> ToolMisuse,
    EvaluationAwareness <=> EvaluationAwareness,
    PolicyViolation <=> PolicyViolation,
    PrivilegeEscalation <=> PrivilegeEscalation,
    DataExfiltration <=> DataExfiltration,
    DestructiveOperation <=> DestructiveOperation,
    CredentialExposure <=> CredentialExposure,
);

enum_conv!(
    "MessageType", MessageType, pb::MessageType,
    ToolCall <=> ToolCall,
    ToolResult <=> ToolResult,
    UserInput <=> UserInput,
    Reasoning <=> Reasoning,
    Lifecycle <=> Lifecycle,
    Adjudication <=> Adjudication,
    StateCapture <=> StateCapture,
);

enum_conv!(
    "AgentIntent", AgentIntent, pb::AgentIntent,
    Investigate <=> Investigate,
    Plan <=> Plan,
    Implement <=> Implement,
    Verify <=> Verify,
    Debug <=> Debug,
    Communicate <=> Communicate,
    Lifecycle <=> Lifecycle,
    Govern <=> Govern,
);

enum_conv!(
    "TranscriptOutcome", TranscriptOutcome, pb::TranscriptOutcome,
    Success <=> Success,
    Partial <=> Partial,
    Failure <=> Failure,
    Interrupted <=> Interrupted,
    InProgress <=> InProgress,
);

// ============================================================================
// Attribution
// ============================================================================

impl From<&sondera_types::Agent> for pb::Agent {
    fn from(agent: &sondera_types::Agent) -> Self {
        Self {
            id: agent.id.clone(),
            provider: agent.provider.clone(),
            platform: agent.platform.clone(),
        }
    }
}

impl From<&pb::Agent> for sondera_types::Agent {
    fn from(agent: &pb::Agent) -> Self {
        Self {
            id: agent.id.clone(),
            provider: agent.provider.clone(),
            platform: agent.platform.clone(),
        }
    }
}

impl From<&sondera_types::Actor> for pb::Actor {
    fn from(actor: &sondera_types::Actor) -> Self {
        Self {
            id: actor.id.clone(),
            actor_type: actor.actor_type.encode(),
        }
    }
}

impl TryFrom<&pb::Actor> for sondera_types::Actor {
    type Error = ValidationError;

    fn try_from(actor: &pb::Actor) -> Result<Self, Self::Error> {
        Ok(Self {
            id: actor.id.clone(),
            actor_type: decode_enum(actor.actor_type, "actor_type")?,
        })
    }
}

impl From<&sondera_types::Causality> for pb::Causality {
    fn from(causality: &sondera_types::Causality) -> Self {
        Self {
            correlation_id: causality.correlation_id.clone(),
            causation_id: causality.causation_id.clone(),
            parent_id: causality.parent_id.clone(),
        }
    }
}

impl From<&pb::Causality> for sondera_types::Causality {
    fn from(causality: &pb::Causality) -> Self {
        Self {
            correlation_id: causality.correlation_id.clone(),
            causation_id: causality.causation_id.clone(),
            parent_id: causality.parent_id.clone(),
        }
    }
}

// ============================================================================
// TrajectoryEvent
// ============================================================================

impl From<&TrajectoryEvent> for pb::TrajectoryEvent {
    fn from(event: &TrajectoryEvent) -> Self {
        use pb::trajectory_event::Category;
        Self {
            category: Some(match event {
                TrajectoryEvent::Action(v) => Category::Action(v.into()),
                TrajectoryEvent::Observation(v) => Category::Observation(v.into()),
                TrajectoryEvent::Control(v) => Category::Control(v.into()),
                TrajectoryEvent::State(v) => Category::State(v.into()),
            }),
        }
    }
}

impl TryFrom<&pb::TrajectoryEvent> for TrajectoryEvent {
    type Error = ValidationError;

    fn try_from(event: &pb::TrajectoryEvent) -> Result<Self, Self::Error> {
        use pb::trajectory_event::Category;
        let category = require(event.category.as_ref(), "event.category")?;
        Ok(match category {
            Category::Action(v) => Self::Action(v.try_into()?),
            Category::Observation(v) => Self::Observation(v.try_into()?),
            Category::Control(v) => Self::Control(v.try_into()?),
            Category::State(v) => Self::State(v.try_into()?),
        })
    }
}

// ============================================================================
// Action
// ============================================================================

impl From<&Action> for pb::Action {
    fn from(action: &Action) -> Self {
        use pb::action::Kind;
        Self {
            kind: Some(match action {
                Action::ToolCall(v) => Kind::ToolCall(v.into()),
                Action::ShellCommand(v) => Kind::ShellCommand(v.into()),
                Action::WebFetch(v) => Kind::WebFetch(v.into()),
                Action::FileOperation(v) => Kind::FileOperation(v.into()),
            }),
        }
    }
}

impl TryFrom<&pb::Action> for Action {
    type Error = ValidationError;

    fn try_from(action: &pb::Action) -> Result<Self, Self::Error> {
        use pb::action::Kind;
        let kind = require(action.kind.as_ref(), "action")?;
        Ok(match kind {
            Kind::ToolCall(v) => Self::ToolCall(v.into()),
            Kind::ShellCommand(v) => Self::ShellCommand(v.into()),
            Kind::WebFetch(v) => Self::WebFetch(v.into()),
            Kind::FileOperation(v) => Self::FileOperation(v.try_into()?),
        })
    }
}

impl From<&ToolCall> for pb::ToolCall {
    fn from(call: &ToolCall) -> Self {
        Self {
            call_id: call.call_id.clone(),
            tool: call.tool.clone(),
            arguments: json_value_to_proto_struct(&call.arguments),
        }
    }
}

impl From<&pb::ToolCall> for ToolCall {
    fn from(call: &pb::ToolCall) -> Self {
        Self {
            call_id: call.call_id.clone(),
            tool: call.tool.clone(),
            arguments: call
                .arguments
                .as_ref()
                .map_or(serde_json::Value::Null, proto_struct_to_json_value),
        }
    }
}

impl From<&ShellCommand> for pb::ShellCommand {
    fn from(command: &ShellCommand) -> Self {
        Self {
            call_id: command.call_id.clone(),
            command: command.command.clone(),
            working_dir: command.working_dir.clone(),
        }
    }
}

impl From<&pb::ShellCommand> for ShellCommand {
    fn from(command: &pb::ShellCommand) -> Self {
        Self {
            call_id: command.call_id.clone(),
            command: command.command.clone(),
            working_dir: command.working_dir.clone(),
        }
    }
}

impl From<&WebFetch> for pb::WebFetch {
    fn from(fetch: &WebFetch) -> Self {
        Self {
            call_id: fetch.call_id.clone(),
            url: fetch.url.clone(),
            prompt: fetch.prompt.clone(),
        }
    }
}

impl From<&pb::WebFetch> for WebFetch {
    fn from(fetch: &pb::WebFetch) -> Self {
        Self {
            call_id: fetch.call_id.clone(),
            url: fetch.url.clone(),
            prompt: fetch.prompt.clone(),
        }
    }
}

impl From<&FileOperation> for pb::FileOperation {
    fn from(op: &FileOperation) -> Self {
        Self {
            call_id: op.call_id.clone(),
            operation: op.operation.encode(),
            path: op.path.clone(),
            content: op.content.clone(),
            old_content: op.old_content.clone(),
        }
    }
}

impl TryFrom<&pb::FileOperation> for FileOperation {
    type Error = ValidationError;

    fn try_from(op: &pb::FileOperation) -> Result<Self, Self::Error> {
        Ok(Self {
            call_id: op.call_id.clone(),
            operation: decode_enum(op.operation, "operation")?,
            path: op.path.clone(),
            content: op.content.clone(),
            old_content: op.old_content.clone(),
        })
    }
}

// ============================================================================
// Observation
// ============================================================================

impl From<&Observation> for pb::Observation {
    fn from(observation: &Observation) -> Self {
        use pb::observation::Kind;
        Self {
            kind: Some(match observation {
                Observation::Prompt(v) => Kind::Prompt(v.into()),
                Observation::Thought(v) => Kind::Thought(v.into()),
                Observation::ToolOutput(v) => Kind::ToolOutput(v.into()),
                Observation::ShellCommandOutput(v) => Kind::ShellCommandOutput(v.into()),
                Observation::WebFetchOutput(v) => Kind::WebFetchOutput(v.into()),
                Observation::FileOperationResult(v) => Kind::FileOperationResult(v.into()),
            }),
        }
    }
}

impl TryFrom<&pb::Observation> for Observation {
    type Error = ValidationError;

    fn try_from(observation: &pb::Observation) -> Result<Self, Self::Error> {
        use pb::observation::Kind;
        let kind = require(observation.kind.as_ref(), "observation")?;
        Ok(match kind {
            Kind::Prompt(v) => Self::Prompt(v.try_into()?),
            Kind::Thought(v) => Self::Thought(v.into()),
            Kind::ToolOutput(v) => Self::ToolOutput(v.into()),
            Kind::ShellCommandOutput(v) => Self::ShellCommandOutput(v.into()),
            Kind::WebFetchOutput(v) => Self::WebFetchOutput(v.into()),
            Kind::FileOperationResult(v) => Self::FileOperationResult(v.into()),
        })
    }
}

impl From<&Prompt> for pb::Prompt {
    fn from(prompt: &Prompt) -> Self {
        Self {
            content: prompt.content.clone(),
            role: prompt.role.encode(),
        }
    }
}

impl TryFrom<&pb::Prompt> for Prompt {
    type Error = ValidationError;

    fn try_from(prompt: &pb::Prompt) -> Result<Self, Self::Error> {
        Ok(Self {
            content: prompt.content.clone(),
            role: decode_enum(prompt.role, "role")?,
        })
    }
}

impl From<&Thought> for pb::Thought {
    fn from(thought: &Thought) -> Self {
        Self {
            thought: thought.thought.clone(),
        }
    }
}

impl From<&pb::Thought> for Thought {
    fn from(thought: &pb::Thought) -> Self {
        Self {
            thought: thought.thought.clone(),
        }
    }
}

impl From<&ToolOutput> for pb::ToolOutput {
    fn from(output: &ToolOutput) -> Self {
        Self {
            call_id: output.call_id.clone(),
            success: output.success,
            output: Some(json_to_proto_value(&output.output)),
            error: output.error.clone(),
        }
    }
}

impl From<&pb::ToolOutput> for ToolOutput {
    fn from(output: &pb::ToolOutput) -> Self {
        Self {
            call_id: output.call_id.clone(),
            success: output.success,
            output: output
                .output
                .as_ref()
                .map_or(serde_json::Value::Null, proto_value_to_json),
            error: output.error.clone(),
        }
    }
}

impl From<&ShellCommandOutput> for pb::ShellCommandOutput {
    fn from(output: &ShellCommandOutput) -> Self {
        Self {
            call_id: output.call_id.clone(),
            exit_code: output.exit_code,
            stdout: output.stdout.clone(),
            stderr: output.stderr.clone(),
        }
    }
}

impl From<&pb::ShellCommandOutput> for ShellCommandOutput {
    fn from(output: &pb::ShellCommandOutput) -> Self {
        Self {
            call_id: output.call_id.clone(),
            exit_code: output.exit_code,
            stdout: output.stdout.clone(),
            stderr: output.stderr.clone(),
        }
    }
}

impl From<&WebFetchOutput> for pb::WebFetchOutput {
    fn from(output: &WebFetchOutput) -> Self {
        Self {
            call_id: output.call_id.clone(),
            url: output.url.clone(),
            code: output.code,
            result: output.result.clone(),
        }
    }
}

impl From<&pb::WebFetchOutput> for WebFetchOutput {
    fn from(output: &pb::WebFetchOutput) -> Self {
        Self {
            call_id: output.call_id.clone(),
            url: output.url.clone(),
            code: output.code,
            result: output.result.clone(),
        }
    }
}

impl From<&FileOperationResult> for pb::FileOperationResult {
    fn from(result: &FileOperationResult) -> Self {
        Self {
            call_id: result.call_id.clone(),
            success: result.success,
            content: result.content.clone(),
            error: result.error.clone(),
            path: result.path.clone(),
        }
    }
}

impl From<&pb::FileOperationResult> for FileOperationResult {
    fn from(result: &pb::FileOperationResult) -> Self {
        Self {
            call_id: result.call_id.clone(),
            success: result.success,
            path: result.path.clone(),
            content: result.content.clone(),
            error: result.error.clone(),
        }
    }
}

// ============================================================================
// Control
// ============================================================================

impl From<&Control> for pb::Control {
    fn from(control: &Control) -> Self {
        use pb::control::Kind;
        Self {
            kind: Some(match control {
                Control::Started(v) => Kind::Started(v.into()),
                Control::Completed(v) => Kind::Completed(v.into()),
                Control::Failed(v) => Kind::Failed(v.into()),
                Control::Terminated(v) => Kind::Terminated(v.into()),
                Control::Suspended(v) => Kind::Suspended(v.into()),
                Control::Resumed(v) => Kind::Resumed(v.into()),
                Control::Adjudicated(v) => Kind::Adjudicated(v.into()),
                Control::Scanned(v) => Kind::Scanned(v.into()),
            }),
        }
    }
}

impl TryFrom<&pb::Control> for Control {
    type Error = ValidationError;

    fn try_from(control: &pb::Control) -> Result<Self, Self::Error> {
        use pb::control::Kind;
        let kind = require(control.kind.as_ref(), "control")?;
        Ok(match kind {
            Kind::Started(v) => Self::Started(v.try_into()?),
            Kind::Completed(v) => Self::Completed(v.into()),
            Kind::Failed(v) => Self::Failed(v.into()),
            Kind::Terminated(v) => Self::Terminated(v.into()),
            Kind::Suspended(v) => Self::Suspended(v.into()),
            Kind::Resumed(v) => Self::Resumed(v.into()),
            Kind::Adjudicated(v) => Self::Adjudicated(v.try_into()?),
            Kind::Scanned(v) => Self::Scanned(v.try_into()?),
        })
    }
}

impl From<&Started> for pb::Started {
    fn from(started: &Started) -> Self {
        Self {
            agent: Some((&started.agent).into()),
            task: started.task.clone(),
        }
    }
}

impl TryFrom<&pb::Started> for Started {
    type Error = ValidationError;

    fn try_from(started: &pb::Started) -> Result<Self, Self::Error> {
        Ok(Self {
            agent: require(started.agent.as_ref(), "started.agent")?.into(),
            task: started.task.clone(),
        })
    }
}

impl From<&Completed> for pb::Completed {
    fn from(completed: &Completed) -> Self {
        Self {
            summary: completed.summary.clone(),
        }
    }
}

impl From<&pb::Completed> for Completed {
    fn from(completed: &pb::Completed) -> Self {
        Self {
            summary: completed.summary.clone(),
        }
    }
}

impl From<&Failed> for pb::Failed {
    fn from(failed: &Failed) -> Self {
        Self {
            reason: failed.reason.clone(),
        }
    }
}

impl From<&pb::Failed> for Failed {
    fn from(failed: &pb::Failed) -> Self {
        Self {
            reason: failed.reason.clone(),
        }
    }
}

impl From<&Terminated> for pb::Terminated {
    fn from(terminated: &Terminated) -> Self {
        Self {
            reason: terminated.reason.clone(),
            terminated_by: terminated.terminated_by.clone(),
        }
    }
}

impl From<&pb::Terminated> for Terminated {
    fn from(terminated: &pb::Terminated) -> Self {
        Self {
            reason: terminated.reason.clone(),
            terminated_by: terminated.terminated_by.clone(),
        }
    }
}

impl From<&Suspended> for pb::Suspended {
    fn from(suspended: &Suspended) -> Self {
        Self {
            reason: suspended.reason.clone(),
        }
    }
}

impl From<&pb::Suspended> for Suspended {
    fn from(suspended: &pb::Suspended) -> Self {
        Self {
            reason: suspended.reason.clone(),
        }
    }
}

impl From<&Resumed> for pb::Resumed {
    fn from(resumed: &Resumed) -> Self {
        Self {
            resumed_by: resumed.resumed_by.clone(),
        }
    }
}

impl From<&pb::Resumed> for Resumed {
    fn from(resumed: &pb::Resumed) -> Self {
        Self {
            resumed_by: resumed.resumed_by.clone(),
        }
    }
}

// ============================================================================
// Adjudicated
// ============================================================================

impl From<&Adjudicated> for pb::Adjudicated {
    fn from(adj: &Adjudicated) -> Self {
        Self {
            decision: adj.decision.encode(),
            mode: adj.mode.encode(),
            reason: adj.reason.clone(),
            metadata: adj.metadata.iter().map(Into::into).collect(),
            guardrails: adj.guardrails.as_ref().map(Into::into),
            steering: adj.steering.as_ref().map(Into::into),
        }
    }
}

impl TryFrom<&pb::Adjudicated> for Adjudicated {
    type Error = ValidationError;

    fn try_from(adj: &pb::Adjudicated) -> Result<Self, Self::Error> {
        Ok(Self {
            decision: decode_enum(adj.decision, "decision")?,
            mode: decode_enum(adj.mode, "mode")?,
            reason: adj.reason.clone(),
            metadata: adj.metadata.iter().map(Into::into).collect(),
            guardrails: adj.guardrails.as_ref().map(Into::into),
            steering: adj.steering.as_ref().map(Into::into),
        })
    }
}

impl From<&Steering> for pb::Steering {
    fn from(steering: &Steering) -> Self {
        Self {
            instructions: steering.instructions.clone(),
            explanation: steering.explanation.clone(),
        }
    }
}

impl From<&pb::Steering> for Steering {
    fn from(steering: &pb::Steering) -> Self {
        Self {
            instructions: steering.instructions.clone(),
            explanation: steering.explanation.clone(),
        }
    }
}

impl From<&PolicyMetadata> for pb::PolicyMetadata {
    fn from(meta: &PolicyMetadata) -> Self {
        Self {
            policy_id: meta.policy_id.clone(),
            description: meta.description.clone(),
            escalate: meta.escalate,
            escalate_arg: meta.escalate_arg.clone(),
            metadata: meta.metadata.clone(),
        }
    }
}

impl From<&pb::PolicyMetadata> for PolicyMetadata {
    fn from(meta: &pb::PolicyMetadata) -> Self {
        Self {
            policy_id: meta.policy_id.clone(),
            description: meta.description.clone(),
            escalate: meta.escalate,
            escalate_arg: meta.escalate_arg.clone(),
            metadata: meta.metadata.clone(),
        }
    }
}

impl From<&GuardrailResults> for pb::GuardrailResults {
    fn from(results: &GuardrailResults) -> Self {
        Self {
            signature: results.signature.as_ref().map(Into::into),
            ifc: results.ifc.as_ref().map(Into::into),
        }
    }
}

impl From<&pb::GuardrailResults> for GuardrailResults {
    fn from(results: &pb::GuardrailResults) -> Self {
        Self {
            signature: results.signature.as_ref().map(Into::into),
            ifc: results.ifc.as_ref().map(Into::into),
        }
    }
}

impl From<&SignatureGuardrailResult> for pb::SignatureGuardrailResult {
    fn from(result: &SignatureGuardrailResult) -> Self {
        Self {
            triggered: result.triggered,
            severity: result.severity.clone(),
            categories: result.categories.clone(),
            matches: result.matches.iter().map(Into::into).collect(),
        }
    }
}

impl From<&pb::SignatureGuardrailResult> for SignatureGuardrailResult {
    fn from(result: &pb::SignatureGuardrailResult) -> Self {
        Self {
            triggered: result.triggered,
            severity: result.severity.clone(),
            categories: result.categories.clone(),
            matches: result.matches.iter().map(Into::into).collect(),
        }
    }
}

impl From<&SignatureGuardrailMatch> for pb::SignatureGuardrailMatch {
    fn from(matched: &SignatureGuardrailMatch) -> Self {
        Self {
            rule: matched.rule.clone(),
            namespace: matched.namespace.clone(),
            metadata: matched.metadata.clone(),
        }
    }
}

impl From<&pb::SignatureGuardrailMatch> for SignatureGuardrailMatch {
    fn from(matched: &pb::SignatureGuardrailMatch) -> Self {
        Self {
            rule: matched.rule.clone(),
            namespace: matched.namespace.clone(),
            metadata: matched.metadata.clone(),
        }
    }
}

impl From<&IfcGuardrailResult> for pb::IfcGuardrailResult {
    fn from(result: &IfcGuardrailResult) -> Self {
        Self {
            label: result.label.clone(),
            fallback_reason: result.fallback_reason.clone(),
        }
    }
}

impl From<&pb::IfcGuardrailResult> for IfcGuardrailResult {
    fn from(result: &pb::IfcGuardrailResult) -> Self {
        Self {
            label: result.label.clone(),
            fallback_reason: result.fallback_reason.clone(),
        }
    }
}

// ============================================================================
// Scanned
// ============================================================================

impl From<&Scanned> for pb::Scanned {
    fn from(scanned: &Scanned) -> Self {
        use pb::scanned::Scan;
        Self {
            scan: Some(match scanned {
                Scanned::Message {
                    source_event_id,
                    result,
                } => Scan::Message(pb::MessageScan {
                    source_event_id: source_event_id.clone(),
                    result: Some(result.into()),
                }),
                Scanned::TranscriptDigest {
                    source_event_id,
                    result,
                } => Scan::TranscriptDigest(pb::TranscriptDigestScan {
                    source_event_id: source_event_id.clone(),
                    result: Some(result.into()),
                }),
                Scanned::TranscriptScan {
                    source_event_id,
                    result,
                } => Scan::TranscriptScan(pb::TranscriptScan {
                    source_event_id: source_event_id.clone(),
                    result: Some(result.into()),
                }),
            }),
        }
    }
}

impl TryFrom<&pb::Scanned> for Scanned {
    type Error = ValidationError;

    fn try_from(scanned: &pb::Scanned) -> Result<Self, Self::Error> {
        use pb::scanned::Scan;
        let scan = require(scanned.scan.as_ref(), "scanned")?;
        Ok(match scan {
            Scan::Message(v) => Self::Message {
                source_event_id: v.source_event_id.clone(),
                result: require(v.result.as_ref(), "message.result")?.try_into()?,
            },
            Scan::TranscriptDigest(v) => Self::TranscriptDigest {
                source_event_id: v.source_event_id.clone(),
                result: require(v.result.as_ref(), "transcript_digest.result")?.into(),
            },
            Scan::TranscriptScan(v) => Self::TranscriptScan {
                source_event_id: v.source_event_id.clone(),
                result: require(v.result.as_ref(), "transcript_scan.result")?.try_into()?,
            },
        })
    }
}

impl From<&Signal> for pb::Signal {
    fn from(signal: &Signal) -> Self {
        Self {
            focus: signal.focus.encode(),
            category: signal.category.encode(),
            severity: signal.severity.encode(),
            description: signal.description.clone(),
            evidence_indices: encode_indices(&signal.evidence_indices),
        }
    }
}

impl TryFrom<&pb::Signal> for Signal {
    type Error = ValidationError;

    fn try_from(signal: &pb::Signal) -> Result<Self, Self::Error> {
        Ok(Self {
            focus: decode_enum(signal.focus, "focus")?,
            category: decode_enum(signal.category, "category")?,
            severity: decode_enum(signal.severity, "severity")?,
            description: signal.description.clone(),
            evidence_indices: decode_indices(&signal.evidence_indices),
        })
    }
}

impl From<&EventScanResult> for pb::EventScanResult {
    fn from(result: &EventScanResult) -> Self {
        Self {
            explanation: result.explanation.clone(),
            message_type: result.message_type.encode(),
            intent: result.intent.encode(),
            description: result.description.clone(),
            key_entities: result.key_entities.clone(),
            is_side_effecting: result.is_side_effecting,
            signals: result.signals.iter().map(Into::into).collect(),
            confidence: result.confidence,
            embedding: result.embedding.clone().unwrap_or_default(),
        }
    }
}

impl TryFrom<&pb::EventScanResult> for EventScanResult {
    type Error = ValidationError;

    fn try_from(result: &pb::EventScanResult) -> Result<Self, Self::Error> {
        Ok(Self {
            explanation: result.explanation.clone(),
            message_type: decode_enum(result.message_type, "message_type")?,
            intent: decode_enum(result.intent, "intent")?,
            description: result.description.clone(),
            key_entities: result.key_entities.clone(),
            is_side_effecting: result.is_side_effecting,
            signals: decode_all(&result.signals)?,
            confidence: result.confidence,
            // `repeated double` cannot distinguish "absent" from "empty", and an
            // empty embedding carries no information, so both decode to `None`.
            embedding: (!result.embedding.is_empty()).then(|| result.embedding.clone()),
        })
    }
}

impl From<&TranscriptPhase> for pb::TranscriptPhase {
    fn from(phase: &TranscriptPhase) -> Self {
        Self {
            name: phase.name.clone(),
            description: phase.description.clone(),
            event_indices: encode_indices(&phase.event_indices),
        }
    }
}

impl From<&pb::TranscriptPhase> for TranscriptPhase {
    fn from(phase: &pb::TranscriptPhase) -> Self {
        Self {
            name: phase.name.clone(),
            description: phase.description.clone(),
            event_indices: decode_indices(&phase.event_indices),
        }
    }
}

impl From<&TranscriptDigest> for pb::TranscriptDigest {
    fn from(digest: &TranscriptDigest) -> Self {
        Self {
            trajectory_id: digest.trajectory_id.clone(),
            title: digest.title.clone(),
            summary: digest.summary.clone(),
            interim: digest.interim,
            phases: digest.phases.iter().map(Into::into).collect(),
            files_modified: digest.files_modified.clone(),
            tools_used: digest.tools_used.clone(),
            total_events: u32_to_i32(digest.total_events),
            side_effecting_count: u32_to_i32(digest.side_effecting_count),
        }
    }
}

impl From<&pb::TranscriptDigest> for TranscriptDigest {
    fn from(digest: &pb::TranscriptDigest) -> Self {
        Self {
            trajectory_id: digest.trajectory_id.clone(),
            title: digest.title.clone(),
            summary: digest.summary.clone(),
            interim: digest.interim,
            phases: digest.phases.iter().map(Into::into).collect(),
            files_modified: digest.files_modified.clone(),
            tools_used: digest.tools_used.clone(),
            total_events: i32_to_u32(digest.total_events),
            side_effecting_count: i32_to_u32(digest.side_effecting_count),
        }
    }
}

impl From<&TranscriptScanResult> for pb::TranscriptScanResult {
    fn from(result: &TranscriptScanResult) -> Self {
        Self {
            explanation: result.explanation.clone(),
            outcome: result.outcome.encode(),
            outcome_description: result.outcome_description.clone(),
            aggregate_severity: result.aggregate_severity.encode(),
            signals: result.signals.iter().map(Into::into).collect(),
            adjudication_summary: result.adjudication_summary.clone(),
            behavioral_notes: result.behavioral_notes.clone(),
            confidence: result.confidence,
        }
    }
}

impl TryFrom<&pb::TranscriptScanResult> for TranscriptScanResult {
    type Error = ValidationError;

    fn try_from(result: &pb::TranscriptScanResult) -> Result<Self, Self::Error> {
        Ok(Self {
            explanation: result.explanation.clone(),
            outcome: decode_enum(result.outcome, "outcome")?,
            outcome_description: result.outcome_description.clone(),
            aggregate_severity: decode_enum(result.aggregate_severity, "aggregate_severity")?,
            signals: decode_all(&result.signals)?,
            adjudication_summary: result.adjudication_summary.clone(),
            behavioral_notes: result.behavioral_notes.clone(),
            confidence: result.confidence,
        })
    }
}

// ============================================================================
// State
// ============================================================================

impl From<&State> for pb::State {
    fn from(state: &State) -> Self {
        use pb::state::Kind;
        Self {
            kind: Some(match state {
                State::Snapshot(v) => Kind::Snapshot(v.into()),
            }),
        }
    }
}

impl TryFrom<&pb::State> for State {
    type Error = ValidationError;

    fn try_from(state: &pb::State) -> Result<Self, Self::Error> {
        use pb::state::Kind;
        let kind = require(state.kind.as_ref(), "state")?;
        Ok(match kind {
            Kind::Snapshot(v) => Self::Snapshot(v.into()),
        })
    }
}

impl From<&Snapshot> for pb::Snapshot {
    fn from(snapshot: &Snapshot) -> Self {
        Self {
            snapshot_id: snapshot.snapshot_id.clone(),
            working_dir: snapshot.working_dir.clone(),
            open_files: snapshot.open_files.clone(),
            git_branch: snapshot.git_branch.clone(),
            variables: snapshot
                .variables
                .iter()
                .map(|(key, value)| (key.clone(), json_to_proto_value(value)))
                .collect(),
        }
    }
}

impl From<&pb::Snapshot> for Snapshot {
    fn from(snapshot: &pb::Snapshot) -> Self {
        Self {
            snapshot_id: snapshot.snapshot_id.clone(),
            working_dir: snapshot.working_dir.clone(),
            open_files: snapshot.open_files.clone(),
            git_branch: snapshot.git_branch.clone(),
            variables: snapshot
                .variables
                .iter()
                .map(|(key, value)| (key.clone(), proto_value_to_json(value)))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sondera_types::Agent;
    use std::collections::HashMap;

    fn map(key: &str, value: &str) -> HashMap<String, String> {
        [(key.to_string(), value.to_string())].into_iter().collect()
    }

    /// Fixtures deliberately give every field a value derived from its own
    /// name, and give same-typed neighbours (`stdout`/`stderr`,
    /// `content`/`old_content`, `reason`/`terminated_by`, …) different values.
    /// A one-sided field swap then fails the equality instead of round-tripping
    /// through the mistake. Every `Option` is `Some` and every collection is
    /// non-empty so no field is skipped by being absent.
    mod populated {
        use super::*;

        fn signal() -> Signal {
            Signal {
                focus: SignalFocus::Governance,
                category: SignalCategory::CredentialExposure,
                severity: SignalSeverity::Critical,
                description: "description".to_string(),
                evidence_indices: vec![7, 8, 9],
            }
        }

        pub fn tool_call() -> TrajectoryEvent {
            TrajectoryEvent::Action(Action::ToolCall(ToolCall {
                call_id: "call_id".to_string(),
                tool: "tool".to_string(),
                arguments: serde_json::json!({ "nested": { "n": 3 }, "list": [1, 2] }),
            }))
        }

        pub fn shell_command() -> TrajectoryEvent {
            TrajectoryEvent::Action(Action::ShellCommand(ShellCommand {
                call_id: "call_id".to_string(),
                command: "command".to_string(),
                working_dir: Some("working_dir".to_string()),
            }))
        }

        pub fn web_fetch() -> TrajectoryEvent {
            TrajectoryEvent::Action(Action::WebFetch(WebFetch {
                call_id: "call_id".to_string(),
                url: "url".to_string(),
                prompt: "prompt".to_string(),
            }))
        }

        pub fn file_operation() -> TrajectoryEvent {
            TrajectoryEvent::Action(Action::FileOperation(FileOperation {
                call_id: "call_id".to_string(),
                operation: FileOpType::Delete,
                path: "path".to_string(),
                content: Some("content".to_string()),
                old_content: Some("old_content".to_string()),
            }))
        }

        pub fn prompt() -> TrajectoryEvent {
            TrajectoryEvent::Observation(Observation::Prompt(Prompt {
                content: "content".to_string(),
                role: PromptRole::Assistant,
            }))
        }

        pub fn thought() -> TrajectoryEvent {
            TrajectoryEvent::Observation(Observation::Thought(Thought {
                thought: "thought".to_string(),
            }))
        }

        pub fn tool_output() -> TrajectoryEvent {
            TrajectoryEvent::Observation(Observation::ToolOutput(ToolOutput {
                call_id: "call_id".to_string(),
                success: true,
                output: serde_json::json!({ "lines": 12, "truncated": false }),
                error: Some("error".to_string()),
            }))
        }

        pub fn shell_command_output() -> TrajectoryEvent {
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(ShellCommandOutput {
                call_id: "call_id".to_string(),
                exit_code: 42,
                stdout: "stdout".to_string(),
                stderr: "stderr".to_string(),
            }))
        }

        pub fn web_fetch_output() -> TrajectoryEvent {
            TrajectoryEvent::Observation(Observation::WebFetchOutput(WebFetchOutput {
                call_id: "call_id".to_string(),
                url: "url".to_string(),
                code: 404,
                result: "result".to_string(),
            }))
        }

        pub fn file_operation_result() -> TrajectoryEvent {
            TrajectoryEvent::Observation(Observation::FileOperationResult(FileOperationResult {
                call_id: "call_id".to_string(),
                success: false,
                path: Some("/workspace/input.md".to_string()),
                content: Some("content".to_string()),
                error: Some("error".to_string()),
            }))
        }

        pub fn started() -> TrajectoryEvent {
            TrajectoryEvent::Control(Control::Started(Started {
                agent: Agent {
                    id: "id".to_string(),
                    provider: "provider".to_string(),
                    platform: "platform".to_string(),
                },
                task: Some("task".to_string()),
            }))
        }

        pub fn completed() -> TrajectoryEvent {
            TrajectoryEvent::Control(Control::Completed(Completed {
                summary: Some("summary".to_string()),
            }))
        }

        pub fn failed() -> TrajectoryEvent {
            TrajectoryEvent::Control(Control::Failed(Failed {
                reason: "reason".to_string(),
            }))
        }

        pub fn terminated() -> TrajectoryEvent {
            TrajectoryEvent::Control(Control::Terminated(Terminated {
                reason: "reason".to_string(),
                terminated_by: "terminated_by".to_string(),
            }))
        }

        pub fn suspended() -> TrajectoryEvent {
            TrajectoryEvent::Control(Control::Suspended(Suspended {
                reason: "reason".to_string(),
            }))
        }

        pub fn resumed() -> TrajectoryEvent {
            TrajectoryEvent::Control(Control::Resumed(Resumed {
                resumed_by: "resumed_by".to_string(),
            }))
        }

        pub fn adjudicated() -> TrajectoryEvent {
            TrajectoryEvent::Control(Control::Adjudicated(Adjudicated {
                decision: Decision::Allow,
                mode: Mode::Steer,
                reason: Some("reason".to_string()),
                metadata: vec![PolicyMetadata {
                    policy_id: Some("policy_id".to_string()),
                    description: Some("description".to_string()),
                    escalate: true,
                    escalate_arg: Some("escalate_arg".to_string()),
                    metadata: map("meta_key", "meta_value"),
                }],
                guardrails: Some(GuardrailResults {
                    signature: Some(SignatureGuardrailResult {
                        triggered: true,
                        severity: Some("severity".to_string()),
                        categories: vec!["categories".to_string()],
                        matches: vec![SignatureGuardrailMatch {
                            rule: "rule".to_string(),
                            namespace: Some("namespace".to_string()),
                            metadata: map("match_key", "match_value"),
                        }],
                    }),
                    ifc: Some(IfcGuardrailResult {
                        label: "label".to_string(),
                        fallback_reason: Some("fallback_reason".to_string()),
                    }),
                }),
                steering: Some(Steering {
                    instructions: vec!["instructions".to_string()],
                    explanation: "explanation".to_string(),
                }),
            }))
        }

        pub fn message_scan() -> TrajectoryEvent {
            TrajectoryEvent::Control(Control::Scanned(Scanned::Message {
                source_event_id: "source_event_id".to_string(),
                result: EventScanResult {
                    explanation: "explanation".to_string(),
                    message_type: MessageType::StateCapture,
                    intent: AgentIntent::Communicate,
                    description: "description".to_string(),
                    key_entities: vec!["key_entities".to_string()],
                    is_side_effecting: true,
                    signals: vec![signal()],
                    confidence: 0.25,
                    // `Some(vec![])` decodes to `None` by design, so the
                    // fixture has to be non-empty to round-trip.
                    embedding: Some(vec![0.5, 0.75]),
                },
            }))
        }

        pub fn digest_scan() -> TrajectoryEvent {
            TrajectoryEvent::Control(Control::Scanned(Scanned::TranscriptDigest {
                source_event_id: "source_event_id".to_string(),
                result: TranscriptDigest {
                    trajectory_id: "trajectory_id".to_string(),
                    title: "title".to_string(),
                    summary: "summary".to_string(),
                    interim: true,
                    phases: vec![TranscriptPhase {
                        name: "name".to_string(),
                        description: "description".to_string(),
                        event_indices: vec![1, 2],
                    }],
                    files_modified: vec!["files_modified".to_string()],
                    tools_used: vec!["tools_used".to_string()],
                    total_events: 11,
                    side_effecting_count: 22,
                },
            }))
        }

        pub fn transcript_scan() -> TrajectoryEvent {
            TrajectoryEvent::Control(Control::Scanned(Scanned::TranscriptScan {
                source_event_id: "source_event_id".to_string(),
                result: TranscriptScanResult {
                    explanation: "explanation".to_string(),
                    outcome: TranscriptOutcome::Interrupted,
                    outcome_description: "outcome_description".to_string(),
                    aggregate_severity: SignalSeverity::Medium,
                    signals: vec![signal()],
                    adjudication_summary: "adjudication_summary".to_string(),
                    behavioral_notes: vec!["behavioral_notes".to_string()],
                    confidence: 0.5,
                },
            }))
        }

        pub fn snapshot() -> TrajectoryEvent {
            TrajectoryEvent::State(State::Snapshot(Snapshot {
                snapshot_id: "snapshot_id".to_string(),
                working_dir: Some("working_dir".to_string()),
                open_files: vec!["open_files".to_string()],
                git_branch: Some("git_branch".to_string()),
                variables: [("depth".to_string(), serde_json::json!(3))]
                    .into_iter()
                    .collect(),
            }))
        }
    }

    #[rstest]
    #[case::action_tool_call(populated::tool_call())]
    #[case::action_shell_command(populated::shell_command())]
    #[case::action_web_fetch(populated::web_fetch())]
    #[case::action_file_operation(populated::file_operation())]
    #[case::observation_prompt(populated::prompt())]
    #[case::observation_thought(populated::thought())]
    #[case::observation_tool_output(populated::tool_output())]
    #[case::observation_shell_command_output(populated::shell_command_output())]
    #[case::observation_web_fetch_output(populated::web_fetch_output())]
    #[case::observation_file_operation_result(populated::file_operation_result())]
    #[case::control_started(populated::started())]
    #[case::control_completed(populated::completed())]
    #[case::control_failed(populated::failed())]
    #[case::control_terminated(populated::terminated())]
    #[case::control_suspended(populated::suspended())]
    #[case::control_resumed(populated::resumed())]
    #[case::control_adjudicated(populated::adjudicated())]
    #[case::control_scanned_message(populated::message_scan())]
    #[case::control_scanned_digest(populated::digest_scan())]
    #[case::control_scanned_transcript(populated::transcript_scan())]
    #[case::state_snapshot(populated::snapshot())]
    fn every_trajectory_event_variant_survives_a_proto_roundtrip(#[case] payload: TrajectoryEvent) {
        let proto: pb::TrajectoryEvent = (&payload).into();

        assert_eq!(
            TrajectoryEvent::try_from(&proto).expect("roundtrip"),
            payload
        );
    }

    #[test]
    fn an_unspecified_mode_is_rejected_rather_than_read_as_monitor() {
        // The permissive mode is the domain default, so a dropped `mode` that
        // decoded silently would record an enforced deny as merely observed.
        let err = decode_enum::<Mode>(pb::Mode::Unspecified as i32, "mode")
            .expect_err("UNSPECIFIED mode must be rejected");

        assert!(err.to_string().contains("'mode'"), "{err}");
    }

    #[test]
    fn enforcement_enums_encode_to_their_declared_wire_discriminants() {
        // Pins the numbers rather than the mapping: a round-trip test cannot
        // catch a symmetric `enum_conv!` mis-pair, nor a proto renumbering.
        assert_eq!(Decision::Allow.encode(), 1);
        assert_eq!(Decision::Deny.encode(), 2);
        assert_eq!(Decision::Escalate.encode(), 3);
        assert_eq!(Mode::Monitor.encode(), 1);
        assert_eq!(Mode::Govern.encode(), 2);
        assert_eq!(Mode::Steer.encode(), 3);
    }
}
