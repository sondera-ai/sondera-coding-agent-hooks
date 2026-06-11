// TypeScript mirror of the dashboard wire contract (crates/dashboard/src/dto.rs).
// Casing varies by field and is pinned here:
//
//   - DTO object keys:            camelCase
//   - `decision`:                 PascalCase ('Allow' | 'Deny' | 'Escalate')
//   - monitor verdict/state/label: lowercase snake_case
//   - stream envelope keys:       snake_case (`type`, `trajectory_id`, `data`, `missed`)
//
// Optional fields are absent from the JSON when None (serde skip_serializing_if),
// hence `?` — except `monitor.taints`, which serializes even when empty.

// ============================================================================
// Pinned enums (exact wire strings)
// ============================================================================

/** Cedar decision — PascalCase on the wire (Debug rendering of the enum). */
export type Decision = 'Allow' | 'Deny' | 'Escalate';

/** Monitor verdict — snake_case serde rendering of the harness `Verdict`. */
export type MonitorVerdict = 'satisfied' | 'violated' | 'pending';

/** Monitor FSM state name. */
export type MonitorState = 'clean' | 'armed' | 'violated';

/** IFC sensitivity label — snake_case serde rendering. */
export type Label = 'public' | 'internal' | 'confidential' | 'highly_confidential';

/** Trajectory lifecycle status, flattened onto each list row. */
export type TrajectoryStatus = 'active' | 'completed' | 'failed' | 'terminated';

// ============================================================================
// GET /health (the token-validation target)
// ============================================================================

export interface DbHealth {
	state: 'absent' | 'readable' | 'unavailable';
	eventCount?: number;
	snapshotAgeSeconds?: number;
}

export interface JsonlHealth {
	state: 'readable' | 'absent';
	fileCount: number;
}

export interface HealthDto {
	status: string;
	db: DbHealth;
	jsonl: JsonlHealth;
}

// ============================================================================
// GET /trajectories (list page)
// ============================================================================

/** One row of the trajectory list: TrajectorySummaryDto + flattened `status`. */
export interface TrajectoryListItem {
	status: TrajectoryStatus;
	trajectoryId: string;
	eventCount: number;
	firstEventAt?: string;
	lastEventAt?: string;
	durationSeconds?: number;
	agentId?: string;
	agentProvider?: string;
	actionCount: number;
	observationCount: number;
	controlCount: number;
	stateCount: number;
	/** Cedar-actor records only — monitor mirrors can never inflate this. */
	denyCount: number;
	escalateCount: number;
}

export interface TrajectoryListResponse {
	trajectories: TrajectoryListItem[];
	/** Keyset cursor — present only when the page is full; pass BOTH back. */
	nextBefore?: string;
	nextBeforeId?: string;
}

/** Client-side filter params; serialized by the client with snake_case keys
 * and REPEATED keys for array dimensions (dimensions AND, values OR). */
export interface ListFilterParams {
	decision?: Decision[];
	label?: Label[];
	policyId?: string[];
	/** RFC 3339, strict. */
	from?: string;
	to?: string;
	/** Clamped server-side to 1..=200, default 50. */
	limit?: number;
	/** Keyset cursor: both or neither (server 400s on half a cursor). */
	before?: string;
	beforeId?: string;
}

// ============================================================================
// The harness TrajectoryEvent (nested tagging)
// ============================================================================

/** Outer tagging is `category`/`payload`; inner enums tag with `type`/`data`;
 * payload field names keep harness snake_case (e.g. `command`, `working_dir`). */
export type TrajectoryEvent =
	| {
			category: 'Action';
			payload: {
				type: 'ToolCall' | 'ShellCommand' | 'WebFetch' | 'FileOperation';
				data: Record<string, unknown>;
			};
	  }
	| {
			category: 'Observation';
			payload: {
				type:
					| 'Prompt'
					| 'Think'
					| 'ToolOutput'
					| 'ShellCommandOutput'
					| 'WebFetchOutput'
					| 'FileOperationResult';
				data: Record<string, unknown>;
			};
	  }
	| {
			category: 'Control';
			payload: {
				type:
					| 'Started'
					| 'Completed'
					| 'Failed'
					| 'Terminated'
					| 'Suspended'
					| 'Resumed'
					| 'Adjudicated';
				data: Record<string, unknown>;
			};
	  }
	| {
			category: 'State';
			payload: { type: 'Snapshot'; data: Record<string, unknown> };
	  };

// ============================================================================
// GET /trajectories/{id}/events
// ============================================================================

export interface EventDto {
	eventId: string;
	trajectoryId: string;
	agentId: string;
	agentProvider: string;
	/** RFC 3339. */
	timestamp: string;
	actorId: string;
	/** Debug rendering of the actor type: "Agent" | "System" | "Policy". */
	actorType: string;
	correlationId: string;
	/** For Adjudicated/snapshot records: the event_id this record adjudicated.
	 * Hook-adapter events carry no causation today. */
	causationId?: string;
	parentId?: string;
	/** Full typed event payload — no truncation. */
	event: TrajectoryEvent;
}

// ============================================================================
// GET /trajectories/{id}/adjudications
// ============================================================================

export interface AnnotationDto {
	policyId?: string;
	description?: string;
	/** Absent on the wire when empty (serde skips empty maps) — match the
	 * backstop PAIR via `annotations?.['source'] === 'monitor'`. */
	annotations?: Record<string, string>;
}

export interface MonitorDto {
	verdict: MonitorVerdict;
	state: MonitorState;
	armedEventId?: string;
	clearedEventId?: string;
	trippedEventId?: string;
	untrustedPending: boolean;
	/** Always present, even when empty (monitor mirror). */
	taints: string[];
	label: Label;
}

/** Cedar request identity triple; the request context object never crosses. */
export interface CedarRequestDto {
	principal?: string;
	action?: string;
	resource?: string;
}

export interface CedarResponseDto {
	decision: string;
	reasonPolicyIds: string[];
	errors: string[];
}

export interface SignatureSignalDto {
	matches: number;
	categories: string[];
	severity: number;
}

export interface PolicySignalDto {
	compliant: boolean;
	violations: string[];
}

export interface GuardrailSignalsDto {
	signature?: SignatureSignalDto;
	policy?: PolicySignalDto;
	/** Per-event IFC label, snake_case (same convention as MonitorDto.label). */
	label?: Label;
}

/** An adjudication record. NOTE: it has NO causationId field — the timeline
 * join goes through the Adjudicated EventDto's `causationId` (the triggering
 * event) matched against this record's `eventId`. */
export interface AdjudicationDto {
	eventId: string;
	trajectoryId: string;
	/** RFC 3339. */
	timestamp: string;
	/** 'cedar' = real Cedar adjudication; 'monitor' = synthetic snapshot record. */
	actorId: string;
	decision: Decision;
	reason?: string;
	annotations: AnnotationDto[];
	monitor?: MonitorDto;
	request?: CedarRequestDto;
	response?: CedarResponseDto;
	guardrails?: GuardrailSignalsDto;
}

// ============================================================================
// GET /stream (WebSocket) — envelope with snake_case keys
// ============================================================================

export type StreamEnvelope =
	| { type: 'event'; trajectory_id: string; data: EventDto }
	| { type: 'adjudication'; trajectory_id: string; data: AdjudicationDto }
	| { type: 'lagged'; missed: number };

// ============================================================================
// Client-side error type
// ============================================================================

/** Thrown by the API client for non-OK responses. `message` carries the
 * server's `{"error": …}` body verbatim for 400s (rendered by the filter
 * bar), a generic fallback otherwise. 401s are bodyless — status only. */
export class ApiError extends Error {
	readonly status: number;

	constructor(status: number, message: string) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
	}
}
