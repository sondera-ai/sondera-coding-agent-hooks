// Timeline <-> adjudication join.
//
// The load-bearing data fact (crates/dashboard/src/dto.rs): `AdjudicationDto`
// has no causationId. The join is two-step — the events list contains the
// Adjudicated control records (EventDto) whose `causationId` points at the
// triggering event and whose `eventId` equals the AdjudicationDto's `eventId`.
// This module encapsulates that index so every view (timeline badges, tree
// children, detail panel, live merge) shares one correct implementation.

import type { AdjudicationDto, AnnotationDto, EventDto, MonitorDto } from '$lib/api/types';

/** Anti-spoofing backstop check: an annotation is a monitor backstop only
 * when both markers match — `policyId` starts with `monitor-backstop-` and
 * `annotations.source === 'monitor'`. A Cedar policy minting either marker
 * alone never earns the badge. */
export function isBackstop(a: AnnotationDto): boolean {
	return (
		(a.policyId?.startsWith('monitor-backstop-') ?? false) &&
		a.annotations?.['source'] === 'monitor'
	);
}

/** Latest monitor verdict: the LAST adjudication record carrying a monitor
 * block. Unlike the decision index (cedar-actor only), BOTH cedar and
 * monitor-actor records qualify here — the monitor block is the harness's
 * own state mirror either way. */
export function latestMonitor(adjudications: AdjudicationDto[]): MonitorDto | null {
	for (let i = adjudications.length - 1; i >= 0; i--) {
		const m = adjudications[i]?.monitor;
		if (m !== undefined) return m;
	}
	return null;
}

/** True for Control/Adjudicated records — the adjudication mirrors written
 * by the harness (both cedar-actor decisions AND monitor-actor snapshots).
 * These never render as primary timeline rows. */
export function isAdjudicatedRecord(e: EventDto): boolean {
	return e.event.category === 'Control' && e.event.payload.type === 'Adjudicated';
}

/** True for events that render as primary timeline rows. Everything except
 * Adjudicated records qualifies: Action/Observation rows are the agent's
 * sequence, and Control lifecycle rows (Started/Resumed/…) plus State
 * snapshots render as muted rows so approvals stay visible. */
export function isAgentRow(e: EventDto): boolean {
	return !isAdjudicatedRecord(e);
}

/**
 * Build the decision index: triggering event id -> its cedar adjudication.
 *
 * Two-step join (dto.rs ground truth):
 *   1. index AdjudicationDto records by their own `eventId`;
 *   2. for each Adjudicated EventDto in the events list, follow its
 *      `causationId` (the triggering event) and map it to the adjudication
 *      record sharing the Adjudicated event's `eventId`.
 *
 * Only `actorId === 'cedar'` records enter the index: monitor-actor records
 * are synthetic Started/Resumed snapshots and must never colorize timeline
 * rows as decisions.
 */
export function buildDecisionIndex(
	events: EventDto[],
	adjudications: AdjudicationDto[]
): Map<string, AdjudicationDto> {
	const byEventId = new Map<string, AdjudicationDto>();
	for (const adjudication of adjudications) {
		byEventId.set(adjudication.eventId, adjudication);
	}

	const index = new Map<string, AdjudicationDto>();
	for (const e of events) {
		// The causationId is read from the EVENTS list (the Adjudicated
		// EventDto), never from the adjudication record — it has none.
		if (!isAdjudicatedRecord(e) || e.causationId === undefined) continue;
		const adjudication = byEventId.get(e.eventId);
		if (adjudication !== undefined && adjudication.actorId === 'cedar') {
			index.set(e.causationId, adjudication);
		}
	}
	return index;
}
