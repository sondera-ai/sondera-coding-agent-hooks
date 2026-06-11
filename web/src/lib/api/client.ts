// Bearer-auth fetch wrapper + typed API functions.
//
// Auth contract (crates/dashboard/src/auth.rs):
//   - REST: `Authorization: Bearer` header only — the token never rides a
//     REST query string. The query-param credential exists solely for the WS
//     upgrade (the stream module, via WS_BASE below).
//   - 401s are bodyless — detection is status-only; any 401 clears the stored
//     token and the layout gate returns to the token screen.

import { token } from '$lib/stores/token.svelte';
import { snapshot } from '$lib/stores/snapshot.svelte';
import {
	ApiError,
	type AdjudicationDto,
	type EventDto,
	type HealthDto,
	type ListFilterParams,
	type TrajectoryListResponse
} from './types';

// Dev: direct cross-origin to the loopback API (the CORS allowlist already
// covers Vite's 5173 origins). Prod: same-origin (relative), served by the
// dashboard's --ui-dir static fallback. No Vite proxy.
export const API_BASE = import.meta.env.DEV ? 'http://127.0.0.1:8787' : '';

/** WS endpoint base for the stream module. */
export const WS_BASE = API_BASE
	? API_BASE.replace(/^http/, 'ws')
	: `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`;

/**
 * Authenticated fetch against the dashboard API.
 *
 * - Attaches `Authorization: Bearer <token>` (header only, never the URL).
 * - Captures `x-sondera-snapshot-at` (the only CORS-exposed header) into the
 *   snapshot store on every response.
 * - 401 → clears the token, throws ApiError(401) — bodyless, status-only.
 * - 400 → parses the server's `{"error": …}` body into ApiError.message
 *   (rendered verbatim by the filter bar).
 * - Other non-OK → generic ApiError.
 */
export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
	const headers = new Headers(init?.headers);
	if (token.value !== null) {
		headers.set('Authorization', `Bearer ${token.value}`);
	}

	const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
	snapshot.update(res.headers.get('x-sondera-snapshot-at'));

	if (res.status === 401) {
		token.clear(); // the layout gate reacts
		throw new ApiError(401, 'token rejected');
	}
	if (res.status === 400) {
		let message = 'bad request';
		try {
			const body: unknown = await res.json();
			if (
				typeof body === 'object' &&
				body !== null &&
				'error' in body &&
				typeof (body as { error: unknown }).error === 'string'
			) {
				message = (body as { error: string }).error;
			}
		} catch {
			// non-JSON 400 body — keep the generic message
		}
		throw new ApiError(400, message);
	}
	if (!res.ok) {
		throw new ApiError(res.status, `request failed (${res.status})`);
	}
	return res;
}

export async function fetchHealth(): Promise<HealthDto> {
	const res = await apiFetch('/health');
	return res.json();
}

// Approvals are a WRITE (they mutate monitor state), so they target the
// separate `sondera-approve --serve` endpoint — never the read-only dashboard
// API. Run that endpoint with SONDERA_APPROVE_TOKEN matching the dashboard
// token so the stored bearer token is accepted. Override with VITE_APPROVE_BASE.
const approveBaseEnv: string = import.meta.env.VITE_APPROVE_BASE ?? '';
export const APPROVE_BASE = approveBaseEnv || (import.meta.env.DEV ? 'http://127.0.0.1:8799' : '');

export interface ApproveResult {
	trajectoryId: string;
	resumedBy: string;
	decision: string;
}

/**
 * Inject a user approval for a trajectory's armed multi-hop obligation. Clears
 * Armed → Clean; a Violated trajectory is terminal and is not recovered (the
 * server still returns 200). Reuses the stored bearer token.
 */
export async function approveTrajectory(trajectoryId: string): Promise<ApproveResult> {
	if (APPROVE_BASE === '') {
		throw new ApiError(0, 'approval endpoint not configured — set VITE_APPROVE_BASE');
	}
	const headers = new Headers({ 'Content-Type': 'application/json' });
	if (token.value !== null) headers.set('Authorization', `Bearer ${token.value}`);

	let res: Response;
	try {
		res = await fetch(`${APPROVE_BASE}/approve`, {
			method: 'POST',
			headers,
			body: JSON.stringify({ trajectory_id: trajectoryId })
		});
	} catch (err) {
		throw new ApiError(
			0,
			`approval endpoint unreachable — is \`sondera-approve --serve\` running? (${err instanceof Error ? err.message : String(err)})`
		);
	}

	if (res.status === 401) {
		throw new ApiError(
			401,
			'approval token rejected — launch `sondera-approve --serve` with SONDERA_APPROVE_TOKEN set to your dashboard token'
		);
	}
	if (!res.ok) {
		let detail = `approval failed (${res.status})`;
		try {
			detail = (await res.text()) || detail;
		} catch {
			// keep the generic message
		}
		throw new ApiError(res.status, detail);
	}

	const body: { trajectory_id: string; resumed_by: string; decision: string } = await res.json();
	return { trajectoryId: body.trajectory_id, resumedBy: body.resumed_by, decision: body.decision };
}

/**
 * List trajectories. Query-string semantics (crates/dashboard/src/filter.rs):
 * snake_case param names, REPEATED keys for OR within a dimension
 * (`decision=Deny&decision=Escalate`), dimensions AND together, and the
 * keyset cursor is all-or-nothing — `before` + `before_id` are emitted only
 * as a pair (the server 400s on half a cursor).
 */
export async function fetchTrajectories(
	params: ListFilterParams = {}
): Promise<TrajectoryListResponse> {
	const query = new URLSearchParams();
	for (const decision of params.decision ?? []) query.append('decision', decision);
	for (const label of params.label ?? []) query.append('label', label);
	for (const policyId of params.policyId ?? []) query.append('policy_id', policyId);
	if (params.from !== undefined) query.append('from', params.from);
	if (params.to !== undefined) query.append('to', params.to);
	if (params.limit !== undefined) query.append('limit', String(params.limit));
	if (params.before !== undefined && params.beforeId !== undefined) {
		query.append('before', params.before);
		query.append('before_id', params.beforeId);
	}

	const qs = query.toString();
	const res = await apiFetch(`/trajectories${qs ? `?${qs}` : ''}`);
	return res.json();
}

export async function fetchEvents(id: string): Promise<EventDto[]> {
	const res = await apiFetch(`/trajectories/${encodeURIComponent(id)}/events`);
	return res.json();
}

export async function fetchAdjudications(id: string): Promise<AdjudicationDto[]> {
	const res = await apiFetch(`/trajectories/${encodeURIComponent(id)}/adjudications`);
	return res.json();
}

/** Discriminated result for the token screen. */
export type TokenValidation =
	| { result: 'ok' }
	| { result: 'rejected' }
	| { result: 'unreachable'; detail: string };

/**
 * Probe `GET /health` with a candidate token WITHOUT storing it first.
 * 200 → ok; 401 → rejected (bodyless — status-only); anything else
 * (network error, 5xx) → unreachable.
 */
export async function validateToken(candidate: string): Promise<TokenValidation> {
	try {
		const res = await fetch(`${API_BASE}/health`, {
			headers: { Authorization: `Bearer ${candidate}` }
		});
		if (res.status === 401) return { result: 'rejected' };
		if (!res.ok) return { result: 'unreachable', detail: `status ${res.status}` };
		snapshot.update(res.headers.get('x-sondera-snapshot-at'));
		return { result: 'ok' };
	} catch (err) {
		return {
			result: 'unreachable',
			detail: err instanceof Error ? err.message : String(err)
		};
	}
}
