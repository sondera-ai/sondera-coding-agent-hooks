// One-line event summaries for timeline/tree rows.
//
// Payload field names are harness snake_case (crates/harness/src/types.rs:
// ShellCommand.command, FileOperation.operation/.path, WebFetchOutput.url/
// .code, …) and `data` is an untyped Record — every read is defensive.
//
// SECURITY: every return value is a plain string and every render site uses
// Svelte text interpolation only — no HTML is ever constructed from event
// content (shell commands, file contents, fetched bodies and prompts are all
// attacker-influenced).
//
// Summaries are truncated to ~120 chars so oversized payloads never dump into
// row DOM; full payloads appear only in the detail panel's collapsed JSON.

import type { EventDto } from '$lib/api/types';

const MAX = 120;

/** First line only, hard-capped at MAX chars. */
function clip(s: string): string {
	const line = s.split('\n', 1)[0] ?? '';
	return line.length > MAX ? `${line.slice(0, MAX)}…` : line;
}

function asString(v: unknown): string | null {
	return typeof v === 'string' ? v : null;
}

/** Defensive fallback for unknown/missing shapes: truncated JSON text. */
function asJson(v: unknown): string {
	try {
		return clip(JSON.stringify(v) ?? '');
	} catch {
		return '';
	}
}

/** One-line, plain-text summary per payload type. */
export function summarize(e: EventDto): string {
	const { type, data } = e.event.payload;
	const d: Record<string, unknown> = data;
	switch (type) {
		case 'ShellCommand':
			return clip(asString(d['command']) ?? asJson(d));
		case 'FileOperation': {
			const op = asString(d['operation']) ?? asString(d['op']) ?? 'op';
			const path = asString(d['path']) ?? '';
			return clip(`${op} ${path}`.trim());
		}
		case 'WebFetch':
			return clip(asString(d['url']) ?? asJson(d));
		case 'WebFetchOutput': {
			const url = asString(d['url']);
			if (url === null) return asJson(d);
			const code = typeof d['code'] === 'number' ? ` (${d['code']})` : '';
			return clip(`${url}${code}`);
		}
		case 'ToolCall':
			return clip(asString(d['tool']) ?? asString(d['name']) ?? asJson(d));
		case 'Prompt': {
			const role = asString(d['role']) ?? 'prompt';
			const content = asString(d['content']) ?? '';
			return clip(`${role}: ${content}`);
		}
		case 'Think':
			return clip(asString(d['thought']) ?? asJson(d));
		case 'ToolOutput': {
			const error = asString(d['error']);
			if (error !== null) return clip(error);
			const output = d['output'];
			return typeof output === 'string' ? clip(output) : asJson(output);
		}
		case 'ShellCommandOutput': {
			const exit = typeof d['exit_code'] === 'number' ? `exit ${d['exit_code']}` : '';
			const stdout = asString(d['stdout']) ?? '';
			const stderr = asString(d['stderr']) ?? '';
			const body = stdout !== '' ? stdout : stderr;
			const joined = [exit, body].filter((s) => s !== '').join(' · ');
			return joined !== '' ? clip(joined) : asJson(d);
		}
		case 'FileOperationResult': {
			const error = asString(d['error']);
			if (error !== null) return clip(error);
			const content = asString(d['content']);
			if (content !== null) return clip(content);
			return d['success'] === true ? 'ok' : asJson(d);
		}
		case 'Started': {
			const task = asString(d['task']);
			return task !== null ? clip(`Started — ${task}`) : 'Started';
		}
		case 'Completed':
			return 'Completed';
		case 'Failed':
			return clip(`Failed — ${asString(d['reason']) ?? ''}`);
		case 'Terminated':
			return clip(`Terminated — ${asString(d['reason']) ?? ''}`);
		case 'Suspended':
			return clip(`Suspended — ${asString(d['reason']) ?? ''}`);
		case 'Resumed': {
			const by = asString(d['resumed_by']);
			return by !== null ? clip(`Resumed by ${by}`) : 'Resumed';
		}
		case 'Adjudicated': {
			const decision = asString(d['decision']);
			return decision !== null ? clip(`decision: ${decision}`) : asJson(d);
		}
		case 'Snapshot':
			return 'state snapshot';
		default:
			return asJson(d);
	}
}
