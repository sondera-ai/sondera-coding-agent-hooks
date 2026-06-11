// Live /stream WebSocket client.
//
// Hand-rolled deliberately: the npm reconnect wrappers are unmaintained, and
// the resync hooks need custom integration anyway.
//
// Auth contract: the bearer token rides `?token=` on the WS upgrade only —
// never a REST URL, never a log line. This module is the single place in
// web/src where a token appears in a URL, and the server never logs URIs on
// /stream.

import { WS_BASE, fetchHealth } from '$lib/api/client';
import { ApiError, type StreamEnvelope } from '$lib/api/types';

/** Envelopes delivered to view merge handlers (`lagged` is consumed
 * internally by the resync flow and never reaches views). */
export type DataEnvelope = Extract<StreamEnvelope, { type: 'event' | 'adjudication' }>;

export type MessageHandler = (envelope: DataEnvelope) => void;
export type ResyncHandler = () => Promise<void>;

// Full-jitter exponential backoff: delay drawn uniformly from
// [0, min(cap, base * factor^attempt)).
const BACKOFF_BASE_MS = 500;
const BACKOFF_FACTOR = 2;
const BACKOFF_CAP_MS = 30_000;

class LiveStream {
	/** Drives the header chip dot (green Live / amber Reconnecting…). */
	status = $state<'live' | 'reconnecting' | 'off'>('off');

	/** Persistent gap notice: `missed` is set on a `lagged` envelope and
	 * undefined on a plain reconnect. Never auto-cleared on resync — the chip
	 * note must outlive the transient toast and clears only on the next clean
	 * page load. */
	lastGap = $state<{ missed?: number; at: Date } | null>(null);

	/** Per-envelope merge handlers. Views register on mount and unregister on
	 * destroy via the returned function; every handler runs for every
	 * event/adjudication envelope (views filter by trajectory_id themselves —
	 * single firehose). */
	private messageHandlers = new Set<MessageHandler>();

	/** Resync hooks: all awaited before any later envelope is processed, so no
	 * stale deltas merge over pre-resync state. Views re-fetch their REST state
	 * here. */
	private resyncHandlers = new Set<ResyncHandler>();

	/** Fired AFTER a resync completes — the layout's transient-toast hook.
	 * `lastGap` is up to date when this runs (missed set ⇒ lag resync). */
	onResynced: (() => void) | null = null;

	private ws: WebSocket | null = null;
	private token: string | null = null;
	private attempt = 0;
	private timer: ReturnType<typeof setTimeout> | null = null;
	/** Bumped on every connect/disconnect so stale async callbacks no-op. */
	private generation = 0;
	/** Promise chain serializing all message work: a `lagged` resync must
	 * finish before later envelopes merge. */
	private queue: Promise<void> = Promise.resolve();

	/** Register a merge handler; returns the unregister function. */
	onMessage(handler: MessageHandler): () => void {
		this.messageHandlers.add(handler);
		return () => this.messageHandlers.delete(handler);
	}

	/** Register a resync hook; returns the unregister function. */
	onResync(handler: ResyncHandler): () => void {
		this.resyncHandlers.add(handler);
		return () => this.resyncHandlers.delete(handler);
	}

	connect(token: string): void {
		this.disconnect();
		this.token = token;
		this.generation += 1;
		this.attempt = 0;
		this.open(this.generation);
	}

	disconnect(): void {
		this.generation += 1;
		if (this.timer !== null) {
			clearTimeout(this.timer);
			this.timer = null;
		}
		if (this.ws !== null) {
			// Detach handlers first so the intentional close neither schedules
			// a reconnect nor flips status.
			this.ws.onopen = null;
			this.ws.onmessage = null;
			this.ws.onclose = null;
			this.ws.close();
			this.ws = null;
		}
		this.token = null;
		this.attempt = 0;
		this.status = 'off';
	}

	private open(gen: number): void {
		if (gen !== this.generation || this.token === null) return;
		// ?token= on the WS upgrade only. The URL is never logged.
		const ws = new WebSocket(`${WS_BASE}/stream?token=${encodeURIComponent(this.token)}`);
		this.ws = ws;

		ws.onopen = () => {
			if (gen !== this.generation) return;
			const reconnected = this.attempt > 0;
			this.attempt = 0;
			this.status = 'live';
			if (reconnected) {
				// Heal the drop gap before any post-reopen envelope merges (the
				// queue serializes). Subscribe-after-connect means messages during
				// the outage are gone — REST re-hydration is the state.
				this.enqueue(gen, async () => {
					await this.resync();
					this.lastGap = { at: new Date() }; // reconnected notice — no count
					this.onResynced?.();
				});
			}
		};

		ws.onmessage = (e: MessageEvent) => {
			if (gen !== this.generation) return;
			let envelope: StreamEnvelope;
			try {
				envelope = JSON.parse(String(e.data)) as StreamEnvelope;
			} catch {
				// Malformed frame — warn and skip; the connection stays up
				// (fail-loud, not fail-dead).
				console.warn('stream: dropping malformed envelope');
				return;
			}
			if (envelope.type === 'lagged') {
				const missed = envelope.missed;
				// On lag the server continues — the client owns healing. Set the
				// gap, then resync before any later envelope processes.
				this.enqueue(gen, async () => {
					this.lastGap = { missed, at: new Date() };
					await this.resync();
					this.onResynced?.();
				});
				return;
			}
			if (envelope.type !== 'event' && envelope.type !== 'adjudication') {
				// Envelope type allowlist: unknown shapes never reach render
				// paths — warn and ignore without crashing.
				console.warn('stream: ignoring unknown envelope type');
				return;
			}
			this.enqueue(gen, async () => {
				for (const handler of this.messageHandlers) handler(envelope);
			});
		};

		ws.onclose = () => {
			if (gen !== this.generation) return;
			this.ws = null;
			this.status = 'reconnecting';
			this.scheduleReconnect(gen);
		};
	}

	private scheduleReconnect(gen: number): void {
		// Full-jitter exponential backoff: U(0, min(cap, base * factor^n)).
		const ceiling = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * BACKOFF_FACTOR ** this.attempt);
		const delay = Math.random() * ceiling;
		this.attempt += 1;
		this.timer = setTimeout(() => {
			void this.reconnect(gen);
		}, delay);
	}

	private async reconnect(gen: number): Promise<void> {
		if (gen !== this.generation) return;
		this.timer = null;
		if (this.attempt > 1) {
			// A 401 WS upgrade is opaque in browsers (plain close, no status).
			// Past the first retry, disambiguate "auth died" from "server down"
			// with an authenticated REST probe. On 401 the client.ts wrapper has
			// already cleared the token — call disconnect() and exit the
			// reconnect loop (no reschedule); the layout gate shows the token
			// screen.
			try {
				await fetchHealth();
			} catch (err) {
				if (err instanceof ApiError && err.status === 401) {
					this.disconnect();
					return;
				}
				// Network error / 5xx: the server is down, not the token —
				// fall through and keep retrying with backoff.
			}
		}
		if (gen !== this.generation) return;
		this.open(gen);
	}

	private enqueue(gen: number, task: () => Promise<void>): void {
		this.queue = this.queue.then(async () => {
			if (gen !== this.generation) return;
			try {
				await task();
			} catch {
				// A failed merge/resync must not kill the queue.
				console.warn('stream: merge/resync handler failed');
			}
		});
	}

	private async resync(): Promise<void> {
		// Runs inside the serialized queue: every registered hook completes
		// before any later envelope is processed.
		await Promise.all([...this.resyncHandlers].map((h) => h()));
	}
}

/** The single app-wide stream: one firehose connection, views filter by
 * trajectory_id and merge deltas; REST hydrates, WS applies deltas. */
export const live = new LiveStream();
