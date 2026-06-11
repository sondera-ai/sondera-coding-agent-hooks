// Snapshot freshness store: the header status chip's "data as of HH:MM:SS"
// reads `lastSnapshotAt`, fed by the API client from the
// `X-Sondera-Snapshot-At` response header on every store-backed REST response.

class SnapshotStore {
	lastSnapshotAt = $state<Date | null>(null);

	/** Parse an RFC 3339 header value; ignore absent/unparseable values. */
	update(headerValue: string | null): void {
		if (!headerValue) return;
		const parsed = new Date(headerValue);
		if (!Number.isNaN(parsed.getTime())) {
			this.lastSnapshotAt = parsed;
		}
	}
}

export const snapshot = new SnapshotStore();
