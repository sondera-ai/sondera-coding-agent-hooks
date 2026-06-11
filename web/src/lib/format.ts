// Shared formatting helpers — pure functions, zero deps (no dayjs/date-fns,
// to keep the dep tree minimal).

/** 24-hour HH:MM:SS clock for the live chip ("data as of {HH:MM:SS}"). */
const clock = new Intl.DateTimeFormat('en-GB', {
	hour: '2-digit',
	minute: '2-digit',
	second: '2-digit',
	hour12: false
});

export function formatClock(d: Date): string {
	return clock.format(d);
}

/** Coarse relative time: "12s ago", "3m ago", "2h ago", date fallback. */
export function formatRelative(iso: string): string {
	const t = new Date(iso).getTime();
	if (Number.isNaN(t)) return iso;
	const seconds = Math.max(0, Math.round((Date.now() - t) / 1000));
	if (seconds < 60) return `${seconds}s ago`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m ago`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours}h ago`;
	return new Date(t).toLocaleDateString();
}

/** Middle-ellipsis for long mono ids. */
export function truncateMiddle(id: string, max = 20): string {
	if (id.length <= max || max < 3) return id;
	const keep = max - 1; // one slot for the ellipsis
	const head = Math.ceil(keep / 2);
	const tail = Math.floor(keep / 2);
	return `${id.slice(0, head)}…${id.slice(id.length - tail)}`;
}
