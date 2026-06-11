<script lang="ts">
	// Live-status chip: the stream module drives the live/reconnecting states
	// and the persistent gap note. Colors reuse the semantic palette
	// (green/amber), never the cyan accent.
	import { snapshot } from '$lib/stores/snapshot.svelte';
	import { formatClock } from '$lib/format';

	let {
		status = 'off',
		lastGap = null
	}: {
		status?: 'live' | 'reconnecting' | 'off';
		lastGap?: { missed?: number; at: Date } | null;
	} = $props();
</script>

<div class="flex items-center gap-2 text-xs text-zinc-400">
	{#if status === 'live'}
		<span class="size-2 rounded-full bg-[#34D399]" aria-hidden="true"></span>
		<span>Live</span>
	{:else if status === 'reconnecting'}
		<span class="size-2 rounded-full bg-[#FBBF24]" aria-hidden="true"></span>
		<span>Reconnecting…</span>
	{/if}
	{#if lastGap !== null}
		<!-- Persistent gap notice: stays visible after the transient toast
		     disappears; the stream module never auto-clears it, so it survives
		     until the next clean page load. -->
		<span class="text-zinc-500">
			{#if lastGap.missed !== undefined}missed {lastGap.missed} events{:else}resynced{/if}
			· {formatClock(lastGap.at)}
		</span>
	{/if}
	{#if snapshot.lastSnapshotAt !== null}
		<span>data as of {formatClock(snapshot.lastSnapshotAt)}</span>
	{/if}
</div>
