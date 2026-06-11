<script lang="ts" module>
	// Four-state monitor badge mapping:
	//
	//   state=violated                  -> "Violated"         red,   solid
	//   state=armed (verdict pending)   -> "Armed · Pending"   amber, solid + pulsing dot
	//   state=clean + clearedEventId    -> "Cleared"           green, outline
	//   state=clean, never armed        -> "Clean · Satisfied" muted zinc, outline
	//
	// Pending vs Satisfied is distinguished twice over — different hue (amber
	// vs zinc) AND different label text — never by color alone.
	import type { MonitorDto } from '$lib/api/types';

	export type MonitorTone = 'red' | 'amber' | 'green' | 'muted';

	export function monitorBadge(m: MonitorDto): { label: string; tone: MonitorTone } {
		if (m.state === 'violated') return { label: 'Violated', tone: 'red' };
		if (m.state === 'armed') return { label: 'Armed · Pending', tone: 'amber' };
		return m.clearedEventId !== undefined
			? { label: 'Cleared', tone: 'green' }
			: { label: 'Clean · Satisfied', tone: 'muted' };
	}
</script>

<script lang="ts">
	let { monitor }: { monitor: MonitorDto | null } = $props();

	// Null monitor (trajectory never produced a monitor block) renders nothing.
	const badge = $derived(monitor === null ? null : monitorBadge(monitor));
</script>

{#if badge !== null}
	{#if badge.tone === 'red'}
		<span
			class="inline-flex shrink-0 items-center gap-1 rounded-full bg-[#EF4444]/15 px-2 py-0.5 text-xs font-semibold text-[#F87171]"
		>
			<span class="size-1.5 rounded-full bg-[#F87171]" aria-hidden="true"></span>
			{badge.label}
		</span>
	{:else if badge.tone === 'amber'}
		<!-- Armed · Pending: the pulse animation sits on the dot only. -->
		<span
			class="inline-flex shrink-0 items-center gap-1 rounded-full bg-[#F59E0B]/15 px-2 py-0.5 text-xs font-semibold text-[#FBBF24]"
		>
			<span class="size-1.5 animate-pulse rounded-full bg-[#FBBF24]" aria-hidden="true"></span>
			{badge.label}
		</span>
	{:else if badge.tone === 'green'}
		<span
			class="inline-flex shrink-0 items-center rounded-full border border-[#34D399]/40 bg-transparent px-2 py-0.5 text-xs text-[#34D399]"
		>
			{badge.label}
		</span>
	{:else}
		<span
			class="inline-flex shrink-0 items-center rounded-full border border-zinc-700 bg-transparent px-2 py-0.5 text-xs text-zinc-400"
		>
			{badge.label}
		</span>
	{/if}
{/if}
