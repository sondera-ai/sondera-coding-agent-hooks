<script lang="ts">
	// Shared event-row anatomy: time · category icon · payload type · one-line
	// summary · trailing decision badge or muted "monitor snapshot" label.
	// Extracted so Timeline.svelte and Tree.svelte can't diverge.
	//
	// Each row carries id="evt-{eventId}" — the scroll target for witness
	// links. Selected row: cyan left rail + tint.
	import type { Decision, EventDto } from '$lib/api/types';
	import CameraIcon from '@lucide/svelte/icons/camera';
	import EyeIcon from '@lucide/svelte/icons/eye';
	import FlagIcon from '@lucide/svelte/icons/flag';
	import ZapIcon from '@lucide/svelte/icons/zap';
	import { formatClock } from '$lib/format';
	import { summarize } from '$lib/summarize';
	import DecisionBadge from './DecisionBadge.svelte';

	let {
		event,
		decision,
		monitorSnapshot = false,
		selected = false,
		onselect
	}: {
		event: EventDto;
		/** Cedar decision to render as the trailing inline badge. */
		decision?: Decision;
		/** Monitor-actor records get a muted label, never a decision badge. */
		monitorSnapshot?: boolean;
		selected?: boolean;
		onselect: (eventId: string) => void;
	} = $props();

	// Icon per event category.
	const icons = {
		Action: ZapIcon,
		Observation: EyeIcon,
		Control: FlagIcon,
		State: CameraIcon
	} as const;

	const Icon = $derived(icons[event.event.category]);
	const muted = $derived(event.event.category === 'Control' || event.event.category === 'State');
</script>

<button
	type="button"
	id={`evt-${event.eventId}`}
	aria-pressed={selected}
	class={`flex w-full items-center gap-2 border-l-2 px-3 py-3 text-left transition-colors ${
		selected ? 'border-l-[#22D3EE] bg-[#22D3EE]/10' : 'border-l-transparent hover:bg-zinc-900'
	}`}
	onclick={() => onselect(event.eventId)}
>
	<span class="shrink-0 font-mono text-xs text-zinc-400">
		{formatClock(new Date(event.timestamp))}
	</span>
	<Icon class="size-4 shrink-0 text-zinc-400" aria-hidden="true" />
	<span class={`shrink-0 text-sm ${muted ? 'text-zinc-500' : ''}`}>
		{event.event.payload.type}
	</span>
	<!-- summarize() returns a plain string, rendered via text interpolation
	     only — never HTML. -->
	<span class="min-w-0 flex-1 truncate text-sm text-zinc-400">{summarize(event)}</span>
	{#if monitorSnapshot}
		<span class="shrink-0 text-xs text-zinc-500">monitor snapshot</span>
	{:else if decision !== undefined}
		<DecisionBadge {decision} />
	{/if}
</button>
