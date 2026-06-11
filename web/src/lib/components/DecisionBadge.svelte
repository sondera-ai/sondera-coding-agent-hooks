<script lang="ts">
	// Decision chip. Allow is deliberately quiet (muted emerald outline, no
	// dot) so Deny (red) and Escalate (amber) pop against Allow rows.
	import type { Decision } from '$lib/api/types';

	let { decision }: { decision: Decision } = $props();
</script>

{#if decision === 'Deny'}
	<span
		class="inline-flex shrink-0 items-center gap-1 rounded-full bg-[#EF4444]/15 px-2 py-0.5 text-xs font-semibold text-[#F87171]"
	>
		<span class="size-1.5 rounded-full bg-[#F87171]" aria-hidden="true"></span>
		Deny
	</span>
{:else if decision === 'Escalate'}
	<span
		class="inline-flex shrink-0 items-center gap-1 rounded-full bg-[#F59E0B]/15 px-2 py-0.5 text-xs font-semibold text-[#FBBF24]"
	>
		<span class="size-1.5 rounded-full bg-[#FBBF24]" aria-hidden="true"></span>
		Escalate
	</span>
{:else}
	<span
		class="inline-flex shrink-0 items-center rounded-full border border-[#34D399]/40 bg-transparent px-2 py-0.5 text-xs text-[#34D399]"
	>
		Allow
	</span>
{/if}
