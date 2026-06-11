<script lang="ts" module>
	import type { TrajectoryListItem } from '$lib/api/types';

	export type Severity = 'deny' | 'escalate' | 'clean';

	/**
	 * Severity precedence deny > escalate > clean, derived only from the
	 * cedar-actor counts. Lifecycle `status` is never an input — it renders as
	 * a separate neutral badge.
	 */
	export function severityOf(t: TrajectoryListItem): Severity {
		if (t.denyCount > 0) return 'deny';
		if (t.escalateCount > 0) return 'escalate';
		return 'clean';
	}
</script>

<script lang="ts">
	import { Badge } from '$lib/components/ui/badge';

	let { item }: { item: TrajectoryListItem } = $props();
</script>

<!-- Deny/escalate count badges: deny red, escalate amber; clean counts stay
     muted. -->
<span class="flex items-center gap-2">
	{#if item.denyCount > 0}
		<Badge class="bg-[#EF4444]/15 text-[#F87171]">
			<span class="size-1.5 rounded-full bg-[#F87171]" aria-hidden="true"></span>
			{item.denyCount} deny
		</Badge>
	{:else}
		<span class="text-xs text-zinc-400">0 deny</span>
	{/if}
	{#if item.escalateCount > 0}
		<Badge class="bg-[#F59E0B]/15 text-[#FBBF24]">
			<span class="size-1.5 rounded-full bg-[#FBBF24]" aria-hidden="true"></span>
			{item.escalateCount} escalate
		</Badge>
	{:else}
		<span class="text-xs text-zinc-400">0 escalate</span>
	{/if}
</span>
