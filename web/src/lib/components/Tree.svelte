<script lang="ts">
	// Causality tree view — honest about shallow data.
	//
	// Hook-adapter events carry no causality, so only Adjudicated and
	// monitor-snapshot records have a causation_id (pointing at their
	// triggering event). The tree is therefore shallow today: roots = agent
	// events in time order, children = their adjudication/snapshot records.
	// Built from causationId ?? parentId with a flat orphan fallback — this
	// component must not invent hierarchy the data doesn't support (no
	// recursion, no faked depth).
	import type { AdjudicationDto, EventDto } from '$lib/api/types';
	import { ScrollArea } from '$lib/components/ui/scroll-area';
	import TimelineRow from './TimelineRow.svelte';

	let {
		events,
		adjudications,
		decisionIndex,
		selectedEventId = $bindable(null)
	}: {
		events: EventDto[];
		adjudications: AdjudicationDto[];
		/** Triggering event id -> cedar adjudication (join.ts) — root rows
		 * render the same inline badge as Timeline rows. */
		decisionIndex: Map<string, AdjudicationDto>;
		selectedEventId?: string | null;
	} = $props();

	function parentOf(e: EventDto): string | undefined {
		return e.causationId ?? e.parentId;
	}

	/** Adjudication record by its OWN eventId — child rows discriminate
	 * cedar (DecisionBadge) vs monitor ("monitor snapshot" label) on it. */
	const adjByEventId = $derived(new Map(adjudications.map((a) => [a.eventId, a])));

	/** Roots: events with no causation/parent reference, in the server's
	 * timestamp order (the events endpoint returns them ordered). */
	const roots = $derived(events.filter((e) => parentOf(e) === undefined));

	const rootIds = $derived(new Set(roots.map((e) => e.eventId)));

	/** Children grouped under the root they reference. */
	const childrenByRoot = $derived.by(() => {
		const grouped = new Map<string, EventDto[]>();
		for (const e of events) {
			const parent = parentOf(e);
			if (parent === undefined || !rootIds.has(parent)) continue;
			const siblings = grouped.get(parent);
			if (siblings === undefined) {
				grouped.set(parent, [e]);
			} else {
				siblings.push(e);
			}
		}
		return grouped;
	});

	/** Orphans (defensive flat fallback): events that reference an id that
	 * is not a rendered root — e.g. a causation pointing outside the set or
	 * at another child. Rendered flat at the end, never re-parented. */
	const orphans = $derived(
		events.filter((e) => {
			const parent = parentOf(e);
			return parent !== undefined && !rootIds.has(parent);
		})
	);

	function select(eventId: string): void {
		selectedEventId = eventId;
	}
</script>

<ScrollArea class="h-full">
	<div class="flex flex-col">
		{#each roots as root (root.eventId)}
			<TimelineRow
				event={root}
				decision={decisionIndex.get(root.eventId)?.decision}
				selected={selectedEventId === root.eventId}
				onselect={select}
			/>
			{#each childrenByRoot.get(root.eventId) ?? [] as child (child.eventId)}
				{@const adjudication = adjByEventId.get(child.eventId)}
				<!-- One indent level + connector border; cedar children show the
				     decision badge, monitor-actor children a muted "monitor
				     snapshot" label. -->
				<div class="ml-4 border-l border-zinc-800">
					<TimelineRow
						event={child}
						decision={adjudication?.actorId === 'cedar' ? adjudication.decision : undefined}
						monitorSnapshot={adjudication?.actorId === 'monitor'}
						selected={selectedEventId === child.eventId}
						onselect={select}
					/>
				</div>
			{/each}
		{:else}
			<p class="px-3 py-12 text-center text-sm text-zinc-400">
				No events recorded for this trajectory.
			</p>
		{/each}

		{#if orphans.length > 0}
			<div class="mt-4 border-t border-zinc-800 pt-2">
				<p class="px-3 py-1 text-xs font-semibold tracking-wide text-zinc-500 uppercase">
					Orphaned events
				</p>
				{#each orphans as orphan (orphan.eventId)}
					{@const adjudication = adjByEventId.get(orphan.eventId)}
					<TimelineRow
						event={orphan}
						decision={adjudication?.actorId === 'cedar' ? adjudication.decision : undefined}
						monitorSnapshot={adjudication?.actorId === 'monitor'}
						selected={selectedEventId === orphan.eventId}
						onselect={select}
					/>
				{/each}
			</div>
		{/if}
	</div>
</ScrollArea>
