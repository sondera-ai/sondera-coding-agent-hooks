<script lang="ts">
	// Timeline pane: the agent's action sequence as dense rows with inline
	// decision badges joined from cedar-actor adjudications. Row anatomy lives
	// in TimelineRow.svelte (shared with Tree.svelte so the two views can't
	// diverge).
	//
	// Adjudicated records are not primary rows (isAgentRow) — they surface as
	// inline badges here and as tree children in Tree.svelte, so the timeline
	// reads as the agent's action sequence. Control lifecycle rows
	// (Started/Resumed/…) and State snapshots do render, muted, so approvals
	// stay visible in the sequence.
	//
	// Scroll preservation: live appends never programmatically scroll an
	// off-bottom view — they increment the floating pill instead; views
	// already at bottom (within 40px) follow along silently.
	import { tick, untrack } from 'svelte';
	import type { AdjudicationDto, EventDto } from '$lib/api/types';
	import { ScrollArea } from '$lib/components/ui/scroll-area';
	import { isAgentRow } from '$lib/join';
	import NewEventsPill from './NewEventsPill.svelte';
	import TimelineRow from './TimelineRow.svelte';

	let {
		events,
		decisionIndex,
		selectedEventId = $bindable(null)
	}: {
		/** Full ordered event list (server returns timestamp order);
		 * Adjudicated records are filtered out here, not by the caller, so
		 * Timeline and Tree receive identical inputs. */
		events: EventDto[];
		/** Triggering event id -> cedar adjudication (join.ts owns the
		 * two-step causationId join and the cedar-actor filter). */
		decisionIndex: Map<string, AdjudicationDto>;
		/** Two-way binding shared with Tree.svelte and the page's detail
		 * pane — selection survives the timeline<->tree toggle. */
		selectedEventId?: string | null;
	} = $props();

	/** Primary rows: everything except Adjudicated records (those surface
	 * as inline badges via decisionIndex instead). */
	const rows = $derived(events.filter(isAgentRow));

	function select(eventId: string): void {
		selectedEventId = eventId;
	}

	// --- at-bottom tracking + new-events pill ------------------------------

	/** "At bottom" threshold: within 40px of the scroll end counts. */
	const AT_BOTTOM_PX = 40;

	let viewport = $state<HTMLElement | null>(null);
	let atBottom = $state(true);
	let pendingCount = $state(0);
	/** Non-reactive previous row count for append detection. */
	let prevCount = 0;

	function measureAtBottom(el: HTMLElement): boolean {
		return el.scrollHeight - el.scrollTop - el.clientHeight <= AT_BOTTOM_PX;
	}

	$effect(() => {
		const el = viewport;
		if (el === null) return;
		const onScroll = () => {
			atBottom = measureAtBottom(el);
			// Reaching the bottom by hand consumes the pill.
			if (atBottom) pendingCount = 0;
		};
		onScroll();
		el.addEventListener('scroll', onScroll, { passive: true });
		return () => el.removeEventListener('scroll', onScroll);
	});

	function scrollToBottom(behavior: ScrollBehavior): void {
		const el = viewport;
		if (el === null) return;
		el.scrollTo({ top: el.scrollHeight, behavior });
	}

	function jump(): void {
		scrollToBottom('smooth');
		pendingCount = 0;
	}

	// Append detection: when rows grow while NOT at bottom, count them into
	// the pill instead of scrolling (no scroll yank); when at bottom, follow
	// along. `atBottom` is read untracked so this effect runs only on row
	// changes, never on scroll.
	$effect(() => {
		const count = rows.length;
		const wasAtBottom = untrack(() => atBottom);
		if (count > prevCount && prevCount > 0) {
			const added = count - prevCount;
			if (wasAtBottom) {
				// Auto-follow only when already at bottom.
				void tick().then(() => scrollToBottom('auto'));
			} else {
				pendingCount += added;
			}
		} else if (count < prevCount) {
			// Shrink = a fresh load/resync replaced the list — reset the pill.
			pendingCount = 0;
		}
		prevCount = count;
	});
</script>

<div class="relative h-full">
	<ScrollArea class="h-full" bind:viewportRef={viewport}>
		<div class="flex flex-col">
			{#each rows as e (e.eventId)}
				<TimelineRow
					event={e}
					decision={decisionIndex.get(e.eventId)?.decision}
					selected={selectedEventId === e.eventId}
					onselect={select}
				/>
			{:else}
				<p class="px-3 py-12 text-center text-sm text-zinc-400">
					No events recorded for this trajectory.
				</p>
			{/each}
		</div>
	</ScrollArea>
	<!-- New-events pill: bottom-center of the timeline pane. -->
	<NewEventsPill count={pendingCount} onJump={jump} />
</div>
