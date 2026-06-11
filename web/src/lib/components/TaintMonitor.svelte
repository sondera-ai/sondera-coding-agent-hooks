<script lang="ts">
	// Taint & Monitor tab: the monitor journey as a horizontal lane/stepper —
	// Source (armed event) → Carry (armed window: taints as mono chips, label,
	// pending flag, window size) → Sink (tripped red / cleared green /
	// still-armed pending). The MonitorBadge sits above the lane and the FSM
	// journey (Clean → Armed → Violated/Cleared) reads left-to-right as the
	// caption.
	//
	// Witness event ids are accent links: clicking one switches to the
	// Timeline tab, selects the event, and scrolls its evt-{id} row into view.
	// Ids that don't resolve to a loaded event render as plain mono text (live
	// data may reference events not currently loaded). getElementById treats
	// the id literally, so there's no selector injection surface.
	import { tick } from 'svelte';
	import { approveTrajectory } from '$lib/api/client';
	import type { AdjudicationDto, EventDto } from '$lib/api/types';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import { formatClock } from '$lib/format';
	import { isAgentRow, latestMonitor } from '$lib/join';
	import { summarize } from '$lib/summarize';
	import MonitorBadge from './MonitorBadge.svelte';

	let {
		events,
		adjudications,
		activeTab = $bindable('taint'),
		selectedEventId = $bindable(null),
		viewMode = $bindable('timeline'),
		trajectoryId = null,
		onApproved
	}: {
		events: EventDto[];
		adjudications: AdjudicationDto[];
		/** Bound to the page's view state — witness links drive all three. */
		activeTab?: 'timeline' | 'taint';
		selectedEventId?: string | null;
		viewMode?: 'timeline' | 'tree';
		/** Trajectory id — enables the in-UI approval action when armed. */
		trajectoryId?: string | null;
		/** Called after a successful approval so the page can re-load and the
		 * monitor lane re-derives to the "cleared" state. */
		onApproved?: () => void;
	} = $props();

	const monitor = $derived(latestMonitor(adjudications));

	// In-UI approval (separate write surface — see client.approveTrajectory).
	let approving = $state(false);
	let approved = $state(false);
	let approveError = $state<string | null>(null);

	async function doApprove(): Promise<void> {
		if (trajectoryId === null || approving || approved) return;
		approving = true;
		approveError = null;
		try {
			await approveTrajectory(trajectoryId);
			approved = true;
			onApproved?.();
		} catch (err) {
			approveError = err instanceof Error ? err.message : String(err);
		} finally {
			approving = false;
		}
	}

	const hasWitness = $derived(
		monitor !== null &&
			(monitor.armedEventId !== undefined ||
				monitor.trippedEventId !== undefined ||
				monitor.clearedEventId !== undefined)
	);

	/** Empty state when no monitor block ever left 'clean' AND no witness
	 * ids exist — the trajectory never armed the multi-hop monitor. */
	const everArmed = $derived(monitor !== null && (monitor.state !== 'clean' || hasWitness));

	const byId = $derived(new Map(events.map((e) => [e.eventId, e])));

	const armedEvent = $derived(
		monitor?.armedEventId !== undefined ? byId.get(monitor.armedEventId) : undefined
	);
	const trippedEvent = $derived(
		monitor?.trippedEventId !== undefined ? byId.get(monitor.trippedEventId) : undefined
	);
	const clearedEvent = $derived(
		monitor?.clearedEventId !== undefined ? byId.get(monitor.clearedEventId) : undefined
	);

	// Armed-window size: agent rows strictly between the armed event and the
	// sink. With no sink yet, everything after the armed event is still in the
	// window. Unresolvable ids degrade to "no count" rather than crashing.
	const carryCount = $derived.by(() => {
		if (monitor === null || monitor.armedEventId === undefined) return null;
		const rows = events.filter(isAgentRow);
		const start = rows.findIndex((e) => e.eventId === monitor.armedEventId);
		if (start === -1) return null;
		const sinkId = monitor.trippedEventId ?? monitor.clearedEventId;
		if (sinkId === undefined) return Math.max(0, rows.length - start - 1);
		const end = rows.findIndex((e) => e.eventId === sinkId);
		if (end === -1) return null;
		return Math.max(0, end - start - 1);
	});

	// The FSM journey caption: Clean → Armed → Violated/Cleared, left-to-right.
	const journey = $derived.by(() => {
		if (monitor === null) return '';
		if (monitor.state === 'violated') return 'Clean → Armed → Violated';
		if (monitor.clearedEventId !== undefined) return 'Clean → Armed → Cleared';
		if (monitor.state === 'armed') return 'Clean → Armed';
		return 'Clean';
	});

	/** Witness navigation: switch to the Timeline tab (timeline view), select
	 * the witness event, and scroll its row into view. The Timeline tab
	 * measures its split width before rendering rows (bind:clientWidth), so the
	 * target may take a few frames to exist — retry briefly rather than
	 * assuming one tick suffices. */
	async function gotoWitness(id: string): Promise<void> {
		activeTab = 'timeline';
		viewMode = 'timeline';
		selectedEventId = id;
		await tick();
		let attempts = 0;
		const scroll = (): void => {
			const el = document.getElementById('evt-' + id);
			if (el !== null) {
				el.scrollIntoView({ block: 'center' });
			} else if (attempts++ < 10) {
				requestAnimationFrame(scroll);
			}
		};
		requestAnimationFrame(scroll);
	}
</script>

{#snippet witnessLink(id: string)}
	{#if byId.has(id)}
		<!-- Witness-event-id link (accent). -->
		<button
			type="button"
			class="self-start font-mono text-xs break-all text-[#22D3EE] underline-offset-2 hover:underline"
			onclick={() => void gotoWitness(id)}
		>
			{id}
		</button>
	{:else}
		<!-- Unresolved witness id: plain mono text, never a broken link. -->
		<span class="font-mono text-xs break-all text-zinc-400">{id}</span>
	{/if}
{/snippet}

{#if monitor === null || !everArmed}
	<div class="flex flex-col items-center gap-2 py-12 text-center">
		<p class="text-sm text-zinc-400">
			No monitor activity — this trajectory never armed the multi-hop monitor.
		</p>
	</div>
{:else}
	<div class="flex flex-col gap-4 py-4">
		<!-- Monitor state above the lane; the journey caption reads the
		     transitions left-to-right. -->
		<div class="flex flex-wrap items-center gap-3">
			<MonitorBadge {monitor} />
			<span class="font-mono text-xs text-zinc-400">{journey}</span>
		</div>

		<!-- The lane: Source → Carry → Sink, full width. -->
		<div class="flex w-full items-stretch gap-2">
			<section class="flex min-w-0 flex-1 flex-col gap-2 rounded-lg border border-zinc-800 bg-zinc-900 p-4">
				<h3 class="text-xs font-semibold tracking-wide text-zinc-400 uppercase">Source</h3>
				{#if monitor.armedEventId !== undefined}
					{#if armedEvent !== undefined}
						<p class="truncate text-sm">{summarize(armedEvent)}</p>
						<p class="font-mono text-xs text-zinc-400">
							{formatClock(new Date(armedEvent.timestamp))}
						</p>
					{:else}
						<p class="text-sm text-zinc-500">armed event not loaded</p>
					{/if}
					{@render witnessLink(monitor.armedEventId)}
				{:else}
					<p class="text-sm text-zinc-500">no armed event recorded</p>
				{/if}
			</section>

			<div class="flex shrink-0 items-center text-zinc-600" aria-hidden="true">→</div>

			<section class="flex min-w-0 flex-1 flex-col gap-2 rounded-lg border border-zinc-800 bg-zinc-900 p-4">
				<h3 class="text-xs font-semibold tracking-wide text-zinc-400 uppercase">Carry</h3>
				{#if monitor.taints.length > 0}
					<div class="flex flex-wrap gap-1">
						{#each monitor.taints as t (t)}
							<span class="rounded bg-zinc-950 px-1.5 py-0.5 font-mono text-xs">{t}</span>
						{/each}
					</div>
				{:else}
					<p class="text-sm text-zinc-500">no taints recorded</p>
				{/if}
				<div class="flex flex-wrap items-center gap-2">
					<Badge variant="outline" class="border-zinc-700 font-mono text-zinc-400">
						{monitor.label}
					</Badge>
					{#if monitor.untrustedPending}
						<span class="text-xs text-zinc-400">untrusted read pending</span>
					{/if}
				</div>
				{#if carryCount !== null}
					<p class="text-xs text-zinc-400">
						{carryCount}
						{carryCount === 1 ? 'event' : 'events'} in the armed window
					</p>
				{/if}
			</section>

			<div class="flex shrink-0 items-center text-zinc-600" aria-hidden="true">→</div>

			<section
				class={`flex min-w-0 flex-1 flex-col gap-2 rounded-lg border bg-zinc-900 p-4 ${
					monitor.trippedEventId !== undefined
						? 'border-[#F87171]/40'
						: monitor.clearedEventId !== undefined
							? 'border-[#34D399]/40'
							: 'border-zinc-800'
				}`}
			>
				<h3 class="text-xs font-semibold tracking-wide text-zinc-400 uppercase">Sink</h3>
				{#if monitor.trippedEventId !== undefined}
					<p class="text-sm font-semibold text-[#F87171]">tripped</p>
					{#if trippedEvent !== undefined}
						<p class="truncate text-sm">{summarize(trippedEvent)}</p>
						<p class="font-mono text-xs text-zinc-400">
							{formatClock(new Date(trippedEvent.timestamp))}
						</p>
					{/if}
					{@render witnessLink(monitor.trippedEventId)}
				{:else if monitor.clearedEventId !== undefined}
					<p class="text-sm font-semibold text-[#34D399]">cleared by approval</p>
					{#if clearedEvent !== undefined}
						<p class="truncate text-sm">{summarize(clearedEvent)}</p>
						<p class="font-mono text-xs text-zinc-400">
							{formatClock(new Date(clearedEvent.timestamp))}
						</p>
					{/if}
					{@render witnessLink(monitor.clearedEventId)}
				{:else}
					<p class="text-sm text-[#FBBF24]">still armed — no sink event yet</p>
					{#if trajectoryId !== null}
						<!-- Writes to the separate approval endpoint, not the read-only API. -->
						<Button
							size="sm"
							variant="outline"
							class="mt-1 self-start"
							disabled={approving || approved}
							onclick={() => void doApprove()}
						>
							{approving ? 'Approving…' : approved ? 'Approved ✓' : 'Approve (clear obligation)'}
						</Button>
						{#if approved}
							<p class="text-xs text-[#34D399]">
								Approval sent — the lane shows “cleared” once the event syncs.
							</p>
						{/if}
						{#if approveError !== null}
							<p class="text-xs break-words text-[#F87171]">{approveError}</p>
						{/if}
					{/if}
				{/if}
			</section>
		</div>
	</div>
{/if}
