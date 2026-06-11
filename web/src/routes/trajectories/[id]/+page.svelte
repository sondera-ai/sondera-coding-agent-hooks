<script lang="ts" module>
	// Trajectory page. Data state and the load operation live at module scope
	// — stream re-hydration calls loadTrajectory() after gaps, and witness
	// links drive the exported `view` state (selectedEventId / activeTab /
	// viewMode).
	import { fetchAdjudications, fetchEvents } from '$lib/api/client';
	import type { DataEnvelope } from '$lib/api/stream.svelte';
	import { ApiError } from '$lib/api/types';
	import type { AdjudicationDto, EventDto } from '$lib/api/types';

	type LoadStatus = 'loading' | 'loaded' | 'notfound' | 'error';

	const traj = $state({
		id: null as string | null,
		events: [] as EventDto[],
		adjudications: [] as AdjudicationDto[],
		status: 'loading' as LoadStatus
	});

	/** Page-level view state, exported so witness links can select an event,
	 * switch tabs, and force the timeline view. */
	export const view = $state({
		selectedEventId: null as string | null,
		activeTab: 'timeline' as 'timeline' | 'taint',
		viewMode: 'timeline' as 'timeline' | 'tree'
	});

	/** Load (or re-load) a trajectory: events + adjudications in parallel.
	 * Exported for stream re-hydration (no-arg call refetches the current
	 * trajectory). `silent` keeps the loaded view on screen (no skeleton
	 * flash) for live rehydrates/resyncs — keyed rows keep their DOM identity,
	 * so scroll position survives. */
	export async function loadTrajectory(id?: string, opts?: { silent?: boolean }): Promise<void> {
		const target = id ?? traj.id;
		if (target === null) return;
		if (target !== traj.id) {
			// New trajectory: drop the previous one's data and selection.
			traj.id = target;
			traj.events = [];
			traj.adjudications = [];
			view.selectedEventId = null;
		}
		if (opts?.silent !== true) traj.status = 'loading';
		try {
			const [events, adjudications] = await Promise.all([
				fetchEvents(target),
				fetchAdjudications(target)
			]);
			traj.events = events;
			traj.adjudications = adjudications;
			traj.status = 'loaded';
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 401) return; // the layout gate took over
				if (err.status === 404) {
					// Unknown trajectory id — a dedicated 404 state, not a crash.
					traj.status = 'notfound';
					return;
				}
			}
			traj.status = 'error';
		}
	}

	// --- live merge --------------------------------------------------------

	let rehydrateTimer: ReturnType<typeof setTimeout> | null = null;

	/** Debounced (400ms) silent re-load: adjudication bursts coalesce into
	 * one REST round-trip re-running the page load function (events +
	 * adjudications; the decision index is $derived and rebuilds itself). */
	export function rehydrate(): void {
		if (rehydrateTimer !== null) clearTimeout(rehydrateTimer);
		rehydrateTimer = setTimeout(() => {
			rehydrateTimer = null;
			void loadTrajectory(undefined, { silent: true });
		}, 400);
	}

	export function cancelRehydrate(): void {
		if (rehydrateTimer !== null) {
			clearTimeout(rehydrateTimer);
			rehydrateTimer = null;
		}
	}

	/** Stream merge handler: client-side firehose filter on trajectory_id
	 * (one app-wide connection, views filter). */
	export function applyEnvelopeToTrajectory(envelope: DataEnvelope): void {
		if (traj.id === null || envelope.trajectory_id !== traj.id) return;

		if (envelope.type === 'event') {
			// Idempotent append keyed on eventId: a resync may overlap with
			// deltas already merged — presence check before push.
			if (traj.events.some((e) => e.eventId === envelope.data.eventId)) return;
			traj.events.push(envelope.data);
			return;
		}

		// adjudication: AdjudicationDto carries NO causationId, so a live
		// adjudication CANNOT be joined to its timeline row from the envelope
		// alone — the join needs the Adjudicated EventDto's causationId
		// (two-step join in join.ts). REST hydrates: the debounced re-load
		// returns events + adjudications together and the decision index,
		// header monitor badge, and Taint tab all re-derive correctly.
		rehydrate();
	}
</script>

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { live } from '$lib/api/stream.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Resizable from '$lib/components/ui/resizable';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import * as Tabs from '$lib/components/ui/tabs';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import GitBranchIcon from '@lucide/svelte/icons/git-branch';
	import ListIcon from '@lucide/svelte/icons/list';
	import DecisionPanel from '$lib/components/DecisionPanel.svelte';
	import MonitorBadge from '$lib/components/MonitorBadge.svelte';
	import TaintMonitor from '$lib/components/TaintMonitor.svelte';
	import Timeline from '$lib/components/Timeline.svelte';
	import Tree from '$lib/components/Tree.svelte';
	import { buildDecisionIndex, latestMonitor } from '$lib/join';

	const routeId = $derived(page.params.id);

	$effect(() => {
		if (routeId !== undefined) void loadTrajectory(routeId);
	});

	onMount(() => {
		// Merge stream envelopes for this trajectory while mounted.
		const unsubMessage = live.onMessage(applyEnvelopeToTrajectory);
		// Gap healing re-runs the full load (events + adjudications; the
		// decision index re-derives) — silent, so keyed rows keep DOM identity
		// and scroll position. Appends after resync stay idempotent (eventId
		// presence check), so overlap is harmless.
		const unsubResync = live.onResync(async () => {
			await loadTrajectory(undefined, { silent: true });
		});
		return () => {
			unsubMessage();
			unsubResync();
			cancelRehydrate();
		};
	});

	// The decision index: triggering event id -> cedar adjudication (join.ts
	// owns the two-step causationId join and the cedar-actor filter).
	const decisionIndex = $derived(buildDecisionIndex(traj.events, traj.adjudications));

	// Header status badge: derived from the LAST Control lifecycle event
	// (Adjudicated records are not lifecycle), else "active".
	const lifecycleStatus = $derived.by(() => {
		for (let i = traj.events.length - 1; i >= 0; i--) {
			const e = traj.events[i];
			if (e === undefined || e.event.category !== 'Control') continue;
			const t = e.event.payload.type;
			if (t === 'Adjudicated') continue;
			if (t === 'Completed') return 'completed';
			if (t === 'Failed') return 'failed';
			if (t === 'Terminated') return 'terminated';
			return 'active'; // Started / Resumed / Suspended
		}
		return 'active';
	});

	// Header monitor badge: the last adjudication carrying a monitor block
	// (cedar and monitor-actor records both qualify — join.ts latestMonitor).
	const monitor = $derived(latestMonitor(traj.adjudications));

	// Decision detail for the selected row: the decision for the selected agent
	// event via the decision index; when the selected row is an Adjudicated
	// record itself (tree-view child click), fall back to a lookup by its own
	// eventId in the adjudications list.
	const selectedAdjudication = $derived.by(() => {
		if (view.selectedEventId === null) return null;
		const byTrigger = decisionIndex.get(view.selectedEventId);
		if (byTrigger !== undefined) return byTrigger;
		return traj.adjudications.find((a) => a.eventId === view.selectedEventId) ?? null;
	});

	// Resizable split: paneforge sizes are percentages, so the pixel targets
	// (right pane default 420px, min 320px, max 50%) are converted from the
	// measured split width at mount.
	let splitWidth = $state(0);
	const rightDefault = $derived(splitWidth > 0 ? Math.min(50, (420 / splitWidth) * 100) : 30);
	const rightMin = $derived(splitWidth > 0 ? Math.min(50, (320 / splitWidth) * 100) : 24);
</script>

{#if traj.status === 'loading'}
	<div class="flex flex-col gap-3" data-state="loading">
		<Skeleton class="h-8 w-2/3" />
		<Skeleton class="h-6 w-48" />
		{#each Array.from({ length: 8 }) as _, i (i)}
			<Skeleton class="h-10 w-full" />
		{/each}
	</div>
{:else if traj.status === 'notfound'}
	<div class="flex flex-col items-center gap-4 py-12 text-center">
		<h1 class="text-base font-semibold">Trajectory not found</h1>
		<p class="text-sm text-zinc-400">
			No trajectory with id <code class="font-mono">{traj.id}</code> — it may have been seeded under
			a different run.
		</p>
		<Button variant="outline" href="/">Back to trajectories</Button>
	</div>
{:else if traj.status === 'error'}
	<div class="flex flex-col items-center gap-4 py-12 text-center">
		<p class="text-sm text-zinc-400">
			Couldn't load trajectory — check that sondera-dashboard is running.
		</p>
		<Button variant="outline" onclick={() => void loadTrajectory()}>Retry</Button>
	</div>
{:else}
	<!-- Header row: trajectory id + neutral status badge + monitor-state badge
	     + event count. -->
	<div class="flex flex-wrap items-center gap-3">
		<h1 class="font-mono text-xl font-semibold break-all">{traj.id}</h1>
		<Badge variant="outline" class="border-zinc-700 text-zinc-400">{lifecycleStatus}</Badge>
		<MonitorBadge {monitor} />
		<span class="text-xs text-zinc-400">{traj.events.length} events</span>
	</div>

	<Tabs.Root
		bind:value={() => view.activeTab, (v) => (view.activeTab = v === 'taint' ? 'taint' : 'timeline')}
		class="mt-6"
	>
		<Tabs.List variant="line">
			<!-- Active tab indicator uses the reserved cyan accent. -->
			<Tabs.Trigger value="timeline" class="after:bg-[#22D3EE]">Timeline</Tabs.Trigger>
			<Tabs.Trigger value="taint" class="after:bg-[#22D3EE]">Taint &amp; Monitor</Tabs.Trigger>
		</Tabs.List>

		<Tabs.Content value="timeline">
			<!-- Toggle: timeline <-> causality tree, top-right inside the
			     Timeline tab. Icon-only, so each button carries an aria-label
			     and a tooltip. -->
			<div class="flex items-center justify-end gap-1">
				<Tooltip.Provider>
					<Tooltip.Root>
						<Tooltip.Trigger>
							{#snippet child({ props })}
								<Button
									{...props}
									variant={view.viewMode === 'timeline' ? 'secondary' : 'ghost'}
									size="icon-sm"
									aria-label="timeline view"
									aria-pressed={view.viewMode === 'timeline'}
									onclick={() => (view.viewMode = 'timeline')}
								>
									<ListIcon class="size-4" />
								</Button>
							{/snippet}
						</Tooltip.Trigger>
						<Tooltip.Content>timeline view</Tooltip.Content>
					</Tooltip.Root>
					<Tooltip.Root>
						<Tooltip.Trigger>
							{#snippet child({ props })}
								<Button
									{...props}
									variant={view.viewMode === 'tree' ? 'secondary' : 'ghost'}
									size="icon-sm"
									aria-label="tree view"
									aria-pressed={view.viewMode === 'tree'}
									onclick={() => (view.viewMode = 'tree')}
								>
									<GitBranchIcon class="size-4" />
								</Button>
							{/snippet}
						</Tooltip.Trigger>
						<Tooltip.Content>tree view</Tooltip.Content>
					</Tooltip.Root>
				</Tooltip.Provider>
			</div>

			<!-- A resizable pane split (never an overlay/sheet) so the timeline
			     stays visible for click-through comparison. -->
			<div
				bind:clientWidth={splitWidth}
				class="mt-2 h-[calc(100vh-280px)] min-h-[360px] overflow-hidden rounded-lg border border-zinc-800"
			>
				{#if splitWidth > 0}
					<Resizable.PaneGroup direction="horizontal">
						<Resizable.Pane defaultSize={100 - rightDefault} minSize={50}>
							<!-- The toggle swaps Timeline/Tree in this pane only;
							     selection (shared selectedEventId binding) and the
							     right pane persist across the swap. -->
							{#if view.viewMode === 'timeline'}
								<Timeline
									events={traj.events}
									{decisionIndex}
									bind:selectedEventId={view.selectedEventId}
								/>
							{:else}
								<Tree
									events={traj.events}
									adjudications={traj.adjudications}
									{decisionIndex}
									bind:selectedEventId={view.selectedEventId}
								/>
							{/if}
						</Resizable.Pane>
						<Resizable.Handle />
						<Resizable.Pane defaultSize={rightDefault} minSize={rightMin} maxSize={50}>
							<!-- Persistent decision-detail panel: the full decision
							     anatomy for the selected row; placeholder copy stays
							     when nothing is selected. -->
							<div class="flex h-full flex-col gap-4 overflow-y-auto p-6">
								<h2 class="text-base font-semibold">Decision Detail</h2>
								<DecisionPanel adjudication={selectedAdjudication} />
							</div>
						</Resizable.Pane>
					</Resizable.PaneGroup>
				{/if}
			</div>
		</Tabs.Content>

		<Tabs.Content value="taint">
			<!-- Taint lane + monitor view (full width). Witness links drive the
			     bound tab/selection/view-mode state to jump back into the
			     timeline. -->
			<TaintMonitor
				events={traj.events}
				adjudications={traj.adjudications}
				trajectoryId={traj.id}
				onApproved={() => void loadTrajectory(undefined, { silent: true })}
				bind:activeTab={view.activeTab}
				bind:selectedEventId={view.selectedEventId}
				bind:viewMode={view.viewMode}
			/>
		</Tabs.Content>
	</Tabs.Root>
{/if}
