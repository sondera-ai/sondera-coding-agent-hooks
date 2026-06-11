<script lang="ts" module>
	// Trajectory list page. The list state and its three operations live at
	// module scope so the stream module can call
	// loadFirstPage()/loadMore()/applyFilters() for re-hydration after gaps.
	import { fetchTrajectories } from '$lib/api/client';
	import type { DataEnvelope } from '$lib/api/stream.svelte';
	import { ApiError } from '$lib/api/types';
	import type { ListFilterParams, TrajectoryListItem } from '$lib/api/types';

	type LoadStatus = 'loading' | 'loaded' | 'error';

	const list = $state({
		rows: [] as TrajectoryListItem[],
		status: 'loading' as LoadStatus,
		/** Server 400 message, rendered verbatim under the filter bar. */
		filterError: null as string | null,
		nextBefore: null as string | null,
		nextBeforeId: null as string | null,
		loadingMore: false,
		/** Server-side filter params — the params ARE the filter; the fetched
		 * rows are never re-filtered client-side. */
		filters: {} as ListFilterParams
	});

	function hasActiveFilters(params: ListFilterParams): boolean {
		return (
			(params.decision?.length ?? 0) > 0 ||
			(params.label?.length ?? 0) > 0 ||
			(params.policyId?.length ?? 0) > 0 ||
			params.from !== undefined ||
			params.to !== undefined
		);
	}

	export async function loadFirstPage(): Promise<void> {
		list.status = 'loading';
		list.filterError = null;
		// Reset the keyset cursor on every first-page load: a stale
		// before/before_id pair against a new filter set produces wrong pages.
		list.nextBefore = null;
		list.nextBeforeId = null;
		try {
			const res = await fetchTrajectories(list.filters);
			list.rows = res.trajectories;
			list.nextBefore = res.nextBefore ?? null;
			list.nextBeforeId = res.nextBeforeId ?? null;
			list.status = 'loaded';
		} catch (err) {
			handleError(err);
		}
	}

	export async function loadMore(): Promise<void> {
		// The cursor is both-or-neither — loadMore only runs when both halves
		// are present, and passes both back.
		if (list.nextBefore === null || list.nextBeforeId === null || list.loadingMore) return;
		list.loadingMore = true;
		try {
			const res = await fetchTrajectories({
				...list.filters,
				before: list.nextBefore,
				beforeId: list.nextBeforeId
			});
			// Keyset concatenation — no page numbers.
			list.rows = [...list.rows, ...res.trajectories];
			list.nextBefore = res.nextBefore ?? null;
			list.nextBeforeId = res.nextBeforeId ?? null;
		} catch (err) {
			handleError(err);
		} finally {
			list.loadingMore = false;
		}
	}

	export async function applyFilters(params: ListFilterParams): Promise<void> {
		list.filters = params;
		// loadFirstPage resets the pagination cursor before fetching.
		await loadFirstPage();
	}

	function handleError(err: unknown): void {
		if (err instanceof ApiError) {
			if (err.status === 401) return; // the layout gate took over
			if (err.status === 400) {
				// Render the server's message verbatim — never rewrite.
				list.filterError = err.message;
				if (list.status === 'loading') list.status = 'loaded';
				return;
			}
		}
		list.status = 'error';
	}

	// --- live merge --------------------------------------------------------

	/** Rows wearing the 600ms update flash (neutral zinc, never accent). */
	const flashing = $state<Record<string, true>>({});

	function flash(trajectoryId: string): void {
		flashing[trajectoryId] = true;
		setTimeout(() => {
			delete flashing[trajectoryId];
		}, 600);
	}

	function eventTime(iso?: string): number {
		if (iso === undefined) return 0;
		const t = Date.parse(iso);
		return Number.isNaN(t) ? 0 : t;
	}

	/** Re-sort in place by last activity, newest first — an updated row floats
	 * up. */
	function sortRows(): void {
		list.rows.sort((a, b) => eventTime(b.lastEventAt) - eventTime(a.lastEventAt));
	}

	/** Stream merge handler (registered while the page is mounted). REST
	 * hydrates, WS applies deltas: counts and ordering update in place;
	 * anything the current rows can't express re-runs loadFirstPage with the
	 * current filters — server-side filters stay authoritative, with no
	 * client-side filter re-derivation. */
	export function applyEnvelopeToList(envelope: DataEnvelope): void {
		const row = list.rows.find((r) => r.trajectoryId === envelope.trajectory_id);

		if (envelope.type === 'event') {
			if (row === undefined) {
				// New trajectory (or a filtered view that may now match): the
				// cheap correct path is a first-page refetch — guard against
				// burst re-entrancy while a load is already running.
				if (list.status !== 'loading') void loadFirstPage();
				return;
			}
			row.eventCount += 1;
			row.lastEventAt = envelope.data.timestamp;
			sortRows();
			flash(row.trajectoryId);
			return;
		}

		// adjudication: only cedar-actor Deny/Escalate moves severity counts —
		// monitor mirror records can never inflate them.
		if (envelope.data.actorId !== 'cedar') return;
		const decision = envelope.data.decision;
		if (decision !== 'Deny' && decision !== 'Escalate') return;
		if (row === undefined) {
			// A decision-filtered view may match this trajectory only now.
			if (list.status !== 'loading') void loadFirstPage();
			return;
		}
		if (decision === 'Deny') row.denyCount += 1;
		else row.escalateCount += 1;
		flash(row.trajectoryId);
	}
</script>

<script lang="ts">
	import { onMount } from 'svelte';
	import { live } from '$lib/api/stream.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import * as Table from '$lib/components/ui/table';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import FilterBar from '$lib/components/FilterBar.svelte';
	import SeverityBadges, { severityOf, type Severity } from '$lib/components/SeverityBadges.svelte';
	import { formatRelative, truncateMiddle } from '$lib/format';

	/** bind:this so the filtered-empty state's "Clear filters" button resets
	 * the bar's controls (which re-emits empty params). */
	let filterBar: FilterBar | undefined = $state();

	const filtered = $derived(hasActiveFilters(list.filters));

	// Severity rail: colored left-edge border on the row; clean rows keep a
	// transparent rail so columns stay aligned.
	const railClass: Record<Severity, string> = {
		deny: 'border-l-[#F87171]',
		escalate: 'border-l-[#FBBF24]',
		clean: 'border-l-transparent'
	};

	onMount(() => {
		void loadFirstPage();
		// Merge stream envelopes into the list while mounted.
		const unsubMessage = live.onMessage(applyEnvelopeToList);
		// On lag/reconnect the stream resyncs before later envelopes process —
		// re-run the first-page load with the current filters (loadFirstPage
		// also clears the stale Load more cursor).
		const unsubResync = live.onResync(async () => {
			await loadFirstPage();
		});
		return () => {
			unsubMessage();
			unsubResync();
		};
	});
</script>

<h1 class="text-xl font-semibold">Trajectories</h1>

<!-- Filter strip: every change refetches from page one via applyFilters
     (which resets the keyset cursor). -->
<div class="mt-6">
	<FilterBar bind:this={filterBar} onchange={(params) => void applyFilters(params)} />
	{#if list.filterError !== null}
		<!-- The server's 400 message, verbatim — it already names the
		     offending param; never rewritten. -->
		<p class="mt-2 text-xs text-[#F87171]">{list.filterError}</p>
	{/if}
</div>

<div class="mt-8">
	{#if list.status === 'loading'}
		<!-- Skeleton loading state — no copy. -->
		<div class="flex flex-col gap-2" data-state="loading">
			{#each Array.from({ length: 8 }) as _, i (i)}
				<Skeleton class="h-10 w-full" />
			{/each}
		</div>
	{:else if list.status === 'error'}
		<div class="flex flex-col items-center gap-4 py-12 text-center">
			<p class="text-sm text-zinc-400">
				Couldn't load trajectories — check that sondera-dashboard is running.
			</p>
			<Button variant="outline" onclick={() => void loadFirstPage()}>Retry</Button>
		</div>
	{:else if list.rows.length === 0}
		{#if filtered}
			<div class="flex flex-col items-center gap-4 py-12 text-center">
				<p class="text-sm text-zinc-400">No trajectories match these filters.</p>
				<Button variant="secondary" size="sm" onclick={() => filterBar?.clear()}>
					Clear filters
				</Button>
			</div>
		{:else}
			<div class="flex flex-col items-center gap-2 py-12 text-center">
				<h2 class="text-base font-semibold">No trajectories yet</h2>
				<p class="text-sm text-zinc-400">
					Run an agent with Sondera hooks installed, or load demo data: <code class="font-mono"
						>cargo run -p sondera-seed</code
					>.
				</p>
			</div>
		{/if}
	{:else}
		<Tooltip.Provider>
			<Table.Root>
				<Table.Header>
					<Table.Row>
						<Table.Head class="text-xs font-semibold tracking-wide uppercase">Trajectory</Table.Head
						>
						<Table.Head class="text-xs font-semibold tracking-wide uppercase">Status</Table.Head>
						<Table.Head class="text-xs font-semibold tracking-wide uppercase">Provider</Table.Head>
						<Table.Head class="text-right text-xs font-semibold tracking-wide uppercase"
							>Events</Table.Head
						>
						<Table.Head class="text-xs font-semibold tracking-wide uppercase">Decisions</Table.Head
						>
						<Table.Head class="text-xs font-semibold tracking-wide uppercase"
							>Last activity</Table.Head
						>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each list.rows as row (row.trajectoryId)}
						<!-- Whole row clickable via the stretched anchor
						     (back-button-correct). -->
						<!-- Live-merge flash: 600ms hold, then the color transition
						     settles it back (no accent). -->
						<Table.Row
							class={`group relative border-l-2 transition-colors ${railClass[severityOf(row)]} ${
								flashing[row.trajectoryId] ? 'bg-[#27272A]' : ''
							}`}
						>
							<Table.Cell class="py-3 font-mono text-xs">
								<Tooltip.Root>
									<Tooltip.Trigger>
										{#snippet child({ props })}
											<a
												{...props}
												href={`/trajectories/${encodeURIComponent(row.trajectoryId)}`}
												class="text-foreground after:absolute after:inset-0 group-hover:underline"
											>
												{truncateMiddle(row.trajectoryId)}
											</a>
										{/snippet}
									</Tooltip.Trigger>
									<Tooltip.Content>
										<span class="font-mono text-xs">{row.trajectoryId}</span>
									</Tooltip.Content>
								</Tooltip.Root>
							</Table.Cell>
							<Table.Cell class="py-3">
								<!-- Lifecycle status: separate neutral zinc badge, never
								     blended with severity color. -->
								<Badge variant="outline" class="border-zinc-700 text-zinc-400">{row.status}</Badge>
							</Table.Cell>
							<Table.Cell class="py-3 text-sm text-zinc-400">
								{row.agentProvider ?? '—'}
							</Table.Cell>
							<Table.Cell class="py-3 text-right text-sm">{row.eventCount}</Table.Cell>
							<Table.Cell class="py-3">
								<SeverityBadges item={row} />
							</Table.Cell>
							<Table.Cell class="py-3 text-sm text-zinc-400">
								{#if row.lastEventAt !== undefined}
									<Tooltip.Root>
										<Tooltip.Trigger>
											{#snippet child({ props })}
												<span {...props}>{formatRelative(row.lastEventAt ?? '')}</span>
											{/snippet}
										</Tooltip.Trigger>
										<Tooltip.Content>
											<span class="font-mono text-xs">{row.lastEventAt}</span>
										</Tooltip.Content>
									</Tooltip.Root>
								{:else}
									—
								{/if}
							</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		</Tooltip.Provider>

		{#if list.nextBefore !== null && list.nextBeforeId !== null}
			<!-- Keyset pagination: rendered only when both cursor halves are
			     present; loadMore passes both back. -->
			<div class="mt-4 flex justify-center">
				<Button variant="ghost" disabled={list.loadingMore} onclick={() => void loadMore()}>
					Load more
				</Button>
			</div>
		{/if}
	{/if}
</div>
