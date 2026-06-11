<script lang="ts">
	// Filter bar: builds server-side query params only — the emitted
	// ListFilterParams object IS the filter (repeated keys OR within a
	// dimension, dimensions AND together). Nothing is re-filtered client-side.
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import type { Decision, Label, ListFilterParams } from '$lib/api/types';

	let { onchange }: { onchange: (params: ListFilterParams) => void } = $props();

	// Canonical wire values, sent verbatim: decisions PascalCase, labels
	// snake_case.
	const DECISIONS: Decision[] = ['Allow', 'Deny', 'Escalate'];
	const LABELS: Label[] = ['public', 'internal', 'confidential', 'highly_confidential'];

	let decisions = $state<Decision[]>([]);
	let labels = $state<Label[]>([]);
	let policyId = $state('');
	let from = $state('');
	let to = $state('');

	function toggleDecision(d: Decision): void {
		decisions = decisions.includes(d) ? decisions.filter((x) => x !== d) : [...decisions, d];
		emit();
	}

	function toggleLabel(l: Label): void {
		labels = labels.includes(l) ? labels.filter((x) => x !== l) : [...labels, l];
		emit();
	}

	/**
	 * Build the params object. Blank values are omitted (never empty strings);
	 * datetime-local values are converted to strict RFC 3339 via
	 * Date.toISOString, since the server rejects sloppy formats with a 400.
	 * Multi-select arrays become repeated query keys in client.ts
	 * (decision=...&decision=...).
	 */
	function build(): ListFilterParams {
		const params: ListFilterParams = {};
		if (decisions.length > 0) params.decision = [...decisions];
		if (labels.length > 0) params.label = [...labels];
		const id = policyId.trim();
		if (id !== '') params.policyId = [id];
		if (from !== '') params.from = new Date(from).toISOString();
		if (to !== '') params.to = new Date(to).toISOString();
		return params;
	}

	function emit(): void {
		onchange(build());
	}

	/** Reset every control and re-emit empty params. Also callable from the
	 * page's filtered-empty state via bind:this. */
	export function clear(): void {
		decisions = [];
		labels = [];
		policyId = '';
		from = '';
		to = '';
		emit();
	}
</script>

<!-- Filter strip on the secondary zinc-900 surface. -->
<div class="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md bg-zinc-900 p-4">
	<div class="flex items-center gap-2">
		<span class="text-xs font-semibold tracking-wide text-zinc-400 uppercase">Decision</span>
		{#each DECISIONS as d (d)}
			<button
				type="button"
				aria-pressed={decisions.includes(d)}
				onclick={() => toggleDecision(d)}
				class={`rounded-full border px-2 py-0.5 text-xs transition-colors ${
					decisions.includes(d)
						? 'border-zinc-600 bg-zinc-800 text-zinc-50'
						: 'border-zinc-800 text-zinc-400 hover:text-zinc-50'
				}`}
			>
				{d}
			</button>
		{/each}
	</div>

	<div class="flex items-center gap-2">
		<span class="text-xs font-semibold tracking-wide text-zinc-400 uppercase">Label</span>
		{#each LABELS as l (l)}
			<button
				type="button"
				aria-pressed={labels.includes(l)}
				onclick={() => toggleLabel(l)}
				class={`rounded-full border px-2 py-0.5 font-mono text-xs transition-colors ${
					labels.includes(l)
						? 'border-zinc-600 bg-zinc-800 text-zinc-50'
						: 'border-zinc-800 text-zinc-400 hover:text-zinc-50'
				}`}
			>
				{l}
			</button>
		{/each}
	</div>

	<Input
		class="h-8 w-44 font-mono text-xs"
		placeholder="policy id (exact)"
		bind:value={policyId}
		onchange={emit}
	/>

	<label class="flex items-center gap-1 text-xs text-zinc-400">
		from
		<Input type="datetime-local" class="h-8 w-fit text-xs" bind:value={from} onchange={emit} />
	</label>
	<label class="flex items-center gap-1 text-xs text-zinc-400">
		to
		<Input type="datetime-local" class="h-8 w-fit text-xs" bind:value={to} onchange={emit} />
	</label>

	<Button variant="ghost" size="sm" onclick={clear}>Clear filters</Button>
</div>
