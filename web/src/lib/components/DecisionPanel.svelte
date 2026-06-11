<script lang="ts">
	// Decision detail panel: five stacked sections —
	//   1 Decision badge + reason
	//   2 Matched policy (@id + @description; backstop badge)
	//   3 Guardrails (Signature / Policy / Label rows)
	//   4 Monitor verdict block
	//   5 Cedar request/response (collapsed <details>, JSON)
	//
	// Rendering safety: every API string is text-interpolated and Cedar JSON
	// goes through JSON.stringify into a <pre> text node — no raw HTML.
	import type { AdjudicationDto } from '$lib/api/types';
	import { Badge } from '$lib/components/ui/badge';
	import { Separator } from '$lib/components/ui/separator';
	import { isBackstop } from '$lib/join';
	import DecisionBadge from './DecisionBadge.svelte';
	import MonitorBadge from './MonitorBadge.svelte';

	let { adjudication }: { adjudication: AdjudicationDto | null } = $props();
</script>

{#if adjudication === null}
	<p class="text-sm text-zinc-400">Select an event to inspect its decision.</p>
{:else}
	<div class="flex flex-col gap-6">
		<!-- 1 · Decision -->
		<section class="flex flex-col gap-2">
			<div><DecisionBadge decision={adjudication.decision} /></div>
			{#if adjudication.reason !== undefined}
				<p class="text-sm text-zinc-400">{adjudication.reason}</p>
			{/if}
		</section>

		<Separator class="bg-zinc-800" />

		<!-- 2 · Matched policy: one row per annotation. The "monitor backstop"
		     badge requires both a 'monitor-backstop-' policyId prefix AND
		     source === 'monitor' (isBackstop ANDs both; never either alone, to
		     resist spoofing). -->
		<section class="flex flex-col gap-2">
			<h3 class="text-xs font-semibold tracking-wide text-zinc-400 uppercase">Matched policy</h3>
			{#each adjudication.annotations as a, i (i)}
				<div class="flex flex-col gap-1">
					<div class="flex flex-wrap items-center gap-2">
						{#if a.policyId !== undefined}
							<span class="font-mono text-xs break-all">{a.policyId}</span>
						{/if}
						{#if isBackstop(a)}
							<Badge variant="outline" class="border-zinc-700 text-zinc-400">
								monitor backstop
							</Badge>
						{/if}
					</div>
					{#if a.description !== undefined}
						<p class="text-sm">{a.description}</p>
					{/if}
				</div>
			{:else}
				<p class="text-sm text-zinc-500">no matched policies</p>
			{/each}
		</section>

		<Separator class="bg-zinc-800" />

		<!-- 3 · Guardrails: three rows. Each block is optional — absent blocks
		     render a muted "no signal". -->
		<section class="flex flex-col gap-2">
			<h3 class="text-xs font-semibold tracking-wide text-zinc-400 uppercase">Guardrails</h3>
			<div class="flex flex-col gap-2 text-sm">
				<div class="flex flex-wrap items-baseline gap-2">
					<span class="w-20 shrink-0 text-zinc-400">Signature</span>
					{#if adjudication.guardrails?.signature !== undefined}
						{@const sig = adjudication.guardrails.signature}
						<span>
							{sig.matches}
							{sig.matches === 1 ? 'match' : 'matches'} · severity {sig.severity}
						</span>
						{#each sig.categories as c (c)}
							<span class="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-xs">{c}</span>
						{/each}
					{:else}
						<span class="text-zinc-500">no signal</span>
					{/if}
				</div>
				<div class="flex flex-wrap items-baseline gap-2">
					<span class="w-20 shrink-0 text-zinc-400">Policy</span>
					{#if adjudication.guardrails?.policy !== undefined}
						{@const pol = adjudication.guardrails.policy}
						<span>{pol.compliant ? 'compliant' : 'non-compliant'}</span>
						{#each pol.violations as v, i (i)}
							<span class="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-xs">{v}</span>
						{/each}
					{:else}
						<span class="text-zinc-500">no signal</span>
					{/if}
				</div>
				<div class="flex flex-wrap items-baseline gap-2">
					<span class="w-20 shrink-0 text-zinc-400">Label</span>
					{#if adjudication.guardrails?.label !== undefined}
						<Badge variant="outline" class="border-zinc-700 font-mono text-zinc-300">
							{adjudication.guardrails.label}
						</Badge>
					{:else}
						<span class="text-zinc-500">no signal</span>
					{/if}
				</div>
			</div>
		</section>

		<Separator class="bg-zinc-800" />

		<!-- 4 · Monitor verdict block -->
		<section class="flex flex-col gap-2">
			<h3 class="text-xs font-semibold tracking-wide text-zinc-400 uppercase">Monitor</h3>
			{#if adjudication.monitor !== undefined}
				{@const m = adjudication.monitor}
				<div class="flex flex-wrap items-center gap-2">
					<MonitorBadge monitor={m} />
					<Badge variant="outline" class="border-zinc-700 font-mono text-zinc-400">{m.label}</Badge>
					{#if m.untrustedPending}
						<span class="text-xs text-zinc-400">untrusted read pending</span>
					{/if}
				</div>
				{#if m.taints.length > 0}
					<div class="flex flex-wrap gap-1">
						{#each m.taints as t (t)}
							<span class="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-xs">{t}</span>
						{/each}
					</div>
				{/if}
				<div class="flex flex-col gap-1 text-xs text-zinc-400">
					{#if m.armedEventId !== undefined}
						<span>armed by <span class="font-mono break-all">{m.armedEventId}</span></span>
					{/if}
					{#if m.trippedEventId !== undefined}
						<span>tripped by <span class="font-mono break-all">{m.trippedEventId}</span></span>
					{/if}
					{#if m.clearedEventId !== undefined}
						<span>cleared by <span class="font-mono break-all">{m.clearedEventId}</span></span>
					{/if}
				</div>
			{:else}
				<p class="text-sm text-zinc-500">no monitor block on this decision</p>
			{/if}
		</section>

		<Separator class="bg-zinc-800" />

		<!-- 5 · Cedar request/response: collapsed <details>; JSON.stringify
		     into a <pre> text node only, never raw HTML. -->
		<section class="flex flex-col gap-2">
			{#if adjudication.request !== undefined}
				<details class="rounded border border-zinc-800">
					<summary class="cursor-pointer px-3 py-2 text-sm text-zinc-400 select-none">
						Cedar request
					</summary>
					<pre
						class="overflow-x-auto px-3 pb-3 font-mono text-sm whitespace-pre-wrap">{JSON.stringify(
							adjudication.request,
							null,
							2
						)}</pre>
				</details>
			{:else}
				<p class="text-sm text-zinc-500">no Cedar request recorded</p>
			{/if}
			{#if adjudication.response !== undefined}
				<details class="rounded border border-zinc-800">
					<summary class="cursor-pointer px-3 py-2 text-sm text-zinc-400 select-none">
						Cedar response
					</summary>
					<pre
						class="overflow-x-auto px-3 pb-3 font-mono text-sm whitespace-pre-wrap">{JSON.stringify(
							adjudication.response,
							null,
							2
						)}</pre>
				</details>
			{:else}
				<p class="text-sm text-zinc-500">no Cedar response recorded</p>
			{/if}
		</section>
	</div>
{/if}
