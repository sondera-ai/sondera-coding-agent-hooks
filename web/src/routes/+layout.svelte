<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { live } from '$lib/api/stream.svelte';
	import StatusChip from '$lib/components/StatusChip.svelte';
	import TokenScreen from '$lib/components/TokenScreen.svelte';
	import { Toaster } from '$lib/components/ui/sonner';
	import { token } from '$lib/stores/token.svelte';
	import { toast } from 'svelte-sonner';

	let { children } = $props();

	// The layout owns the user-facing resync notices. The stream module fires
	// this after a resync completes (views have already re-fetched). The
	// transient toast is only half of it — the persistent half is the chip's
	// gap note: lastGap is deliberately not auto-cleared on resync, so the
	// notice stays visible until the next clean page load.
	live.onResynced = () => {
		if (live.lastGap?.missed !== undefined) {
			toast(`Missed ${live.lastGap.missed} events — resynced`);
		} else {
			toast('Reconnected — resynced');
		}
	};

	// One app-wide stream connection, owned by the layout. The token gate
	// doubles as the connection gate: token present -> connect (the token
	// rides the WS upgrade only, never logged); token cleared (the 401 path)
	// -> disconnect, and the gate below shows the token screen.
	$effect(() => {
		if (token.value !== null) {
			live.connect(token.value);
		} else {
			live.disconnect();
		}
		return () => live.disconnect();
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Sondera Dashboard</title>
</svelte:head>

{#if token.value === null}
	<!-- Token gate: with no token, every route shows only the token screen —
	     no header/nav leaks before auth. Because client.ts clears the token on
	     any 401, this branch reactively takes over the moment auth dies; no
	     extra event wiring needed. -->
	<TokenScreen />
{:else}
	<!-- Global shell: header bar, zinc-900 surface, bottom border. -->
	<header
		class="flex h-12 items-center justify-between border-b border-zinc-800 bg-zinc-900 px-4"
	>
		<div class="flex items-baseline gap-2">
			<span class="text-base font-semibold">Sondera</span>
			<span class="text-xs text-zinc-400">Dashboard</span>
		</div>
		<!-- Live-status chip: live/reconnecting dot + persistent gap note
		     driven by the stream module. -->
		<StatusChip status={live.status} lastGap={live.lastGap} />
	</header>

	<!-- Content area: full-bleed console with the page gutter. -->
	<main class="p-6">
		{@render children()}
	</main>
{/if}

<!-- Transient resync notices render through sonner; toasts fire from the
     layout's onResynced hook. -->
<Toaster />
