<script lang="ts">
	// Paste-once token gate: the candidate is validated against GET /health
	// before it is stored, so a "valid" state can't exist without server
	// confirmation. The token is never echoed — password-type input, no
	// logging, never placed in a URL.
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { Input } from '$lib/components/ui/input';
	import { API_BASE, validateToken } from '$lib/api/client';
	import { token } from '$lib/stores/token.svelte';

	let candidate = $state('');
	let probing = $state(false);
	let error = $state<string | null>(null);

	// Host shown in the unreachable message: the loopback constant in dev, the
	// serving host in built (same-origin) mode.
	const base = API_BASE !== '' ? API_BASE : (typeof location === 'undefined' ? '' : location.host);

	async function submit(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		if (probing) return;
		probing = true;
		error = null;
		const validation = await validateToken(candidate);
		probing = false;
		if (validation.result === 'ok') {
			token.set(candidate); // stored only after a 200 from /health
		} else if (validation.result === 'rejected') {
			error = 'Token rejected — check SONDERA_DASHBOARD_TOKEN and try again.';
		} else {
			error = `Can't reach the dashboard API at ${base} — start it with scripts/dev.sh, then retry.`;
		}
	}
</script>

<!-- Token screen: top spacing, centered card. -->
<div class="pt-16">
	<Card.Root class="mx-auto mt-12 w-full max-w-sm">
		<Card.Header>
			<Card.Title class="text-xl font-semibold">Sondera Dashboard</Card.Title>
		</Card.Header>
		<Card.Content>
			<form class="flex flex-col gap-4" onsubmit={submit}>
				<div class="flex flex-col gap-2">
					<label for="dashboard-token" class="text-base font-semibold">Dashboard token</label>
					<p class="text-xs text-zinc-400">Paste the bearer token (SONDERA_DASHBOARD_TOKEN).</p>
					<Input
						id="dashboard-token"
						type="password"
						autocomplete="off"
						bind:value={candidate}
						disabled={probing}
					/>
				</div>
				{#if error !== null}
					<p class="text-xs text-[#F87171]">{error}</p>
				{/if}
				<!-- Token-screen primary button (accent). -->
				<Button
					type="submit"
					disabled={probing}
					class="bg-[#22D3EE] text-zinc-950 hover:bg-[#22D3EE]/80"
				>
					Connect to dashboard
				</Button>
			</form>
		</Card.Content>
	</Card.Root>
</div>
