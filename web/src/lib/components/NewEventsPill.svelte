<script lang="ts">
	// Floating new-events pill, fixed bottom-center of the timeline pane.
	// Renders only while the view is not at bottom; the owner zeroes `count`
	// when the user reaches the bottom or jumps.
	let { count, onJump }: { count: number; onJump: () => void } = $props();
</script>

{#if count > 0}
	<button
		type="button"
		class="absolute bottom-4 left-1/2 z-10 -translate-x-1/2 rounded-full bg-[#22D3EE] px-3 py-1 text-xs font-semibold whitespace-nowrap text-zinc-950 shadow-md hover:brightness-110"
		onclick={onJump}
	>
		{count === 1 ? '1 new event ↓' : `${count} new events ↓`}
	</button>
{/if}
