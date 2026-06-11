// Static SPA build (D-71/D-86): adapter-static with an index.html fallback so
// client-side routes (/trajectories/[id]) resolve when served by the dashboard's
// --ui-dir ServeDir fallback. NOT adapter-auto (RESEARCH Pitfall 8).
import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		// fallback named index.html (not 200.html): our own ServeDir serves it
		// with status 200 anyway (RESEARCH Pattern 1).
		adapter: adapter({ fallback: 'index.html' })
	}
};

export default config;
