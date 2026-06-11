// Fully client-rendered SPA: without these, vite build fails trying to
// prerender the dynamic /trajectories/[id] route.
export const ssr = false;
export const prerender = false;
