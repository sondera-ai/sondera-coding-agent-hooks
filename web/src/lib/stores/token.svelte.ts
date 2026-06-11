// sessionStorage-backed dashboard token store.
//
// sessionStorage only: per-tab, gone on browser close, cleared on any 401.
// Never "upgrade" this to persistent browser storage — the accepted threat
// model is a localhost console with a short-lived credential.

const KEY = 'sondera_token';

/** Defensive guard: ssr=false means we always run in a browser, but keep the
 * store safe under any non-DOM evaluation (e.g. tooling). */
function storage(): Storage | null {
	return typeof sessionStorage === 'undefined' ? null : sessionStorage;
}

class TokenStore {
	value = $state<string | null>(storage()?.getItem(KEY) ?? null);

	set(t: string): void {
		this.value = t;
		storage()?.setItem(KEY, t);
	}

	/** Any 401 (or WS auth failure) calls this — the layout gate reacts. */
	clear(): void {
		this.value = null;
		storage()?.removeItem(KEY);
	}
}

export const token = new TokenStore();
