/**
 * Solid bindings for the session store. The package has no dependency on solid-js:
 * pass the two primitives you already import, and you get accessors back. That keeps
 * one build working with any solid-js 1.x version and on edge runtimes.
 *
 * ```ts
 * import { createSignal, onCleanup } from "solid-js";
 * const { useSession } = createSolidAuth({ createSignal, onCleanup }, store);
 * ```
 */
import type { SessionState, SessionStore, StoreUser } from "./session-store.js";

/** Solid's `createSignal` and `onCleanup`, structurally typed. */
export interface SolidPrimitives {
	createSignal<T>(value: T): [() => T, (value: T) => unknown];
	onCleanup(fn: () => void): unknown;
}

export interface SolidAuth {
	/** Reactive accessor for `{ session, isLoading }`. Call inside a Solid owner. */
	useSession(): () => SessionState;
	/** Reactive accessor for the signed in user, or `null`. */
	useUser(): () => StoreUser | null;
	/** Reactive accessor for whether a session exists. */
	useIsAuthenticated(): () => boolean;
	/** Re-reads the session from the server. Deduped, so calling it often is safe. */
	refresh: SessionStore["refresh"];
	/** Seeds the session from SSR output. See `SessionStore.hydrateSession`. */
	hydrateSession: SessionStore["hydrateSession"];
	store: SessionStore;
}

export function createSolidAuth(solid: SolidPrimitives, store: SessionStore): SolidAuth {
	function useSession(): () => SessionState {
		const [state, setState] = solid.createSignal<SessionState>(store.getState());
		// Pick up changes made between the first read and the subscription.
		setState(store.getState());
		solid.onCleanup(store.subscribe((next) => setState(next)));
		return state;
	}
	return {
		store,
		refresh: () => store.refresh(),
		hydrateSession: (initial) => store.hydrateSession(initial),
		useSession,
		useUser() {
			const state = useSession();
			return () => state().session?.user ?? null;
		},
		useIsAuthenticated() {
			const state = useSession();
			return () => state().session !== null;
		},
	};
}
