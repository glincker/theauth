/**
 * Refetch triggers for a session: window focus, tab visibility, an interval, and
 * the browser coming back online. Everything is injected through `RefetchEnvironment`,
 * so tests use fake event targets, and with no `window` (servers, workers, edge
 * runtimes) `attachRefetch` does nothing and returns a no-op `stop`.
 */

/** The slice of `EventTarget` the triggers need. */
export interface EventTargetLike {
	addEventListener(type: string, listener: () => void): void;
	removeEventListener(type: string, listener: () => void): void;
}

export interface RefetchEnvironment {
	/** Receives `focus`, `online` and `offline`. Default `globalThis.window`. */
	window?: EventTargetLike;
	/** Receives `visibilitychange`. Default `globalThis.document`. */
	document?: EventTargetLike & { visibilityState?: string };
	/** Reports connectivity. Default reads `navigator.onLine`, or true without it. */
	isOnline?: () => boolean;
}

export interface RefetchOptions {
	/** Refetch when the window gains focus or the tab becomes visible. Default true. */
	onFocus?: boolean;
	/** Refetch when the browser reports it is back online. Default true. */
	onReconnect?: boolean;
	/** Refetch every N milliseconds. 0 or unset disables the interval. */
	intervalMs?: number;
	/** Keep the interval running while offline. Default false. */
	whenOffline?: boolean;
	env?: RefetchEnvironment;
}

interface GlobalsWithBrowser {
	window?: EventTargetLike;
	document?: EventTargetLike & { visibilityState?: string };
	navigator?: { onLine?: boolean };
}

function resolveEnv(env: RefetchEnvironment | undefined): Required<RefetchEnvironment> | null {
	const g = globalThis as GlobalsWithBrowser;
	const win = env?.window ?? g.window;
	if (!win) return null;
	const doc = env?.document ?? g.document;
	return {
		window: win,
		document: doc ?? { addEventListener() {}, removeEventListener() {} },
		isOnline: env?.isOnline ?? (() => g.navigator?.onLine ?? true),
	};
}

/**
 * Calls `trigger` on focus, visibility, reconnect and on an interval. Returns a
 * `stop` function that removes every listener and clears the timer. Safe to call
 * `stop` more than once. Overlapping triggers are the caller's concern: pass a
 * `trigger` that dedupes, as `createSessionStore().refresh` does.
 */
export function attachRefetch(trigger: () => void, options: RefetchOptions = {}): () => void {
	const env = resolveEnv(options.env);
	if (!env) return () => {};

	const cleanups: Array<() => void> = [];
	const listen = (target: EventTargetLike, type: string, fn: () => void): void => {
		target.addEventListener(type, fn);
		cleanups.push(() => target.removeEventListener(type, fn));
	};

	if (options.onFocus !== false) {
		listen(env.window, "focus", trigger);
		listen(env.document, "visibilitychange", () => {
			if (env.document.visibilityState !== "hidden") trigger();
		});
	}
	if (options.onReconnect !== false) listen(env.window, "online", trigger);

	const intervalMs = options.intervalMs ?? 0;
	if (Number.isFinite(intervalMs) && intervalMs > 0) {
		const timer = setInterval(() => {
			if (options.whenOffline || env.isOnline()) trigger();
		}, intervalMs);
		cleanups.push(() => clearInterval(timer));
	}

	let stopped = false;
	return () => {
		if (stopped) return;
		stopped = true;
		for (const c of cleanups) c();
	};
}
