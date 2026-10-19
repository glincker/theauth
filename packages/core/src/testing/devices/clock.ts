/**
 * A deterministic clock for device tests. `install()` swaps `globalThis.Date` for a proxy that reads
 * this clock, so the server side (token expiry, bundle issue time, replay windows, row timestamps)
 * and jose see the same virtual time. Test use only: never install it in a running service.
 */
export interface VirtualClock {
	/** Virtual time in ms since the epoch. */
	now(): number;
	/** Move time forward by `ms`. */
	advance(ms: number): void;
	set(ms: number): void;
	/** Make `Date.now()` and `new Date()` read this clock. Safe to call twice. */
	install(): void;
	/** Put the real `Date` back. */
	restore(): void;
}

/** 2026-01-01T00:00:00Z, an arbitrary fixed start so runs are repeatable. */
export const DEFAULT_START_MS = Date.UTC(2026, 0, 1);

export function createVirtualClock(startMs = DEFAULT_START_MS): VirtualClock {
	let current = startMs;
	const RealDate = globalThis.Date;
	let installed = false;
	const patched = new Proxy(RealDate, {
		construct(target, args, newTarget) {
			return Reflect.construct(target, args.length === 0 ? [current] : args, newTarget);
		},
		get(target, prop) {
			if (prop === "now") return () => current;
			return Reflect.get(target, prop, target);
		},
	});
	return {
		now: () => current,
		advance(ms) {
			if (ms < 0) throw new Error("advance() takes a non negative number of ms");
			current += ms;
		},
		set(ms) {
			current = ms;
		},
		install() {
			if (installed) return;
			installed = true;
			globalThis.Date = patched;
		},
		restore() {
			if (!installed) return;
			installed = false;
			globalThis.Date = RealDate;
		},
	};
}
