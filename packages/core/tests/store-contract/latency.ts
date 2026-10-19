/**
 * Wraps a Drizzle handle so every awaited query first yields to the event loop (a macrotask).
 * better-sqlite3 and sql.js answer synchronously, so parallel callers run each read-then-write pair
 * back to back and a non-atomic claim looks fine. With a real network database the gap between the
 * read and the write is wide. This wrapper widens it on SQLite so the suite can tell the two apart.
 */
function tick(): Promise<void> {
	return new Promise((resolve) => setImmediate(resolve));
}

function wrap<T extends object>(target: T): T {
	return new Proxy(target, {
		get(obj, prop) {
			const value = Reflect.get(obj, prop, obj) as unknown;
			if (prop === "then" && typeof value === "function") {
				return (resolve: (v: unknown) => unknown, reject: (e: unknown) => unknown) =>
					tick().then(() =>
						(value as (a: unknown, b: unknown) => unknown).call(obj, resolve, reject),
					);
			}
			if (typeof value === "function") {
				return (...args: unknown[]) => {
					const out = (value as (...a: unknown[]) => unknown).apply(obj, args);
					return typeof out === "object" && out !== null ? wrap(out) : out;
				};
			}
			return value;
		},
	});
}

export function withQueryLatency<T extends object>(db: T): T {
	return wrap(db);
}
