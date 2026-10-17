import type { Checkpoint, CheckpointStore } from "./checkpoint-types.js";

function sameCheckpoint(a: Checkpoint, b: Checkpoint): boolean {
	return (
		a.size === b.size &&
		a.rootHash === b.rootHash &&
		a.keyId === b.keyId &&
		a.timestamp === b.timestamp &&
		a.since === b.since &&
		a.until === b.until &&
		a.signature === b.signature
	);
}

function order(a: Checkpoint, b: Checkpoint): number {
	return a.size - b.size || a.timestamp - b.timestamp;
}

/**
 * Checkpoint store that keeps everything in process memory. Good for tests and single-process tools. There is no drizzle-backed store yet: it needs a new table and migration, so it is left out rather than half done.
 */
export function createMemoryCheckpointStore(): CheckpointStore {
	const items: Checkpoint[] = [];
	return {
		put(checkpoint) {
			try {
				if (!items.some((c) => sameCheckpoint(c, checkpoint))) {
					items.push({ ...checkpoint });
					items.sort(order);
				}
				return Promise.resolve();
			} catch (error) {
				return Promise.reject(error);
			}
		},
		latest() {
			const last = items[items.length - 1];
			return Promise.resolve(last ? { ...last } : undefined);
		},
		getBySize(size) {
			return Promise.resolve(items.filter((c) => c.size === size).map((c) => ({ ...c })));
		},
		list() {
			return Promise.resolve(items.map((c) => ({ ...c })));
		},
	};
}
