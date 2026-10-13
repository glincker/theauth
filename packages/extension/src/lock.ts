import type { StoredLock, TokenStore } from "./token-store.js";

export interface LockOptions {
	store: TokenStore;
	owner: string;
	ttlMs: number;
	pollMs: number;
	clock: () => number;
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Best effort cross-context lock built on extension storage, which has no
 * compare-and-set. It writes its claim, yields once, then reads it back: when
 * two workers race, the last writer wins and the other keeps waiting. The
 * expiry means a worker killed mid-refresh cannot wedge sign in.
 */
export async function acquireRefreshLock(options: LockOptions): Promise<() => Promise<void>> {
	const { store, owner, ttlMs, pollMs, clock } = options;
	const maxPolls = Math.ceil(ttlMs / Math.max(pollMs, 1)) + 2;

	for (let i = 0; i <= maxPolls; i++) {
		const current = await store.readLock();
		const free = !current || current.expiresAt <= clock() || current.owner === owner;
		if (free) {
			const claim: StoredLock = { owner, expiresAt: clock() + ttlMs };
			await store.writeLock(claim);
			await sleep(0);
			const confirmed = await store.readLock();
			if (confirmed?.owner === owner) break;
		}
		if (i === maxPolls) {
			// The holder never released and the clock never moved. Take over.
			await store.writeLock({ owner, expiresAt: clock() + ttlMs });
			break;
		}
		await sleep(pollMs);
	}

	return async () => {
		const current = await store.readLock();
		if (current?.owner === owner) await store.clearLock();
	};
}
