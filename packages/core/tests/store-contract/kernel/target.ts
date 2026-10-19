import type { Stores } from "../../../src/db/store/index.js";

/** What a backend hands the kernel suites: the repositories, a second handle for a second process, a close hook. */
export interface KernelTarget {
	stores: Stores;
	/** A second instance on the same database with its own driver handle and its own write queues. Absent when the backend cannot be shared (an in-memory database). */
	peer?: () => Promise<KernelTarget>;
	close(): Promise<void>;
}

export type MakeTarget = () => Promise<KernelTarget>;

export interface SuiteOptions {
	/** Parallel callers per race. Default 24. */
	parallel?: number;
	/** Backend folds ASCII case in LIKE (SQLite). */
	likeFoldsCase?: boolean;
}

let counter = 0;
export const uid = (tag: string): string => `${tag}-${Date.now().toString(36)}-${++counter}`;
export const future = (): Date => new Date(Date.now() + 3_600_000);
export const past = (): Date => new Date(Date.now() - 3_600_000);
