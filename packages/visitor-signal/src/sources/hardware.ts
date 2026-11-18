import { DEFAULTS } from "../defaults.js";
import { fail, ok } from "../result.js";
import type { Result } from "../types.js";

export interface HardwareData {
	cores?: number;
	memoryGb?: number;
}

const MEMORY_VALUES: readonly number[] = [0.25, 0.5, 1, 2, 4, 8];

/** Nearest power of two, ties round up, clamped to [1, max]. */
export const bucketCores = (n: number, max: number = DEFAULTS.maxCores): number => {
	if (!Number.isFinite(n) || n < 1) return 1;
	const lower = 2 ** Math.floor(Math.log2(n));
	const upper = lower * 2;
	const nearest = n - lower < upper - n ? lower : upper;
	return Math.min(max, nearest);
};

/** Snap to the schema enum, the browser already coarsens deviceMemory. */
export const bucketMemory = (gb: number): number | undefined => {
	if (!Number.isFinite(gb) || gb <= 0) return undefined;
	return MEMORY_VALUES.find((v) => v === gb) ?? MEMORY_VALUES.filter((v) => v <= gb).pop();
};

export const hardware = async (): Promise<Result<HardwareData>> => {
	const nav = globalThis.navigator as (Navigator & { deviceMemory?: number }) | undefined;
	if (!nav) return fail("unavailable", "navigator missing");
	const data: HardwareData = {};
	if (typeof nav.hardwareConcurrency === "number" && nav.hardwareConcurrency > 0) {
		data.cores = bucketCores(nav.hardwareConcurrency);
	}
	if (typeof nav.deviceMemory === "number") {
		const mem = bucketMemory(nav.deviceMemory);
		if (mem !== undefined) data.memoryGb = mem;
	}
	return Object.keys(data).length > 0 ? ok(data) : fail("unavailable", "no hardware data");
};
