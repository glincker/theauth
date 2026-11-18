import { DEFAULTS } from "../defaults.js";
import { fail, ok } from "../result.js";
import type { Result } from "../types.js";

export const touch = async (): Promise<Result<{ touchPoints: number }>> => {
	const points = globalThis.navigator?.maxTouchPoints;
	if (typeof points !== "number" || !Number.isFinite(points)) {
		return fail("unavailable", "maxTouchPoints missing");
	}
	return ok({ touchPoints: Math.min(DEFAULTS.maxTouchPoints, Math.max(0, Math.trunc(points))) });
};
