import { fail, ok } from "../result.js";
import type { Result } from "../types.js";

export interface TimezoneData {
	tz?: string;
	tzOffsetMin: number;
}

/** Offset is clamped to the schema range, sign flipped so UTC+1 is +60. */
export const clampOffset = (minutes: number): number => Math.max(-840, Math.min(840, minutes));

export const timezone = async (): Promise<Result<TimezoneData>> => {
	try {
		const now = new Date();
		const offset = now.getTimezoneOffset();
		const tzOffsetMin = clampOffset(offset === 0 ? 0 : -offset);
		const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
		// Over-long names would fail schema validation, so drop them and report tz unavailable.
		return ok(tz && [...tz].length <= 64 ? { tz, tzOffsetMin } : { tzOffsetMin });
	} catch {
		return fail("unavailable", "timezone unavailable");
	}
};
