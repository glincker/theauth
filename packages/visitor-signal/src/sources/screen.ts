import { DEFAULTS } from "../defaults.js";
import { fail, ok } from "../result.js";
import type { Result } from "../types.js";

export interface ScreenData {
	screenBucket: string;
	colorDepth?: number;
}

const COLOR_DEPTHS: readonly number[] = [16, 24, 30, 32, 48];

const roundSide = (px: number, bucket: number): number =>
	Math.min(99900, Math.max(bucket, Math.round(px / bucket) * bucket));

/** 1512x982 at 2 becomes "1500x1000@2.0". Sides are clamped to the schema pattern range. */
export const bucketScreen = (
	width: number,
	height: number,
	dpr: number,
	bucketPx: number = DEFAULTS.screenBucketPx,
): string => {
	const ratio = Math.min(9.9, Math.max(0, Math.round(dpr * 10) / 10));
	return `${roundSide(width, bucketPx)}x${roundSide(height, bucketPx)}@${ratio.toFixed(1)}`;
};

export const screenSource = async (): Promise<Result<ScreenData>> => {
	const scr = globalThis.screen;
	if (!scr || !Number.isFinite(scr.width) || !Number.isFinite(scr.height)) {
		return fail("unavailable", "screen missing");
	}
	const dpr = globalThis.devicePixelRatio ?? 1;
	const screenBucket = bucketScreen(scr.width, scr.height, Number.isFinite(dpr) ? dpr : 1);
	const depth = scr.colorDepth;
	return ok(COLOR_DEPTHS.includes(depth) ? { screenBucket, colorDepth: depth } : { screenBucket });
};
