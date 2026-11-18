import type { ConfidenceModel, VisitorSignalPayload } from "./types.js";

export const DEFAULT_CONFIDENCE_MODEL: ConfidenceModel = {
	base: 0.9,
	analyticsMode: 0.15,
	mobileSafari: 0.3,
	android: 0.2,
	protectedBrowser: 0.3,
	inconsistent: 0.2,
	perUnavailable: 0.05,
	unavailableCap: 0.25,
	fewComponents: 0.1,
	fewComponentsMin: 6,
};

const round4 = (n: number): number => Math.round(n * 10000) / 10000;

type Input = Pick<VisitorSignalPayload, "mode" | "components" | "flags" | "unavailable">;

/** Heuristic in [0, 1], not a calibrated probability. */
export const computeConfidence = (payload: Input, model: Partial<ConfidenceModel> = {}): number => {
	const m: ConfidenceModel = { ...DEFAULT_CONFIDENCE_MODEL, ...model };
	const c = payload.components;
	let score = m.base;
	if (payload.mode === "analytics") score -= m.analyticsMode;
	const platform = c.platform ?? "";
	const isIos = platform === "iPhone" || platform === "iPad";
	const androidPlatform = platform.startsWith("Linux armv") || platform.startsWith("Android");
	// Mutually exclusive: the Safari or iOS check wins, Android applies only otherwise.
	if (isIos || (c.mobile === true && c.uaBrand === "Safari")) score -= m.mobileSafari;
	else if (androidPlatform && c.mobile === true) score -= m.android;
	if (payload.flags.protectedBrowser) score -= m.protectedBrowser;
	if (payload.flags.inconsistent) score -= m.inconsistent;
	const missing = payload.unavailable?.length ?? 0;
	score -= Math.min(m.unavailableCap, missing * m.perUnavailable);
	if (Object.keys(c).length < m.fewComponentsMin) score -= m.fewComponents;
	return round4(Math.min(1, Math.max(0, score)));
};
