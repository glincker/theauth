import { fail, ok } from "../result.js";
import type { Result } from "../types.js";

export interface PreferencesData {
	reducedMotion: boolean;
	colorScheme: "light" | "dark" | "none";
}

export const preferences = async (): Promise<Result<PreferencesData>> => {
	const mm = globalThis.matchMedia;
	if (typeof mm !== "function") return fail("unavailable", "matchMedia missing");
	const reducedMotion = mm("(prefers-reduced-motion: reduce)").matches;
	const colorScheme = mm("(prefers-color-scheme: dark)").matches
		? "dark"
		: mm("(prefers-color-scheme: light)").matches
			? "light"
			: "none";
	return ok({ reducedMotion, colorScheme });
};
