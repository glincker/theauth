import { DEFAULTS } from "../defaults.js";
import { fail, ok } from "../result.js";
import type { Result } from "../types.js";

export interface LanguageData {
	lang: string;
	langCount: number;
}

export const languages = async (): Promise<Result<LanguageData>> => {
	const nav = globalThis.navigator;
	const primary = nav?.language;
	if (!primary) return fail("unavailable", "navigator.language missing");
	const count = nav.languages?.length ?? 1;
	return ok({
		lang: primary.slice(0, 35),
		langCount: Math.min(DEFAULTS.maxLangCount, Math.max(0, count)),
	});
};
