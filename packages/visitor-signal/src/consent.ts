import { DEFAULTS } from "./defaults.js";
import type { CollectOptions, ConsentState, SuppressedReason } from "./types.js";

export type ConsentDecision =
	| { allowed: true; dnt: false; gpc: false }
	| { allowed: false; reason: SuppressedReason; dnt: boolean; gpc: boolean };

export const isDntSet = (value: unknown): boolean =>
	value === true || value === 1 || value === "1" || value === "yes";

const readConsent = async (
	hook: CollectOptions["consent"],
	timeoutMs: number,
): Promise<ConsentState> => {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const timeout = new Promise<ConsentState>((resolve) => {
		timer = setTimeout(() => resolve("unknown"), timeoutMs);
	});
	const asked = (async (): Promise<ConsentState> => {
		try {
			const state = await hook();
			return state === "granted" || state === "denied" ? state : "unknown";
		} catch {
			return "unknown";
		}
	})();
	try {
		return await Promise.race([asked, timeout]);
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
};

/**
 * Analytics matrix. Consent is checked first; DNT and GPC are read only after it is
 * granted. Nothing else on navigator is touched here.
 */
export const evaluateConsent = async (
	hook: CollectOptions["consent"],
	timeoutMs: number = DEFAULTS.consentTimeoutMs,
): Promise<ConsentDecision> => {
	const state = await readConsent(hook, timeoutMs);
	if (state === "denied")
		return { allowed: false, reason: "consent_denied", dnt: false, gpc: false };
	if (state === "unknown") {
		return { allowed: false, reason: "consent_unknown", dnt: false, gpc: false };
	}
	const nav = globalThis.navigator as (Navigator & { globalPrivacyControl?: boolean }) | undefined;
	const dnt = isDntSet(nav?.doNotTrack);
	const gpc = nav?.globalPrivacyControl === true;
	if (dnt) return { allowed: false, reason: "dnt", dnt, gpc };
	if (gpc) return { allowed: false, reason: "gpc", dnt, gpc };
	return { allowed: true, dnt: false, gpc: false };
};
