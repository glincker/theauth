import { ok } from "../result.js";
import type { Result } from "../types.js";

/** Bit positions from SPEC.md. Bits 10 to 31 stay 0. */
export const CAP_BITS = {
	cookies: 0,
	localStorage: 1,
	sessionStorage: 2,
	indexedDB: 3,
	webgl: 4,
	wasm: 5,
	intl: 6,
	pointerEvent: 7,
	notification: 8,
	serviceWorker: 9,
} as const;

export type CapName = keyof typeof CAP_BITS;

export const buildCaps = (present: Partial<Record<CapName, boolean>>): number => {
	let caps = 0;
	for (const name of Object.keys(CAP_BITS) as CapName[]) {
		if (present[name]) caps |= 1 << CAP_BITS[name];
	}
	return caps >>> 0;
};

const safe = (probe: () => boolean): boolean => {
	try {
		return probe();
	} catch {
		return false;
	}
};

const g = globalThis as unknown as Record<string, unknown>;

/** Presence checks only. WebGL is probed on a detached canvas, no renderer string is read. */
export const capabilities = async (): Promise<Result<{ caps: number }>> => {
	const present: Partial<Record<CapName, boolean>> = {
		cookies: safe(() => globalThis.navigator?.cookieEnabled === true),
		localStorage: safe(() => typeof g.localStorage === "object" && g.localStorage !== null),
		sessionStorage: safe(() => typeof g.sessionStorage === "object" && g.sessionStorage !== null),
		indexedDB: safe(() => typeof g.indexedDB === "object" && g.indexedDB !== null),
		webgl: safe(() => {
			if (typeof document === "undefined") return false;
			const canvas = document.createElement("canvas");
			return canvas.getContext("webgl") !== null || canvas.getContext("webgl2") !== null;
		}),
		wasm: safe(() => typeof g.WebAssembly === "object"),
		intl: safe(() => typeof Intl?.DateTimeFormat === "function"),
		pointerEvent: safe(() => typeof g.PointerEvent === "function"),
		notification: safe(() => typeof g.Notification !== "undefined"),
		serviceWorker: safe(() => globalThis.navigator !== undefined && "serviceWorker" in navigator),
	};
	return ok({ caps: buildCaps(present) });
};
