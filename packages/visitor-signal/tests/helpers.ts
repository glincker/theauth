import { vi } from "vitest";

export interface FakeEnv {
	nav: Record<string, unknown>;
	width: number;
	height: number;
	dpr: number;
}

export const fullNav = (): Record<string, unknown> => ({
	language: "de-DE",
	languages: ["de-DE", "en"],
	platform: "MacIntel",
	userAgent: "Mozilla/5.0 (Macintosh) Chrome/130.0.0.0 Safari/537.36",
	userAgentData: {
		mobile: false,
		platform: "macOS",
		brands: [
			{ brand: "Not?A_Brand", version: "99" },
			{ brand: "Chromium", version: "130" },
			{ brand: "Google Chrome", version: "130" },
		],
	},
	maxTouchPoints: 0,
	hardwareConcurrency: 8,
	deviceMemory: 8,
	cookieEnabled: true,
	webdriver: false,
	doNotTrack: null,
	serviceWorker: {},
});

export const installEnv = (over: Partial<FakeEnv> = {}): void => {
	vi.stubGlobal("navigator", over.nav ?? fullNav());
	vi.stubGlobal("screen", {
		width: over.width ?? 1512,
		height: over.height ?? 982,
		colorDepth: 24,
	});
	vi.stubGlobal("devicePixelRatio", over.dpr ?? 2);
	vi.stubGlobal("innerWidth", 1400);
	vi.stubGlobal("innerHeight", 800);
	vi.stubGlobal("matchMedia", (q: string) => ({ matches: q.includes("dark") }));
	vi.stubGlobal("localStorage", {});
	vi.stubGlobal("sessionStorage", {});
	vi.stubGlobal("indexedDB", {});
	vi.stubGlobal("PointerEvent", class {});
	vi.stubGlobal("Notification", class {});
};
