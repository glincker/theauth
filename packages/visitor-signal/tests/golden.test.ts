import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalise } from "../src/canonical.js";
import { computeConfidence } from "../src/confidence.js";
import { validatePayload } from "../src/schema.js";
import { toSignalV1 } from "../src/signal-v1.js";
import type { Components, Flags, UnavailableName } from "../src/types.js";

const fixture = <T>(path: string): T =>
	JSON.parse(readFileSync(new URL(`./fixtures/${path}`, import.meta.url), "utf8")) as T;

interface Vectors {
	vectors: Array<{ name: string; components: Components; canonical: string }>;
}
interface Extra {
	signalV1: Array<{ name: string; pepper: string; components: Components; digest: string }>;
}
interface Manifest {
	cases: Array<{ file: string; valid: boolean; error: string | null }>;
}

describe("canonical golden vectors", () => {
	for (const v of fixture<Vectors>("vectors.json").vectors) {
		it(v.name, () => expect(canonicalise(v.components)).toBe(v.canonical));
	}
});

describe("SignalV1 golden vectors", () => {
	for (const v of fixture<Extra>("vectors-extra.json").signalV1) {
		it(v.name, async () => {
			const out = await toSignalV1(v.components, v.pepper, 0.75, 1763452800123);
			expect(out.digest).toBe(v.digest);
			expect(out).toMatchObject({ v: 1, source: "browser", ts: 1763452800 });
			expect(out.components).toBe(Object.keys(v.components).length);
			expect(Object.keys(out).sort()).toEqual([
				"components",
				"confidence",
				"digest",
				"source",
				"ts",
				"v",
			]);
		});
	}
});

describe("schema validator against manifest", () => {
	for (const c of fixture<Manifest>("manifest.json").cases) {
		it(c.file, () => expect(validatePayload(fixture(c.file)).valid).toBe(c.valid));
	}
});

interface ConfidenceCase {
	name: string;
	mode: "analytics" | "fraud_prevention";
	platform?: string;
	mobile?: boolean;
	uaBrand?: string;
	flags: Partial<Flags>;
	unavailable: UnavailableName[];
	components: number;
	score: number;
}

const PAD: Components[] = [
	{ tz: "UTC" },
	{ lang: "en" },
	{ langCount: 1 },
	{ touchPoints: 0 },
	{ cores: 4 },
	{ caps: 1 },
	{ tzOffsetMin: 0 },
	{ colorDepth: 24 },
];

describe("confidence golden vectors", () => {
	for (const c of fixture<{ confidence: ConfidenceCase[] }>("vectors-extra.json").confidence) {
		it(c.name, () => {
			const components: Components = {};
			if (c.platform !== undefined) components.platform = c.platform;
			if (c.mobile !== undefined) components.mobile = c.mobile;
			if (c.uaBrand !== undefined) components.uaBrand = c.uaBrand;
			for (const pad of PAD) {
				if (Object.keys(components).length >= c.components) break;
				Object.assign(components, pad);
			}
			expect(Object.keys(components)).toHaveLength(c.components);
			const flags: Flags = {
				protectedBrowser: false,
				webdriver: false,
				headlessHint: false,
				inconsistent: false,
				...c.flags,
			};
			const score = computeConfidence({
				mode: c.mode,
				components,
				flags,
				unavailable: c.unavailable,
			});
			expect(score).toBe(c.score);
		});
	}
});
