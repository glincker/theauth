import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalise } from "../src/canonical.js";
import { validatePayload } from "../src/schema.js";
import { toSignalV1 } from "../src/signal-v1.js";
import type { Components } from "../src/types.js";

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
