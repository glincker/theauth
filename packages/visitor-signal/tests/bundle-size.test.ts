import { existsSync, readFileSync, statSync } from "node:fs";
import { describe, expect, it } from "vitest";

const dist = new URL("../dist/index.js", import.meta.url);
const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

/** Env override first, otherwise the default documented in the README. */
const budget = (): number => {
	const fromEnv = Number(process.env.VISITOR_SIGNAL_BUNDLE_BUDGET_BYTES);
	if (Number.isFinite(fromEnv) && fromEnv > 0) return fromEnv;
	const m = /Default budget: (\d+) bytes/.exec(readme);
	return Number(m?.[1]);
};

describe("bundle size", () => {
	it("README documents a default budget", () => expect(Number.isFinite(budget())).toBe(true));
	it.skipIf(!existsSync(dist))("built bundle stays inside the budget", () => {
		expect(statSync(dist).size).toBeLessThanOrEqual(budget());
	});
});
