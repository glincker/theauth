import { afterAll, describe, expect, it } from "vitest";
import { parseArgs } from "../src/args.js";
import { main } from "../src/cli.js";
import type { GuardFlaw } from "../src/guard-reference.js";
import { startGuardReference } from "../src/guard-reference.js";
import { runSuite } from "../src/runner.js";

const SECRET = "conformance-test-secret";
const closers: Array<() => Promise<void>> = [];
afterAll(async () => {
	for (const close of closers) await close();
});

async function runAgainst(flaw?: GuardFlaw, secret = SECRET, delayMs?: number) {
	const guard = await startGuardReference({ secret: SECRET, flaw, delayMs });
	closers.push(guard.close);
	return runSuite({ target: guard.url, timeoutMs: 8000, mode: "guard", guardSecret: secret });
}

function failing(report: Awaited<ReturnType<typeof runAgainst>>): string[] {
	return report.results.filter((r) => r.status === "fail").map((r) => r.id);
}

describe("guard conformance", () => {
	it("passes every check against the reference guard", async () => {
		const report = await runAgainst();
		expect(failing(report)).toEqual([]);
		expect(report.summary.pass).toBe(report.results.length);
		expect(report.results.length).toBeGreaterThanOrEqual(12);
	});

	const cases: Array<[GuardFlaw, string]> = [
		["accepts-unsigned", "guard-rejects-unsigned"],
		["accepts-stale", "guard-rejects-stale"],
		["bad-verdict", "guard-canary-allow"],
		["allows-malformed", "guard-malformed-input"],
		["redirects", "guard-no-redirect"],
		["unsigned-response", "guard-response-signed"],
		["wrong-response-secret", "guard-response-signature"],
		["wrong-response-request-id", "guard-response-signature"],
		["stale-response", "guard-response-fresh"],
	];
	for (const [flaw, id] of cases) {
		it(`flags ${flaw} through ${id}`, async () => {
			expect(failing(await runAgainst(flaw))).toContain(id);
		});
	}

	it("flags a slow guard through the latency budget", async () => {
		const report = await runAgainst("slow", SECRET, 2050);
		expect(failing(report)).toContain("guard-latency");
	}, 90000);

	it("fails the canaries when the secret is wrong", async () => {
		const report = await runAgainst(undefined, "wrong-secret");
		expect(failing(report)).toContain("guard-canary-allow");
	});

	it("parses guard args and demands a secret", () => {
		const parsed = parseArgs(["guard", "https://g.example/x", "--secret", "s"], {});
		expect(parsed.options).toMatchObject({ mode: "guard", guardSecret: "s" });
		expect(() => parseArgs(["guard", "https://g.example/x"], {})).toThrow(/secret/);
		expect(
			parseArgs(["guard", "https://g.example/x"], { THEAUTH_GUARD_SECRET: "e" }).options
				.guardSecret,
		).toBe("e");
	});

	it("the CLI exits 0 for a good guard and 1 for a bad one", async () => {
		const good = await startGuardReference({ secret: SECRET });
		const bad = await startGuardReference({ secret: SECRET, flaw: "accepts-unsigned" });
		closers.push(good.close, bad.close);
		expect(await main(["guard", good.url, "--secret", SECRET], {})).toBe(0);
		expect(await main(["guard", bad.url, "--secret", SECRET], {})).toBe(1);
	});
});
