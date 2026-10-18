import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parsePolicyArgs, runPolicyTest, validateSuite } from "../src/policy-commands.js";

const suite = {
	agents: { reader: { permissions: [{ resource: "mcp:*", actions: ["read"] }] } },
	cases: [
		{ name: "reads", agent: "reader", action: "read", resource: "mcp:x", expect: "allow" },
		{
			name: "no write",
			agent: "reader",
			action: "write",
			resource: "mcp:x",
			expect: "deny",
			code: "no_permission",
		},
	],
};

describe("parsePolicyArgs", () => {
	it("parses test with flags", () => {
		expect(parsePolicyArgs(["test", "s.json", "--json", "--config", "c.mjs"])).toMatchObject({
			file: "s.json",
			config: "c.mjs",
			json: true,
			error: null,
		});
	});
	it("flags problems", () => {
		expect(parsePolicyArgs(["test"]).error).toMatch(/suite file/);
		expect(parsePolicyArgs(["nope"]).error).toMatch(/Unknown policy command/);
		expect(parsePolicyArgs([]).help).toBe(true);
	});
});

describe("validateSuite", () => {
	it("rejects bad shapes", () => {
		expect(() => validateSuite({})).toThrow(/cases/);
		expect(() => validateSuite({ cases: [{ name: "a" }] })).toThrow(/agent/);
		expect(() =>
			validateSuite({
				cases: [{ name: "a", agent: "b", action: "c", resource: "d", expect: "x" }],
			}),
		).toThrow(/expect/);
	});
});

describe("runPolicyTest", () => {
	let dir: string;
	let out: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "theauth-policy-"));
		out = "";
		vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
			out += String(chunk);
			return true;
		});
		vi.spyOn(process.stderr, "write").mockImplementation(() => true);
	});
	afterEach(async () => {
		vi.restoreAllMocks();
		await rm(dir, { recursive: true, force: true });
	});

	async function write(name: string, body: unknown): Promise<string> {
		const file = join(dir, name);
		await writeFile(file, typeof body === "string" ? body : JSON.stringify(body));
		return file;
	}

	it("passes and exits 0", async () => {
		const file = await write("ok.json", suite);
		const code = await runPolicyTest({ file, json: false, help: false, error: null });
		expect(code).toBe(0);
		expect(out).toContain("PASS reads");
		expect(out).toContain("2 passed, 0 failed");
	});

	it("fails with the explain reason and exits 1, as JSON too", async () => {
		const bad = {
			...suite,
			cases: [
				{ name: "oops", agent: "reader", action: "write", resource: "mcp:x", expect: "allow" },
			],
		};
		const file = await write("bad.json", bad);
		expect(await runPolicyTest({ file, json: false, help: false, error: null })).toBe(1);
		expect(out).toContain("FAIL oops");
		expect(out).toContain("near miss");
		out = "";
		expect(await runPolicyTest({ file, json: true, help: false, error: null })).toBe(1);
		const parsed = JSON.parse(out) as { passed: number; failed: Array<{ got: { code: string } }> };
		expect(parsed.passed).toBe(0);
		expect(parsed.failed[0]?.got.code).toBe("no_permission");
	});

	it("loads an ES module suite and reports invalid files with exit 1", async () => {
		const file = await write("s.mjs", `export default ${JSON.stringify(suite)};`);
		expect(await runPolicyTest({ file, json: true, help: false, error: null })).toBe(0);
		const broken = await write("broken.json", "{nope");
		expect(await runPolicyTest({ file: broken, json: false, help: false, error: null })).toBe(1);
	});
});
