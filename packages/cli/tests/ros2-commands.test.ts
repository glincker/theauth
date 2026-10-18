import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	extractPermissions,
	parseRos2Args,
	runRos2Diff,
	runRos2Export,
} from "../src/ros2-commands.js";

let dir: string;
beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "theauth-ros2-"));
	vi.spyOn(process.stdout, "write").mockImplementation(() => true);
	vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});
afterEach(async () => {
	vi.restoreAllMocks();
	await rm(dir, { recursive: true, force: true });
});

const permissions = [
	{ resource: "ros2:/scan", actions: ["publish"] },
	{ resource: "ros2:/cmd_vel", actions: ["publish"], constraints: { requireApproval: true } },
];

describe("parseRos2Args", () => {
	it("parses export flags", () => {
		const a = parseRos2Args([
			"export",
			"--permissions",
			"p.json",
			"--enclave=/fleet/r1/nav",
			"--out",
			"o",
			"--domain",
			"5",
			"--gated",
			"include",
			"--no-ros-discovery",
		]);
		expect(a).toMatchObject({
			sub: "export",
			permissions: "p.json",
			enclave: "/fleet/r1/nav",
			out: "o",
			domain: 5,
			gated: "include",
			rosDiscovery: false,
			error: null,
		});
	});

	it("flags missing and conflicting input", () => {
		expect(parseRos2Args(["export", "--out", "o", "--robot", "a"]).error).toMatch(/enclave/);
		expect(parseRos2Args(["export", "--enclave", "/r", "--robot", "a"]).error).toMatch(/--out/);
		expect(parseRos2Args(["export", "--enclave", "/r", "--out", "o"]).error).toMatch(/--robot/);
		expect(
			parseRos2Args([
				"export",
				"--enclave",
				"/r",
				"--out",
				"o",
				"--robot",
				"a",
				"--permissions",
				"p",
			]).error,
		).toMatch(/not both/);
		expect(parseRos2Args(["export", "--gated", "x"]).error).toMatch(/omit or include/);
		expect(parseRos2Args(["diff", "a.json"]).error).toMatch(/two/);
		expect(parseRos2Args(["nope"]).error).toMatch(/Unknown ros2 command/);
		expect(parseRos2Args([]).help).toBe(true);
	});
});

describe("extractPermissions", () => {
	it("accepts arrays, wrapped objects and the HTTP envelope", () => {
		expect(extractPermissions(permissions)).toHaveLength(2);
		expect(extractPermissions({ permissions })).toHaveLength(2);
		expect(extractPermissions({ data: { id: "a", permissions } })).toHaveLength(2);
	});

	it("rejects bad shapes", () => {
		expect(() => extractPermissions({})).toThrow(/array/);
		expect(() => extractPermissions([{ resource: 1, actions: [] }])).toThrow(/resource/);
		expect(() => extractPermissions([{ resource: "a", actions: [1] }])).toThrow(/action/);
	});
});

describe("runRos2Export", () => {
	it("writes the four files from a permissions file", async () => {
		const file = join(dir, "perms.json");
		await writeFile(file, JSON.stringify(permissions));
		const out = join(dir, "out");
		const code = await runRos2Export(
			parseRos2Args([
				"export",
				"--permissions",
				file,
				"--enclave",
				"/fleet/r1/nav",
				"--out",
				out,
				"--not-before",
				"2026-10-18T00:00:00Z",
				"--not-after",
				"2027-01-01T00:00:00Z",
			]),
		);
		expect(code).toBe(0);
		const permissionsXml = await readFile(join(out, "permissions.xml"), "utf-8");
		expect(permissionsXml).toContain("<topic>rt/scan</topic>");
		expect(permissionsXml).not.toContain("cmd_vel");
		expect(await readFile(join(out, "governance.xml"), "utf-8")).toContain("<dds ");
		expect(await readFile(join(out, "policy.xml"), "utf-8")).toContain('<policy version="0.2.0">');
		const report = JSON.parse(await readFile(join(out, "theauth-export.json"), "utf-8"));
		expect(report.gated).toHaveLength(1);
	});

	it("fails with a message for a bad enclave and writes nothing useful", async () => {
		const file = join(dir, "perms.json");
		await writeFile(file, JSON.stringify(permissions));
		const code = await runRos2Export(
			parseRos2Args([
				"export",
				"--permissions",
				file,
				"--enclave",
				"nope",
				"--out",
				join(dir, "o"),
			]),
		);
		expect(code).toBe(1);
	});

	it("fails for unreadable input", async () => {
		const code = await runRos2Export(
			parseRos2Args([
				"export",
				"--permissions",
				join(dir, "missing.json"),
				"--enclave",
				"/r",
				"--out",
				dir,
			]),
		);
		expect(code).toBe(1);
	});
});

describe("runRos2Diff", () => {
	it("exits 0 when nothing changes and 2 when the policy moves", async () => {
		const a = join(dir, "a.json");
		const b = join(dir, "b.json");
		await writeFile(a, JSON.stringify(permissions));
		await writeFile(
			b,
			JSON.stringify([...permissions, { resource: "ros2:/odom", actions: ["publish"] }]),
		);
		expect(await runRos2Diff(parseRos2Args(["diff", a, a]))).toBe(0);
		expect(await runRos2Diff(parseRos2Args(["diff", a, b]))).toBe(2);
	});
});
