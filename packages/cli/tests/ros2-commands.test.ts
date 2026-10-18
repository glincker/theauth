import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	certificateWindow,
	extractPermissions,
	grantWindow,
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

describe("path matching and certificate window", () => {
	// Self signed test certificate, no private key kept. Valid 2026-10-18T18:21:39Z to 2026-11-17T18:21:39Z.
	const PEM = `-----BEGIN CERTIFICATE-----
MIIBYzCCAQqgAwIBAgIUJAcRT7Pazk5SUWF3Ts1gc5aewRMwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNZmxlZXQtcjEtdGVzdDAeFw0yNjEwMTgxODIxMzlaFw0yNjEx
MTcxODIxMzlaMBgxFjAUBgNVBAMMDWZsZWV0LXIxLXRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASXR40nro+fKGlzY4IsEuq2VCtUh3eFS8it4BPcEDbHU52l
imtpES133cKSqzuwhuyEMLtR7IwNKMbG36gQ7yx0ozIwMDAdBgNVHQ4EFgQUCKt/
ovXRYRVxnRkknjS779xg/lswDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNH
ADBEAiEAgMIouQSjFydp7xy4nE0mgpjWTamCN/70bDfpAlyCsfkCHw5FbLurDs6L
KjE40rK/Hv6FNxxqn9oIg0W/JyUUMYI=
-----END CERTIFICATE-----
`;

	it("parses the new flags and rejects bad values", () => {
		const a = parseRos2Args([
			"export",
			"--permissions",
			"p.json",
			"--enclave",
			"/e",
			"--out",
			"o",
			"--resource-matching",
			"path",
			"--single-level=widen",
			"--enclave-cert",
			"c.pem",
		]);
		expect(a).toMatchObject({
			resourceMatching: "path",
			singleLevel: "widen",
			enclaveCert: "c.pem",
			error: null,
		});
		expect(parseRos2Args(["export", "--resource-matching", "x"]).error).toContain("colon or path");
		expect(parseRos2Args(["export", "--single-level", "x"]).error).toContain("skip or widen");
	});

	it("reads the certificate validity window", () => {
		const w = certificateWindow(PEM);
		expect(w.notBefore.toISOString()).toBe("2026-10-18T18:21:39.000Z");
		expect(w.notAfter.toISOString()).toBe("2026-11-17T18:21:39.000Z");
		expect(() => certificateWindow("nope")).toThrow("PEM certificate");
	});

	it("grantWindow defaults to the certificate and refuses a window outside it", () => {
		const cert = certificateWindow(PEM);
		const now = new Date("2026-10-19T00:00:00Z");
		expect(grantWindow({}, cert, now)).toEqual(cert);
		expect(() => grantWindow({ notAfter: "2027-01-01T00:00:00Z" }, cert, now)).toThrow(
			"outside the certificate window",
		);
		expect(() => grantWindow({ notBefore: "2026-10-01T00:00:00Z" }, cert, now)).toThrow(
			"outside the certificate window",
		);
		expect(grantWindow({ notAfter: "2026-11-01T00:00:00Z" }, cert, now).notAfter).toBe(
			"2026-11-01T00:00:00Z",
		);
		expect(grantWindow({}, undefined, now).notBefore).toEqual(now);
	});

	it("exports path patterns and uses the certificate window end to end", async () => {
		const pfile = join(dir, "p.json");
		const cfile = join(dir, "c.pem");
		await writeFile(pfile, JSON.stringify([{ resource: "ros2:/fleet/**", actions: ["publish"] }]));
		await writeFile(cfile, PEM);
		const args = parseRos2Args([
			"export",
			"--permissions",
			pfile,
			"--enclave",
			"/fleet/r1",
			"--out",
			join(dir, "out"),
			"--resource-matching",
			"path",
			"--enclave-cert",
			cfile,
		]);
		expect(await runRos2Export(args)).toBe(0);
		const xml = await readFile(join(dir, "out", "permissions.xml"), "utf-8");
		expect(xml).toContain("rt/fleet/*");
		expect(xml).toContain("2026-11-17T18:21:39");
	});

	it("--robot includes delegated permissions", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string) => {
				expect(url).toContain("/agents/robot-1?include=delegated");
				return new Response(
					JSON.stringify({
						data: {
							permissions: [{ resource: "ros2:/own", actions: ["publish"] }],
							delegatedPermissions: [{ resource: "ros2:/lent", actions: ["publish"] }],
						},
					}),
				);
			}),
		);
		const mod = await import("../src/ros2-commands.js");
		const auth = await import("../src/auth/token-cache.js");
		vi.spyOn(auth, "loadCredential").mockResolvedValue({
			tokenType: "Bearer",
			accessToken: "t",
		} as never);
		const args = mod.parseRos2Args([
			"export",
			"--robot",
			"robot-1",
			"--server",
			"http://localhost:1",
			"--enclave",
			"/e",
			"--no-node-baseline",
			"--out",
			join(dir, "o2"),
		]);
		expect(await mod.runRos2Export(args)).toBe(0);
		const json = JSON.parse(await readFile(join(dir, "o2", "theauth-export.json"), "utf-8"));
		expect(json.rules.map((r: { name: string }) => r.name)).toEqual(["/lent", "/own"]);
		vi.unstubAllGlobals();
	});
});

describe("ros2 export node baseline", () => {
	async function exportRules(extra: string[]): Promise<string[]> {
		const permFile = join(dir, "p.json");
		await writeFile(
			permFile,
			JSON.stringify([{ resource: "ros2:/chatter", actions: ["publish"] }]),
		);
		const out = join(dir, "o");
		const args = parseRos2Args(["export", "--permissions", permFile, "--out", out, ...extra]);
		expect(await runRos2Export(args)).toBe(0);
		const json = JSON.parse(await readFile(join(out, "theauth-export.json"), "utf-8"));
		return json.rules.map((r: { name: string }) => r.name);
	}

	it("adds rosout, parameter events and the node's parameter services by default", async () => {
		const names = await exportRules(["--enclave", "/fleet/r1/talker"]);
		expect(names).toContain("/rosout");
		expect(names).toContain("/parameter_events");
		expect(names).toContain("/talker/get_parameters");
		expect(names).toContain("/chatter");
	});

	it("honours --node and --namespace, and --no-node-baseline", async () => {
		const names = await exportRules(["--enclave", "/e", "--node", "nav", "--namespace", "/r1"]);
		expect(names).toContain("/r1/nav/set_parameters");
		expect(await exportRules(["--enclave", "/e", "--no-node-baseline"])).toEqual(["/chatter"]);
	});

	it("skips the baseline when the enclave token is not a valid node name", async () => {
		expect(await exportRules(["--enclave", "/fleet/robot-1"])).toEqual(["/chatter"]);
	});
});
