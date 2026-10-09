import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { saveCredential } from "../src/auth/token-cache.js";
import {
	parseSimulateArgs,
	renderTable,
	runPermissions,
	runSimulate,
} from "../src/simulate-commands.js";

describe("parseSimulateArgs", () => {
	it("parses simulate flags in both forms", () => {
		const a = parseSimulateArgs(
			["--agent", "a1", "--action=read", "--resource", "tool:x", "--json"],
			"simulate",
		);
		expect(a).toMatchObject({
			agent: "a1",
			action: "read",
			resource: "tool:x",
			json: true,
			error: null,
		});
	});

	it("requires agent, action and resource", () => {
		expect(parseSimulateArgs(["--agent", "a1"], "simulate").error).toMatch(/action/);
		expect(parseSimulateArgs([], "simulate").error).toMatch(/agent/);
	});

	it("takes the agent id positionally for permissions", () => {
		expect(parseSimulateArgs(["a1", "--json"], "permissions")).toMatchObject({
			agent: "a1",
			json: true,
			error: null,
		});
		expect(parseSimulateArgs([], "permissions").error).toMatch(/agent id/);
	});

	it("flags unknown arguments", () => {
		expect(parseSimulateArgs(["--wat"], "simulate").error).toMatch(/Unknown/);
	});
});

describe("renderTable", () => {
	it("pads columns", () => {
		expect(renderTable(["A", "BB"], [["xxx", "y"]])).toBe("A    BB\n---  --\nxxx  y");
	});
});

describe("simulate commands", () => {
	let dir: string;
	let out: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "theauth-sim-"));
		process.env.THEAUTH_CREDENTIALS_FILE = join(dir, "c.json");
		await saveCredential("https://auth.test", {
			accessToken: "tok",
			tokenType: "Bearer",
			savedAt: Date.now(),
		});
		out = "";
		vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
			out += String(chunk);
			return true;
		});
	});
	afterEach(async () => {
		vi.restoreAllMocks();
		vi.unstubAllGlobals();
		delete process.env.THEAUTH_CREDENTIALS_FILE;
		await rm(dir, { recursive: true, force: true });
	});

	const reply = (status: number, body: unknown) =>
		vi.fn(async () => new Response(JSON.stringify(body), { status }));

	it("prints the decision and trace, exit 0 on allow", async () => {
		const fetchMock = reply(200, {
			decision: "allow",
			reasons: ["Allowed by agent permissions"],
			trace: [{ stage: "permission", outcome: "pass", detail: "Rule 0 grants it" }],
		});
		vi.stubGlobal("fetch", fetchMock);
		const args = parseSimulateArgs(
			[
				"--agent",
				"a1",
				"--action",
				"read",
				"--resource",
				"tool:x",
				"--server",
				"https://auth.test",
			],
			"simulate",
		);
		expect(await runSimulate(args)).toBe(0);
		expect(out).toContain("Decision: allow");
		expect(out).toContain("[permission] pass");
		const call = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(call[0]).toBe("https://auth.test/agents/a1/simulate");
	});

	it("exits 2 on deny and passes --json through", async () => {
		vi.stubGlobal("fetch", reply(200, { decision: "deny", reasons: ["no"], trace: [] }));
		const args = parseSimulateArgs(
			[
				"--agent",
				"a1",
				"--action",
				"w",
				"--resource",
				"r",
				"--json",
				"--server",
				"https://auth.test",
			],
			"simulate",
		);
		expect(await runSimulate(args)).toBe(2);
		expect(JSON.parse(out).decision).toBe("deny");
	});

	it("explains a 403", async () => {
		vi.stubGlobal("fetch", reply(403, { error: "forbidden" }));
		const args = parseSimulateArgs(
			["--agent", "a", "--action", "r", "--resource", "x", "--server", "https://auth.test"],
			"simulate",
		);
		expect(await runSimulate(args)).toBe(1);
		expect(out).toContain("Admin access required");
	});

	it("renders the effective permissions table", async () => {
		vi.stubGlobal(
			"fetch",
			reply(200, {
				agentId: "a1",
				permissions: [
					{ resource: "tool:*", action: "read", source: "own", decision: "allow", reasons: [] },
					{
						resource: "mcp:gh:*",
						action: "read",
						source: "delegation",
						chainId: "c1",
						decision: "allow",
						reasons: [],
					},
				],
			}),
		);
		const args = parseSimulateArgs(["a1", "--server", "https://auth.test"], "permissions");
		expect(await runPermissions(args)).toBe(0);
		expect(out).toContain("RESOURCE");
		expect(out).toContain("delegation:c1");
	});

	it("tells you to log in when there is no credential", async () => {
		const args = parseSimulateArgs(["a1", "--server", "https://other.test"], "permissions");
		expect(await runPermissions(args)).toBe(1);
		expect(out).toContain("theauth login");
	});
});
