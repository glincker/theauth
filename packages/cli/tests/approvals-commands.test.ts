import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseApprovalsArgs, runApprovals } from "../src/approvals-commands.js";

describe("parseApprovalsArgs", () => {
	it("parses request with a quorum and arguments", () => {
		expect(
			parseApprovalsArgs([
				"request",
				"--action",
				"admin:rotate",
				"--resource=agent:a1",
				"--required-approvals",
				"2",
				"--args",
				'{"k":1}',
			]),
		).toMatchObject({
			sub: "request",
			action: "admin:rotate",
			resource: "agent:a1",
			requiredApprovals: 2,
			args: { k: 1 },
			error: null,
		});
	});

	it("rejects a quorum outside 1 to 10 and a non admin action", () => {
		const base = ["request", "--action", "admin:x", "--resource", "r"];
		expect(parseApprovalsArgs([...base, "--required-approvals", "0"]).error).toMatch(/1 to 10/);
		expect(parseApprovalsArgs([...base, "--required-approvals", "11"]).error).toMatch(/1 to 10/);
		expect(parseApprovalsArgs(["request", "--action", "execute", "--resource", "r"]).error).toMatch(
			/admin:<name>/,
		);
	});

	it("needs an id for show, approve and deny, and refuses the quorum flag elsewhere", () => {
		expect(parseApprovalsArgs(["approve"]).error).toMatch(/needs an approval id/);
		expect(parseApprovalsArgs(["show", "a1"])).toMatchObject({ sub: "show", id: "a1" });
		expect(parseApprovalsArgs(["approve", "a1", "--required-approvals", "2"]).error).toMatch(
			/only applies/,
		);
		expect(parseApprovalsArgs(["nope"]).error).toMatch(/Unknown approvals command/);
		expect(parseApprovalsArgs([]).help).toBe(true);
	});
});

describe("runApprovals", () => {
	const saved = { ...process.env };
	beforeEach(() => {
		process.env.THEAUTH_URL = "https://auth.example.test/api/theauth/";
		process.env.THEAUTH_ADMIN_TOKEN = "tok_admin";
	});
	afterEach(() => {
		process.env = { ...saved };
	});

	function harness(status: number, body: unknown, headers: Record<string, string> = {}) {
		const calls: Array<{ url: string; init: RequestInit }> = [];
		const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
			calls.push({ url, init });
			return new Response(JSON.stringify(body), { status, headers });
		}) as unknown as typeof fetch;
		let out = "";
		return {
			calls,
			fetch: fetchMock,
			write: (t: string) => {
				out += t;
			},
			out: () => out,
		};
	}

	it("request posts the quorum with the admin token", async () => {
		const h = harness(201, {
			id: "a1",
			status: "pending",
			action: "admin:rotate",
			resource: "agent:a1",
			expiresAt: "e",
			requiredApprovals: 2,
		});
		const code = await runApprovals(
			parseApprovalsArgs([
				"request",
				"--action",
				"admin:rotate",
				"--resource",
				"agent:a1",
				"--required-approvals",
				"2",
			]),
			h,
		);
		expect(code).toBe(0);
		expect(h.calls[0]?.url).toBe("https://auth.example.test/api/theauth/approvals");
		expect(h.calls[0]?.init.method).toBe("POST");
		expect((h.calls[0]?.init.headers as Record<string, string>).authorization).toBe(
			"Bearer tok_admin",
		);
		expect(JSON.parse(String(h.calls[0]?.init.body))).toEqual({
			action: "admin:rotate",
			resource: "agent:a1",
			requiredApprovals: 2,
		});
		expect(h.out()).toContain("approvals: 0 of 2");
	});

	it("list prints progress and uses the pending filter", async () => {
		const h = harness(200, [
			{
				id: "a1",
				action: "admin:rotate",
				resource: "agent:a1",
				requestedBy: "u1",
				expiresAt: "e",
				requiredApprovals: 3,
				approvalsReceived: 1,
				approvers: ["alice"],
			},
		]);
		const code = await runApprovals(parseApprovalsArgs(["list", "--limit", "5"]), h);
		expect(code).toBe(0);
		expect(h.calls[0]?.url).toBe(
			"https://auth.example.test/api/theauth/approvals?status=pending&limit=5",
		);
		expect(h.out()).toContain("approvals: 1 of 3");
		expect(h.out()).toContain("approved by: alice");
	});

	it("approve says the vote counted while the quorum is open", async () => {
		const h = harness(200, {
			id: "a1",
			status: "pending",
			respondedAt: "r",
			requiredApprovals: 2,
			approvalsReceived: 1,
		});
		expect(await runApprovals(parseApprovalsArgs(["approve", "a1"]), h)).toBe(0);
		expect(h.calls[0]?.url).toMatch(/\/approvals\/a1\/approve$/);
		expect(h.out()).toContain("counted, 1 of 2 approvals");
	});

	it("json mode prints the response and an error exits 1 with the server code", async () => {
		const ok = harness(200, {
			id: "a1",
			status: "denied",
			respondedAt: "r",
			requiredApprovals: 1,
			approvalsReceived: 0,
		});
		expect(await runApprovals(parseApprovalsArgs(["deny", "a1", "--json"]), ok)).toBe(0);
		expect(JSON.parse(ok.out()).status).toBe("denied");

		const bad = harness(409, {
			error: { code: "DUPLICATE_APPROVER", message: "already approved" },
		});
		expect(await runApprovals(parseApprovalsArgs(["approve", "a1"]), bad)).toBe(1);
		expect(bad.out()).toContain("DUPLICATE_APPROVER: already approved");
	});

	it("explains a step-up challenge", async () => {
		const h = harness(
			401,
			{ error: { code: "STEP_UP_REQUIRED", message: "stronger sign-in" } },
			{ "www-authenticate": 'Bearer error="insufficient_user_authentication"' },
		);
		expect(await runApprovals(parseApprovalsArgs(["approve", "a1"]), h)).toBe(1);
		expect(h.out()).toContain("theauth login");
	});

	it("falls back to the saved login and fails clearly without one", async () => {
		delete process.env.THEAUTH_ADMIN_TOKEN;
		const dir = await mkdtemp(join(tmpdir(), "approvals-cli-"));
		const file = join(dir, "credentials.json");
		process.env.THEAUTH_CREDENTIALS_FILE = file;
		const none = harness(200, []);
		expect(await runApprovals(parseApprovalsArgs(["list"]), none)).toBe(1);
		expect(none.out()).toContain("Not logged in");

		await writeFile(
			file,
			JSON.stringify({
				version: 1,
				servers: {
					"https://auth.example.test/api/theauth": {
						accessToken: "saved",
						tokenType: "Bearer",
						savedAt: 1,
					},
				},
			}),
		);
		const h = harness(200, []);
		expect(await runApprovals(parseApprovalsArgs(["list"]), h)).toBe(0);
		expect((h.calls[0]?.init.headers as Record<string, string>).authorization).toBe("Bearer saved");
		expect(h.out()).toContain("No pending approvals.");
	});
});
