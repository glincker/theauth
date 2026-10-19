import { describe, expect, it, vi } from "vitest";
import type { AuthorizeLike } from "../src/integrations/index.js";
import {
	createGate,
	createHttpGuard,
	guardAiSdkTools,
	guardFunctionTool,
	isToolDenial,
} from "../src/integrations/index.js";

const allow: AuthorizeLike = async () => ({ allowed: true, code: "allowed", auditId: "a1" });
const deny: AuthorizeLike = async () => ({
	allowed: false,
	code: "no_permission",
	reason: "no matching permission",
	auditId: "a2",
});

describe("createGate", () => {
	it("allows and sends tool resource, action and arguments", async () => {
		const authorize = vi.fn(allow);
		const gate = createGate({ authorize, agentId: "agt_1" });
		expect(await gate.check("refund", { amount: 5 })).toBeNull();
		expect(authorize).toHaveBeenCalledWith("agt_1", {
			action: "execute",
			resource: "tool:refund",
			arguments: { amount: 5 },
		});
	});

	it("fails closed when authorize throws", async () => {
		const gate = createGate({
			authorize: async () => {
				throw new Error("db down");
			},
			agentId: "agt_1",
		});
		const out = await gate.check("refund", {});
		expect(out).toMatchObject({ denied: true, code: "guard_error", reason: "db down" });
	});

	it("fails closed without an agent id", async () => {
		const gate = createGate({ authorize: allow, agentId: () => undefined });
		expect(await gate.check("t", {})).toMatchObject({ code: "guard_error" });
	});

	it("retries once with an approval id", async () => {
		const authorize = vi.fn<AuthorizeLike>(async (_id, req) =>
			req.approvalId === "apr_1"
				? { allowed: true, code: "approval_consumed" }
				: { allowed: false, code: "approval_required", reason: "needs approval" },
		);
		const gate = createGate({ authorize, agentId: "a", requestApproval: () => "apr_1" });
		expect(await gate.check("refund", { amount: 9 })).toBeNull();
		expect(authorize).toHaveBeenCalledTimes(2);
	});

	it("reports approvalRequired when no approval is granted", async () => {
		const gate = createGate({
			authorize: async () => ({ allowed: false, code: "approval_required", reason: "x" }),
			agentId: "a",
			requestApproval: () => undefined,
		});
		expect(await gate.check("refund", {})).toMatchObject({ approvalRequired: true });
	});

	it("ignores errors thrown by onDecision", async () => {
		const gate = createGate({
			authorize: allow,
			agentId: "a",
			onDecision: () => {
				throw new Error("log failure");
			},
		});
		expect(await gate.check("t", {})).toBeNull();
	});
});

describe("guardAiSdkTools", () => {
	it("runs allowed tools and returns a denial for refused ones", async () => {
		const run = vi.fn(async (args: { id: string }) => ({ refunded: args.id }));
		const tools = guardAiSdkTools(
			{ refund: { description: "refund", execute: run }, clientOnly: { description: "ui" } },
			{
				authorize: async (_a, req) =>
					req.resource === "tool:refund"
						? { allowed: true }
						: { allowed: false, code: "no_permission", reason: "nope" },
				agentId: "agt",
			},
		);
		expect(tools.refund.description).toBe("refund");
		expect(await tools.refund.execute({ id: "i1" }, {} as never)).toEqual({ refunded: "i1" });
		expect(tools.clientOnly).toEqual({ description: "ui" });

		const blocked = guardAiSdkTools(
			{ refund: { execute: run } },
			{ authorize: deny, agentId: "agt" },
		);
		run.mockClear();
		const out = await blocked.refund.execute({ id: "i2" }, {} as never);
		expect(isToolDenial(out)).toBe(true);
		expect(out).toMatchObject({ toolName: "refund", code: "no_permission", auditId: "a2" });
		expect(run).not.toHaveBeenCalled();
	});

	it("reads the agent id from call options", async () => {
		const authorize = vi.fn(allow);
		const tools = guardAiSdkTools(
			{ ping: { execute: async () => "pong" } },
			{
				authorize,
				agentId: (ctx: { agent: string } | undefined) => ctx?.agent,
			},
		);
		await tools.ping.execute({} as never, { agent: "agt_ctx" } as never);
		expect(authorize.mock.calls[0]?.[0]).toBe("agt_ctx");
	});
});

describe("guardFunctionTool", () => {
	it("guards execute and keeps other properties", async () => {
		const execute = vi.fn(async (input: { q: string }) => `ok:${input.q}`);
		const def = { name: "search", description: "d", execute };
		const guarded = guardFunctionTool(def, { authorize: allow, agentId: "agt" });
		expect(guarded.description).toBe("d");
		expect(await guarded.execute({ q: "x" })).toBe("ok:x");

		execute.mockClear();
		const blocked = guardFunctionTool(def, { authorize: deny, agentId: "agt" });
		expect(await blocked.execute({ q: "x" })).toMatchObject({
			denied: true,
			code: "no_permission",
		});
		expect(execute).not.toHaveBeenCalled();
	});

	it("supports formatDenial", async () => {
		const blocked = guardFunctionTool(
			{ name: "t", execute: async () => "ran" },
			{ authorize: deny, agentId: "a", formatDenial: (d) => `denied:${d.code}` },
		);
		expect(await blocked.execute({} as never)).toBe("denied:no_permission");
	});
});

describe("createHttpGuard", () => {
	function fakeFetch(status: number, body: unknown): typeof fetch {
		return (async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;
	}

	it("allows on 200 allowed", async () => {
		const spy = vi.fn(fakeFetch(200, { data: { allowed: true } }));
		const guard = createHttpGuard({
			baseUrl: "https://auth.test/api/auth/",
			token: "tok",
			fetch: spy as unknown as typeof fetch,
		});
		expect(await guard.check("lookup", { id: 1 })).toBeNull();
		const [url, init] = spy.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("https://auth.test/api/auth/authorize/token");
		expect((init.headers as Record<string, string>).authorization).toBe("Bearer tok");
		expect(JSON.parse(init.body as string)).toEqual({
			action: "execute",
			resource: "tool:lookup",
			arguments: { id: 1 },
		});
	});

	it("maps a 403 body to a denial with the code", async () => {
		const guard = createHttpGuard({
			baseUrl: "https://auth.test",
			token: () => "tok",
			fetch: fakeFetch(403, { data: { allowed: false, code: "approval_required", reason: "r" } }),
		});
		expect(await guard.check("pay")).toMatchObject({
			code: "approval_required",
			approvalRequired: true,
		});
	});

	it("maps a 401 error body and network failures to denials", async () => {
		const unauthorized = createHttpGuard({
			baseUrl: "https://auth.test",
			token: "bad",
			fetch: fakeFetch(401, { error: { code: "UNAUTHORIZED", message: "bad token" } }),
		});
		expect(await unauthorized.check("t")).toMatchObject({
			code: "unauthorized",
			reason: "bad token",
		});

		const down = createHttpGuard({
			baseUrl: "https://auth.test",
			token: "t",
			fetch: (async () => {
				throw new Error("ECONNREFUSED");
			}) as unknown as typeof fetch,
		});
		expect(await down.check("t")).toMatchObject({ code: "guard_error" });
	});

	it("guard() skips the function on denial", async () => {
		const fn = vi.fn(async (a: { n: number }) => a.n);
		const guard = createHttpGuard({
			baseUrl: "https://auth.test",
			token: "t",
			fetch: fakeFetch(403, { data: { allowed: false, code: "no_permission" } }),
		});
		const out = await guard.guard("t", fn)({ n: 1 });
		expect(isToolDenial(out)).toBe(true);
		expect(fn).not.toHaveBeenCalled();
	});
});
