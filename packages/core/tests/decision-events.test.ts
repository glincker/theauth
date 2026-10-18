import { describe, expect, it, vi } from "vitest";
import type { DecisionEvent, TheAuthLogger } from "../src/observability/types.js";
import { createTheAuth } from "../src/theauth.js";
import type { TheAuthConfig } from "../src/types.js";
import { delegateTo, newAgent, pause, READ_GITHUB } from "./hook-test-utils.js";

async function setup(extra: Partial<TheAuthConfig> = {}) {
	const events: DecisionEvent[] = [];
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 20,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		observability: { onDecision: (e) => events.push(e) },
		...extra,
	});
	await theauth.user.create({ id: "user-1", email: "user-1@example.com" });
	return { theauth, events };
}

const READ = { action: "read", resource: "mcp:github:issues" };

describe("decision events", () => {
	it("emits one event per authorize decision, with the documented fields", async () => {
		const { theauth, events } = await setup();
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const allowed = await theauth.authorize(agent.id, READ);
		const denied = await theauth.authorize(agent.id, { action: "read", resource: "mcp:slack:x" });
		await pause();
		expect(events).toHaveLength(2);
		expect(events[0]).toMatchObject({
			source: "authorize",
			agentId: agent.id,
			ownerId: "user-1",
			allowed: true,
			decision: "allow",
			code: allowed.code,
			delegationDepth: 0,
			auditId: allowed.auditId,
		});
		expect(events[0].durationMs).toBeGreaterThanOrEqual(0);
		expect(events[1]).toMatchObject({ allowed: false, decision: "deny", code: denied.code });
		const keys = Object.keys(events[0]);
		expect(keys).not.toContain("token");
		expect(keys).not.toContain("arguments");
	});

	it("covers authorizeByToken, unknown agents and invalid tokens", async () => {
		const { theauth, events } = await setup();
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorizeByToken(agent.token, READ);
		await theauth.authorizeByToken("bogus", READ);
		await theauth.authorize("missing", READ);
		await pause();
		expect(events.map((e) => `${e.source}:${e.code}`).sort()).toEqual([
			"authorize:agent_not_found",
			"authorizeByToken:allowed",
			"authorizeByToken:invalid_token",
		]);
	});

	it("emits one event per policy.evaluate call with cacheHit", async () => {
		const { theauth, events } = await setup();
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const input = { subject: { agentId: agent.id }, ...READ };
		await theauth.policy.evaluate(input);
		await theauth.policy.evaluate(input);
		await pause();
		const evals = events.filter((e) => e.source === "policy.evaluate");
		expect(evals).toHaveLength(2);
		expect(evals[0].cacheHit).toBe(false);
		expect(evals[1].cacheHit).toBe(true);
		expect(evals[0].agentId).toBe(agent.id);
	});

	it("reports hook outcome, timing and guard for blocked and allowed calls", async () => {
		const { theauth, events } = await setup({
			hooks: {
				beforeAuthorize: (ctx) =>
					ctx.resource.endsWith("secret")
						? { decision: "deny", reason: "no", guard: "pii-guard" }
						: undefined,
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, { action: "read", resource: "mcp:github:secret" });
		await theauth.authorize(agent.id, READ);
		await pause();
		expect(events[0]).toMatchObject({
			hookOutcome: "deny",
			guard: "pii-guard",
			code: "hook_denied",
		});
		expect(events[0].hookMs).toBeGreaterThanOrEqual(0);
		expect(events[1]).toMatchObject({ hookOutcome: "allow", allowed: true });
	});

	it("reports a hook timeout as outcome timeout and logs a warning", async () => {
		const logger: TheAuthLogger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
		const { theauth, events } = await setup({
			logger,
			hookSafety: { timeoutMs: 20 },
			hooks: { beforeAuthorize: () => new Promise(() => {}) },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const result = await theauth.authorize(agent.id, READ);
		await pause();
		expect(result.code).toBe("hook_timeout");
		expect(events[0]).toMatchObject({ hookOutcome: "timeout", code: "hook_timeout" });
		expect(logger.warn).toHaveBeenCalledWith(
			"beforeAuthorize hook did not finish",
			expect.objectContaining({ code: "hook_timeout" }),
		);
	});

	it("reports delegation depth", async () => {
		const { theauth, events } = await setup();
		const root = await newAgent(theauth, "root", READ_GITHUB);
		const child = await newAgent(theauth, "child", []);
		await delegateTo(theauth, root.id, child.id);
		await theauth.authorize(child.id, READ);
		await pause(20);
		expect(events.at(-1)).toMatchObject({ agentId: child.id, allowed: true, delegationDepth: 1 });
	});

	it("does not await the listener: a slow listener does not delay the result", async () => {
		const { theauth } = await setup({
			observability: {
				onDecision: () => {
					const end = Date.now() + 100;
					while (Date.now() < end) {}
				},
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const t0 = performance.now();
		await theauth.authorize(agent.id, READ);
		expect(performance.now() - t0).toBeLessThan(100);
		await pause(150);
		expect(theauth.observability.stats().slow).toBe(1);
	});

	it("a throwing or rejecting listener changes nothing and is counted", async () => {
		let n = 0;
		const { theauth } = await setup({
			observability: {
				onDecision: () => {
					n += 1;
					if (n === 1) throw new Error("boom");
					return Promise.reject(new Error("later")) as unknown as undefined;
				},
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const first = await theauth.authorize(agent.id, READ);
		const second = await theauth.authorize(agent.id, READ);
		await pause(20);
		expect(first.allowed).toBe(true);
		expect(second.allowed).toBe(true);
		expect(theauth.observability.stats()).toMatchObject({ emitted: 2, errors: 2 });
	});

	it("redacts the resource, and falls back when the redactor throws", async () => {
		const seen: DecisionEvent[] = [];
		const ok = await setup({
			observability: {
				onDecision: (e) => seen.push(e),
				redactResource: (r) => r.replace(/issues/, "***"),
			},
		});
		const a = await newAgent(ok.theauth, "a", READ_GITHUB);
		await ok.theauth.authorize(a.id, READ);
		const bad = await setup({
			observability: {
				onDecision: (e) => seen.push(e),
				redactResource: () => {
					throw new Error("x");
				},
			},
		});
		const b = await newAgent(bad.theauth, "b", READ_GITHUB);
		await bad.theauth.authorize(b.id, READ);
		await pause();
		expect(seen.map((e) => e.resource)).toEqual(["mcp:github:***", "[redacted]"]);
	});

	it("emits nothing and costs nothing without a listener", async () => {
		const { theauth } = await setup({ observability: undefined });
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		expect((await theauth.authorize(agent.id, READ)).allowed).toBe(true);
		expect(theauth.observability.stats().emitted).toBe(0);
	});
});
