import { createTheAuth } from "@glinr/theauth";
import type { Hono } from "hono";
import { createDemoApp } from "../src/app.js";
import type { DemoLimits } from "../src/config.js";
import type { DemoAuth } from "../src/store.js";
import { ensureOwner } from "../src/store.js";

export const TEST_LIMITS: DemoLimits = {
	maxAgents: 50,
	maxAgentsPerClient: 3,
	maxActionsPerAgent: 40,
	requestsPerMinute: 1000,
	ttlMinutes: 60,
};

export interface Harness {
	app: Hono;
	auth: DemoAuth;
	call: (
		path: string,
		init?: { method?: string; body?: unknown; ip?: string },
	) => Promise<Response>;
}

export async function makeHarness(overrides: Partial<DemoLimits> = {}): Promise<Harness> {
	const limits = { ...TEST_LIMITS, ...overrides };
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: limits.maxAgents,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: `${limits.ttlMinutes}m`,
		},
	});
	await ensureOwner(auth);
	const app = createDemoApp({
		auth,
		limits,
		trustedProxy: { trustedHeader: "cf-connecting-ip" },
		clientSalt: "test-salt",
	});
	async function call(
		path: string,
		init: { method?: string; body?: unknown; ip?: string } = {},
	): Promise<Response> {
		const headers: Record<string, string> = { "cf-connecting-ip": init.ip ?? "203.0.113.7" };
		if (init.body !== undefined) headers["content-type"] = "application/json";
		return app.request(path, {
			method: init.method ?? (init.body !== undefined ? "POST" : "GET"),
			headers,
			body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
		});
	}
	return { app, auth, call };
}
