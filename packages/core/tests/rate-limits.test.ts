import { beforeEach, describe, expect, it } from "vitest";
import type { TheAuth } from "./helpers.js";
import { createTestTheAuth } from "./helpers.js";

describe("rate limiting", () => {
	let theauth: TheAuth;

	beforeEach(async () => {
		theauth = await createTestTheAuth();
	});

	it("allows calls within rate limit", async () => {
		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "rate-limited-agent",
			type: "autonomous",
			permissions: [
				{
					resource: "mcp:api",
					actions: ["read"],
					constraints: { maxCallsPerHour: 5 },
				},
			],
		});

		// First 5 calls should be allowed
		for (let i = 0; i < 5; i++) {
			const result = await theauth.authorize(agent.id, { action: "read", resource: "mcp:api" });
			expect(result.allowed).toBe(true);
		}
	});

	it("denies calls exceeding rate limit", async () => {
		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "rate-exceed-agent",
			type: "autonomous",
			permissions: [
				{
					resource: "mcp:api",
					actions: ["read"],
					constraints: { maxCallsPerHour: 3 },
				},
			],
		});

		// Use up the limit
		for (let i = 0; i < 3; i++) {
			await theauth.authorize(agent.id, { action: "read", resource: "mcp:api" });
		}

		// 4th call should be denied
		const result = await theauth.authorize(agent.id, { action: "read", resource: "mcp:api" });
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("Rate limit exceeded");
		expect(result.reason).toContain("3/3");
	});

	it("rate limits are per-resource", async () => {
		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "multi-resource-agent",
			type: "autonomous",
			permissions: [
				{ resource: "mcp:github", actions: ["read"], constraints: { maxCallsPerHour: 2 } },
				{ resource: "mcp:slack", actions: ["read"], constraints: { maxCallsPerHour: 2 } },
			],
		});

		// Exhaust github limit
		await theauth.authorize(agent.id, { action: "read", resource: "mcp:github" });
		await theauth.authorize(agent.id, { action: "read", resource: "mcp:github" });

		// Github should be denied
		const githubResult = await theauth.authorize(agent.id, {
			action: "read",
			resource: "mcp:github",
		});
		expect(githubResult.allowed).toBe(false);

		// Slack should still work
		const slackResult = await theauth.authorize(agent.id, {
			action: "read",
			resource: "mcp:slack",
		});
		expect(slackResult.allowed).toBe(true);
	});

	it("logs rate-limited results in audit", async () => {
		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "audit-rate-agent",
			type: "autonomous",
			permissions: [
				{
					resource: "mcp:api",
					actions: ["read"],
					constraints: { maxCallsPerHour: 1 },
				},
			],
		});

		await theauth.authorize(agent.id, { action: "read", resource: "mcp:api" });
		await theauth.authorize(agent.id, { action: "read", resource: "mcp:api" });

		const logs = await theauth.audit.query({ agentId: agent.id });
		const denied = logs.filter((l) => l.result === "denied");
		expect(denied.length).toBeGreaterThanOrEqual(1);
		expect(denied.some((l) => l.reason?.includes("Rate limit"))).toBe(true);
	});
});

describe("time window constraints", () => {
	let theauth: TheAuth;

	beforeEach(async () => {
		theauth = await createTestTheAuth();
	});

	it("allows within time window", async () => {
		const now = new Date();
		const hours = now.getHours();
		const start = `${String(hours).padStart(2, "0")}:00`;
		const end = `${String(hours + 1).padStart(2, "0")}:00`;

		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "timed-agent",
			type: "autonomous",
			permissions: [
				{
					resource: "mcp:api",
					actions: ["read"],
					constraints: { timeWindow: { start, end } },
				},
			],
		});

		const result = await theauth.authorize(agent.id, { action: "read", resource: "mcp:api" });
		expect(result.allowed).toBe(true);
	});

	it("denies outside time window", async () => {
		// Set window to a time that's definitely not now
		const now = new Date();
		const pastHour = (now.getHours() + 20) % 24; // 20 hours from now
		const start = `${String(pastHour).padStart(2, "0")}:00`;
		const end = `${String(pastHour).padStart(2, "0")}:30`;

		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "off-hours-agent",
			type: "autonomous",
			permissions: [
				{
					resource: "mcp:api",
					actions: ["read"],
					constraints: { timeWindow: { start, end } },
				},
			],
		});

		const result = await theauth.authorize(agent.id, { action: "read", resource: "mcp:api" });
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("only allowed between");
	});
});

describe("argument pattern constraints", () => {
	let theauth: TheAuth;

	beforeEach(async () => {
		theauth = await createTestTheAuth();
	});

	it("allows matching argument patterns", async () => {
		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "scoped-agent",
			type: "autonomous",
			permissions: [
				{
					resource: "tool:file_write",
					actions: ["execute"],
					constraints: { allowedArgPatterns: ["^src/.*\\.ts$"] },
				},
			],
		});

		const result = await theauth.authorize(agent.id, {
			action: "execute",
			resource: "tool:file_write",
			arguments: { path: "src/index.ts" },
		});
		expect(result.allowed).toBe(true);
	});

	it("denies non-matching argument patterns", async () => {
		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "restricted-path-agent",
			type: "autonomous",
			permissions: [
				{
					resource: "tool:file_write",
					actions: ["execute"],
					constraints: { allowedArgPatterns: ["^src/.*\\.ts$"] },
				},
			],
		});

		const result = await theauth.authorize(agent.id, {
			action: "execute",
			resource: "tool:file_write",
			arguments: { path: "/etc/passwd" },
		});
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("does not match pattern");
	});
});
