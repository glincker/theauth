import type { Hono } from "hono";
import { beforeEach, describe, expect, it } from "vitest";
import * as schema from "../../../core/src/db/schema.js";
import type { TheAuth } from "../../../core/src/kavach.js";
import { createTheAuth } from "../../../core/src/kavach.js";
import { kavachHono } from "../src/adapter.js";

// ─── Test Setup ──────────────────────────────────────────────────────────────

async function createTestApp(): Promise<{ app: Hono; kavach: TheAuth }> {
	const kavach = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	// Seed a test user
	kavach.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	const app = kavachHono(kavach);
	return { app, kavach };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const BASE_PERMISSIONS = [{ resource: "mcp:github", actions: ["read"] }];

async function createTestAgent(
	app: Hono,
	overrides: Partial<{
		name: string;
		type: string;
		permissions: Array<{ resource: string; actions: string[] }>;
	}> = {},
): Promise<{ id: string; token: string }> {
	const res = await app.request("/agents", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			ownerId: "user-1",
			name: overrides.name ?? "test-agent",
			type: overrides.type ?? "autonomous",
			permissions: overrides.permissions ?? BASE_PERMISSIONS,
		}),
	});
	const body = (await res.json()) as { data: { id: string; token: string } };
	return { id: body.data.id, token: body.data.token };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("Hono adapter", () => {
	let app: Hono;
	let kavach: TheAuth;

	beforeEach(async () => {
		({ app, kavach } = await createTestApp());
	});

	// ── Agent CRUD ─────────────────────────────────────────────────────────────

	describe("POST /agents", () => {
		it("creates an agent and returns a token", async () => {
			const res = await app.request("/agents", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					ownerId: "user-1",
					name: "my-agent",
					type: "autonomous",
					permissions: BASE_PERMISSIONS,
				}),
			});

			expect(res.status).toBe(201);
			const body = (await res.json()) as {
				data: { id: string; name: string; token: string; status: string };
			};
			expect(body.data.id).toBeDefined();
			expect(body.data.name).toBe("my-agent");
			expect(body.data.token).toMatch(/^kv_/);
			expect(body.data.status).toBe("active");
		});

		it("rejects invalid JSON", async () => {
			const res = await app.request("/agents", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: "not-json",
			});

			expect(res.status).toBe(400);
			const body = (await res.json()) as { error: { code: string } };
			expect(body.error.code).toBe("BAD_REQUEST");
		});

		it("rejects missing required fields", async () => {
			const res = await app.request("/agents", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "no-owner" }),
			});

			expect(res.status).toBe(400);
			const body = (await res.json()) as { error: { code: string; message: string } };
			expect(body.error.code).toBe("BAD_REQUEST");
			expect(body.error.message).toContain("Validation failed");
		});

		it("rejects empty permissions array", async () => {
			const res = await app.request("/agents", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					ownerId: "user-1",
					name: "empty-perms",
					type: "service",
					permissions: [],
				}),
			});

			expect(res.status).toBe(400);
		});
	});

	describe("GET /agents", () => {
		it("lists all agents", async () => {
			await createTestAgent(app, { name: "agent-a" });
			await createTestAgent(app, { name: "agent-b", type: "service" });

			const res = await app.request("/agents");

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: unknown[] };
			expect(body.data).toHaveLength(2);
		});

		it("filters agents by userId", async () => {
			await createTestAgent(app, { name: "owned-agent" });

			const res = await app.request("/agents?userId=user-1");

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: unknown[] };
			expect(body.data).toHaveLength(1);
		});

		it("filters agents by type", async () => {
			await createTestAgent(app, { name: "auto-agent", type: "autonomous" });
			await createTestAgent(app, { name: "svc-agent", type: "service" });

			const res = await app.request("/agents?type=service");

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: Array<{ name: string }> };
			expect(body.data).toHaveLength(1);
			expect(body.data[0]?.name).toBe("svc-agent");
		});

		it("returns an empty array when no agents exist", async () => {
			const res = await app.request("/agents");

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: unknown[] };
			expect(body.data).toHaveLength(0);
		});
	});

	describe("GET /agents/:id", () => {
		it("returns an agent by id", async () => {
			const { id } = await createTestAgent(app, { name: "fetchable" });

			const res = await app.request(`/agents/${id}`);

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: { id: string; name: string; token: string } };
			expect(body.data.id).toBe(id);
			expect(body.data.name).toBe("fetchable");
			expect(body.data.token).toBe(""); // token is redacted on get
		});

		it("returns 404 for a non-existent agent", async () => {
			const res = await app.request("/agents/does-not-exist");

			expect(res.status).toBe(404);
			const body = (await res.json()) as { error: { code: string } };
			expect(body.error.code).toBe("NOT_FOUND");
		});
	});

	describe("PATCH /agents/:id", () => {
		it("updates an agent name", async () => {
			const { id } = await createTestAgent(app, { name: "original-name" });

			const res = await app.request(`/agents/${id}`, {
				method: "PATCH",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "updated-name" }),
			});

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: { name: string } };
			expect(body.data.name).toBe("updated-name");
		});

		it("updates agent permissions", async () => {
			const { id } = await createTestAgent(app);

			const res = await app.request(`/agents/${id}`, {
				method: "PATCH",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					permissions: [
						{ resource: "mcp:github", actions: ["read", "write"] },
						{ resource: "tool:deploy", actions: ["execute"] },
					],
				}),
			});

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: { permissions: unknown[] } };
			expect(body.data.permissions).toHaveLength(2);
		});

		it("returns 404 when updating a non-existent agent", async () => {
			const res = await app.request("/agents/does-not-exist", {
				method: "PATCH",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "ghost" }),
			});

			expect(res.status).toBe(404);
		});
	});

	describe("DELETE /agents/:id", () => {
		it("revokes an agent and returns 204", async () => {
			const { id } = await createTestAgent(app);

			const res = await app.request(`/agents/${id}`, { method: "DELETE" });

			expect(res.status).toBe(204);

			// Verify the agent is revoked
			const getRes = await app.request(`/agents/${id}`);
			const body = (await getRes.json()) as { data: { status: string } };
			expect(body.data.status).toBe("revoked");
		});

		it("returns 404 for a non-existent agent", async () => {
			const res = await app.request("/agents/does-not-exist", { method: "DELETE" });

			expect(res.status).toBe(404);
		});
	});

	describe("POST /agents/:id/rotate", () => {
		it("rotates the agent token", async () => {
			const { id, token: originalToken } = await createTestAgent(app);

			const res = await app.request(`/agents/${id}/rotate`, { method: "POST" });

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: { token: string } };
			expect(body.data.token).toMatch(/^kv_/);
			expect(body.data.token).not.toBe(originalToken);
		});

		it("returns 404 for a non-existent agent", async () => {
			const res = await app.request("/agents/does-not-exist/rotate", { method: "POST" });

			expect(res.status).toBe(404);
		});
	});

	// ── Authorization ──────────────────────────────────────────────────────────

	describe("POST /authorize", () => {
		it("allows an authorized action", async () => {
			const { id } = await createTestAgent(app, {
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});

			const res = await app.request("/authorize", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ agentId: id, action: "read", resource: "mcp:github" }),
			});

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: { allowed: boolean; auditId: string } };
			expect(body.data.allowed).toBe(true);
			expect(body.data.auditId).toBeDefined();
		});

		it("denies an unauthorized action with 403", async () => {
			const { id } = await createTestAgent(app, {
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});

			const res = await app.request("/authorize", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ agentId: id, action: "delete", resource: "mcp:github" }),
			});

			expect(res.status).toBe(403);
			const body = (await res.json()) as { data: { allowed: boolean; reason: string } };
			expect(body.data.allowed).toBe(false);
			expect(body.data.reason).toContain("No permission");
		});

		it("returns 400 for missing required fields", async () => {
			const res = await app.request("/authorize", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ action: "read" }), // missing agentId and resource
			});

			expect(res.status).toBe(400);
		});
	});

	describe("POST /authorize/token", () => {
		it("allows an authorized action by bearer token", async () => {
			const { token } = await createTestAgent(app, {
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});

			const res = await app.request("/authorize/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Authorization: `Bearer ${token}`,
				},
				body: JSON.stringify({ action: "read", resource: "mcp:github" }),
			});

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: { allowed: boolean } };
			expect(body.data.allowed).toBe(true);
		});

		it("returns 403 when token lacks the required permission", async () => {
			const { token } = await createTestAgent(app, {
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});

			const res = await app.request("/authorize/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Authorization: `Bearer ${token}`,
				},
				body: JSON.stringify({ action: "write", resource: "mcp:github" }),
			});

			expect(res.status).toBe(403);
			const body = (await res.json()) as { data: { allowed: boolean } };
			expect(body.data.allowed).toBe(false);
		});

		it("returns 401 when Authorization header is missing", async () => {
			const res = await app.request("/authorize/token", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ action: "read", resource: "mcp:github" }),
			});

			expect(res.status).toBe(401);
			const body = (await res.json()) as { error: { code: string } };
			expect(body.error.code).toBe("UNAUTHORIZED");
		});

		it("returns 401 when Authorization header is not Bearer", async () => {
			const res = await app.request("/authorize/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Authorization: "Basic abc123",
				},
				body: JSON.stringify({ action: "read", resource: "mcp:github" }),
			});

			expect(res.status).toBe(401);
		});
	});

	// ── Delegation ─────────────────────────────────────────────────────────────

	describe("POST /delegations", () => {
		it("creates a delegation chain", async () => {
			const { id: fromId } = await createTestAgent(app, {
				name: "parent-agent",
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});
			const { id: toId } = await createTestAgent(app, {
				name: "child-agent",
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});

			const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
			const res = await app.request("/delegations", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					fromAgent: fromId,
					toAgent: toId,
					permissions: [{ resource: "mcp:github", actions: ["read"] }],
					expiresAt,
				}),
			});

			expect(res.status).toBe(201);
			const body = (await res.json()) as { data: { id: string; fromAgent: string } };
			expect(body.data.id).toBeDefined();
			expect(body.data.fromAgent).toBe(fromId);
		});

		it("returns 400 for missing required fields", async () => {
			const res = await app.request("/delegations", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ fromAgent: "some-id" }), // missing toAgent, permissions, expiresAt
			});

			expect(res.status).toBe(400);
		});

		it("returns 404 when source agent does not exist", async () => {
			const { id: toId } = await createTestAgent(app, { name: "real-child" });
			const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

			const res = await app.request("/delegations", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					fromAgent: "non-existent",
					toAgent: toId,
					permissions: [{ resource: "mcp:github", actions: ["read"] }],
					expiresAt,
				}),
			});

			expect(res.status).toBe(404);
		});
	});

	describe("GET /delegations/:agentId", () => {
		it("lists delegation chains for an agent", async () => {
			const { id: fromId } = await createTestAgent(app, { name: "delegator" });
			const { id: toId } = await createTestAgent(app, { name: "delegatee" });

			const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
			await app.request("/delegations", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					fromAgent: fromId,
					toAgent: toId,
					permissions: [{ resource: "mcp:github", actions: ["read"] }],
					expiresAt,
				}),
			});

			const res = await app.request(`/delegations/${fromId}`);

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: unknown[] };
			expect(body.data).toHaveLength(1);
		});

		it("returns an empty array when the agent has no delegations", async () => {
			const { id } = await createTestAgent(app);

			const res = await app.request(`/delegations/${id}`);

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: unknown[] };
			expect(body.data).toHaveLength(0);
		});
	});

	// ── Audit ──────────────────────────────────────────────────────────────────

	describe("GET /audit", () => {
		it("returns audit logs after an authorization check", async () => {
			const { id } = await createTestAgent(app, {
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});

			// Trigger an authorization to generate an audit entry
			await app.request("/authorize", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ agentId: id, action: "read", resource: "mcp:github" }),
			});

			const res = await app.request(`/audit?agentId=${id}`);

			expect(res.status).toBe(200);
			const body = (await res.json()) as {
				data: Array<{ agentId: string; result: string }>;
			};
			expect(body.data).toHaveLength(1);
			expect(body.data[0]?.agentId).toBe(id);
			expect(body.data[0]?.result).toBe("allowed");
		});

		it("filters by result", async () => {
			const { id } = await createTestAgent(app, {
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});

			await app.request("/authorize", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ agentId: id, action: "read", resource: "mcp:github" }),
			});
			await app.request("/authorize", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ agentId: id, action: "delete", resource: "mcp:github" }),
			});

			const res = await app.request(`/audit?agentId=${id}&result=denied`);

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: Array<{ result: string }> };
			expect(body.data).toHaveLength(1);
			expect(body.data[0]?.result).toBe("denied");
		});

		it("returns an empty array when no logs exist", async () => {
			const res = await app.request("/audit");

			expect(res.status).toBe(200);
			const body = (await res.json()) as { data: unknown[] };
			expect(body.data).toHaveLength(0);
		});
	});

	describe("GET /audit/export", () => {
		it("exports audit logs as JSON", async () => {
			const { id } = await createTestAgent(app, {
				permissions: [{ resource: "test:*", actions: ["read"] }],
			});
			await kavach.authorize(id, { action: "read", resource: "test:data" });

			const res = await app.request("/audit/export?format=json");

			expect(res.status).toBe(200);
			expect(res.headers.get("Content-Type")).toContain("application/json");
			const text = await res.text();
			expect(text).toContain("allowed");
		});

		it("exports audit logs as CSV", async () => {
			const { id } = await createTestAgent(app, {
				permissions: [{ resource: "test:*", actions: ["read"] }],
			});
			await kavach.authorize(id, { action: "read", resource: "test:data" });

			const res = await app.request("/audit/export?format=csv");

			expect(res.status).toBe(200);
			expect(res.headers.get("Content-Type")).toContain("text/csv");
			const text = await res.text();
			expect(text).toContain("id,agentId");
		});

		it("returns 400 for an invalid format", async () => {
			const res = await app.request("/audit/export?format=xml");

			expect(res.status).toBe(400);
			const body = (await res.json()) as { error: { code: string } };
			expect(body.error.code).toBe("BAD_REQUEST");
		});
	});

	// ── Dashboard ──────────────────────────────────────────────────────────────

	describe("GET /dashboard/stats", () => {
		it("returns agent and audit stats", async () => {
			await createTestAgent(app, { name: "stat-agent" });

			const res = await app.request("/dashboard/stats");

			expect(res.status).toBe(200);
			const body = (await res.json()) as {
				data: {
					agents: { total: number; active: number };
					users: { total: number };
					audit: { last24h: number };
				};
			};
			expect(body.data.agents.total).toBe(1);
			expect(body.data.agents.active).toBe(1);
			expect(body.data.users.total).toBe(1);
			expect(typeof body.data.audit.last24h).toBe("number");
		});
	});
});
