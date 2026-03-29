import Fastify from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as schema from "../../../core/src/db/schema.js";
import type { Kavach } from "../../../core/src/kavach.js";
import { createKavach } from "../../../core/src/kavach.js";
import { kavachFastify } from "../src/adapter.js";

const BASE_PERMISSIONS = [{ resource: "mcp:github", actions: ["read"] }];

async function createTestApp(): Promise<{ app: ReturnType<typeof Fastify>; kavach: Kavach }> {
	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

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

	const app = Fastify();
	await app.register(kavachFastify(kavach), { prefix: "/api/kavach" });

	return { app, kavach };
}

async function createTestAgent(
	app: ReturnType<typeof Fastify>,
	overrides: Partial<{
		name: string;
		type: string;
		permissions: Array<{ resource: string; actions: string[] }>;
	}> = {},
): Promise<{ id: string; token: string }> {
	const res = await app.inject({
		method: "POST",
		url: "/api/kavach/agents",
		payload: {
			ownerId: "user-1",
			name: overrides.name ?? "test-agent",
			type: overrides.type ?? "autonomous",
			permissions: overrides.permissions ?? BASE_PERMISSIONS,
		},
	});

	const body = res.json() as { data: { id: string; token: string } };
	return { id: body.data.id, token: body.data.token };
}

describe("Fastify adapter", () => {
	let app: ReturnType<typeof Fastify>;

	beforeEach(async () => {
		({ app } = await createTestApp());
	});

	afterEach(async () => {
		await app.close();
	});

	it("creates, lists, and fetches agents under the registered prefix", async () => {
		const { id } = await createTestAgent(app, { name: "prefix-agent" });

		const listRes = await app.inject({
			method: "GET",
			url: "/api/kavach/agents?userId=user-1",
		});
		expect(listRes.statusCode).toBe(200);
		const listBody = listRes.json() as { data: Array<{ id: string; name: string }> };
		expect(listBody.data).toHaveLength(1);
		expect(listBody.data[0]?.name).toBe("prefix-agent");

		const getRes = await app.inject({
			method: "GET",
			url: `/api/kavach/agents/${id}`,
		});
		expect(getRes.statusCode).toBe(200);
		const getBody = getRes.json() as { data: { id: string; name: string; token: string } };
		expect(getBody.data.id).toBe(id);
		expect(getBody.data.name).toBe("prefix-agent");
		expect(getBody.data.token).toBe("");
	});

	it("authorizes by bearer token and denies the same token after revoke", async () => {
		const { id, token } = await createTestAgent(app);

		const allowRes = await app.inject({
			method: "POST",
			url: "/api/kavach/authorize/token",
			headers: {
				authorization: `Bearer ${token}`,
				"content-type": "application/json",
			},
			payload: { action: "read", resource: "mcp:github" },
		});
		expect(allowRes.statusCode).toBe(200);
		expect((allowRes.json() as { data: { allowed: boolean } }).data.allowed).toBe(true);

		const revokeRes = await app.inject({
			method: "DELETE",
			url: `/api/kavach/agents/${id}`,
		});
		expect(revokeRes.statusCode).toBe(204);

		const getRes = await app.inject({
			method: "GET",
			url: `/api/kavach/agents/${id}`,
		});
		expect(getRes.statusCode).toBe(200);
		expect((getRes.json() as { data: { status: string } }).data.status).toBe("revoked");

		const denyRes = await app.inject({
			method: "POST",
			url: "/api/kavach/authorize/token",
			headers: {
				authorization: `Bearer ${token}`,
				"content-type": "application/json",
			},
			payload: { action: "read", resource: "mcp:github" },
		});
		expect(denyRes.statusCode).toBe(403);
		const denyBody = denyRes.json() as { data: { allowed: boolean; reason: string } };
		expect(denyBody.data.allowed).toBe(false);
		expect(denyBody.data.reason).toContain("Invalid or expired");
	});

	it("serves MCP preflight responses with CORS headers", async () => {
		const res = await app.inject({
			method: "OPTIONS",
			url: "/api/kavach/mcp/register",
		});

		expect(res.statusCode).toBe(204);
		expect(res.headers["access-control-allow-origin"]).toBe("*");
		expect(res.headers["access-control-allow-methods"]).toContain("OPTIONS");
	});
});
