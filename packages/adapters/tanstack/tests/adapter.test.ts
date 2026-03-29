import { beforeEach, describe, expect, it } from "vitest";
import * as schema from "../../../core/src/db/schema.js";
import type { Kavach } from "../../../core/src/kavach.js";
import { createKavach } from "../../../core/src/kavach.js";
import { kavachTanStack } from "../src/adapter.js";

const BASE_URL = "http://localhost/api/auth/kavach";
const BASE_PERMISSIONS = [{ resource: "mcp:github", actions: ["read"] }];

type Handlers = ReturnType<typeof kavachTanStack>;

async function createTestHandlers(): Promise<{ handlers: Handlers; kavach: Kavach }> {
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

	return {
		handlers: kavachTanStack(kavach, { basePath: "/api/auth/kavach" }),
		kavach,
	};
}

async function createTestAgent(
	handlers: Handlers,
	overrides: Partial<{
		name: string;
		type: string;
		permissions: Array<{ resource: string; actions: string[] }>;
	}> = {},
): Promise<{ id: string; token: string }> {
	const res = await handlers.POST(
		new Request(`${BASE_URL}/agents`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				ownerId: "user-1",
				name: overrides.name ?? "test-agent",
				type: overrides.type ?? "autonomous",
				permissions: overrides.permissions ?? BASE_PERMISSIONS,
			}),
		}),
	);
	const body = (await res.json()) as { data: { id: string; token: string } };
	return { id: body.data.id, token: body.data.token };
}

describe("TanStack adapter", () => {
	let handlers: Handlers;

	beforeEach(async () => {
		({ handlers } = await createTestHandlers());
	});

	it("uses the configured basePath for create, list, and fetch", async () => {
		const { id } = await createTestAgent(handlers, { name: "tanstack-agent" });

		const listRes = await handlers.GET(
			new Request(`${BASE_URL}/agents?userId=user-1`, { method: "GET" }),
		);
		expect(listRes.status).toBe(200);
		const listBody = (await listRes.json()) as { data: Array<{ name: string }> };
		expect(listBody.data).toHaveLength(1);
		expect(listBody.data[0]?.name).toBe("tanstack-agent");

		const getRes = await handlers.GET(new Request(`${BASE_URL}/agents/${id}`, { method: "GET" }));
		expect(getRes.status).toBe(200);
		const getBody = (await getRes.json()) as { data: { id: string; token: string } };
		expect(getBody.data.id).toBe(id);
		expect(getBody.data.token).toBe("");
	});

	it("authorizes by bearer token and denies after revoke", async () => {
		const { id, token } = await createTestAgent(handlers);

		const allowRes = await handlers.POST(
			new Request(`${BASE_URL}/authorize/token`, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${token}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ action: "read", resource: "mcp:github" }),
			}),
		);
		expect(allowRes.status).toBe(200);
		expect(((await allowRes.json()) as { data: { allowed: boolean } }).data.allowed).toBe(true);

		const revokeRes = await handlers.DELETE(
			new Request(`${BASE_URL}/agents/${id}`, { method: "DELETE" }),
		);
		expect(revokeRes.status).toBe(204);

		const denyRes = await handlers.POST(
			new Request(`${BASE_URL}/authorize/token`, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${token}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ action: "read", resource: "mcp:github" }),
			}),
		);
		expect(denyRes.status).toBe(403);
		const denyBody = (await denyRes.json()) as { data: { allowed: boolean; reason: string } };
		expect(denyBody.data.allowed).toBe(false);
		expect(denyBody.data.reason).toContain("Invalid or expired");
	});

	it("serves MCP preflight responses with CORS headers", async () => {
		const res = await handlers.OPTIONS(
			new Request(`${BASE_URL}/mcp/register`, { method: "OPTIONS" }),
		);

		expect(res.status).toBe(204);
		expect(res.headers.get("access-control-allow-origin")).toBe("*");
		expect(res.headers.get("access-control-allow-methods")).toContain("OPTIONS");
	});
});
