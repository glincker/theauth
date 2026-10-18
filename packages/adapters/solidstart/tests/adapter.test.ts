import { beforeEach, describe, expect, it } from "vitest";
import * as schema from "../../../core/src/db/schema.js";
import type { TheAuth } from "../../../core/src/theauth.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthSolidStart } from "../src/adapter.js";

const BASE_URL = "http://localhost/api/auth/theauth";
const BASE_PERMISSIONS = [{ resource: "mcp:github", actions: ["read"] }];

type Handlers = ReturnType<typeof theAuthSolidStart>;
type CorsOption = NonNullable<Parameters<typeof theAuthSolidStart>[1]>["cors"];

async function createTestHandlers(
	cors?: CorsOption,
): Promise<{ handlers: Handlers; theauth: TheAuth }> {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	theauth.db
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
		handlers: theAuthSolidStart(theauth, {
			basePath: "/api/auth/theauth",
			allowUnauthenticated: true,
			cors,
		}),
		theauth,
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

describe("SolidStart adapter", () => {
	let handlers: Handlers;

	beforeEach(async () => {
		({ handlers } = await createTestHandlers());
	});

	it("uses the configured basePath for create, list, and fetch", async () => {
		const { id } = await createTestAgent(handlers, { name: "solidstart-agent" });

		const listRes = await handlers.GET(
			new Request(`${BASE_URL}/agents?userId=user-1`, { method: "GET" }),
		);
		expect(listRes.status).toBe(200);
		const listBody = (await listRes.json()) as { data: Array<{ name: string }> };
		expect(listBody.data).toHaveLength(1);
		expect(listBody.data[0]?.name).toBe("solidstart-agent");

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
		expect(denyRes.status).toBe(401); // revoked agent: identity failure, 401 on every adapter
		const denyBody = (await denyRes.json()) as { data: { allowed: boolean; reason: string } };
		expect(denyBody.data.allowed).toBe(false);
		expect(denyBody.data.reason).toContain("Invalid or expired");
	});

	const ORIGIN = "https://app.example.com";
	const CORS = { origins: [ORIGIN], groups: { register: true } };

	function preflight(origin: string): Request {
		return new Request(`${BASE_URL}/mcp/register`, {
			method: "OPTIONS",
			headers: { Origin: origin, "Access-Control-Request-Method": "POST" },
		});
	}

	it("sends no CORS headers on a preflight when cors is not configured", async () => {
		const res = await handlers.OPTIONS(preflight(ORIGIN));
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
	});

	it("serves MCP preflight responses for the configured origin only", async () => {
		const { handlers: corsHandlers } = await createTestHandlers(CORS);
		const res = await corsHandlers.OPTIONS(preflight(ORIGIN));
		expect(res.status).toBe(204);
		expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
		expect(res.headers.get("vary")).toContain("Origin");
		expect(res.headers.get("access-control-allow-methods")).toContain("POST");
		expect(res.headers.get("access-control-allow-methods")).toContain("OPTIONS");

		const other = await corsHandlers.OPTIONS(preflight("https://evil.example.com"));
		expect(other.headers.get("access-control-allow-origin")).toBeNull();
	});
});
