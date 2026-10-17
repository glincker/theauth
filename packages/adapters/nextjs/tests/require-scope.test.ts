import { beforeAll, describe, expect, it } from "vitest";
import * as schema from "../../../core/src/db/schema.js";
import type { TheAuth } from "../../../core/src/theauth.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { requireScope } from "../src/require-scope.js";

describe("requireScope (nextjs)", () => {
	let theauth: TheAuth;
	let token: string;
	let agentId: string;

	beforeAll(async () => {
		theauth = await createTheAuth({
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
				id: "u1",
				email: "u1@example.com",
				name: "U1",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
		const agent = await theauth.agent.create({
			ownerId: "u1",
			name: "scoped",
			type: "autonomous",
			permissions: [{ resource: "docs", actions: ["read"] }],
		});
		token = agent.token;
		agentId = agent.id;
	});

	const guard = (action: string) =>
		requireScope(theauth, { action, resource: "docs" })(async (_req, agent) =>
			Response.json({ agentId: agent.id }),
		);
	const call = (handler: (r: Request) => Promise<Response>, auth?: string) =>
		handler(
			new Request("http://localhost/api/docs", auth ? { headers: { Authorization: auth } } : {}),
		);

	it("returns 401 when the token is missing", async () => {
		expect((await call(guard("read"))).status).toBe(401);
	});

	it("returns 401 for an invalid token", async () => {
		expect((await call(guard("read"), "Bearer kv_nope")).status).toBe(401);
	});

	it("returns 403 with the reason when the scope is not granted", async () => {
		const res = await call(guard("write"), `Bearer ${token}`);
		expect(res.status).toBe(403);
		const body = (await res.json()) as { error: { code: string; message: string } };
		expect(body.error.code).toBe("FORBIDDEN");
		expect(body.error.message.length).toBeGreaterThan(0);
	});

	it("passes the agent to the handler when allowed", async () => {
		const res = await call(guard("read"), `Bearer ${token}`);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ agentId });
	});
});
