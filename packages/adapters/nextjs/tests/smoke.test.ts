import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { requireScope, theAuthNextjs } from "../src/index.js";

describe("nextjs adapter smoke", () => {
	it("serves the handler, authorizes by token, and guards routes with requireScope", async () => {
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
		const now = new Date();
		await theauth.db
			.insert(users)
			.values({ id: "u1", email: "u1@test.com", name: "u1", createdAt: now, updatedAt: now });
		const agent = await theauth.agent.create({
			ownerId: "u1",
			name: "smoke",
			type: "autonomous",
			permissions: [{ resource: "docs", actions: ["read"] }],
		});
		const handlers = theAuthNextjs(theauth, { authenticate: async () => ({ id: "admin" }) });
		const read = requireScope(theauth, { action: "read", resource: "docs" })(async (_req, a) =>
			Response.json({ id: a.id }),
		);
		const write = requireScope(theauth, { action: "write", resource: "docs" })(
			async () => new Response("ok"),
		);
		const bearer = { Authorization: `Bearer ${agent.token}` };

		const allowed = await handlers.POST(
			new Request("http://localhost/api/theauth/authorize/token", {
				method: "POST",
				headers: { ...bearer, "Content-Type": "application/json" },
				body: JSON.stringify({ action: "read", resource: "docs" }),
			}),
		);
		expect(allowed.status).toBe(200);

		const url = "http://localhost/docs";
		expect((await read(new Request(url, { headers: bearer }))).status).toBe(200);
		expect((await read(new Request(url))).status).toBe(401);
		expect((await write(new Request(url, { headers: bearer }))).status).toBe(403);
	});
});
