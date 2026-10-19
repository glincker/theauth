import { describe, expect, it } from "vitest";
import * as schema from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";

const PERMS = [{ resource: "mcp:github:*", actions: ["read"] }];

describe("agent.revoke with same-named agents", () => {
	it("revokes only the agent id given, never a same-named agent of the same owner", async () => {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], tokenExpiry: "24h" },
		});
		theauth.db
			.insert(schema.users)
			.values({
				id: "user-1",
				email: "u@example.com",
				name: "U",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
		const mk = () =>
			theauth.agent.create({
				ownerId: "user-1",
				name: "deploy-bot",
				type: "autonomous",
				permissions: PERMS,
			});
		const first = await mk();
		const second = await mk();

		await theauth.agent.revoke(first.id);

		expect((await theauth.agent.get(first.id))?.status).toBe("revoked");
		expect((await theauth.agent.get(second.id))?.status).toBe("active");
		expect(await theauth.agent.validateToken(first.token)).toBeNull();
		expect((await theauth.agent.validateToken(second.token))?.id).toBe(second.id);
	});
});
