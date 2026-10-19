/** GET /agents/:id?include=delegated adds live delegated permissions; the plain GET is unchanged. */
import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../../src/http/index.js";
import { createTheAuth } from "../../src/theauth.js";
import { BASE, SESSION_SECRET, sessionToken } from "./helpers.js";

describe("GET /agents/:id include=delegated", () => {
	it("returns delegated permissions only when asked", async () => {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
			auth: { session: { secret: SESSION_SECRET } },
		});
		const token = await sessionToken(auth, "u1");
		const handler = createTheAuthHandler(auth, { rateLimit: false });
		const get = async (path: string) =>
			(await (
				await handler(
					new Request(`${BASE}${path}`, { headers: { authorization: `Bearer ${token}` } }),
				)
			).json()) as { data: Record<string, unknown> };
		const grant = [{ resource: "ros2:/fleet/a", actions: ["publish"] }];
		const parent = await auth.agent.create({
			ownerId: "u1",
			name: "p",
			type: "autonomous",
			permissions: grant,
		});
		const robot = await auth.agent.create({
			ownerId: "u1",
			name: "r",
			type: "autonomous",
			permissions: [],
		});
		await auth.delegate({
			fromAgent: parent.id,
			toAgent: robot.id,
			permissions: grant,
			expiresAt: new Date(Date.now() + 3_600_000),
		});
		const plain = await get(`/agents/${robot.id}`);
		expect(plain.data.delegatedPermissions).toBeUndefined();
		const full = await get(`/agents/${robot.id}?include=delegated`);
		expect(full.data.delegatedPermissions).toEqual(grant);
	});
});
