import { beforeEach, describe, expect, it, vi } from "vitest";
import * as schema from "../../../packages/core/src/db/schema.js";
import type { TheAuth } from "../../../packages/core/src/kavach.js";
import { createTheAuth } from "../../../packages/core/src/kavach.js";

const state = vi.hoisted(() => ({ kavach: null as TheAuth | null }));

vi.mock("@/lib/kavach", () => ({
	getKavach: async () => state.kavach,
}));

vi.mock("@glinr/theauth-nextjs", async () => {
	return import("../../../packages/adapters/nextjs/src/adapter.ts");
});

async function loadRouteModule() {
	vi.resetModules();
	return import("../app/api/theauth/[...path]/route.ts");
}

describe("nextjs-app example", () => {
	beforeEach(async () => {
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

		kavach.db
			.insert(schema.users)
			.values({
				id: "user-1",
				email: "demo@theauth.dev",
				name: "Demo User",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();

		state.kavach = kavach;
	});

	it("mounts the catch-all route and serves the TheAuth API under /api/theauth", async () => {
		const route = await loadRouteModule();

		const emptyListRes = await route.GET(
			new Request("http://localhost/api/theauth/agents?userId=user-1"),
		);
		expect(emptyListRes.status).toBe(200);
		expect(((await emptyListRes.json()) as { data: unknown[] }).data).toHaveLength(0);

		const createRes = await route.POST(
			new Request("http://localhost/api/theauth/agents", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					ownerId: "user-1",
					name: "next-app-agent",
					type: "autonomous",
					permissions: [{ resource: "mcp:github", actions: ["read"] }],
				}),
			}),
		);
		expect(createRes.status).toBe(201);
		const created = (await createRes.json()) as {
			data: { id: string; token: string; name: string };
		};
		expect(created.data.name).toBe("next-app-agent");
		expect(created.data.token).toMatch(/^kv_/);

		const statsRes = await route.GET(new Request("http://localhost/api/theauth/dashboard/stats"));
		expect(statsRes.status).toBe(200);
		const stats = (await statsRes.json()) as { data: { agents: { total: number } } };
		expect(stats.data.agents.total).toBe(1);

		const deleteRes = await route.DELETE(
			new Request(`http://localhost/api/theauth/agents/${created.data.id}`, {
				method: "DELETE",
			}),
		);
		expect(deleteRes.status).toBe(204);
	});
});
